#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def load_json(p: Path, default=None):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def save_json(p: Path, obj: Any):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def load_csv(p: Path) -> List[Dict[str, str]]:
    try:
        return list(csv.DictReader(p.open(encoding="utf-8", errors="ignore")))
    except Exception:
        return []


def norm_addr(x: Any) -> str:
    if not x:
        return ""
    try:
        return f"0x{int(str(x), 0):X}"
    except Exception:
        return str(x)


def mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


class Runner:
    def __init__(self, args):
        self.args = args
        self.repo = Path(args.repo).resolve()
        self.out_root = (self.repo / args.out_root).resolve() if not Path(args.out_root).is_absolute() else Path(args.out_root)
        self.timeline = self.out_root / "timeline.csv"
        self.state_path = self.out_root / "controller_state.json"
        self.summary_path = self.out_root / "final_summary.json"
        self.states_completed: List[str] = []
        self.failed = False
        self.failure_reason = ""
        mkdir(self.out_root)
        mkdir(self.out_root / "logs")
        self.firmware_config = self.infer_firmware_config()
        self.init_timeline()

    def infer_firmware_config(self) -> str:
        """
        Infer firmware config path for the current case from the JSONL manifest.
        This keeps long validation generic instead of hard-coding Heat_Press.
        """
        manifest = Path(self.args.manifest)
        if not manifest.is_absolute():
            manifest = self.repo / manifest

        if not manifest.exists():
            raise RuntimeError(f"manifest not found: {manifest}")

        def row_matches(row):
            for k in ("case_id", "id", "target_id", "name"):
                if str(row.get(k, "")) == self.args.case_id:
                    return True
            # Fallback: exact value match somewhere in the row.
            return any(str(v) == self.args.case_id for v in row.values())

        def scan_strings(obj, out):
            if isinstance(obj, dict):
                for v in obj.values():
                    scan_strings(v, out)
            elif isinstance(obj, list):
                for v in obj:
                    scan_strings(v, out)
            elif isinstance(obj, str):
                out.append(obj)

        matched = None
        for line in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row_matches(row):
                matched = row
                break

        if matched is None:
            raise RuntimeError(f"case_id not found in manifest: {self.args.case_id}")

        strings = []
        scan_strings(matched, strings)

        # Prefer explicit config.yml/config.yaml-looking paths.
        candidates = []
        for x in strings:
            low = x.lower()
            if (low.endswith(".yml") or low.endswith(".yaml")) and "config" in low:
                candidates.append(x)

        # Secondary: any YAML under benchmarks.
        for x in strings:
            low = x.lower()
            if "benchmarks/" in low and (low.endswith(".yml") or low.endswith(".yaml")):
                if x not in candidates:
                    candidates.append(x)

        for x in candidates:
            q = Path(x)
            if not q.is_absolute():
                q_abs = self.repo / q
            else:
                q_abs = q
            if q_abs.exists():
                try:
                    return str(q_abs.relative_to(self.repo))
                except Exception:
                    return str(q_abs)

        raise RuntimeError(
            f"cannot infer firmware config for {self.args.case_id}; "
            f"candidate yaml strings={candidates[:10]}"
        )


    def rel(self, p: Path | str) -> str:
        p = Path(p)
        try:
            return str(p.relative_to(self.repo))
        except Exception:
            return str(p)

    def init_timeline(self):
        if not self.timeline.exists():
            with self.timeline.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=[
                    "time", "state", "status", "decision", "reason", "path"
                ])
                w.writeheader()

    def log_state(self, state: str, status: str = "ok", decision: str = "", reason: str = "", path: str = ""):
        self.states_completed.append(state)
        with self.timeline.open("a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=[
                "time", "state", "status", "decision", "reason", "path"
            ])
            w.writerow({
                "time": now(),
                "state": state,
                "status": status,
                "decision": decision,
                "reason": reason,
                "path": path,
            })
        self.write_state(state, status, decision, reason, path)

    def write_state(self, state: str, status: str, decision: str, reason: str, path: str):
        save_json(self.state_path, {
            "case_id": self.args.case_id,
            "mode": self.args.mode,
            "current_state": state,
            "status": status,
            "decision": decision,
            "reason": reason,
            "path": path,
            "states_completed": self.states_completed,
            "updated_at": now(),
        })

    def fail(self, state: str, reason: str):
        self.failed = True
        self.failure_reason = reason
        self.log_state(state, status="failed", reason=reason)
        self.finalize()

    def run_cmd(self, state: str, cmd: List[str], log_name: str, allow_fail: bool = False):
        log_path = self.out_root / "logs" / log_name
        self.log_state(state, status="running", path=self.rel(log_path))

        print(f"\n===== {state} =====")
        print(" ".join(cmd))
        print("log:", log_path)

        with log_path.open("w", encoding="utf-8", errors="ignore") as f:
            f.write(f"[time] {now()}\n")
            f.write("[cmd] " + " ".join(cmd) + "\n\n")
            p = subprocess.run(
                cmd,
                cwd=self.repo,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
            )

        if p.returncode != 0 and not allow_fail:
            self.fail(state, f"command failed rc={p.returncode}; see {self.rel(log_path)}")
            raise SystemExit(1)

        self.log_state(state, status="ok", path=self.rel(log_path))
        return p.returncode

    def find_latest_event(self, root: Path) -> Optional[Path]:
        events = sorted(root.glob("**/bottleneck_events/bottleneck_*"))
        events = [e for e in events if (e / "signature.json").exists()]
        if events:
            return events[-1]

        events = sorted(root.glob("**/chain_events/chain_*"))
        events = [e for e in events if (e / "signature.json").exists()]
        return events[-1] if events else None

    def infer_target_addr_from_context(self, event_dir: Path) -> str:
        ctx = load_json(event_dir / "llm_context.json", {}) or {}
        hs = ctx.get("hotspots") or []
        if hs and isinstance(hs[0], dict):
            return norm_addr(hs[0].get("addr"))

        sig = load_json(event_dir / "signature.json", {}) or {}
        focus = sig.get("chain_focus_addr")
        if focus:
            return norm_addr(focus)

        latest = sig.get("signature_key", {}).get("latest_mmio_top_addrs", "")
        m = re.search(r"0x[0-9a-fA-F]+", str(latest))
        if m:
            return norm_addr(m.group(0))

        return ""


    def depth1_all_guidance_not_consumed(self, val_root: Path) -> bool:
        """
        Return True when depth1 short validation produced candidates, but every
        non-control candidate was classified as guidance_not_consumed.
        This prevents wasting a Depth2 LLM/materialization round on candidates
        that never fired at Depth1.
        """
        csv_path = val_root / "short_validation_summary_robust.csv"
        if not csv_path.exists():
            csv_path = val_root / "short_validation_summary.csv"
        if not csv_path.exists():
            return False

        rows = []
        with csv_path.open(newline="") as f:
            for r in csv.DictReader(f):
                rows.append(r)

        non_control = [
            r for r in rows
            if (r.get("candidate_id") or r.get("id") or "").strip() != "control"
        ]
        if not non_control:
            return False

        return all(
            (r.get("classification") or "").strip() == "guidance_not_consumed"
            for r in non_control
        )

    def infer_import_queue_from_event(self, event_dir: Path) -> Path:
        sig = load_json(event_dir / "signature.json", {}) or {}
        run_root = Path((sig.get("latest_history_row") or {}).get("run_root", ""))
        if run_root:
            q = run_root / "workdir" / "queue"
            if not q.is_absolute():
                q = self.repo / q
            if q.exists():
                return q

        # For chain event from shift.
        sel = load_json(event_dir / "chain_selection.json", {}) or {}
        run_root_s = (((sel.get("selected") or {}).get("row") or {}).get("run_root"))
        if run_root_s:
            q = Path(run_root_s) / "workdir" / "queue"
            if not q.is_absolute():
                q = self.repo / q
            if q.exists():
                return q

        raise RuntimeError(f"cannot infer import queue from {event_dir}")

    def create_event_from_random_history(self, random_root: Path) -> Path:
        """
        Fallback event creator if run_random_until_bottleneck.py did not create bottleneck_events.
        This is intentionally generic: it copies the latest CSV row into signature.json.
        """
        existing = self.find_latest_event(random_root)
        if existing:
            return existing

        hist = random_root / "random_bottleneck_history.csv"
        if not hist.exists():
            # Some scripts put it under case-id directory.
            hits = list(random_root.glob("**/random_bottleneck_history.csv"))
            if hits:
                hist = hits[0]
        rows = load_csv(hist)
        if not rows:
            raise RuntimeError(f"no random history rows found under {random_root}")

        # Prefer confirmed/reached/bottleneck rows, otherwise last row.
        selected = None
        for r in reversed(rows):
            st = (r.get("status") or "").lower()
            if "bottleneck" in st or "trap" in st:
                selected = r
                break
        if selected is None:
            selected = rows[-1]

        event = random_root / self.args.case_id / "bottleneck_events" / "bottleneck_001"
        mkdir(event)

        top_addrs = (
            selected.get("mmio_top_addrs")
            or selected.get("top_mmio_addrs")
            or selected.get("latest_mmio_top_addrs")
            or selected.get("mmio_top")
            or ""
        )

        sig = {
            "schema": "multifuzz_bottleneck_signature_v1",
            "case_id": self.args.case_id,
            "created_at": now(),
            "source": "run_llm_chain_closed_loop.py:fallback_create_event",
            "latest_history_row": selected,
            "signature_key": {
                "latest_mmio_top_addrs": top_addrs,
                "status": selected.get("status"),
                "decision": selected.get("decision"),
                "reasons": selected.get("reasons"),
            },
        }
        save_json(event / "signature.json", sig)
        return event

    def choose_best_guidance_from_index(self, index_path: Path, prefer_candidate_id: Optional[str] = None) -> Optional[Path]:
        idx = load_json(index_path, {}) or {}
        compiled = idx.get("compiled") or []
        if not compiled:
            return None

        if prefer_candidate_id:
            for item in compiled:
                if item.get("candidate_id") == prefer_candidate_id:
                    return Path(item["guidance_path"])

        return Path(compiled[0]["guidance_path"])

    def choose_prefix_from_score_or_shift(self, guidance_index: Path, shift_csv: Path, score_csv: Optional[Path] = None) -> Optional[Path]:
        # Prefer score decisions if available.
        if score_csv and score_csv.exists():
            rows = load_csv(score_csv)
            for decision in ["return_to_random_candidate", "promising_stack_repeat", "partial_stack_repeat"]:
                for r in rows:
                    if r.get("decision") == decision and r.get("candidate_id") != "control":
                        p = self.choose_best_guidance_from_index(guidance_index, r["candidate_id"])
                        if p:
                            return p

        # Fallback to selected row from shift candidate.
        rows = load_csv(shift_csv)
        best = None
        best_score = -10**9
        for r in rows:
            if r.get("candidate_id") == "control":
                continue
            try:
                fire = int(r.get("fire_lines") or 0)
                target_delta = int(r.get("target_delta_vs_control") or 0)
                next_count = int(r.get("next_non_target_count") or 0)
            except Exception:
                continue
            score = fire * 2 + max(0, -target_delta) + next_count
            if score > best_score:
                best_score = score
                best = r.get("candidate_id")
        if best:
            return self.choose_best_guidance_from_index(guidance_index, best)

        return self.choose_best_guidance_from_index(guidance_index)

    def run(self):
        if self.args.mode != "closure-smoke":
            raise SystemExit("v0 only supports --mode closure-smoke")

        self.log_state("INIT", decision="start_closure_smoke")

        # 1. Random until bottleneck.
        random_root = self.out_root / "random_until_bottleneck"
        mkdir(random_root)

        self.run_cmd("RANDOM_UNTIL_BOTTLENECK", [
            "python3", "scripts/newmulti_ab/run_random_until_bottleneck.py",
            "--repo", str(self.args.repo),
            "--manifest", str(self.args.manifest),
            "--case-id", self.args.case_id,
            "--out-root", str(random_root),
            "--engine", "newmulti-guided-warmup",
            "--reps", str(self.args.random_reps),
            "--chunk-run-for", self.args.random_chunk_run_for,
            "--max-iters", str(self.args.random_max_iters),
            "--majority", "2",
            "--consecutive", "2",
            "--window-s", str(self.args.window_s),
            "--min-elapsed-s", str(self.args.min_elapsed_s),
        ], "01_random_until_bottleneck.log")

        event = self.create_event_from_random_history(random_root)
        self.log_state("BOTTLENECK_EVENT", decision="event_ready", path=self.rel(event))

        # 2. Build context.
        self.run_cmd("BUILD_CONTEXT_DEPTH1", [
            "python3", "scripts/newmulti_ab/build_bottleneck_context.py",
            "--repo", str(self.args.repo),
            "--manifest", str(self.args.manifest),
            "--event-dir", str(event),
        ], "02_build_context_depth1.log")

        # 3. LLM plan.
        self.run_cmd("LLM_PLAN_DEPTH1", [
            "python3", "scripts/newmulti_ab/llm_plan_guidance_from_context.py",
            "--event-dir", str(event),
            "--model", self.args.llm_model,
            "--timeout-s", str(self.args.llm_timeout_s),
            "--max-output-tokens", str(self.args.llm_max_output_tokens),
            "--feedback-md", str(self.args.feedback_md),
        ], "03_llm_plan_depth1.log")

        # 4. Materialize first guidance.
        guidance1 = event / "guidance_chain_v1"
        shutil.rmtree(guidance1, ignore_errors=True)
        self.run_cmd("MATERIALIZE_DEPTH1", [
            "python3", "scripts/newmulti_ab/materialize_chain_guidance_plan.py",
            "--event-dir", str(event),
            "--out-dir", str(guidance1),
            "--priority-max", "3",
            "--max-candidates", str(self.args.materialize_max_candidates),
            "--repeat", "100000",
        ], "04_materialize_depth1.log", allow_fail=True)

        # Fallback: if chain materializer produced no candidates, use round2 read actions.
        idx1 = guidance1 / "guidance_index.json"
        if not idx1.exists() or len((load_json(idx1, {}) or {}).get("compiled", [])) == 0:
            guidance1 = event / "guidance_round2"
            shutil.rmtree(guidance1, ignore_errors=True)
            self.run_cmd("MATERIALIZE_DEPTH1_FALLBACK_ROUND2", [
                "python3", "scripts/newmulti_ab/materialize_round2_read_actions.py",
                "--event-dir", str(event),
                "--out-dir", str(guidance1),
                "--max-candidates", str(self.args.materialize_max_candidates),
                "--repeat", "100000",
            ], "04b_materialize_round2_depth1.log")

        idx1 = guidance1 / "guidance_index.json"
        if not idx1.exists():
            self.fail("MATERIALIZE_DEPTH1", "no guidance_index.json produced")
            return

        # 5. Short validation depth1.
        val1 = self.out_root / "validation_depth1"
        shutil.rmtree(val1, ignore_errors=True)
        depth1_compiled = (load_json(idx1, {}) or {}).get("compiled", [])
        if len(depth1_compiled) == 0:
            self.log_state(
                "SHORT_VALIDATE_SKIPPED_NO_DEPTH1_CANDIDATE",
                status="ok",
                decision="chain_no_materialized_candidate",
                reason="Depth1 materialization and fallback produced an empty candidate index; skip short validation/shift/depth2.",
                path=self.rel(idx1),
            )
            self.log_state(
                "LONG_VALIDATE_SKIPPED_NO_MATERIALIZED_CANDIDATE",
                status="ok",
                decision="chain_no_materialized_candidate",
                reason="No materialized candidate was available after manifest-scoped materialization.",
                path=self.rel(idx1),
            )
            self.finalize()
            return

        import_q = self.infer_import_queue_from_event(event)

        self.run_cmd("SHORT_VALIDATE_DEPTH1", [
            "python3", "scripts/newmulti_ab/run_guidance_short_validation.py",
            "--repo", str(self.args.repo),
            "--firmware-config", self.firmware_config,
            "--event-dir", str(event),
            "--guidance-index", str(idx1),
            "--out-root", str(val1),
            "--import-dir", str(import_q),
            "--run-for", self.args.short_run_for,
            "--max-candidates", str(self.args.short_max_candidates),
        ], "05_short_validate_depth1.log")

        addr1 = self.infer_target_addr_from_context(event)
        if not addr1:
            self.fail("INFER_TARGET_DEPTH1", "cannot infer target addr depth1")
            return

        self.run_cmd("RESUMMARIZE_DEPTH1", [
            "python3", "scripts/newmulti_ab/resummarize_short_validation.py",
            "--batch-root", str(val1),
            "--target-addr", addr1,
        ], "06_resummarize_depth1.log")

        if self.depth1_all_guidance_not_consumed(val1):
            self.log_state(
                "DEPTH1_GUIDANCE_NOT_CONSUMED",
                status="ok",
                decision="gate_no_firing_candidate",
                reason="All non-control Depth1 candidates were classified as guidance_not_consumed; skip shift/depth2 and retarget/refine trigger conditions.",
                path=self.rel(val1 / "short_validation_summary_robust.csv"),
            )
            self.log_state(
                "LONG_VALIDATE_SKIPPED_NO_FIRING_DEPTH1",
                status="ok",
                decision="gate_no_firing_candidate",
                reason="No Depth1 candidate fired during short validation.",
                path=self.rel(val1),
            )
            self.finalize()
            return

        self.run_cmd("SHIFT_ANALYZE_DEPTH1", [
            "python3", "scripts/newmulti_ab/analyze_bottleneck_shift.py",
            "--batch-root", str(val1),
            "--target-addr", addr1,
            "--top-k", "12",
            "--target-reduce-min", "300",
            "--next-min-count", "500",
            "--next-vs-target-ratio", "0.8",
        ], "07_shift_depth1.log")

        # 6. Create chain event if depth allowed.
        chain_event = None
        if self.args.max_chain_depth >= 2:
            chain_root = self.out_root / "chain_events"
            chain_event = chain_root / "chain_002"
            shutil.rmtree(chain_event, ignore_errors=True)

            self.run_cmd("CREATE_CHAIN_EVENT_DEPTH2", [
                "python3", "scripts/newmulti_ab/create_chain_event_from_shift.py",
                "--source-event-dir", str(event),
                "--shift-csv", str(val1 / "bottleneck_shift_summary.csv"),
                "--out-event-dir", str(chain_event),
                "--chain-depth", "2",
            ], "08_create_chain_event_depth2.log")

            self.run_cmd("BUILD_CONTEXT_DEPTH2", [
                "python3", "scripts/newmulti_ab/build_bottleneck_context.py",
                "--repo", str(self.args.repo),
                "--manifest", str(self.args.manifest),
                "--event-dir", str(chain_event),
            ], "09_build_context_depth2.log")

            self.run_cmd("LLM_PLAN_DEPTH2", [
                "python3", "scripts/newmulti_ab/llm_plan_guidance_from_context.py",
                "--event-dir", str(chain_event),
                "--model", self.args.llm_model,
                "--timeout-s", str(self.args.llm_timeout_s),
                "--max-output-tokens", str(self.args.llm_max_output_tokens),
                "--feedback-md", str(self.args.feedback_md),
            ], "10_llm_plan_depth2.log")

            guidance2 = chain_event / "guidance_chain"
            shutil.rmtree(guidance2, ignore_errors=True)
            self.run_cmd("MATERIALIZE_DEPTH2", [
                "python3", "scripts/newmulti_ab/materialize_chain_guidance_plan.py",
                "--event-dir", str(chain_event),
                "--out-dir", str(guidance2),
                "--priority-max", "3",
                "--max-candidates", str(self.args.materialize_max_candidates),
                "--repeat", "100000",
            ], "11_materialize_depth2.log")

            idx2 = guidance2 / "guidance_index.json"
            if not idx2.exists():
                self.fail("MATERIALIZE_DEPTH2", "no guidance_index.json produced")
                return

            depth2_compiled = (load_json(idx2, {}) or {}).get("compiled", [])
            if len(depth2_compiled) == 0:
                self.log_state(
                    "BUILD_STACK_DEPTH2",
                    status="ok",
                    decision="chain_no_materialized_candidate",
                    reason="Depth2 materialization produced an empty candidate index; skip stack/gate/long validation.",
                    path=self.rel(idx2),
                )
                self.log_state(
                    "LONG_VALIDATE_SKIPPED_NO_DEPTH2_CANDIDATE",
                    status="ok",
                    decision="chain_no_materialized_candidate",
                    reason="No depth2 candidate was available after manifest-scoped materialization.",
                    path=self.rel(idx2),
                )
                self.finalize()
                return

            # 7. Build stack: prefix from depth1 + all depth2 candidates.
            prefix = self.choose_prefix_from_score_or_shift(
                guidance_index=idx1,
                shift_csv=val1 / "bottleneck_shift_summary.csv",
            )
            if not prefix or not prefix.exists():
                self.fail("BUILD_STACK", "cannot select prefix guidance")
                return

            stack_dir = chain_event / "guidance_stack"
            shutil.rmtree(stack_dir, ignore_errors=True)
            self.run_cmd("BUILD_STACK_DEPTH2", [
                "python3", "scripts/newmulti_ab/build_guidance_stack.py",
                "--out-dir", str(stack_dir),
                "--prefix-guidance", str(prefix),
                "--candidate-index", str(idx2),
            ], "12_build_stack_depth2.log")

            # 8. Stack validation.
            stack_val = self.out_root / "validation_stack_depth2"
            shutil.rmtree(stack_val, ignore_errors=True)
            self.run_cmd("SHORT_VALIDATE_STACK_DEPTH2", [
                "python3", "scripts/newmulti_ab/run_guidance_short_validation.py",
                "--repo", str(self.args.repo),
                "--firmware-config", self.firmware_config,
                "--event-dir", str(chain_event),
                "--guidance-index", str(stack_dir / "guidance_index.json"),
                "--out-root", str(stack_val),
                "--import-dir", str(import_q),
                "--run-for", self.args.short_run_for,
                "--max-candidates", str(self.args.stack_short_max_candidates),
            ], "13_short_validate_stack_depth2.log")

            addr2 = self.infer_target_addr_from_context(chain_event)
            if not addr2:
                self.fail("INFER_TARGET_DEPTH2", "cannot infer target addr depth2")
                return

            self.run_cmd("RESUMMARIZE_STACK_OLD_TARGET", [
                "python3", "scripts/newmulti_ab/resummarize_short_validation.py",
                "--batch-root", str(stack_val),
                "--target-addr", addr1,
            ], "14_resummarize_stack_old.log")
            shutil.copyfile(stack_val / "short_validation_summary_robust.csv", stack_val / f"summary_target_{addr1.replace('0x','').replace('0X','')}.csv")

            self.run_cmd("RESUMMARIZE_STACK_NEW_TARGET", [
                "python3", "scripts/newmulti_ab/resummarize_short_validation.py",
                "--batch-root", str(stack_val),
                "--target-addr", addr2,
            ], "15_resummarize_stack_new.log")
            shutil.copyfile(stack_val / "short_validation_summary_robust.csv", stack_val / f"summary_target_{addr2.replace('0x','').replace('0X','')}.csv")

            self.run_cmd("SHIFT_ANALYZE_STACK", [
                "python3", "scripts/newmulti_ab/analyze_bottleneck_shift.py",
                "--batch-root", str(stack_val),
                "--target-addr", addr2,
                "--top-k", "12",
                "--target-reduce-min", "300",
                "--next-min-count", "500",
                "--next-vs-target-ratio", "0.8",
            ], "16_shift_stack.log")

            score_csv = stack_val / "stack_score_summary.csv"
            self.run_cmd("SCORE_STACK", [
                "python3", "scripts/newmulti_ab/score_guidance_stack.py",
                "--old-target-summary", str(stack_val / f"summary_target_{addr1.replace('0x','').replace('0X','')}.csv"),
                "--new-target-summary", str(stack_val / f"summary_target_{addr2.replace('0x','').replace('0X','')}.csv"),
                "--shift-summary", str(stack_val / "bottleneck_shift_summary.csv"),
                "--out-csv", str(score_csv),
                "--out-json", str(stack_val / "stack_score_summary.json"),
            ], "17_score_stack.log")

            # 9. Repeat-gate top candidates before long validation.
            # This prevents non-fired or unstable candidates from being promoted
            # directly into long validation.
            gate_root = self.out_root / "repeat_gate_stack_depth2"
            shutil.rmtree(gate_root, ignore_errors=True)

            self.run_cmd("REPEAT_GATE_STACK_DEPTH2", [
                "python3", "scripts/newmulti_ab/repeat_gate_long_candidates.py",
                "--repo", str(self.args.repo),
                "--case-root", str(self.out_root),
                "--stack-index", str(stack_dir / "guidance_index.json"),
                "--score-csv", str(score_csv),
                "--import-dir", str(import_q),
                "--firmware-config", self.firmware_config,
                "--out-root", str(gate_root),
                "--run-for", self.args.gate_run_for,
                "--top-k", str(self.args.gate_top_k),
                "--repeats", str(self.args.gate_repeats),
            ], "18_repeat_gate_stack_depth2.log")

            # 10. Long validate only repeat-gate-promoted candidates.
            # Hard invariant: long validation candidates must come from
            # repeat_gate_stack_depth2/promoted_candidates.json. Do not fall
            # back to stack_score_summary.csv or guidance_index.json here.
            promoted_candidates = self.load_repeat_gate_promoted_candidates(
                gate_root / "promoted_candidates.json",
                self.args.top_k_repeat,
            )

            if promoted_candidates:
                long_root = self.out_root / "long_validation"
                shutil.rmtree(long_root, ignore_errors=True)
                mkdir(long_root)

                with (long_root / "selected_candidates.json").open("w", encoding="utf-8") as f:
                    json.dump([
                        {
                            "candidate_id": x.get("candidate_id"),
                            "guidance_path": str(x.get("guidance_path")),
                            "source": x.get("source"),
                            "pass_gate": x.get("pass_gate"),
                        }
                        for x in promoted_candidates
                    ], f, indent=2)

                top_candidates = [Path(x["guidance_path"]) for x in promoted_candidates]
                self.run_long_validation(long_root, import_q, top_candidates, addr1, addr2)
            else:
                gate_stats = self.summarize_repeat_gate(gate_root / "repeat_gate_aggregate.csv")
                if gate_stats.get("candidate_count", 0) == 0:
                    gate_decision = "repeat_gate_no_pass_candidate"
                    gate_reason = "repeat gate selected no promotable candidates; skip long candidate validation"
                elif gate_stats.get("fire_positive_count", 0) == 0:
                    gate_decision = "gate_no_firing_candidate"
                    gate_reason = "repeat gate produced no firing candidate"
                elif gate_stats.get("pass_gate_count", 0) == 0:
                    gate_decision = "repeat_gate_no_pass_candidate"
                    gate_reason = "repeat gate produced active candidates but none passed stability gate"
                else:
                    gate_decision = "repeat_gate_no_pass_candidate"
                    gate_reason = "no promoted candidates were written by repeat gate"

                self.log_state(
                    "LONG_VALIDATE_SKIPPED_NO_REPEAT_GATE_PASS",
                    status="ok",
                    decision=gate_decision,
                    reason=gate_reason,
                    path=self.rel(gate_root / "promoted_candidates.json"),
                )

        self.finalize()

    def load_repeat_gate_promoted_candidates(self, promoted_json: Path, k: int) -> List[Dict[str, Any]]:
        """Load the only legal long-validation candidates.

        Candidates must have passed repeat gate and must include an existing
        guidance file. This intentionally has no fallback to stack scoring.
        """
        data = load_json(promoted_json, {}) or {}
        promoted = data.get("promoted") or []
        out: List[Dict[str, Any]] = []
        for item in promoted:
            if not item.get("pass_gate"):
                continue
            cid = item.get("candidate_id")
            gpath = item.get("guidance_path")
            if not cid or not gpath:
                continue
            gp = Path(gpath)
            if not gp.exists():
                print(f"[WARN] promoted guidance path missing: {gp}")
                continue
            item = dict(item)
            item["guidance_path"] = str(gp)
            out.append(item)
            if len(out) >= k:
                break
        return out

    def pick_top_candidates(self, score_csv: Path, stack_idx: Path, k: int) -> List[Path]:
        rows = load_csv(score_csv)
        if not rows:
            return []

        idx = load_json(stack_idx, {}) or {}
        by_id = {x.get("candidate_id"): Path(x.get("guidance_path")) for x in idx.get("compiled", [])}

        def to_i(v):
            try:
                return int(v)
            except Exception:
                return 0

        def fire_count(row):
            return to_i(row.get("fire_lines") or row.get("fire") or 0)

        def score(row):
            return to_i(row.get("score"))

        def valid_row(r):
            cid = r.get("candidate_id")
            return cid and cid != "control" and cid in by_id

        good_decisions = [
            "return_to_random_candidate",
            "promising_stack_repeat",
            "partial_stack_repeat",
            "old_solved_current_not_solved",
        ]

        selected = []

        # 1. Prefer good-decision candidates that actually fired.
        for d in good_decisions:
            xs = [r for r in rows if valid_row(r) and r.get("decision") == d and fire_count(r) > 0]
            xs.sort(key=lambda r: (-score(r), r.get("candidate_id", "")))
            for r in xs:
                selected.append(by_id[r["candidate_id"]])
                if len(selected) >= k:
                    return selected

        # 2. Then allow good-decision candidates even if fire is zero.
        for d in good_decisions:
            xs = [r for r in rows if valid_row(r) and r.get("decision") == d]
            xs.sort(key=lambda r: (-score(r), r.get("candidate_id", "")))
            for r in xs:
                selected.append(by_id[r["candidate_id"]])
                if len(selected) >= k:
                    return selected

        # 3. Diagnostic fallback: if all candidates are not_promising,
        # still pick the best fired candidate so the pipeline can produce
        # long-validation evidence and report a weak/negative decision.
        xs = [r for r in rows if valid_row(r) and fire_count(r) > 0]
        xs.sort(key=lambda r: (-score(r), r.get("candidate_id", "")))
        for r in xs:
            selected.append(by_id[r["candidate_id"]])
            if len(selected) >= k:
                return selected

        # 4. Last fallback: pick highest score non-control candidate.
        xs = [r for r in rows if valid_row(r)]
        xs.sort(key=lambda r: (-score(r), r.get("candidate_id", "")))
        for r in xs:
            selected.append(by_id[r["candidate_id"]])
            if len(selected) >= k:
                return selected

        return selected


    def summarize_repeat_gate(self, gate_csv: Path) -> dict:
        """Summarize repeat-gate aggregate rows for diagnostic decisions."""
        rows = load_csv(gate_csv)
        stats = {
            "candidate_count": len(rows),
            "pass_gate_count": 0,
            "fire_positive_count": 0,
            "fire_zero_count": 0,
            "unstable_count": 0,
        }

        def to_bool(v):
            return str(v).strip().lower() in {"true", "1", "yes"}

        def to_i(v, default=0):
            try:
                return int(v)
            except Exception:
                return default

        for r in rows:
            fire_total = to_i(r.get("fire_total"))
            unstable_reps = to_i(r.get("unstable_reps"))

            if to_bool(r.get("pass_gate")):
                stats["pass_gate_count"] += 1

            if fire_total > 0:
                stats["fire_positive_count"] += 1
            else:
                stats["fire_zero_count"] += 1

            if unstable_reps > 0:
                stats["unstable_count"] += 1

        return stats

    def pick_candidates_from_repeat_gate(
        self,
        gate_csv: Path,
        fallback_score_csv: Path,
        stack_idx: Path,
        k: int,
    ) -> List[Path]:
        """Deprecated strict wrapper retained for compatibility.

        Long validation must not fall back to score/index candidates. Use
        load_repeat_gate_promoted_candidates() with promoted_candidates.json.
        """
        rows = load_csv(gate_csv)
        if not rows:
            return []

        def to_bool(v):
            return str(v).strip().lower() in {"true", "1", "yes"}

        passed = [r for r in rows if to_bool(r.get("pass_gate"))]
        out: List[Path] = []
        for r in passed:
            gp = r.get("guidance_path")
            if gp:
                out.append(Path(gp))
            if len(out) >= k:
                break
        return out


    def run_long_validation(self, root: Path, import_q: Path, candidates: List[Path], addr1: str, addr2: str):
        # control
        out = root / "control"
        mkdir(out)
        self.run_cmd("LONG_VALIDATE_CONTROL", [
            "python3", "extractor/closed_loop.py", "run-fuzz",
            "--fuzzer-manifest", "Cargo.toml",
            "--fuzzer-bin", "target/debug/hail-fuzz",
            "--firmware-config", self.firmware_config,
            "--ghidra-src", "tools/ghidra",
            "--workdir", str(out / "workdir"),
            "--run-log", str(out / "run.log"),
            "--run-for", self.args.long_run_for,
            "--observer-dir", str(out / "observer"),
            "--import-dir", str(import_q),
            "--dump-trace",
            "--trace-basename", "replay_trace",
        ], "18_long_control.log")

        for i, cand in enumerate(candidates, 1):
            cid = cand.name.replace(".guidance.json", "")
            out = root / cid
            mkdir(out)
            self.run_cmd(f"LONG_VALIDATE_CANDIDATE_{i}", [
                "python3", "extractor/closed_loop.py", "run-fuzz",
                "--fuzzer-manifest", "Cargo.toml",
                "--fuzzer-bin", "target/debug/hail-fuzz",
                "--firmware-config", self.firmware_config,
                "--ghidra-src", "tools/ghidra",
                "--workdir", str(out / "workdir"),
                "--run-log", str(out / "run.log"),
                "--run-for", self.args.long_run_for,
                "--observer-dir", str(out / "observer"),
                "--guidance-file", str(cand),
                "--guidance-summary-out", str(out / "guidance_runtime_summary.json"),
                "--import-dir", str(import_q),
                "--dump-trace",
                "--trace-basename", "replay_trace",
            ], f"19_long_candidate_{i}.log")

        self.write_long_summary(root, addr1, addr2)

    def count_fire(self, log: Path) -> int:
        if not log.exists():
            return 0
        return sum(1 for line in log.read_text(errors="ignore").splitlines() if "[strategy-runtime] fire" in line)

    def count_addr(self, trace: Path, target: str) -> int:
        if not trace.exists() or not target:
            return 0
        target = norm_addr(target).lower()
        text = trace.read_text(errors="ignore")
        mmio_re = re.compile(r"mmio=(read|write)\s+addr=(0x[0-9a-fA-F]+).*?size=(\d+)")
        c = 0
        for m in mmio_re.finditer(text):
            op, addr, _size = m.groups()
            if op == "read" and norm_addr(addr).lower() == target:
                c += 1
        return c

    def load_run_summary(self, root: Path) -> Dict[str, Any]:
        run = load_json(root / "run_fuzz_summary.json", {}) or {}
        return run.get("run_summary", run)

    def write_long_summary(self, root: Path, addr1: str, addr2: str):
        rows = []
        for d in sorted(root.iterdir()):
            if not d.is_dir():
                continue
            rs = self.load_run_summary(d)
            rows.append({
                "candidate_id": d.name,
                "fire": self.count_fire(d / "run.log"),
                "cov": int(rs.get("last_cov") or 0),
                "input": int(rs.get("last_in") or 0),
                "hang": int(rs.get("last_hang") or 0),
                "crash": int(rs.get("last_crash") or 0),
                "count_addr1": self.count_addr(d / "replay_trace.log", addr1),
                "count_addr2": self.count_addr(d / "replay_trace.log", addr2),
                "run_root": self.rel(d),
            })

        control = next((r for r in rows if r["candidate_id"] == "control"), None)
        if control:
            for r in rows:
                r["delta_cov"] = r["cov"] - control["cov"]
                r["delta_input"] = r["input"] - control["input"]
                r["delta_addr1"] = r["count_addr1"] - control["count_addr1"]
                r["delta_addr2"] = r["count_addr2"] - control["count_addr2"]

        out_csv = root / "long_validation_summary.csv"
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            fields = [
                "candidate_id", "fire", "cov", "input", "hang", "crash",
                "count_addr1", "count_addr2",
                "delta_cov", "delta_input", "delta_addr1", "delta_addr2",
                "run_root",
            ]
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

        save_json(root / "long_validation_summary.json", {
            "addr1": addr1,
            "addr2": addr2,
            "rows": rows,
        })

    def finalize(self):
        checks = {
            "timeline": self.timeline.exists(),
            "controller_state": self.state_path.exists(),
        }

        long_summary = self.out_root / "long_validation" / "long_validation_summary.json"
        long_rows = (load_json(long_summary, {}) or {}).get("rows", [])

        script_success = (not self.failed) and len(self.states_completed) > 0
        core_closure_success = script_success and all(x in self.states_completed for x in [
            "BOTTLENECK_EVENT",
            "BUILD_CONTEXT_DEPTH1",
            "LLM_PLAN_DEPTH1",
            "MATERIALIZE_DEPTH1",
            "SHORT_VALIDATE_DEPTH1",
            "SHIFT_ANALYZE_DEPTH1",
            "CREATE_CHAIN_EVENT_DEPTH2",
            "BUILD_CONTEXT_DEPTH2",
            "LLM_PLAN_DEPTH2",
            "MATERIALIZE_DEPTH2",
            "BUILD_STACK_DEPTH2",
            "SHORT_VALIDATE_STACK_DEPTH2",
            "SCORE_STACK",
        ])

        full_validation_success = script_success and any(
            x.startswith("LONG_VALIDATE_CANDIDATE") for x in self.states_completed
        )

        candidates = [r for r in long_rows if r.get("candidate_id") != "control"]

        def to_i(v, default=0):
            try:
                return int(v)
            except Exception:
                return default

        def candidate_rank(row: Dict[str, Any]):
            # Use coverage-aware ranking for final classification. Directory order
            # is not meaningful when multiple long-validation candidates exist.
            fire = to_i(row.get("fire"))
            hang = to_i(row.get("hang"))
            crash = to_i(row.get("crash"))
            stable = 1 if (hang == 0 and crash == 0) else 0
            delta_cov = to_i(row.get("delta_cov"))
            delta_input = to_i(row.get("delta_input"))
            d1 = to_i(row.get("delta_addr1"))
            d2 = to_i(row.get("delta_addr2"))
            hotspot_reduction = -(d1 + max(d2, 0))
            return (
                1 if fire > 0 else 0,
                stable,
                delta_cov,
                delta_input,
                hotspot_reduction,
                fire,
            )

        best = max(candidates, key=candidate_rank) if candidates else None

        active_guidance_success = bool(best) and to_i(best.get("fire")) > 0

        best_delta_cov = to_i(best.get("delta_cov")) if best else 0
        best_delta_input = to_i(best.get("delta_input")) if best else 0
        best_delta_addr1 = to_i(best.get("delta_addr1")) if best else 0
        best_delta_addr2 = to_i(best.get("delta_addr2")) if best else 0
        best_hang = to_i(best.get("hang")) if best else 0
        best_crash = to_i(best.get("crash")) if best else 0

        repeat_gate_stats = self.summarize_repeat_gate(
            self.out_root / "repeat_gate_stack_depth2" / "repeat_gate_aggregate.csv"
        )

        no_materialized_candidate = (
            "LONG_VALIDATE_SKIPPED_NO_DEPTH2_CANDIDATE" in self.states_completed
            or "SHORT_VALIDATE_SKIPPED_NO_DEPTH1_CANDIDATE" in self.states_completed
            or "LONG_VALIDATE_SKIPPED_NO_MATERIALIZED_CANDIDATE" in self.states_completed
        )

        no_firing_depth1 = (
            "DEPTH1_GUIDANCE_NOT_CONSUMED" in self.states_completed
            or "LONG_VALIDATE_SKIPPED_NO_FIRING_DEPTH1" in self.states_completed
        )

        stable_candidate = bool(best) and best_hang == 0 and best_crash == 0
        nondegrading_candidate = (
            active_guidance_success and
            stable_candidate and
            best_delta_cov >= 0 and
            best_delta_input >= 0
        )

        best_hotspot_ok = (
            active_guidance_success and
            best_delta_addr1 <= 0 and
            best_delta_addr2 <= 100
        )

        best_strong = nondegrading_candidate and best_hotspot_ok

        long_candidate_states = [
            x for x in self.states_completed
            if x.startswith("LONG_VALIDATE_CANDIDATE")
        ]
        controller_invariant_violation = (
            repeat_gate_stats.get("pass_gate_count", 0) <= 0
            and bool(candidates)
            and bool(long_candidate_states)
        )
        invariant_failure_reason = ""
        if controller_invariant_violation:
            invariant_failure_reason = (
                "long validation ran non-control candidates even though "
                "repeat gate pass_gate_count <= 0"
            )

        if controller_invariant_violation:
            final_decision = "controller_invariant_violation_long_without_repeat_gate_pass"
        elif not script_success:
            final_decision = "script_failed"
        elif no_firing_depth1:
            final_decision = "gate_no_firing_candidate"
        elif no_materialized_candidate:
            final_decision = "chain_no_materialized_candidate"
        elif not core_closure_success:
            final_decision = "core_closure_failed"
        elif (
            "LONG_VALIDATE_SKIPPED_NO_GATE_PASS" in self.states_completed
            or "LONG_VALIDATE_SKIPPED_NO_REPEAT_GATE_PASS" in self.states_completed
        ):
            if repeat_gate_stats.get("candidate_count", 0) > 0 and repeat_gate_stats.get("fire_positive_count", 0) == 0:
                final_decision = "gate_no_firing_candidate"
            else:
                final_decision = "repeat_gate_no_pass_candidate"
        elif not full_validation_success:
            final_decision = "core_closure_only_no_long_candidate"
        elif not best:
            final_decision = "long_control_only_no_candidate"
        elif not active_guidance_success:
            final_decision = "long_candidate_not_consumed"
        elif not stable_candidate:
            final_decision = "active_but_unstable_hang_or_crash"
        elif best_delta_cov < 0:
            final_decision = "active_but_coverage_regressed"
        elif best_delta_input < 0:
            final_decision = "active_but_input_regressed"
        elif best_strong:
            final_decision = "strong_active_nondegrading_hotspot_reduced"
        elif nondegrading_candidate and not best_hotspot_ok:
            final_decision = "active_nondegrading_but_hotspot_rebounded"
        elif nondegrading_candidate:
            final_decision = "nondegrading_active_candidate"
        else:
            final_decision = "needs_manual_review"

        # Keep legacy field for backward compatibility, but interpret it as
        # script-level closure only. Use the layered fields for analysis.
        closure_success = script_success

        final = {
            "schema": "llm_chain_closed_loop_final_summary_v1",
            "case_id": self.args.case_id,
            "mode": self.args.mode,
            "closure_success": closure_success,
            "script_success": script_success,
            "core_closure_success": core_closure_success,
            "full_validation_success": full_validation_success,
            "active_guidance_success": active_guidance_success,
            "stable_candidate": stable_candidate,
            "nondegrading_candidate": nondegrading_candidate,
            "best_hotspot_ok": best_hotspot_ok,
            "best_strong": best_strong,
            "best_candidate_id": best.get("candidate_id") if best else None,
            "best_delta_cov": best_delta_cov,
            "best_delta_input": best_delta_input,
            "best_delta_addr1": best_delta_addr1,
            "best_delta_addr2": best_delta_addr2,
            "final_decision": final_decision,
            "failed": bool(self.failed or controller_invariant_violation),
            "failure_reason": self.failure_reason or invariant_failure_reason,
            "controller_invariant_violation": controller_invariant_violation,
            "repeat_gate_stats": repeat_gate_stats,
            "states_completed": self.states_completed,
            "checks": checks,
            "firmware_config": self.firmware_config,
            "paths": {
                "out_root": self.rel(self.out_root),
                "timeline": self.rel(self.timeline),
                "controller_state": self.rel(self.state_path),
                "long_validation_summary": self.rel(long_summary),
            },
            "long_validation_rows": long_rows,
            "finished_at": now(),
        }
        save_json(self.summary_path, final)
        self.log_state("FINALIZE", status="ok" if closure_success else "failed", decision="closure_success" if closure_success else "closure_failed", path=self.rel(self.summary_path))
        print("\n===== FINAL SUMMARY =====")
        print(json.dumps(final, indent=2, ensure_ascii=False))


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--llm-model", default="gpt-5.4")
    ap.add_argument("--random-chunk-run-for", default="5m")
    ap.add_argument("--short-run-for", default="60s")
    ap.add_argument("--long-run-for", default="5m")
    ap.add_argument("--max-chain-depth", type=int, default=2)
    ap.add_argument("--max-candidates", type=int, default=40)
    ap.add_argument("--top-k-repeat", type=int, default=2)
    ap.add_argument("--random-reps", type=int, default=3)
    ap.add_argument("--random-max-iters", type=int, default=6)
    ap.add_argument("--window-s", type=int, default=300)
    ap.add_argument("--min-elapsed-s", type=int, default=150)
    ap.add_argument("--gate-run-for", default="30s")
    ap.add_argument("--materialize-priority-max", type=int, default=3)
    ap.add_argument("--materialize-max-candidates", type=int, default=40)
    ap.add_argument("--short-max-candidates", type=int, default=40)
    ap.add_argument("--stack-short-max-candidates", type=int, default=40)
    ap.add_argument("--gate-top-k", type=int, default=4)
    ap.add_argument("--gate-repeats", type=int, default=2)
    ap.add_argument("--llm-timeout-s", type=int, default=600)
    ap.add_argument("--feedback-md", default="", help="optional closed-loop feedback markdown passed to LLM planner")
    ap.add_argument("--llm-max-output-tokens", type=int, default=6000)
    ap.add_argument("--mode", default="closure-smoke", choices=["closure-smoke"])
    return ap.parse_args()


def main():
    args = parse_args()
    r = Runner(args)
    r.run()


if __name__ == "__main__":
    main()
