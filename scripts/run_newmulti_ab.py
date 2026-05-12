#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run the local newMulti A/B benchmark experiment.

Arms:
  baseline_random: local random-only execution with strategy/knowledge features disabled.
  guided_knowledge: warmup -> hotspot observation -> PDF/SVD/Ghidra materialization -> bounded strategy update.

The script only executes local benchmark cases from the manifest produced by
build_newmulti_manifest.py. It does not connect to external systems. LLM usage is
opt-in via --llm-mode api or --llm-mode prompt-only/json-file.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import datetime as _dt
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def repo_path(p: str | Path) -> Path:
    return Path(p).expanduser().resolve()


def safe_id(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "__", text.strip().strip("/"))


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def append_jsonl(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n")


def parse_duration_seconds(value: str) -> int:
    s = str(value).strip().lower()
    m = re.fullmatch(r"(\d+)([smhd]?)", s)
    if not m:
        raise ValueError(f"Unsupported duration: {value}. Use examples like 30s, 10m, 3h.")
    n = int(m.group(1))
    unit = m.group(2) or "s"
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def duration_min(a: str, b: str) -> str:
    return f"{min(parse_duration_seconds(a), parse_duration_seconds(b))}s"


def shell_join(cmd: Iterable[str]) -> str:
    return " ".join(shlex.quote(str(x)) for x in cmd)


def run_cmd(cmd: List[str], *, cwd: Path, log_path: Path, dry_run: bool = False, extra_env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rec: Dict[str, Any] = {
        "cmd": cmd,
        "cmd_string": shell_join(cmd),
        "cwd": str(cwd),
        "log_path": str(log_path),
        "started_at": now_iso(),
        "dry_run": dry_run,
    }
    if dry_run:
        log_path.write_text("[dry-run] " + rec["cmd_string"] + "\n", encoding="utf-8")
        rec.update({"returncode": 0, "elapsed_sec": 0.0, "finished_at": now_iso()})
        return rec

    env = os.environ.copy()
    if extra_env:
        env.update({str(k): str(v) for k, v in extra_env.items()})
    start = time.monotonic()
    with log_path.open("w", encoding="utf-8", errors="replace") as f:
        f.write(f"[newmulti-runner] started_at={rec['started_at']} cwd={cwd}\n")
        f.write(f"[newmulti-runner] cmd={rec['cmd_string']}\n")
        f.flush()
        proc = subprocess.run(cmd, cwd=str(cwd), env=env, stdout=f, stderr=subprocess.STDOUT, text=True, check=False)
    rec.update({
        "returncode": int(proc.returncode),
        "elapsed_sec": round(time.monotonic() - start, 3),
        "finished_at": now_iso(),
    })
    return rec



def autodetect_fuzzer_manifest(repo: Path, requested: Path) -> Path:
    """Resolve the fuzzer Cargo.toml robustly for either the full repo or uploaded component layout."""
    if requested.exists():
        return requested.resolve()
    candidates = [
        repo / "hail-fuzz" / "Cargo.toml",
        repo / "hail" / "Cargo.toml",
        repo / "Cargo.toml",
    ]
    for cand in candidates:
        if cand.exists():
            return cand.resolve()
    raise FileNotFoundError(f"Cannot find fuzzer manifest. Requested {requested}; tried: {', '.join(str(c) for c in candidates)}")

def cargo_binary_from_manifest(repo: Path, manifest_path: Path, *, force_build: bool = False) -> Path:
    manifest_path = autodetect_fuzzer_manifest(repo, manifest_path)
    if force_build:
        subprocess.run(["cargo", "build", "--manifest-path", str(manifest_path)], cwd=str(repo), check=True)
    meta = subprocess.check_output(
        ["cargo", "metadata", "--manifest-path", str(manifest_path), "--format-version", "1", "--no-deps"],
        cwd=str(repo), text=True,
    )
    data = json.loads(meta)
    target_dir = Path(data["target_directory"])
    pkg = None
    packages = data.get("packages", [])
    for p in packages:
        if Path(p.get("manifest_path", "")).resolve() == manifest_path.resolve():
            pkg = p
            break
    if pkg is None:
        for p in packages:
            for target in p.get("targets", []):
                if "bin" in target.get("kind", []) and target.get("name") == "hail-fuzz":
                    pkg = p
                    break
            if pkg is not None:
                break
    if pkg is None:
        for p in packages:
            if any("bin" in t.get("kind", []) for t in p.get("targets", [])):
                pkg = p
                break
    if not pkg:
        raise RuntimeError(f"Cannot resolve cargo binary package from {manifest_path}")
    bin_name = None
    for target in pkg.get("targets", []):
        if "bin" in target.get("kind", []) and target.get("name") == "hail-fuzz":
            bin_name = target.get("name")
            break
    if not bin_name:
        for target in pkg.get("targets", []):
            if "bin" in target.get("kind", []):
                bin_name = target.get("name")
                break
    bin_name = bin_name or pkg.get("name")
    if not bin_name:
        raise RuntimeError(f"Cannot resolve cargo binary name from {manifest_path}")
    bin_path = target_dir / "debug" / bin_name
    if sys.platform.startswith("win"):
        bin_path = bin_path.with_suffix(".exe")
    if force_build or not bin_path.exists():
        subprocess.run(["cargo", "build", "--manifest-path", str(manifest_path)], cwd=str(repo), check=True)
    return bin_path.resolve()


def baseline_setenv() -> List[str]:
    # Keep the executor local and deterministic, while disabling knowledge-bearing
    # stages so the arm is a true random-mutation control.
    return [
        "ENABLE_CMPLOG=0",
        "ENABLE_COLORIZATION=0",
        "ENABLE_AUTO_DICT=0",
        "ENABLE_TRIM=0",
        "ENABLE_AUTO_TRIM=0",
        "ENABLE_STRIDED_INT_MATCHES=0",
        "USE_ACCESS_CONTEXTS=0",
        "ICICLE_RESIZE_LOADS=0",
        "LENGTH_EXTENSION_ONLY=0",
        "ENABLE_HAVOC=1",
    ]


def guided_setenv() -> List[str]:
    # Guided arm keeps the ordinary mutation pipeline enabled; the bounded runtime
    # materialization enters through closed_loop.py arguments and env vars.
    return [
        "ENABLE_HAVOC=1",
        "ENABLE_CMPLOG=1",
        "ENABLE_COLORIZATION=1",
        "ENABLE_AUTO_DICT=1",
        "ENABLE_TRIM=1",
        "ENABLE_AUTO_TRIM=1",
        "ENABLE_STRIDED_INT_MATCHES=1",
        "USE_ACCESS_CONTEXTS=0",
        "ICICLE_RESIZE_LOADS=3",
    ]


def add_setenv_args(cmd: List[str], pairs: Iterable[str]) -> None:
    for pair in pairs:
        cmd.extend(["--setenv", pair])


def closed_loop_py(repo: Path) -> Path:
    p = repo / "extractor" / "closed_loop.py"
    if not p.exists():
        raise FileNotFoundError(f"missing closed_loop.py: {p}")
    return p.resolve()


def case_out_root(out_root: Path, case: Dict[str, Any], repeat_idx: int) -> Path:
    return out_root / safe_id(case["case_id"]) / f"rep_{repeat_idx:02d}"


def write_case_meta(root: Path, case: Dict[str, Any], repeat_idx: int, arm: str) -> None:
    save_json(root / "case_meta.json", {"case": case, "repeat_idx": repeat_idx, "arm": arm, "created_at": now_iso()})


def run_baseline_case(repo: Path, case: Dict[str, Any], repeat_idx: int, args: argparse.Namespace, fuzzer_bin: Path) -> Dict[str, Any]:
    arm_root = case_out_root(Path(args.out_root), case, repeat_idx) / "baseline_random"
    arm_root.mkdir(parents=True, exist_ok=True)
    write_case_meta(arm_root, case, repeat_idx, "baseline_random")
    cmd = [
        sys.executable, str(closed_loop_py(repo)), "run-fuzz",
        "--fuzzer-manifest", str(Path(args.fuzzer_manifest).resolve()),
        "--fuzzer-bin", str(fuzzer_bin),
        "--firmware-config", case["config"],
        "--ghidra-src", str(Path(args.ghidra_src).resolve()),
        "--workdir", str(arm_root / "workdir"),
        "--run-log", str(arm_root / "run.log"),
        "--run-for", args.baseline_run_for,
    ]
    if args.baseline_with_observer:
        cmd.extend(["--observer-dir", str(arm_root / "observer")])
    if args.dump_trace:
        cmd.append("--dump-trace")
    add_setenv_args(cmd, baseline_setenv())
    add_setenv_args(cmd, args.setenv or [])
    rec = run_cmd(cmd, cwd=repo, log_path=arm_root / "runner.log", dry_run=args.dry_run)
    rec.update({"case_id": case["case_id"], "relative_dir": case["relative_dir"], "repeat_idx": repeat_idx, "arm": "baseline_random", "summary_path": str(arm_root / "run_fuzz_summary.json")})
    save_json(arm_root / "runner_result.json", rec)
    return rec


def run_guided_case(repo: Path, case: Dict[str, Any], repeat_idx: int, args: argparse.Namespace, fuzzer_bin: Path) -> Dict[str, Any]:
    arm_root = case_out_root(Path(args.out_root), case, repeat_idx) / "guided_knowledge"
    arm_root.mkdir(parents=True, exist_ok=True)
    write_case_meta(arm_root, case, repeat_idx, "guided_knowledge")

    if not case.get("pdf") or not case.get("svd"):
        rec = {
            "case_id": case["case_id"],
            "relative_dir": case["relative_dir"],
            "repeat_idx": repeat_idx,
            "arm": "guided_knowledge",
            "returncode": 2,
            "status": "skipped_missing_pdf_or_svd",
            "summary_path": None,
            "started_at": now_iso(),
            "finished_at": now_iso(),
        }
        save_json(arm_root / "runner_result.json", rec)
        return rec

    cmd = [
        sys.executable, str(closed_loop_py(repo)), "adaptive-mmio-loop",
        "--fuzzer-manifest", str(Path(args.fuzzer_manifest).resolve()),
        "--fuzzer-bin", str(fuzzer_bin),
        "--firmware-config", case["config"],
        "--ghidra-src", str(Path(args.ghidra_src).resolve()),
        "--binary", case["elf"],
        "--pdf", case["pdf"],
        "--svd", case["svd"],
        "--board", str(case.get("board") or "unknown_board"),
        "--mcu", str(case.get("mcu") or "unknown_mcu"),
        "--benchmark-name", str(case.get("case_id") or case.get("benchmark") or "benchmark"),
        "--out-root", str(arm_root),
        "--materialization-mode", args.materialization_mode,
        "--warmup-run-for", args.guided_warmup_run_for,
        "--warmup-restarts", str(args.warmup_restarts),
        "--probe-run-for", args.probe_run_for,
        "--followup-run-for", args.followup_run_for,
        "--portfolio-run-for", args.portfolio_run_for,
        "--portfolio-max-candidates", str(args.portfolio_max_candidates),
        "--candidate-run-for", args.candidate_run_for,
        "--rounds", str(args.rounds),
        "--beam-width", str(args.beam_width),
        "--max-llm-cycles", str(args.max_llm_cycles),
        "--main-window-count", str(args.main_window_count),
        "--main-window-run-for", args.main_window_run_for,
        "--shared-cache-root", str(Path(args.shared_cache_root).resolve()),
        "--shared-query-cache-root", str(Path(args.shared_query_cache_root).resolve()),
        "--top-k", str(args.top_k),
        "--max-candidates", str(args.max_candidates),
        "--default-after-reads", str(args.default_after_reads),
        "--trace-basename", "replay_trace",
    ]
    if case.get("ghidra_summary_json"):
        cmd.extend(["--ghidra-summary-json", case["ghidra_summary_json"]])
    if case.get("ghidra_export_json"):
        cmd.extend(["--ghidra-export-json", case["ghidra_export_json"]])
    if case.get("ghidra_outdir"):
        cmd.extend(["--ghidra-outdir", str(arm_root / "ghidra")])
    if args.force_pdf:
        cmd.append("--force-pdf")
    if args.allow_aggressive:
        cmd.append("--allow-aggressive")
    if args.disable_candidate_portfolio:
        cmd.append("--disable-candidate-portfolio")
    if args.dump_trace:
        cmd.append("--dump-trace")
    if args.dump_followup_trace:
        cmd.append("--dump-followup-trace")

    if args.llm_mode == "off":
        cmd.append("--skip-llm")
    elif args.llm_mode == "prompt-only":
        cmd.extend(["--enable-llm-strategy", "--llm-strategy-mode", "prompt-only"])
        if args.llm_model:
            cmd.extend(["--llm-strategy-model", args.llm_model, "--llm-model", args.llm_model])
    elif args.llm_mode == "api":
        cmd.extend(["--enable-llm-strategy", "--llm-strategy-mode", "api", "--force-llm"])
        if args.llm_model:
            cmd.extend(["--llm-strategy-model", args.llm_model, "--llm-model", args.llm_model])
    elif args.llm_mode == "json-file":
        if not args.llm_strategy_json:
            raise ValueError("--llm-mode json-file requires --llm-strategy-json")
        cmd.extend([
            "--enable-llm-strategy", "--llm-strategy-mode", "json-file",
            "--llm-strategy-json", str(Path(args.llm_strategy_json).resolve()),
        ])
    else:
        raise ValueError(f"unknown llm mode: {args.llm_mode}")

    add_setenv_args(cmd, guided_setenv())
    add_setenv_args(cmd, args.setenv or [])
    rec = run_cmd(cmd, cwd=repo, log_path=arm_root / "runner.log", dry_run=args.dry_run)
    rec.update({"case_id": case["case_id"], "relative_dir": case["relative_dir"], "repeat_idx": repeat_idx, "arm": "guided_knowledge", "summary_path": str(arm_root / "adaptive_mmio_loop_summary.json")})
    save_json(arm_root / "runner_result.json", rec)
    return rec


def run_one_task(task: Tuple[str, Dict[str, Any], int, Dict[str, Any]]) -> Dict[str, Any]:
    arm, case, repeat_idx, arg_dict = task
    args = argparse.Namespace(**arg_dict)
    repo = Path(args.repo).resolve()
    fuzzer_bin = Path(args.fuzzer_bin_resolved).resolve()
    try:
        if arm == "baseline_random":
            return run_baseline_case(repo, case, repeat_idx, args, fuzzer_bin)
        if arm == "guided_knowledge":
            return run_guided_case(repo, case, repeat_idx, args, fuzzer_bin)
        raise ValueError(arm)
    except Exception as exc:
        root = case_out_root(Path(args.out_root), case, repeat_idx) / arm
        root.mkdir(parents=True, exist_ok=True)
        rec = {
            "case_id": case.get("case_id"),
            "relative_dir": case.get("relative_dir"),
            "repeat_idx": repeat_idx,
            "arm": arm,
            "returncode": 99,
            "status": "runner_exception",
            "error": f"{type(exc).__name__}: {exc}",
            "started_at": now_iso(),
            "finished_at": now_iso(),
        }
        save_json(root / "runner_result.json", rec)
        return rec


def write_status_table(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = ["case_id", "relative_dir", "repeat_idx", "arm", "returncode", "status", "elapsed_sec", "summary_path", "error"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k) for k in fields})


def main() -> None:
    ap = argparse.ArgumentParser(description="Run newMulti local A/B benchmark experiment.")
    ap.add_argument("--repo", default=".", help="Repository root")
    ap.add_argument("--manifest", default="workdir/newmulti_ab/manifest.jsonl", help="Manifest from build_newmulti_manifest.py")
    ap.add_argument("--out-root", default="workdir/newmulti_ab/runs", help="Experiment output root")
    ap.add_argument("--fuzzer-manifest", default="Cargo.toml", help="Cargo.toml for hail-fuzz/newMulti")
    ap.add_argument("--fuzzer-bin", default=None, help="Optional already-built fuzzer binary")
    ap.add_argument("--ghidra-src", default="tools/ghidra", help="Ghidra install path passed through to closed_loop.py")
    ap.add_argument("--shared-cache-root", default="extractor/.shared_pdf_svd_cache")
    ap.add_argument("--shared-query-cache-root", default="extractor/.shared_query_cache")
    ap.add_argument("--mode", choices=["both", "baseline", "guided"], default="both")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--case-filter", default=None, help="Regex over relative_dir/case_id")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--build", action="store_true", help="Run cargo build before launching tasks")

    # Comparable budgets. For fair A/B, set baseline-run-for equal to guided total budget manually.
    ap.add_argument("--baseline-run-for", default="3h")
    ap.add_argument("--guided-warmup-run-for", default="30m")
    ap.add_argument("--warmup-restarts", type=int, default=1)
    ap.add_argument("--probe-run-for", default="60s")
    ap.add_argument("--followup-run-for", default="5m")
    ap.add_argument("--portfolio-run-for", default="2m")
    ap.add_argument("--candidate-run-for", default="2m")
    ap.add_argument("--main-window-count", type=int, default=0)
    ap.add_argument("--main-window-run-for", default="10m")
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--beam-width", type=int, default=2)
    ap.add_argument("--max-llm-cycles", type=int, default=1)
    ap.add_argument("--portfolio-max-candidates", type=int, default=3)
    ap.add_argument("--top-k", type=int, default=8)
    ap.add_argument("--max-candidates", type=int, default=4)
    ap.add_argument("--default-after-reads", type=int, default=192)
    ap.add_argument("--materialization-mode", choices=["staged-loop", "auto-loop"], default="staged-loop")

    ap.add_argument("--llm-mode", choices=["off", "prompt-only", "api", "json-file"], default="off")
    ap.add_argument("--llm-model", default=os.environ.get("OPENAI_MODEL", ""))
    ap.add_argument("--llm-strategy-json", default=None)

    ap.add_argument("--baseline-with-observer", action="store_true")
    ap.add_argument("--dump-trace", action="store_true")
    ap.add_argument("--dump-followup-trace", action="store_true")
    ap.add_argument("--force-pdf", action="store_true")
    ap.add_argument("--allow-aggressive", action="store_true")
    ap.add_argument("--disable-candidate-portfolio", action="store_true")
    ap.add_argument("--setenv", action="append", help="Extra KEY=VALUE override passed to closed_loop.py; can repeat")
    args = ap.parse_args()

    repo = repo_path(args.repo)
    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = (repo / manifest).resolve()
    out_root = Path(args.out_root)
    if not out_root.is_absolute():
        out_root = (repo / out_root).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    args.repo = str(repo)
    args.manifest = str(manifest)
    args.out_root = str(out_root)
    requested_manifest = (repo / args.fuzzer_manifest).resolve() if not os.path.isabs(args.fuzzer_manifest) else Path(args.fuzzer_manifest).resolve()
    args.fuzzer_manifest = str(autodetect_fuzzer_manifest(repo, requested_manifest))
    args.ghidra_src = str((repo / args.ghidra_src).resolve() if not os.path.isabs(args.ghidra_src) else Path(args.ghidra_src).resolve())
    args.shared_cache_root = str((repo / args.shared_cache_root).resolve() if not os.path.isabs(args.shared_cache_root) else Path(args.shared_cache_root).resolve())
    args.shared_query_cache_root = str((repo / args.shared_query_cache_root).resolve() if not os.path.isabs(args.shared_query_cache_root) else Path(args.shared_query_cache_root).resolve())

    cases = load_jsonl(manifest)
    if args.case_filter:
        rx = re.compile(args.case_filter)
        cases = [c for c in cases if rx.search(c.get("relative_dir", "")) or rx.search(c.get("case_id", ""))]
    if not cases:
        raise RuntimeError("No cases selected")

    if args.fuzzer_bin:
        fuzzer_bin = Path(args.fuzzer_bin).expanduser().resolve()
    else:
        fuzzer_bin = cargo_binary_from_manifest(repo, Path(args.fuzzer_manifest), force_build=args.build)
    args.fuzzer_bin_resolved = str(fuzzer_bin)

    arms = []
    if args.mode in {"both", "baseline"}:
        arms.append("baseline_random")
    if args.mode in {"both", "guided"}:
        arms.append("guided_knowledge")

    tasks: List[Tuple[str, Dict[str, Any], int, Dict[str, Any]]] = []
    arg_dict = vars(args).copy()
    for rep in range(1, max(1, args.repeats) + 1):
        for case in cases:
            for arm in arms:
                tasks.append((arm, case, rep, arg_dict))

    plan = {
        "schema": "newmulti_ab_run_plan_v1",
        "created_at": now_iso(),
        "repo": str(repo),
        "manifest": str(manifest),
        "out_root": str(out_root),
        "fuzzer_bin": str(fuzzer_bin),
        "mode": args.mode,
        "jobs": args.jobs,
        "repeats": args.repeats,
        "case_count": len(cases),
        "task_count": len(tasks),
        "llm_mode": args.llm_mode,
        "baseline_random_setenv": baseline_setenv(),
        "guided_setenv": guided_setenv(),
        "tasks": [{"arm": t[0], "case_id": t[1].get("case_id"), "relative_dir": t[1].get("relative_dir"), "repeat_idx": t[2]} for t in tasks],
    }
    save_json(out_root / "run_plan.json", plan)
    print(json.dumps({k: plan[k] for k in ["out_root", "case_count", "task_count", "mode", "jobs", "llm_mode"]}, indent=2, ensure_ascii=False))

    results: List[Dict[str, Any]] = []
    status_jsonl = out_root / "runner_status.jsonl"
    if status_jsonl.exists() and not args.dry_run:
        status_jsonl.unlink()

    if args.jobs <= 1:
        for task in tasks:
            rec = run_one_task(task)
            results.append(rec)
            append_jsonl(status_jsonl, rec)
            print(f"[{rec.get('arm')}] {rec.get('relative_dir')} rep={rec.get('repeat_idx')} rc={rec.get('returncode')}", flush=True)
    else:
        with cf.ProcessPoolExecutor(max_workers=args.jobs) as ex:
            futs = [ex.submit(run_one_task, task) for task in tasks]
            for fut in cf.as_completed(futs):
                rec = fut.result()
                results.append(rec)
                append_jsonl(status_jsonl, rec)
                print(f"[{rec.get('arm')}] {rec.get('relative_dir')} rep={rec.get('repeat_idx')} rc={rec.get('returncode')}", flush=True)

    save_json(out_root / "runner_results.json", {"finished_at": now_iso(), "results": results})
    write_status_table(out_root / "runner_status.csv", results)
    print(json.dumps({
        "out_root": str(out_root),
        "results": str(out_root / "runner_results.json"),
        "status_csv": str(out_root / "runner_status.csv"),
        "ok": sum(1 for r in results if r.get("returncode") == 0),
        "failed_or_skipped": sum(1 for r in results if r.get("returncode") != 0),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
