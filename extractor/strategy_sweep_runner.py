#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import json
import shutil
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def save_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def median_or_zero(values: List[float]) -> float:
    if not values:
        return 0.0
    return float(statistics.median(values))


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def count_substring(text: str, needle: str) -> int:
    return text.count(needle)


def parse_guidance_summary(path: Optional[Path]) -> Dict[str, Any]:
    if path is None or not path.exists():
        return {
            "active_stages": [],
            "strategy_fire_count": 0,
        }
    obj = load_json(path)
    actions = obj.get("actions") or []
    fire_count = 0
    for act in actions:
        fire_count += int(act.get("fire_count") or 0)
    return {
        "active_stages": obj.get("active_stages") or [],
        "strategy_fire_count": fire_count,
    }


def parse_observer(observer_dir: Path, uart_d_addr: str) -> Dict[str, Any]:
    out = {
        "window_execs": 0,
        "window_interesting_execs": 0,
        "discovered_stream_count": 0,
        "uart_d_read_count": 0,
        "uart_d_executions_seen": 0,
    }

    latest_window_summary = observer_dir / "latest_window_summary.json"
    latest_window_discovered = observer_dir / "latest_window_discovered_streams.json"

    if latest_window_summary.exists():
        obj = load_json(latest_window_summary)
        out["window_execs"] = int(obj.get("window_execs") or 0)
        out["window_interesting_execs"] = int(obj.get("window_interesting_execs") or 0)

    if latest_window_discovered.exists():
        arr = load_json(latest_window_discovered)
        if isinstance(arr, list):
            out["discovered_stream_count"] = len(arr)
            for item in arr:
                addr = str(item.get("addr") or "").lower()
                if addr == uart_d_addr.lower():
                    out["uart_d_read_count"] = int(item.get("read_count") or 0)
                    out["uart_d_executions_seen"] = int(item.get("executions_seen") or 0)
                    break

    return out


def write_guidance(candidate: Dict[str, Any], out_path: Path) -> None:
    guidance = {
        "schema": "mf_runtime_strategy_v1",
        "plan_name": str(candidate["id"]),
        "rationale": str(candidate.get("rationale") or ""),
        "actions": candidate.get("actions") or [],
    }
    save_json(out_path, guidance)


def build_run_cmd(
    *,
    python_bin: str,
    closed_loop_py: str,
    fuzzer_manifest: str,
    firmware_config: str,
    ghidra_src: str,
    workdir: Path,
    run_log: Path,
    run_for: str,
    observer_dir: Path,
    import_dir: str,
    guidance_file: Optional[Path],
    guidance_summary_out: Optional[Path],
) -> List[str]:
    cmd = [
        python_bin,
        closed_loop_py,
        "run-fuzz",
        "--fuzzer-manifest", fuzzer_manifest,
        "--firmware-config", firmware_config,
        "--ghidra-src", ghidra_src,
        "--workdir", str(workdir),
        "--run-log", str(run_log),
        "--run-for", run_for,
        "--observer-dir", str(observer_dir),
        "--import-dir", import_dir,
    ]
    if guidance_file is not None:
        cmd.extend(["--guidance-file", str(guidance_file)])
    if guidance_summary_out is not None:
        cmd.extend(["--guidance-summary-out", str(guidance_summary_out)])
    return cmd


def run_one_candidate(
    *,
    args: argparse.Namespace,
    candidate: Dict[str, Any],
    rep_index: int,
    is_control: bool,
    uart_d_addr: str,
) -> Dict[str, Any]:
    candidate_id = "control" if is_control else str(candidate["id"])
    rep_dir = Path(args.out_root) / "runs" / candidate_id / f"rep_{rep_index:02d}"

    if rep_dir.exists():
        shutil.rmtree(rep_dir)
    rep_dir.mkdir(parents=True, exist_ok=True)

    workdir = rep_dir / "workdir"
    run_log = rep_dir / "run.log"
    observer_dir = rep_dir / "observer"
    guidance_file = None
    guidance_summary_out = None

    if not is_control:
        guidance_file = rep_dir / "guidance.json"
        guidance_summary_out = rep_dir / "guidance_runtime_summary.json"
        write_guidance(candidate, guidance_file)

    cmd = build_run_cmd(
        python_bin=args.python_bin,
        closed_loop_py=args.closed_loop_py,
        fuzzer_manifest=args.fuzzer_manifest,
        firmware_config=args.firmware_config,
        ghidra_src=args.ghidra_src,
        workdir=workdir,
        run_log=run_log,
        run_for=args.run_for,
        observer_dir=observer_dir,
        import_dir=args.import_dir,
        guidance_file=guidance_file,
        guidance_summary_out=guidance_summary_out,
    )

    print(f"[RUN] candidate={candidate_id} rep={rep_index} :: {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=args.repo_root)
    status_code = int(proc.returncode)

    run_summary_path = rep_dir / "run_fuzz_summary.json"
    if not run_summary_path.exists():
        raise RuntimeError(f"missing run_fuzz_summary.json: {run_summary_path}")

    run_summary_obj = load_json(run_summary_path)
    run_summary = run_summary_obj.get("run_summary") or {}

    log_text = read_text(run_log)
    guidance_obj = parse_guidance_summary(guidance_summary_out)
    observer_obj = parse_observer(observer_dir, uart_d_addr)

    result = {
        "candidate_id": candidate_id,
        "rep_index": rep_index,
        "is_control": int(is_control),
        "returncode": status_code,
        "status": str(run_summary.get("status") or ""),
        "last_cov": int(run_summary.get("last_cov") or 0),
        "last_in": int(run_summary.get("last_in") or 0),
        "last_hang": int(run_summary.get("last_hang") or 0),
        "last_crash": int(run_summary.get("last_crash") or 0),
        "strategy_fire_count": int(guidance_obj["strategy_fire_count"]),
        "active_stage_count": len(guidance_obj["active_stages"]),

        "armed_uart_count": count_substring(log_text, "armed uart_handshake_once"),
        "uart_status_fire_count": count_substring(log_text, "fire uart status"),
        "uart_data_fire_count": count_substring(log_text, "fire uart data"),

        "read_override_once_fire_count": count_substring(log_text, "fire read_override_once"),
        "read_override_repeat_fire_count": count_substring(log_text, "fire read_override_repeat"),
        "read_sequence_fire_count": count_substring(log_text, "fire read_sequence"),

        "window_execs": int(observer_obj["window_execs"]),
        "window_interesting_execs": int(observer_obj["window_interesting_execs"]),
        "discovered_stream_count": int(observer_obj["discovered_stream_count"]),
        "uart_d_read_count": int(observer_obj["uart_d_read_count"]),
        "uart_d_executions_seen": int(observer_obj["uart_d_executions_seen"]),
        "rep_dir": str(rep_dir),
        "run_log": str(run_log),
    }
    return result


def summarize_results(raw_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_candidate: Dict[str, List[Dict[str, Any]]] = {}
    for row in raw_rows:
        by_candidate.setdefault(str(row["candidate_id"]), []).append(row)

    control_rows = by_candidate.get("control", [])
    control_median_cov = median_or_zero([float(r["last_cov"]) for r in control_rows])

    summary_rows: List[Dict[str, Any]] = []
    for candidate_id, rows in by_candidate.items():
        last_covs = [float(r["last_cov"]) for r in rows]
        last_ins = [float(r["last_in"]) for r in rows]
        hangs = [float(r["last_hang"]) for r in rows]
        crashes = [float(r["last_crash"]) for r in rows]
        strategy_fires = [float(r["strategy_fire_count"]) for r in rows]

        uart_status_fires = [float(r["uart_status_fire_count"]) for r in rows]
        uart_data_fires = [float(r["uart_data_fire_count"]) for r in rows]
        ro_once_fires = [float(r["read_override_once_fire_count"]) for r in rows]
        ro_repeat_fires = [float(r["read_override_repeat_fire_count"]) for r in rows]
        rseq_fires = [float(r["read_sequence_fire_count"]) for r in rows]

        uart_d_reads = [float(r["uart_d_read_count"]) for r in rows]
        discovered_counts = [float(r["discovered_stream_count"]) for r in rows]
        interesting_execs = [float(r["window_interesting_execs"]) for r in rows]

        median_cov = median_or_zero(last_covs)
        summary_rows.append({
            "candidate_id": candidate_id,
            "repeat_count": len(rows),
            "median_last_cov": median_cov,
            "max_last_cov": max(last_covs) if last_covs else 0.0,
            "delta_vs_control_median_cov": median_cov - control_median_cov,
            "median_last_in": median_or_zero(last_ins),
            "median_last_hang": median_or_zero(hangs),
            "median_last_crash": median_or_zero(crashes),
            "median_strategy_fire_count": median_or_zero(strategy_fires),

            "median_uart_status_fire_count": median_or_zero(uart_status_fires),
            "median_uart_data_fire_count": median_or_zero(uart_data_fires),
            "median_read_override_once_fire_count": median_or_zero(ro_once_fires),
            "median_read_override_repeat_fire_count": median_or_zero(ro_repeat_fires),
            "median_read_sequence_fire_count": median_or_zero(rseq_fires),

            "median_uart_d_read_count": median_or_zero(uart_d_reads),
            "median_discovered_stream_count": median_or_zero(discovered_counts),
            "median_window_interesting_execs": median_or_zero(interesting_execs),
        })

    summary_rows.sort(
        key=lambda x: (
            float(x["median_last_cov"]),
            float(x["max_last_cov"]),
            float(x["median_uart_data_fire_count"]),
            float(x["median_read_sequence_fire_count"]),
            float(x["median_read_override_repeat_fire_count"]),
            float(x["median_read_override_once_fire_count"]),
        ),
        reverse=True,
    )
    return summary_rows


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Batch short-run sweep over manual guidance strategies.")
    ap.add_argument("--repo-root", default="/home/MultiFuzz")
    ap.add_argument("--python-bin", default=sys.executable)
    ap.add_argument("--closed-loop-py", default="/home/MultiFuzz/extractor/closed_loop.py")
    ap.add_argument("--catalog", required=True)
    ap.add_argument("--fuzzer-manifest", default="/home/MultiFuzz/hail-fuzz/Cargo.toml")
    ap.add_argument("--firmware-config", default="/home/MultiFuzz/benchmarks/P2IM/Console/config.yml")
    ap.add_argument("--ghidra-src", default="/home/MultiFuzz/ghidra")
    ap.add_argument("--import-dir", default="/home/MultiFuzz/workdir/console_staged_recovery/round_0_seed/workdir/queue")
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--run-for", default="30s")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--include-control", action="store_true", default=True)
    ap.add_argument("--skip-control", action="store_true")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    catalog = load_json(Path(args.catalog))
    candidates = catalog.get("candidates") or []

    target = catalog.get("target") or {}
    uart_d_addr = str(target.get("d_addr") or "0x4006A007")

    raw_rows: List[Dict[str, Any]] = []

    if args.include_control and not args.skip_control:
        for rep in range(1, args.repeats + 1):
            raw_rows.append(
                run_one_candidate(
                    args=args,
                    candidate={},
                    rep_index=rep,
                    is_control=True,
                    uart_d_addr=uart_d_addr,
                )
            )

    for candidate in candidates:
        for rep in range(1, args.repeats + 1):
            raw_rows.append(
                run_one_candidate(
                    args=args,
                    candidate=candidate,
                    rep_index=rep,
                    is_control=False,
                    uart_d_addr=uart_d_addr,
                )
            )

    summary_rows = summarize_results(raw_rows)

    out_root = Path(args.out_root)
    raw_csv = out_root / "raw_results.csv"
    summary_csv = out_root / "candidate_summary.csv"
    summary_json = out_root / "candidate_summary.json"

    raw_fields = [
        "candidate_id",
        "rep_index",
        "is_control",
        "returncode",
        "status",
        "last_cov",
        "last_in",
        "last_hang",
        "last_crash",
        "strategy_fire_count",
        "active_stage_count",
        "armed_uart_count",
        "uart_status_fire_count",
        "uart_data_fire_count",
        "read_override_once_fire_count",
        "read_override_repeat_fire_count",
        "read_sequence_fire_count",
        "window_execs",
        "window_interesting_execs",
        "discovered_stream_count",
        "uart_d_read_count",
        "uart_d_executions_seen",
        "rep_dir",
        "run_log",
    ]
    summary_fields = [
        "candidate_id",
        "repeat_count",
        "median_last_cov",
        "max_last_cov",
        "delta_vs_control_median_cov",
        "median_last_in",
        "median_last_hang",
        "median_last_crash",
        "median_strategy_fire_count",
        "median_uart_status_fire_count",
        "median_uart_data_fire_count",
        "median_read_override_once_fire_count",
        "median_read_override_repeat_fire_count",
        "median_read_sequence_fire_count",
        "median_uart_d_read_count",
        "median_discovered_stream_count",
        "median_window_interesting_execs",
    ]

    save_csv(raw_csv, raw_rows, raw_fields)
    save_csv(summary_csv, summary_rows, summary_fields)
    save_json(summary_json, {
        "schema": "mf_manual_strategy_sweep_summary_v1",
        "catalog": str(Path(args.catalog).resolve()),
        "raw_count": len(raw_rows),
        "summary": summary_rows,
    })

    print("\n[DONE] wrote:")
    print(f"  - {raw_csv}")
    print(f"  - {summary_csv}")
    print(f"  - {summary_json}")
    print("\n[TOP CANDIDATES]")
    for row in summary_rows[:8]:
        print(
            f"  {row['candidate_id']}: "
            f"median_cov={row['median_last_cov']}, "
            f"delta_vs_control={row['delta_vs_control_median_cov']}, "
            f"uart_data={row['median_uart_data_fire_count']}, "
            f"ro_once={row['median_read_override_once_fire_count']}, "
            f"ro_repeat={row['median_read_override_repeat_fire_count']}, "
            f"rseq={row['median_read_sequence_fire_count']}, "
            f"d_reads={row['median_uart_d_read_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())