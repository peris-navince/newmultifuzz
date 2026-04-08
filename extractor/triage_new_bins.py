#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


def load_json(path: Path) -> Any:
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


def scan_inputs(input_dir: Path) -> List[Path]:
    return sorted([p for p in input_dir.iterdir() if p.is_file()])


def triage_one(
    *,
    seed_path: Path,
    idx: int,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    run_root = Path(args.out_root) / f"{idx:03d}_{seed_path.name}"
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True, exist_ok=True)

    # 为每个 seed 单独构造 import-dir
    import_dir = run_root / "import_queue"
    import_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(seed_path, import_dir / seed_path.name)

    workdir = run_root / "workdir"
    run_log = run_root / "run.log"
    observer_dir = run_root / "observer"

    cmd = [
        args.python_bin,
        args.closed_loop_py,
        "run-fuzz",
        "--fuzzer-manifest", args.fuzzer_manifest,
        "--firmware-config", args.firmware_config,
        "--ghidra-src", args.ghidra_src,
        "--workdir", str(workdir),
        "--run-log", str(run_log),
        "--run-for", args.run_for,
        "--observer-dir", str(observer_dir),
        "--import-dir", str(import_dir),
    ]

    print(f"[TRIAGE] {seed_path.name} :: {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, cwd=args.repo_root)
    rc = int(proc.returncode)

    summary_path = run_root / "run_fuzz_summary.json"
    if not summary_path.exists():
        raise RuntimeError(f"missing run_fuzz_summary.json for {seed_path}")

    summary_obj = load_json(summary_path)
    run_summary = summary_obj.get("run_summary") or {}

    observer_summary_path = observer_dir / "latest_window_summary.json"
    observer_discovered_path = observer_dir / "latest_window_discovered_streams.json"

    window_execs = 0
    window_interesting_execs = 0
    discovered_stream_count = 0

    if observer_summary_path.exists():
        obs = load_json(observer_summary_path)
        window_execs = int(obs.get("window_execs") or 0)
        window_interesting_execs = int(obs.get("window_interesting_execs") or 0)

    if observer_discovered_path.exists():
        arr = load_json(observer_discovered_path)
        if isinstance(arr, list):
            discovered_stream_count = len(arr)

    st = seed_path.stat()
    row = {
        "seed_name": seed_path.name,
        "seed_path": str(seed_path),
        "seed_size": int(st.st_size),
        "returncode": rc,
        "status": str(run_summary.get("status") or ""),
        "last_cov": int(run_summary.get("last_cov") or 0),
        "last_in": int(run_summary.get("last_in") or 0),
        "last_hang": int(run_summary.get("last_hang") or 0),
        "last_crash": int(run_summary.get("last_crash") or 0),
        "window_execs": window_execs,
        "window_interesting_execs": window_interesting_execs,
        "discovered_stream_count": discovered_stream_count,
        "run_root": str(run_root),
        "run_log": str(run_log),
    }
    return row


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Triage newly discovered binary seeds one-by-one.")
    ap.add_argument("--repo-root", default="/home/MultiFuzz")
    ap.add_argument("--python-bin", default=sys.executable)
    ap.add_argument("--closed-loop-py", default="/home/MultiFuzz/extractor/closed_loop.py")
    ap.add_argument("--fuzzer-manifest", default="/home/MultiFuzz/hail-fuzz/Cargo.toml")
    ap.add_argument("--firmware-config", default="/home/MultiFuzz/benchmarks/P2IM/Console/config.yml")
    ap.add_argument("--ghidra-src", default="/home/MultiFuzz/tools/ghidra")
    ap.add_argument("--input-dir", required=True, help="Directory containing new *.bin seeds")
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--run-for", default="5s", help="Per-seed triage time budget")
    ap.add_argument("--limit", type=int, default=0, help="0 means all seeds")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    seeds = scan_inputs(input_dir)
    if args.limit > 0:
        seeds = seeds[:args.limit]

    rows: List[Dict[str, Any]] = []
    for idx, seed in enumerate(seeds, start=1):
        rows.append(triage_one(seed_path=seed, idx=idx, args=args))

    rows.sort(
        key=lambda x: (
            int(x["last_cov"]),
            int(x["window_interesting_execs"]),
            int(x["discovered_stream_count"]),
            -int(x["last_hang"]),
        ),
        reverse=True,
    )

    out_root = Path(args.out_root)
    save_csv(
        out_root / "triage_summary.csv",
        rows,
        [
            "seed_name",
            "seed_size",
            "status",
            "last_cov",
            "last_in",
            "last_hang",
            "last_crash",
            "window_execs",
            "window_interesting_execs",
            "discovered_stream_count",
            "seed_path",
            "run_root",
            "run_log",
        ],
    )
    save_json(out_root / "triage_summary.json", {
        "schema": "mf_seed_triage_summary_v1",
        "input_dir": str(input_dir),
        "seed_count": len(rows),
        "rows": rows,
    })

    print(f"\n[OK] wrote {out_root / 'triage_summary.csv'}")
    print(f"[OK] wrote {out_root / 'triage_summary.json'}")
    print("\n[TOP 10]")
    for row in rows[:10]:
        print(
            f"  {row['seed_name']}: size={row['seed_size']} "
            f"cov={row['last_cov']} in={row['last_in']} "
            f"hang={row['last_hang']} interesting={row['window_interesting_execs']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())