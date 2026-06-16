#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def save_json(path: Path, obj: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def run_cmd(cmd: List[str], log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as f:
        f.write("[cmd] " + " ".join(cmd) + "\n")
        f.flush()
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            f.write(line)
        proc.wait()
        return proc.returncode or 0


def fire_lines_from_log(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(
        1 for line in path.read_text(errors="ignore").splitlines()
        if "[strategy-runtime] fire" in line
    )


def first_fire_lines(path: Path, limit: int = 5) -> List[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        if "[strategy-runtime] fire" in line:
            out.append(line)
            if len(out) >= limit:
                break
    return out


def run_metrics(run_root: Path) -> Dict[str, Any]:
    run = load_json(run_root / "run_fuzz_summary.json", {}) or {}
    rs = run.get("run_summary", run) if isinstance(run, dict) else {}

    grs = load_json(run_root / "guidance_runtime_summary.json", {}) or {}
    obs = load_json(run_root / "observer" / "latest_window_summary.json", {}) or {}

    primary = None
    if isinstance(obs, dict):
        ph = obs.get("primary_hotspots") or []
        if ph:
            primary = ph[0]

    fire_lines = fire_lines_from_log(run_root / "run.log")

    return {
        "status": rs.get("status"),
        "last_cov": int(rs.get("last_cov") or 0),
        "last_in": int(rs.get("last_in") or 0),
        "last_hang": int(rs.get("last_hang") or 0),
        "last_crash": int(rs.get("last_crash") or 0),
        "fire_lines": fire_lines,
        "summary_fire_counts": [
            a.get("fire_count", 0)
            for a in grs.get("actions", [])
        ] if isinstance(grs, dict) else [],
        "primary_hotspot_addr": (primary or {}).get("addr"),
        "primary_hotspot_read_count": int((primary or {}).get("read_count") or 0),
        "primary_hotspot_width_counts": (primary or {}).get("width_counts"),
        "first_fire_lines": first_fire_lines(run_root / "run.log"),
    }


def classify(row: Dict[str, Any]) -> str:
    if row["candidate_id"] == "control":
        return "control"

    if int(row.get("fire_lines") or 0) <= 0:
        return "guidance_not_consumed"

    cov_delta = int(row.get("cov_delta_vs_control") or 0)
    in_delta = int(row.get("in_delta_vs_control") or 0)
    hang_delta = int(row.get("hang_delta_vs_control") or 0)
    crash_delta = int(row.get("crash_delta_vs_control") or 0)
    hotspot_delta = int(row.get("hotspot_read_delta_vs_control") or 0)

    if hang_delta > 0 or crash_delta > 0:
        return "guidance_harmful_crash_or_hang"

    if cov_delta > 0 or in_delta > 0:
        return "short_effective"

    if hotspot_delta < 0:
        return "guidance_consumed_hotspot_reduced_no_gain"

    return "guidance_consumed_no_gain"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--event-dir", required=True)
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--import-dir", required=True)
    ap.add_argument("--run-for", default="60s")
    ap.add_argument("--firmware-config", default="benchmarks/P2IM/Heat_Press/config.yml")
    ap.add_argument("--fuzzer-manifest", default="Cargo.toml")
    ap.add_argument("--fuzzer-bin", default="target/debug/hail-fuzz")
    ap.add_argument("--ghidra-src", default="tools/ghidra")
    ap.add_argument("--max-candidates", type=int, default=12)
    ap.add_argument("--guidance-index", default=None)
    ap.add_argument("--control-only", action="store_true")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    event_dir = Path(args.event_dir)
    if not event_dir.is_absolute():
        event_dir = repo / event_dir

    index_path = Path(args.guidance_index) if args.guidance_index else event_dir / "guidance" / "guidance_index.json"
    if not index_path.is_absolute():
        index_path = repo / index_path
    index = load_json(index_path, {})
    compiled = list(index.get("compiled") or [])[: args.max_candidates]

    out_root = Path(args.out_root)
    if not out_root.is_absolute():
        out_root = repo / out_root
    out_root.mkdir(parents=True, exist_ok=True)

    # Use direct subprocess with stdout file for all runs.
    def run_one(candidate_id: str, guidance_path: Optional[str]) -> Dict[str, Any]:
        root = out_root / candidate_id
        if root.exists():
            subprocess.run(["rm", "-rf", str(root)], check=False)
        root.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable, "extractor/closed_loop.py", "run-fuzz",
            "--fuzzer-manifest", args.fuzzer_manifest,
            "--fuzzer-bin", args.fuzzer_bin,
            "--firmware-config", args.firmware_config,
            "--ghidra-src", args.ghidra_src,
            "--workdir", str(root / "workdir"),
            "--run-log", str(root / "run.log"),
            "--run-for", args.run_for,
            "--observer-dir", str(root / "observer"),
            "--import-dir", args.import_dir,
            "--dump-trace",
            "--trace-basename", "replay_trace",
        ]
        if guidance_path:
            cmd += [
                "--guidance-file", guidance_path,
                "--guidance-summary-out", str(root / "guidance_runtime_summary.json"),
            ]

        with (root / "run_fuzz_summary.json").open("w", encoding="utf-8") as out:
            proc = subprocess.run(
                cmd,
                cwd=str(repo),
                stdout=out,
                stderr=subprocess.STDOUT,
                text=True,
            )
        m = run_metrics(root)
        m.update({
            "candidate_id": candidate_id,
            "guidance_path": guidance_path,
            "run_root": str(root),
            "returncode": proc.returncode,
        })
        return m

    rows = []
    control = run_one("control", None)
    rows.append(control)

    if not args.control_only:
        for item in compiled:
            cid = item.get("candidate_id")
            gpath = item.get("guidance_path")
            if not cid or not gpath:
                continue
            print("[short-validation]", cid)
            rows.append(run_one(cid, gpath))

    c = control
    for r in rows:
        r["cov_delta_vs_control"] = int(r["last_cov"]) - int(c["last_cov"])
        r["in_delta_vs_control"] = int(r["last_in"]) - int(c["last_in"])
        r["hang_delta_vs_control"] = int(r["last_hang"]) - int(c["last_hang"])
        r["crash_delta_vs_control"] = int(r["last_crash"]) - int(c["last_crash"])
        r["hotspot_read_delta_vs_control"] = int(r["primary_hotspot_read_count"]) - int(c["primary_hotspot_read_count"])
        r["classification"] = classify(r)

    save_json(out_root / "short_validation_summary.json", {
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_dir": str(event_dir),
        "import_dir": args.import_dir,
        "run_for": args.run_for,
        "rows": rows,
    })

    fields = [
        "candidate_id",
        "classification",
        "fire_lines",
        "last_cov",
        "last_in",
        "last_hang",
        "last_crash",
        "primary_hotspot_addr",
        "primary_hotspot_read_count",
        "cov_delta_vs_control",
        "in_delta_vs_control",
        "hotspot_read_delta_vs_control",
        "hang_delta_vs_control",
        "crash_delta_vs_control",
        "guidance_path",
        "run_root",
    ]

    with (out_root / "short_validation_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    print("wrote", out_root / "short_validation_summary.csv")
    for r in rows:
        print(
            r["candidate_id"],
            r["classification"],
            "fire=", r["fire_lines"],
            "cov=", r["last_cov"],
            "in=", r["last_in"],
            "hotspot=", r["primary_hotspot_read_count"],
            "Δhotspot=", r["hotspot_read_delta_vs_control"],
        )


if __name__ == "__main__":
    main()
