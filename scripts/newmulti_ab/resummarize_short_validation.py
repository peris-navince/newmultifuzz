#!/usr/bin/env python3
import argparse
import csv
import json
import re
from pathlib import Path
from collections import Counter


def load_json(p, default=None):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def norm_addr(x):
    if not x:
        return ""
    try:
        return f"0x{int(str(x), 0):X}".lower()
    except Exception:
        return str(x).strip().lower()


def addr_token(x):
    return norm_addr(x).replace("0x", "").lower()


def fire_lines_from_log(path):
    p = Path(path)
    if not p.exists():
        return 0
    return sum(
        1 for line in p.read_text(errors="ignore").splitlines()
        if "[strategy-runtime] fire" in line
    )


def trace_addr_count(path, target_addr):
    p = Path(path)
    if not p.exists():
        return 0

    target = addr_token(target_addr)
    count = 0

    # Count only MMIO read/write lines containing the target address.
    # This avoids treating path strings or metadata as hotspot evidence.
    for line in p.read_text(errors="ignore").splitlines():
        low = line.lower()
        if "mmio" not in low:
            continue
        if target in low.replace("0x", ""):
            count += 1

    return count


def observer_target_count(run_root, target_addr):
    target = norm_addr(target_addr)
    root = Path(run_root)

    candidates = []

    latest = load_json(root / "observer" / "latest_window_summary.json", {}) or {}
    for key in ["primary_hotspots", "raw_top_hotspots", "auxiliary_hotspots"]:
        vals = latest.get(key) or []
        if isinstance(vals, list):
            candidates.extend(vals)

    for fname in [
        "all_ranked_hotspots.json",
        "summary.json",
        "latest_window_summary.json",
    ]:
        obj = load_json(root / "observer" / fname, None)
        if isinstance(obj, list):
            candidates.extend(obj)
        elif isinstance(obj, dict):
            for key in ["primary_hotspots", "raw_top_hotspots", "auxiliary_hotspots", "hotspots", "ranked_hotspots"]:
                vals = obj.get(key) or []
                if isinstance(vals, list):
                    candidates.extend(vals)

    best = 0
    for h in candidates:
        if not isinstance(h, dict):
            continue
        if norm_addr(h.get("addr")) == target:
            rc = int(h.get("read_count") or h.get("count") or 0)
            best = max(best, rc)

    return best


def find_target_hotspot_count(run_root, target_addr):
    root = Path(run_root)

    observer_count = observer_target_count(root, target_addr)

    trace_log_count = trace_addr_count(root / "replay_trace.log", target_addr)
    trace_json_count = trace_addr_count(root / "replay_trace.json", target_addr)

    # Prefer observer read_count if available; otherwise use trace count.
    return max(observer_count, trace_log_count, trace_json_count)


def run_metrics(run_root, target_addr):
    root = Path(run_root)
    run = load_json(root / "run_fuzz_summary.json", {}) or {}
    rs = run.get("run_summary", run) if isinstance(run, dict) else {}

    return {
        "status": rs.get("status"),
        "last_cov": int(rs.get("last_cov") or 0),
        "last_in": int(rs.get("last_in") or 0),
        "last_hang": int(rs.get("last_hang") or 0),
        "last_crash": int(rs.get("last_crash") or 0),
        "fire_lines": fire_lines_from_log(root / "run.log"),
        "target_hotspot_addr": norm_addr(target_addr),
        "target_hotspot_read_count": find_target_hotspot_count(root, target_addr),
    }


def classify(row):
    if row["candidate_id"] == "control":
        return "control"

    if int(row["fire_lines"]) <= 0:
        return "guidance_not_consumed"

    if int(row["hang_delta_vs_control"]) > 0 or int(row["crash_delta_vs_control"]) > 0:
        return "guidance_harmful_crash_or_hang"

    if int(row["cov_delta_vs_control"]) > 0 or int(row["in_delta_vs_control"]) > 0:
        return "short_effective"

    if int(row["target_hotspot_delta_vs_control"]) < 0:
        return "guidance_consumed_hotspot_reduced_no_gain"

    return "guidance_consumed_no_gain"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-root", required=True)
    ap.add_argument("--target-addr", required=True)
    args = ap.parse_args()

    root = Path(args.batch_root)
    old_csv = root / "short_validation_summary.csv"
    rows0 = list(csv.DictReader(old_csv.open()))

    rows = []
    control_metrics = None

    for r in rows0:
        cid = r["candidate_id"]
        run_root = Path(r["run_root"])
        m = run_metrics(run_root, args.target_addr)
        out = dict(r)
        out.update(m)
        if cid == "control":
            control_metrics = m
        rows.append(out)

    if control_metrics is None:
        raise SystemExit("missing control row")

    for r in rows:
        r["cov_delta_vs_control"] = int(r["last_cov"]) - int(control_metrics["last_cov"])
        r["in_delta_vs_control"] = int(r["last_in"]) - int(control_metrics["last_in"])
        r["hang_delta_vs_control"] = int(r["last_hang"]) - int(control_metrics["last_hang"])
        r["crash_delta_vs_control"] = int(r["last_crash"]) - int(control_metrics["last_crash"])
        r["target_hotspot_delta_vs_control"] = int(r["target_hotspot_read_count"]) - int(control_metrics["target_hotspot_read_count"])
        r["classification"] = classify(r)

    out_csv = root / "short_validation_summary_robust.csv"
    fields = [
        "candidate_id",
        "classification",
        "fire_lines",
        "last_cov",
        "last_in",
        "last_hang",
        "last_crash",
        "target_hotspot_addr",
        "target_hotspot_read_count",
        "cov_delta_vs_control",
        "in_delta_vs_control",
        "target_hotspot_delta_vs_control",
        "hang_delta_vs_control",
        "crash_delta_vs_control",
        "guidance_path",
        "run_root",
    ]

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    out_json = root / "short_validation_summary_robust.json"
    out_json.write_text(json.dumps({
        "batch_root": str(root),
        "target_addr": args.target_addr,
        "classification": dict(Counter(r["classification"] for r in rows)),
        "rows": rows,
    }, indent=2, ensure_ascii=False))

    print("wrote", out_csv)
    print("classification:", Counter(r["classification"] for r in rows))
    for r in rows:
        print(
            r["candidate_id"],
            r["classification"],
            "fire", r["fire_lines"],
            "cov", r["last_cov"],
            "in", r["last_in"],
            "target_hotspot", r["target_hotspot_read_count"],
            "Δtarget_hotspot", r["target_hotspot_delta_vs_control"],
        )


if __name__ == "__main__":
    main()
