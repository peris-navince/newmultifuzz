#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path


MMIO_RE = re.compile(
    r"mmio=(?P<op>read|write)\s+addr=(?P<addr>0x[0-9a-fA-F]+).*?size=(?P<size>\d+)"
)


def norm_addr(x: str) -> str:
    if not x:
        return ""
    try:
        return f"0x{int(str(x), 0):X}".lower()
    except Exception:
        return str(x).strip().lower()


def parse_trace_mmio(trace_path: Path):
    read_counts = Counter()
    write_counts = Counter()
    width_counts = {}

    if not trace_path.exists():
        return {
            "read_counts": read_counts,
            "write_counts": write_counts,
            "width_counts": width_counts,
            "record_count": 0,
        }

    # Important: replay_trace.log may contain many MMIO records in one physical
    # line, or escaped newline text. Use finditer over the full text instead of
    # splitlines()+search, otherwise we only count the first MMIO record per line.
    text = trace_path.read_text(errors="ignore")

    record_count = 0
    for m in MMIO_RE.finditer(text):
        record_count += 1
        op = m.group("op")
        addr = norm_addr(m.group("addr"))
        size = int(m.group("size"))

        if op == "read":
            read_counts[addr] += 1
        else:
            write_counts[addr] += 1

        width_counts.setdefault(addr, Counter())[size] += 1

    return {
        "read_counts": read_counts,
        "write_counts": write_counts,
        "width_counts": width_counts,
        "record_count": record_count,
    }


def top_items(counter: Counter, k: int):
    return [{"addr": a, "count": c} for a, c in counter.most_common(k)]


def compact_widths(width_counter):
    out = {}
    for addr, c in width_counter.items():
        out[addr] = {str(k): v for k, v in sorted(c.items())}
    return out


def classify_shift(row, target_addr, control_top_addr, control_target_count, candidate_stats, args):
    cid = row["candidate_id"]

    if cid == "control":
        return "control"

    fire = int(row.get("fire_lines") or 0)
    if fire <= 0:
        return "no_guidance_consumption"

    reads = candidate_stats["read_counts"]
    target_count = reads.get(target_addr, 0)
    top = reads.most_common(1)
    top_addr, top_count = top[0] if top else ("", 0)

    target_delta = target_count - control_target_count

    # Find strongest non-target read hotspot.
    non_target = [(a, c) for a, c in reads.most_common() if a != target_addr]
    next_addr, next_count = non_target[0] if non_target else ("", 0)

    target_reduced = target_delta < -args.target_reduce_min
    next_dominant = (
        next_addr
        and next_count >= args.next_min_count
        and next_count >= target_count * args.next_vs_target_ratio
    )

    if target_reduced and next_dominant:
        return "shifted_to_new_mmio_bottleneck"

    if top_addr != target_addr and next_dominant:
        return "possible_shift_to_new_mmio_bottleneck"

    if target_count >= control_target_count * args.same_target_ratio:
        return "same_bottleneck_still_dominant"

    if target_reduced:
        return "target_reduced_no_clear_next_bottleneck"

    return "guidance_consumed_no_clear_shift"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-root", required=True)
    ap.add_argument("--summary-csv", default=None)
    ap.add_argument("--target-addr", required=True)
    ap.add_argument("--top-k", type=int, default=12)
    ap.add_argument("--target-reduce-min", type=int, default=1000)
    ap.add_argument("--next-min-count", type=int, default=1000)
    ap.add_argument("--next-vs-target-ratio", type=float, default=0.8)
    ap.add_argument("--same-target-ratio", type=float, default=0.9)
    args = ap.parse_args()

    batch = Path(args.batch_root)
    summary_csv = Path(args.summary_csv) if args.summary_csv else batch / "short_validation_summary_robust.csv"
    target_addr = norm_addr(args.target_addr)

    rows0 = list(csv.DictReader(summary_csv.open()))

    per_run = {}
    for r in rows0:
        cid = r["candidate_id"]
        run_root = Path(r["run_root"])
        stats = parse_trace_mmio(run_root / "replay_trace.log")
        per_run[cid] = stats

    control = per_run.get("control")
    if not control:
        raise SystemExit("missing control run in summary")

    control_reads = control["read_counts"]
    control_target_count = control_reads.get(target_addr, 0)
    control_top = control_reads.most_common(1)
    control_top_addr, control_top_count = control_top[0] if control_top else ("", 0)

    out_rows = []
    json_rows = []

    for r in rows0:
        cid = r["candidate_id"]
        stats = per_run[cid]
        reads = stats["read_counts"]

        target_count = reads.get(target_addr, 0)
        top_reads = top_items(reads, args.top_k)
        non_target = [(a, c) for a, c in reads.most_common() if a != target_addr]
        next_addr, next_count = non_target[0] if non_target else ("", 0)

        shift_class = classify_shift(
            r,
            target_addr,
            control_top_addr,
            control_target_count,
            stats,
            args,
        )

        out = {
            "candidate_id": cid,
            "prior_classification": r.get("classification", ""),
            "shift_classification": shift_class,
            "fire_lines": r.get("fire_lines", "0"),
            "last_cov": r.get("last_cov", ""),
            "last_in": r.get("last_in", ""),
            "target_addr": target_addr,
            "control_target_count": control_target_count,
            "candidate_target_count": target_count,
            "target_delta_vs_control": target_count - control_target_count,
            "control_top_addr": control_top_addr,
            "control_top_count": control_top_count,
            "candidate_top_addr": top_reads[0]["addr"] if top_reads else "",
            "candidate_top_count": top_reads[0]["count"] if top_reads else 0,
            "next_non_target_addr": next_addr,
            "next_non_target_count": next_count,
            "run_root": r.get("run_root", ""),
        }
        out_rows.append(out)

        json_rows.append({
            **out,
            "top_reads": top_reads,
            "width_counts": compact_widths(stats["width_counts"]),
        })

    out_csv = batch / "bottleneck_shift_summary.csv"
    fields = [
        "candidate_id",
        "prior_classification",
        "shift_classification",
        "fire_lines",
        "last_cov",
        "last_in",
        "target_addr",
        "control_target_count",
        "candidate_target_count",
        "target_delta_vs_control",
        "control_top_addr",
        "control_top_count",
        "candidate_top_addr",
        "candidate_top_count",
        "next_non_target_addr",
        "next_non_target_count",
        "run_root",
    ]

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(out_rows)

    out_json = batch / "bottleneck_shift_summary.json"
    out_json.write_text(json.dumps({
        "batch_root": str(batch),
        "target_addr": target_addr,
        "control": {
            "target_count": control_target_count,
            "top_reads": top_items(control_reads, args.top_k),
            "width_counts": compact_widths(control["width_counts"]),
        },
        "rows": json_rows,
    }, indent=2, ensure_ascii=False))

    print("wrote", out_csv)
    print("control_target_count:", control_target_count)
    print("control_top:", control_top_addr, control_top_count)

    for r in out_rows:
        print(
            r["candidate_id"],
            r["shift_classification"],
            "fire", r["fire_lines"],
            "target", r["candidate_target_count"],
            "Δtarget", r["target_delta_vs_control"],
            "next", r["next_non_target_addr"], r["next_non_target_count"],
            "cov", r["last_cov"],
            "in", r["last_in"],
        )


if __name__ == "__main__":
    main()
