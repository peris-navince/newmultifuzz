#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Summarize local newMulti A/B experiment outputs.

Reads runner_result.json plus closed_loop summaries under an experiment output
root and writes compact CSV/JSON files for analysis.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def load_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def int_or_none(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


def flatten_run_summary(summary: Any) -> Dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    rs = summary.get("run_summary") if isinstance(summary.get("run_summary"), dict) else summary
    if not isinstance(rs, dict):
        return {}
    return {
        "last_cov": int_or_none(rs.get("last_cov")),
        "last_in": int_or_none(rs.get("last_in")),
        "last_hang": int_or_none(rs.get("last_hang")),
        "last_crash": int_or_none(rs.get("last_crash")),
        "run_status": rs.get("status"),
    }


def recursive_find_numbers(obj: Any, key_names: Iterable[str]) -> List[int]:
    keys = set(key_names)
    out: List[int] = []
    def rec(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if k in keys:
                    iv = int_or_none(v)
                    if iv is not None:
                        out.append(iv)
                rec(v)
        elif isinstance(x, list):
            for v in x:
                rec(v)
    rec(obj)
    return out


def recursive_find_paths(obj: Any, suffix_names: Iterable[str]) -> List[str]:
    suffixes = tuple(suffix_names)
    paths: List[str] = []
    def rec(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if isinstance(v, str) and (k.endswith(suffixes) or any(v.endswith(s) for s in suffixes)):
                    paths.append(v)
                rec(v)
        elif isinstance(x, list):
            for v in x:
                rec(v)
    rec(obj)
    return paths


def sum_guidance_signals(summary: Any) -> Dict[str, Any]:
    # Different closed_loop modes store action fire counts in slightly different
    # places. Keep this robust by recursively collecting common fields.
    fire_values = recursive_find_numbers(summary, [
        "fire_count", "fires", "action_fires", "cumulative_action_fires", "tail_fires"
    ])
    progress_values = recursive_find_numbers(summary, [
        "sequence_progress", "cumulative_sequence_progress", "active_stage_count"
    ])
    return {
        "guidance_signal_sum": sum(fire_values) if fire_values else 0,
        "guidance_progress_sum": sum(progress_values) if progress_values else 0,
        "guidance_signal_fields_seen": len(fire_values),
    }


def summarize_guided(summary: Any) -> Dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    covs = recursive_find_numbers(summary, [
        "last_cov", "frontier_last_cov", "final_cov", "child_cov", "coverage", "baseline_cov"
    ])
    inputs = recursive_find_numbers(summary, ["last_in", "final_last_in"])
    hangs = recursive_find_numbers(summary, ["last_hang", "last_hangs", "final_hangs", "hangs"])
    crashes = recursive_find_numbers(summary, ["last_crash", "last_crashes", "crashes"])
    out = {
        "last_cov": max(covs) if covs else None,
        "last_in": max(inputs) if inputs else None,
        "last_hang": max(hangs) if hangs else None,
        "last_crash": max(crashes) if crashes else None,
        "mode_summary": summary.get("mode") or summary.get("schema"),
        "materialization_mode": summary.get("materialization_mode"),
        "summary_path_nested": summary.get("summary_path"),
        "long_horizon_summary_path": summary.get("long_horizon_summary_path"),
    }
    out.update(sum_guidance_signals(summary))
    return out


def collect_rows(out_root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for rr in sorted(out_root.rglob("runner_result.json")):
        runner = load_json(rr) or {}
        arm = runner.get("arm") or rr.parent.name
        meta = load_json(rr.parent / "case_meta.json") or {}
        case = meta.get("case") if isinstance(meta, dict) else {}
        if not isinstance(case, dict):
            case = {}
        summary_path_raw = runner.get("summary_path")
        summary_path = Path(summary_path_raw) if summary_path_raw else None
        if summary_path and not summary_path.is_absolute():
            summary_path = (rr.parent / summary_path).resolve()
        summary = load_json(summary_path) if summary_path and summary_path.exists() else None
        metrics = summarize_guided(summary) if arm == "guided_knowledge" else flatten_run_summary(summary)
        if arm == "baseline_random":
            metrics.update(sum_guidance_signals(summary))
        row = {
            "case_id": runner.get("case_id") or case.get("case_id"),
            "relative_dir": runner.get("relative_dir") or case.get("relative_dir"),
            "dataset": case.get("dataset"),
            "benchmark": case.get("benchmark"),
            "repeat_idx": runner.get("repeat_idx") or meta.get("repeat_idx"),
            "arm": arm,
            "returncode": runner.get("returncode"),
            "runner_status": runner.get("status"),
            "elapsed_sec": runner.get("elapsed_sec"),
            "summary_path": str(summary_path) if summary_path else None,
            "runner_result": str(rr),
            "manual_mapping_confidence": case.get("manual_mapping_confidence"),
            "board": case.get("board"),
            "mcu": case.get("mcu"),
        }
        row.update(metrics)
        rows.append(row)
    return rows


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = [
        "case_id", "relative_dir", "dataset", "benchmark", "repeat_idx", "arm",
        "returncode", "runner_status", "elapsed_sec", "last_cov", "last_in", "last_hang", "last_crash",
        "guidance_signal_sum", "guidance_progress_sum", "guidance_signal_fields_seen",
        "manual_mapping_confidence", "board", "mcu", "mode_summary", "materialization_mode",
        "summary_path", "runner_result",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def paired_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_key: Dict[Tuple[str, Any], Dict[str, Dict[str, Any]]] = {}
    for r in rows:
        key = (str(r.get("case_id")), r.get("repeat_idx"))
        by_key.setdefault(key, {})[str(r.get("arm"))] = r
    out: List[Dict[str, Any]] = []
    for (case_id, rep), arms in sorted(by_key.items()):
        b = arms.get("baseline_random") or {}
        g = arms.get("guided_knowledge") or {}
        bc = int_or_none(b.get("last_cov"))
        gc = int_or_none(g.get("last_cov"))
        bi = int_or_none(b.get("last_in"))
        gi = int_or_none(g.get("last_in"))
        out.append({
            "case_id": case_id,
            "relative_dir": b.get("relative_dir") or g.get("relative_dir"),
            "repeat_idx": rep,
            "baseline_cov": bc,
            "guided_cov": gc,
            "coverage_delta": (gc - bc) if gc is not None and bc is not None else None,
            "coverage_ratio": round(gc / bc, 4) if gc is not None and bc not in (None, 0) else None,
            "baseline_inputs": bi,
            "guided_inputs": gi,
            "guided_signal_sum": g.get("guidance_signal_sum"),
            "baseline_rc": b.get("returncode"),
            "guided_rc": g.get("returncode"),
            "mapping_confidence": g.get("manual_mapping_confidence") or b.get("manual_mapping_confidence"),
        })
    return out


def write_paired_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = [
        "case_id", "relative_dir", "repeat_idx", "baseline_cov", "guided_cov", "coverage_delta", "coverage_ratio",
        "baseline_inputs", "guided_inputs", "guided_signal_sum", "baseline_rc", "guided_rc", "mapping_confidence",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize newMulti local A/B experiment outputs.")
    ap.add_argument("--out-root", required=True, help="Experiment output root used by run_newmulti_ab.py")
    ap.add_argument("--csv-out", default=None)
    ap.add_argument("--paired-csv-out", default=None)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    out_root = Path(args.out_root).expanduser().resolve()
    rows = collect_rows(out_root)
    csv_out = Path(args.csv_out).expanduser().resolve() if args.csv_out else out_root / "ab_summary.csv"
    paired_out = Path(args.paired_csv_out).expanduser().resolve() if args.paired_csv_out else out_root / "ab_paired_summary.csv"
    json_out = Path(args.json_out).expanduser().resolve() if args.json_out else out_root / "ab_summary.json"
    pairs = paired_rows(rows)
    write_csv(csv_out, rows)
    write_paired_csv(paired_out, pairs)
    payload = {
        "out_root": str(out_root),
        "row_count": len(rows),
        "pair_count": len(pairs),
        "csv": str(csv_out),
        "paired_csv": str(paired_out),
        "rows": rows,
        "pairs": pairs,
    }
    json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: payload[k] for k in ["out_root", "row_count", "pair_count", "csv", "paired_csv"]}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
