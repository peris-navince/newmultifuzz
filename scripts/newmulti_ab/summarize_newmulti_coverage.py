#!/usr/bin/env python3
"""
Summarize exact coverage changes for NewMultiFuzz closed-loop experiments.

Later --roots files override earlier roots for duplicate case IDs. This is useful
when an interrupted target was rerun and the rerun should be treated as final.

Outputs:
  coverage_epoch_details.csv
  coverage_target_summary.csv
  coverage_summary.md
  coverage_summary.json
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass
class EpochCoverage:
    case_id: str
    root: str
    epoch: str
    script_success: bool
    failed: bool
    decision: str
    has_long_candidate: bool
    control_cov: int | None
    best_candidate_id: str
    best_candidate_cov: int | None
    best_delta_cov: int | None
    best_delta_cov_pct: float | None
    best_fire: int | None
    best_delta_input: int | None
    best_delta_addr1: int | None
    best_delta_addr2: int | None


def natural_epoch_key(path: Path) -> tuple[int, str]:
    try:
        return int(path.name.split("_", 1)[1]), path.name
    except (IndexError, ValueError):
        return 10**9, path.name


def read_root_lists(paths: Iterable[Path]) -> dict[str, Path]:
    """Read root-list files. Later files override earlier duplicate case IDs."""
    selected: dict[str, Path] = {}
    for root_list in paths:
        if not root_list.is_file():
            raise FileNotFoundError(f"roots file not found: {root_list}")
        for lineno, raw in enumerate(root_list.read_text(errors="replace").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                raise ValueError(f"invalid roots line at {root_list}:{lineno}: {raw!r}")
            selected[parts[0]] = Path(parts[1])
    return selected


def as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def candidate_score(row: dict[str, Any]) -> tuple[int, int, int, int]:
    delta_cov = as_int(row.get("delta_cov")) or 0
    delta_input = as_int(row.get("delta_input")) or 0
    fire = as_int(row.get("fire")) or 0
    d1 = as_int(row.get("delta_addr1")) or 0
    d2 = as_int(row.get("delta_addr2")) or 0
    hotspot_reduction = -(d1 + d2)
    return delta_cov, delta_input, fire, hotspot_reduction


def parse_epoch(case_id: str, root: Path, epoch_dir: Path) -> EpochCoverage:
    summary_path = epoch_dir / "final_summary.json"
    if not summary_path.is_file():
        return EpochCoverage(case_id, str(root), epoch_dir.name, False, True,
                             "missing_final_summary", False, None, "", None,
                             None, None, None, None, None, None)

    try:
        data = json.loads(summary_path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {summary_path}: {exc}") from exc

    rows = data.get("long_validation_rows") or []
    control = next((r for r in rows if str(r.get("candidate_id", "")).lower() == "control"), None)
    candidates = [r for r in rows if str(r.get("candidate_id", "")).lower() != "control"]
    control_cov = as_int(control.get("cov")) if control else None

    normalized: list[dict[str, Any]] = []
    for item in candidates:
        row = dict(item)
        candidate_cov = as_int(row.get("cov"))
        delta_cov = as_int(row.get("delta_cov"))
        if delta_cov is None and candidate_cov is not None and control_cov is not None:
            delta_cov = candidate_cov - control_cov
        row["delta_cov"] = delta_cov
        normalized.append(row)

    if normalized:
        best = max(normalized, key=candidate_score)
        best_cov = as_int(best.get("cov"))
        best_delta = as_int(best.get("delta_cov"))
        best_pct = (best_delta / control_cov * 100.0
                    if best_delta is not None and control_cov not in (None, 0)
                    else None)
    else:
        best, best_cov, best_delta, best_pct = {}, None, None, None

    return EpochCoverage(
        case_id=case_id,
        root=str(root),
        epoch=epoch_dir.name,
        script_success=bool(data.get("script_success")),
        failed=bool(data.get("failed")),
        decision=str(data.get("final_decision", "")),
        has_long_candidate=bool(normalized),
        control_cov=control_cov,
        best_candidate_id=str(best.get("candidate_id", "")),
        best_candidate_cov=best_cov,
        best_delta_cov=best_delta,
        best_delta_cov_pct=best_pct,
        best_fire=as_int(best.get("fire")),
        best_delta_input=as_int(best.get("delta_input")),
        best_delta_addr1=as_int(best.get("delta_addr1")),
        best_delta_addr2=as_int(best.get("delta_addr2")),
    )


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def fmt_num(value: Any) -> str:
    return "NA" if value is None else str(value)


def fmt_pct(value: float | None) -> str:
    return "NA" if value is None else f"{value:.2f}%"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--roots", nargs="+", required=True, type=Path,
                        help="One or more roots.txt files; later files override earlier duplicates.")
    parser.add_argument("--out-dir", required=True, type=Path,
                        help="Directory for generated CSV/Markdown/JSON reports.")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    roots = read_root_lists(args.roots)
    epoch_rows: list[EpochCoverage] = []
    missing_roots: list[str] = []

    for case_id, root in sorted(roots.items()):
        if not root.is_dir():
            missing_roots.append(f"{case_id}: {root}")
            continue
        epochs_dir = root / "epochs"
        if not epochs_dir.is_dir():
            missing_roots.append(f"{case_id}: missing {epochs_dir}")
            continue
        for epoch_dir in sorted(epochs_dir.glob("epoch_*"), key=natural_epoch_key):
            epoch_rows.append(parse_epoch(case_id, root, epoch_dir))

    by_case: dict[str, list[EpochCoverage]] = {}
    for row in epoch_rows:
        by_case.setdefault(row.case_id, []).append(row)

    target_rows: list[dict[str, Any]] = []
    for case_id, rows in sorted(by_case.items()):
        candidate_rows = [r for r in rows if r.has_long_candidate and r.best_delta_cov is not None]
        positive = [r for r in candidate_rows if (r.best_delta_cov or 0) > 0]
        zero = [r for r in candidate_rows if r.best_delta_cov == 0]
        negative = [r for r in candidate_rows if (r.best_delta_cov or 0) < 0]
        failed = [r for r in rows if r.failed or not r.script_success]
        best = max(candidate_rows, key=lambda r: (
            r.best_delta_cov if r.best_delta_cov is not None else -10**9,
            r.best_delta_input if r.best_delta_input is not None else -10**9,
        )) if candidate_rows else None

        target_rows.append({
            "case_id": case_id,
            "epoch_count": len(rows),
            "successful_epoch_count": sum(1 for r in rows if r.script_success and not r.failed),
            "failed_epoch_count": len(failed),
            "long_candidate_epoch_count": len(candidate_rows),
            "positive_cov_epoch_count": len(positive),
            "zero_cov_epoch_count": len(zero),
            "negative_cov_epoch_count": len(negative),
            "best_epoch": best.epoch if best else "",
            "best_decision": best.decision if best else "",
            "best_candidate_id": best.best_candidate_id if best else "",
            "best_control_cov": best.control_cov if best else None,
            "best_candidate_cov": best.best_candidate_cov if best else None,
            "best_delta_cov": best.best_delta_cov if best else None,
            "best_delta_cov_pct": best.best_delta_cov_pct if best else None,
            "best_delta_input": best.best_delta_input if best else None,
            "best_fire": best.best_fire if best else None,
        })

    epoch_dicts = [asdict(r) for r in epoch_rows]
    epoch_fields = list(EpochCoverage.__dataclass_fields__.keys())
    target_fields = [
        "case_id", "epoch_count", "successful_epoch_count", "failed_epoch_count",
        "long_candidate_epoch_count", "positive_cov_epoch_count",
        "zero_cov_epoch_count", "negative_cov_epoch_count", "best_epoch",
        "best_decision", "best_candidate_id", "best_control_cov",
        "best_candidate_cov", "best_delta_cov", "best_delta_cov_pct",
        "best_delta_input", "best_fire",
    ]
    write_csv(args.out_dir / "coverage_epoch_details.csv", epoch_dicts, epoch_fields)
    write_csv(args.out_dir / "coverage_target_summary.csv", target_rows, target_fields)

    improved_targets = [r for r in target_rows if r["best_delta_cov"] is not None and r["best_delta_cov"] > 0]
    nonnegative_targets = [r for r in target_rows if r["best_delta_cov"] is not None and r["best_delta_cov"] >= 0]
    best_pcts = [float(r["best_delta_cov_pct"]) for r in improved_targets if r["best_delta_cov_pct"] is not None]
    best_deltas = [int(r["best_delta_cov"]) for r in improved_targets if r["best_delta_cov"] is not None]

    global_summary = {
        "roots_files": [str(p) for p in args.roots],
        "target_count": len(target_rows),
        "epoch_count": len(epoch_rows),
        "successful_epoch_count": sum(1 for r in epoch_rows if r.script_success and not r.failed),
        "failed_epoch_count": sum(1 for r in epoch_rows if r.failed or not r.script_success),
        "long_candidate_epoch_count": sum(1 for r in epoch_rows if r.has_long_candidate),
        "positive_cov_epoch_count": sum(1 for r in epoch_rows if r.best_delta_cov is not None and r.best_delta_cov > 0),
        "zero_cov_epoch_count": sum(1 for r in epoch_rows if r.best_delta_cov == 0),
        "negative_cov_epoch_count": sum(1 for r in epoch_rows if r.best_delta_cov is not None and r.best_delta_cov < 0),
        "targets_with_positive_best_cov": len(improved_targets),
        "targets_with_nonnegative_best_cov": len(nonnegative_targets),
        "macro_mean_best_positive_delta_cov": statistics.mean(best_deltas) if best_deltas else None,
        "macro_median_best_positive_delta_cov": statistics.median(best_deltas) if best_deltas else None,
        "macro_mean_best_positive_delta_cov_pct": statistics.mean(best_pcts) if best_pcts else None,
        "macro_median_best_positive_delta_cov_pct": statistics.median(best_pcts) if best_pcts else None,
        "missing_roots": missing_roots,
    }

    (args.out_dir / "coverage_summary.json").write_text(json.dumps({
        "global": global_summary,
        "targets": target_rows,
        "epochs": epoch_dicts,
    }, indent=2, sort_keys=True))

    md = [
        "# NewMultiFuzz Coverage Summary",
        "",
        "## Global summary",
        "",
        f"- Targets: {global_summary['target_count']}",
        f"- Epochs: {global_summary['epoch_count']}",
        f"- Successful epochs: {global_summary['successful_epoch_count']}",
        f"- Failed epochs: {global_summary['failed_epoch_count']}",
        f"- Epochs with a long-validation candidate: {global_summary['long_candidate_epoch_count']}",
        f"- Positive / zero / negative best-coverage epochs: {global_summary['positive_cov_epoch_count']} / {global_summary['zero_cov_epoch_count']} / {global_summary['negative_cov_epoch_count']}",
        f"- Targets with a positive best coverage delta: {global_summary['targets_with_positive_best_cov']}",
        f"- Mean best positive absolute delta across improved targets: {fmt_num(global_summary['macro_mean_best_positive_delta_cov'])}",
        f"- Median best positive absolute delta across improved targets: {fmt_num(global_summary['macro_median_best_positive_delta_cov'])}",
        f"- Mean best positive relative delta across improved targets: {fmt_pct(global_summary['macro_mean_best_positive_delta_cov_pct'])}",
        f"- Median best positive relative delta across improved targets: {fmt_pct(global_summary['macro_median_best_positive_delta_cov_pct'])}",
        "",
        "> Coverage values from different firmware targets are not directly additive. The recommended aggregate is the number of improved targets plus the macro mean/median of each target's best relative improvement.",
        "",
        "## Per-target best result",
        "",
        "| Target | Candidate epochs | + / 0 / - epochs | Best epoch | Control cov | Candidate cov | Δcov | Δcov % | Decision |",
        "|---|---:|---:|---|---:|---:|---:|---:|---|",
    ]

    for row in sorted(target_rows, key=lambda x: (
        x["best_delta_cov"] is not None,
        x["best_delta_cov"] if x["best_delta_cov"] is not None else -10**9,
    ), reverse=True):
        md.append(
            f"| `{row['case_id']}` | {row['long_candidate_epoch_count']} | "
            f"{row['positive_cov_epoch_count']} / {row['zero_cov_epoch_count']} / {row['negative_cov_epoch_count']} | "
            f"{row['best_epoch'] or 'NA'} | {fmt_num(row['best_control_cov'])} | "
            f"{fmt_num(row['best_candidate_cov'])} | {fmt_num(row['best_delta_cov'])} | "
            f"{fmt_pct(row['best_delta_cov_pct'])} | `{row['best_decision'] or 'NA'}` |"
        )

    if missing_roots:
        md.extend(["", "## Missing roots", ""])
        md.extend([f"- {x}" for x in missing_roots])

    (args.out_dir / "coverage_summary.md").write_text("\n".join(md) + "\n")

    print("== coverage summary ==")
    print(f"targets={global_summary['target_count']}")
    print(f"epochs={global_summary['epoch_count']}")
    print(f"successful_epochs={global_summary['successful_epoch_count']}")
    print(f"failed_epochs={global_summary['failed_epoch_count']}")
    print("positive/zero/negative_candidate_epochs="
          f"{global_summary['positive_cov_epoch_count']}/"
          f"{global_summary['zero_cov_epoch_count']}/"
          f"{global_summary['negative_cov_epoch_count']}")
    print(f"targets_with_positive_best_cov={global_summary['targets_with_positive_best_cov']}")
    print(f"macro_mean_best_positive_delta_cov_pct={fmt_pct(global_summary['macro_mean_best_positive_delta_cov_pct'])}")
    print(f"macro_median_best_positive_delta_cov_pct={fmt_pct(global_summary['macro_median_best_positive_delta_cov_pct'])}")
    for name in ("coverage_epoch_details.csv", "coverage_target_summary.csv", "coverage_summary.md", "coverage_summary.json"):
        print(f"[WROTE] {args.out_dir / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
