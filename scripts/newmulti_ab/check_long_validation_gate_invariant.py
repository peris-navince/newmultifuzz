#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    try:
        return list(csv.DictReader(path.open(encoding="utf-8", errors="ignore")))
    except Exception:
        return []


def to_bool(v: Any) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "y", "pass"}


def pass_gate_count(epoch_dir: Path) -> Optional[int]:
    promoted = load_json(epoch_dir / "repeat_gate_stack_depth2" / "promoted_candidates.json")
    if isinstance(promoted, dict):
        return int(promoted.get("promoted_count", len(promoted.get("promoted") or [])))

    rows = read_csv(epoch_dir / "repeat_gate_stack_depth2" / "repeat_gate_aggregate.csv")
    if not rows:
        return None
    return sum(1 for r in rows if to_bool(r.get("pass_gate")))


def long_candidate_count_from_summary(epoch_dir: Path) -> int:
    summary = load_json(epoch_dir / "long_validation" / "long_validation_summary.json", {}) or {}
    rows = summary.get("rows") or []
    return sum(1 for r in rows if r.get("candidate_id") != "control")


def long_candidate_count_from_dirs(epoch_dir: Path) -> int:
    lv = epoch_dir / "long_validation"
    if not lv.exists():
        return 0
    n = 0
    for d in lv.iterdir():
        if not d.is_dir() or d.name == "control":
            continue
        if (d / "run.log").exists() or (d / "guidance_runtime_summary.json").exists():
            n += 1
    return n


def timeline_has_long_candidate(epoch_dir: Path) -> bool:
    p = epoch_dir / "timeline.csv"
    if not p.exists():
        return False
    text = p.read_text(encoding="utf-8", errors="ignore")
    return "LONG_VALIDATE_CANDIDATE" in text


def iter_roots(roots: List[str], roots_file: Optional[Path]) -> List[Tuple[str, Path]]:
    out: List[Tuple[str, Path]] = []
    for r in roots:
        p = Path(r)
        out.append((p.name, p))
    if roots_file:
        for line in roots_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                out.append((parts[0], Path(parts[1])))
    return out


def check_epoch(case_id: str, epoch_dir: Path) -> Optional[str]:
    pg = pass_gate_count(epoch_dir)
    long_n = max(
        long_candidate_count_from_summary(epoch_dir),
        long_candidate_count_from_dirs(epoch_dir),
        1 if timeline_has_long_candidate(epoch_dir) else 0,
    )

    if (pg is None or pg <= 0) and long_n > 0:
        return (
            f"{case_id} {epoch_dir.name}: long validation ran {long_n} non-control "
            f"candidate(s) with repeat-gate pass count {pg}"
        )
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Check invariant: long-validation candidates must have repeat-gate pass evidence."
    )
    ap.add_argument("--root", action="append", default=[], help="closed-loop root to check; can repeat")
    ap.add_argument("--roots", help="roots.txt from multi-target run")
    args = ap.parse_args()

    roots_file = Path(args.roots) if args.roots else None
    roots = iter_roots(args.root, roots_file)
    if not roots:
        raise SystemExit("provide --root or --roots")

    bad: List[str] = []
    checked = 0
    for case_id, root in roots:
        epochs_dir = root / "epochs"
        if not epochs_dir.exists():
            bad.append(f"{case_id}: missing epochs dir: {epochs_dir}")
            continue
        for epoch_dir in sorted(epochs_dir.glob("epoch_*")):
            checked += 1
            msg = check_epoch(case_id, epoch_dir)
            if msg:
                bad.append(msg)

    print(f"checked_epochs={checked}")
    if bad:
        print("BAD: long validation without repeat-gate pass")
        for x in bad:
            print(" -", x)
        return 1

    print("OK: no long-validation candidate bypassed repeat gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
