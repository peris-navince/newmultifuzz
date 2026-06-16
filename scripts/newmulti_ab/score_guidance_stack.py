#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any, Dict


def load_rows(path):
    return {r["candidate_id"]: r for r in csv.DictReader(Path(path).open())}


def to_i(x, default=0):
    try:
        return int(x)
    except Exception:
        try:
            return int(float(x))
        except Exception:
            return default


def truthy(x: Any) -> bool:
    return str(x).strip().lower() in {"1", "true", "yes", "y"}


def risk_profile(candidate_id: str, row: Dict[str, Any]) -> Dict[str, Any]:
    """Cheap static risk signals derived from candidate names/metadata.

    These are intentionally conservative and only affect ranking; repeat gate
    still decides whether a candidate is stable enough for long validation.
    """
    cid = str(candidate_id or "").lower()
    text = " ".join(str(row.get(k, "")) for k in row).lower() + " " + cid

    all_ones = "all_ones" in text or "0xffffffff" in text or "0xffff" in text
    broad_override = "override" in text and ("allbits" in text or all_ones)
    first_touch = bool(re.search(r"(^|_)first($|_)", cid)) or "on_first_touch" in text
    delayed_or_nth = bool(re.search(r"nth(2|4|8|16|32)", cid)) or "after_write" in text or "delayed" in text
    sequence = "sequence" in text
    narrow_bit = bool(re.search(r"_bit\d+_", cid)) or "bits_value" in text

    risk = 0
    if all_ones:
        risk += 5
    if broad_override:
        risk += 3
    if first_touch:
        risk += 2
    if sequence and all_ones:
        risk += 2
    if delayed_or_nth:
        risk -= 2
    if narrow_bit:
        risk -= 1

    return {
        "all_ones": all_ones,
        "broad_override": broad_override,
        "first_touch": first_touch,
        "delayed_or_nth": delayed_or_nth,
        "sequence": sequence,
        "narrow_bit": narrow_bit,
        "risk_score": risk,
    }


def classify_candidate(
    *,
    fire: int,
    cov_delta: int,
    in_delta: int,
    old_delta: int,
    new_delta: int,
    shift_class: str,
    risk: Dict[str, Any],
) -> str:
    if fire <= 0 or shift_class == "no_guidance_consumption":
        return "no_guidance_consumption"

    # Coverage and input regressions are not promoted to repeat gate by default.
    # They may be useful diagnostics, but they should not drive the next long run.
    if cov_delta < 0:
        return "coverage_regression"
    if in_delta < 0:
        return "input_regression"

    # Strongest evidence: genuine new coverage without regression.
    if cov_delta > 0:
        if old_delta <= 0 and new_delta <= 100:
            return "coverage_positive_hotspot_safe"
        return "coverage_positive_candidate"

    # Coverage-preserving candidates can still be useful if they reduce hotspots.
    if old_delta < 0 and new_delta < 0 and in_delta >= 0:
        return "coverage_neutral_hotspot_candidate"
    if old_delta < 0 and in_delta > 0:
        return "partial_stack_repeat"
    if old_delta < 0 and new_delta >= 0:
        return "old_solved_current_not_solved"

    # Fired and non-regressing but did not solve the measured hotspot.
    return "active_nonregressing_but_unfocused"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-target-summary", required=True)
    ap.add_argument("--new-target-summary", required=True)
    ap.add_argument("--shift-summary", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--out-json", required=True)
    args = ap.parse_args()

    old_rows = load_rows(args.old_target_summary)
    new_rows = load_rows(args.new_target_summary)
    shift_rows = load_rows(args.shift_summary)

    candidate_ids = sorted(set(old_rows) & set(new_rows))
    out = []

    old_control = old_rows.get("control", {})
    new_control = new_rows.get("control", {})

    control_cov = to_i(old_control.get("last_cov"))
    control_in = to_i(old_control.get("last_in"))

    for cid in candidate_ids:
        old = old_rows[cid]
        new = new_rows[cid]
        sh = shift_rows.get(cid, {})

        if cid == "control":
            score = 0
            decision = "control"
            fire = 0
            cov = control_cov
            inp = control_in
            old_delta = 0
            new_delta = 0
            cov_delta = 0
            in_delta = 0
            risk = risk_profile(cid, old)
        else:
            fire = to_i(old.get("fire_lines"))
            cov = to_i(old.get("last_cov"))
            inp = to_i(old.get("last_in"))

            old_delta = to_i(old.get("target_hotspot_delta_vs_control"))
            new_delta = to_i(new.get("target_hotspot_delta_vs_control"))

            cov_delta = cov - control_cov
            in_delta = inp - control_in
            shift_class = sh.get("shift_classification", "")
            risk = risk_profile(cid, {**old, **new, **sh})

            decision = classify_candidate(
                fire=fire,
                cov_delta=cov_delta,
                in_delta=in_delta,
                old_delta=old_delta,
                new_delta=new_delta,
                shift_class=shift_class,
                risk=risk,
            )

            score = 0

            if fire > 0:
                score += min(500, fire * 4)
            else:
                score -= 2000

            # Coverage is the primary objective. Regression is heavily penalized.
            if cov_delta > 0:
                score += 4000 * cov_delta
            elif cov_delta == 0:
                score += 250
            else:
                score -= 6000 * abs(cov_delta)

            # Input growth is useful but weaker than coverage.
            if in_delta > 0:
                score += 500 * in_delta
            elif in_delta < 0:
                score -= 1000 * abs(in_delta)

            # Old bottleneck should not rebound.
            if old_delta < 0:
                score += min(1500, -old_delta // 5)
            else:
                score -= min(1500, old_delta // 5)

            # Current bottleneck should also ideally decrease or at least not explode.
            if new_delta < 0:
                score += min(1200, -new_delta // 5)
            elif new_delta > 100:
                score -= min(1500, new_delta // 5)

            # Penalize likely broad/aggressive strategies that caused regressions in 12h.
            score -= max(0, risk["risk_score"]) * 700
            if risk["delayed_or_nth"]:
                score += 250
            if risk["narrow_bit"]:
                score += 150

            # Penalize strong oscillation to any non-target hotspot.
            next_addr = (sh.get("next_non_target_addr") or "").lower()
            next_count = to_i(sh.get("next_non_target_count"))
            if next_addr and next_count > 1500:
                score -= 500

            # Apparent coverage/input changes from zero-fire candidates are replay
            # noise or unrelated random progress; never let them look numerically
            # attractive in diagnostics. Repeat gate also hard-filters them.
            if decision == "no_guidance_consumption":
                score -= 1_000_000_000

        row = {
            "candidate_id": cid,
            "score": score,
            "decision": decision,
            "fire_lines": old.get("fire_lines", "0"),
            "cov": old.get("last_cov", ""),
            "input": old.get("last_in", ""),
            "control_cov": control_cov,
            "control_input": control_in,
            "cov_delta": cov_delta,
            "input_delta": in_delta,
            "old_target_delta": old.get("target_hotspot_delta_vs_control", ""),
            "new_target_delta": new.get("target_hotspot_delta_vs_control", ""),
            "shift_classification": sh.get("shift_classification", ""),
            "next_addr": sh.get("next_non_target_addr", ""),
            "next_count": sh.get("next_non_target_count", ""),
            "risk_score": risk["risk_score"],
            "risk_all_ones": risk["all_ones"],
            "risk_broad_override": risk["broad_override"],
            "risk_first_touch": risk["first_touch"],
            "risk_delayed_or_nth": risk["delayed_or_nth"],
            "risk_narrow_bit": risk["narrow_bit"],
            "run_root": old.get("run_root", ""),
        }
        out.append(row)

    decision_rank = {
        "coverage_positive_hotspot_safe": 0,
        "coverage_positive_candidate": 1,
        "coverage_neutral_hotspot_candidate": 2,
        "promising_stack_repeat": 3,
        "partial_stack_repeat": 4,
        "old_solved_current_not_solved": 5,
        "active_nonregressing_but_unfocused": 6,
        "control": 7,
        "input_regression": 8,
        "coverage_regression": 9,
        "no_guidance_consumption": 10,
        "not_promising": 11,
    }
    out.sort(key=lambda r: (
        decision_rank.get(r["decision"], 99),
        -to_i(r["score"]),
        to_i(r.get("risk_score")),
        r["candidate_id"],
    ))

    fields = [
        "candidate_id", "score", "decision", "fire_lines",
        "cov", "input", "control_cov", "control_input", "cov_delta", "input_delta",
        "old_target_delta", "new_target_delta",
        "shift_classification", "next_addr", "next_count",
        "risk_score", "risk_all_ones", "risk_broad_override", "risk_first_touch",
        "risk_delayed_or_nth", "risk_narrow_bit", "run_root",
    ]

    with Path(args.out_csv).open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(out)

    Path(args.out_json).write_text(json.dumps({"rows": out}, indent=2, ensure_ascii=False))

    print("wrote", args.out_csv)
    for r in out:
        print(
            r["candidate_id"],
            "score", r["score"],
            r["decision"],
            "fire", r["fire_lines"],
            "cov", r["cov"],
            "Δcov", r["cov_delta"],
            "in", r["input"],
            "Δin", r["input_delta"],
            "oldΔ", r["old_target_delta"],
            "newΔ", r["new_target_delta"],
            "risk", r["risk_score"],
            "next", r["next_addr"], r["next_count"],
        )


if __name__ == "__main__":
    main()
