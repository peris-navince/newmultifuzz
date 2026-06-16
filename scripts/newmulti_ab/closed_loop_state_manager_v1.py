#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List


def load_json(path: Path, default: Any):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def save_json(path: Path, obj: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    try:
        return list(csv.DictReader(path.open()))
    except Exception:
        return []


def to_i(x, default=0):
    try:
        return int(str(x))
    except Exception:
        return default


def to_bool(x):
    return str(x).strip().lower() in {"true", "1", "yes", "y"}


def default_state(case_id: str) -> Dict[str, Any]:
    return {
        "schema": "newmulti_closed_loop_state_v1",
        "case_id": case_id,
        "epochs": [],
        "portfolio": {
            "accepted": [],
            "shadow": [],
            "rejected": [],
            "needs_retarget": [],
            "needs_stabilization": [],
            "script_failures": [],
            "manual_review": []
        },
        "scheduler": {
            "next_mode": "random_first",
            "last_action": None,
            "consecutive_no_fire": 0,
            "consecutive_unstable": 0,
            "consecutive_regression": 0
        }
    }


def summarize_repeat_gate(epoch_root: Path) -> Dict[str, Any]:
    agg = epoch_root / "repeat_gate_stack_depth2" / "repeat_gate_aggregate.csv"
    rows = read_csv(agg)

    out = {
        "path": str(agg),
        "exists": agg.exists(),
        "candidate_count": len(rows),
        "pass_gate_count": 0,
        "fire_positive_count": 0,
        "fire_zero_count": 0,
        "unstable_count": 0,
        "candidate_ids": [],
        "zero_fire_candidate_ids": [],
        "active_unstable_candidate_ids": [],
        "pass_gate_candidate_ids": []
    }

    for r in rows:
        cid = r.get("candidate_id", "")
        fire_total = to_i(r.get("fire_total"))
        unstable_reps = to_i(r.get("unstable_reps"))
        pass_gate = to_bool(r.get("pass_gate"))

        if cid:
            out["candidate_ids"].append(cid)

        if pass_gate:
            out["pass_gate_count"] += 1
            if cid:
                out["pass_gate_candidate_ids"].append(cid)

        if fire_total > 0:
            out["fire_positive_count"] += 1
        else:
            out["fire_zero_count"] += 1
            if cid:
                out["zero_fire_candidate_ids"].append(cid)

        if unstable_reps > 0:
            out["unstable_count"] += 1
            if fire_total > 0 and cid:
                out["active_unstable_candidate_ids"].append(cid)

    return out


def classify_action(decision: str, repeat_gate: Dict[str, Any] | None = None) -> Dict[str, str]:
    repeat_gate = repeat_gate or {}
    active_unstable = (
        decision == "repeat_gate_no_pass_candidate"
        and to_i(repeat_gate.get("fire_positive_count")) > 0
        and to_i(repeat_gate.get("unstable_count")) > 0
    )
    zero_fire_repeat_gate = (
        decision == "repeat_gate_no_pass_candidate"
        and to_i(repeat_gate.get("candidate_count")) > 0
        and to_i(repeat_gate.get("fire_positive_count")) == 0
    )

    if active_unstable:
        return {
            "action": "stabilize_after_repeat_gate_unstable",
            "next_mode": "stabilize",
            "bucket": "needs_stabilization",
            "instruction": (
                "Repeat gate candidates fired but were unstable. Do not retarget yet; "
                "generate conservative variants of the same evidence-supported family with "
                "lower trigger frequency, narrower masks, bounded one-shot windows, and no "
                "all-ones or persistent full-register overrides."
            )
        }

    if zero_fire_repeat_gate:
        return {
            "action": "retarget_after_repeat_gate_zero_fire",
            "next_mode": "retarget",
            "bucket": "needs_retarget",
            "instruction": (
                "Repeat gate candidates did not fire. Retarget using runtime-observed MMIO "
                "read addresses and bottleneck PCs; do not reuse the same trigger timing, "
                "field, or candidate family."
            )
        }
    if decision == "gate_no_firing_candidate":
        return {
            "action": "retarget",
            "next_mode": "retarget",
            "bucket": "needs_retarget",
            "instruction": (
                "Previous candidates did not fire. Retarget to a different MMIO address, "
                "register field, bit range, or trigger timing. Do not reuse the same "
                "candidate family."
            )
        }

    if decision == "repeat_gate_no_pass_candidate":
        return {
            "action": "retarget_after_repeat_gate_no_pass",
            "next_mode": "retarget",
            "bucket": "needs_retarget",
            "instruction": (
                "Repeat gate did not promote any stable firing candidate. Retarget to a "
                "different MMIO address, field, bit range, or trigger timing rather than "
                "sending unpromoted candidates into long validation."
            )
        }

    if decision == "controller_invariant_violation_long_without_repeat_gate_pass":
        return {
            "action": "manual_review_controller_invariant_violation",
            "next_mode": "manual_review",
            "bucket": "manual_review",
            "instruction": (
                "Controller invariant violation: long validation ran a non-control "
                "candidate without a repeat-gate pass. Inspect the repeat-gate to long "
                "validation promotion path before continuing."
            )
        }

    if decision == "active_but_unstable_hang_or_crash":
        return {
            "action": "stabilize",
            "next_mode": "stabilize",
            "bucket": "needs_stabilization",
            "instruction": (
                "Previous candidates fired but were unstable. Generate conservative "
                "variants with lower trigger frequency, narrower masks, bounded override "
                "windows, and less aggressive values."
            )
        }

    if decision in {"active_but_coverage_regressed", "active_but_input_regressed"}:
        return {
            "action": "non_degrading_repair",
            "next_mode": "repair",
            "bucket": "rejected",
            "instruction": (
                "Previous candidates fired but regressed coverage or input growth. "
                "Generate variants that preserve or improve coverage/input relative to control."
            )
        }

    if decision == "active_nondegrading_but_hotspot_rebounded":
        return {
            "action": "hotspot_refine",
            "next_mode": "repair",
            "bucket": "shadow",
            "instruction": (
                "Previous candidate was non-degrading but did not reduce the hotspot. "
                "Keep useful effects but refine the hotspot-specific target."
            )
        }

    if decision in {"nondegrading_active_candidate"}:
        return {
            "action": "shadow_keep",
            "next_mode": "hybrid",
            "bucket": "shadow",
            "instruction": (
                "Previous candidate was active and non-degrading. Keep as shadow candidate "
                "while continuing to search for stronger hotspot reduction."
            )
        }

    if decision == "strong_active_nondegrading_hotspot_reduced":
        return {
            "action": "accept",
            "next_mode": "hybrid_exploit",
            "bucket": "accepted",
            "instruction": (
                "Previous candidate was strong. Use it as positive evidence and continue "
                "hybrid exploration for later bottlenecks."
            )
        }

    if decision in {"script_failed", "missing_final_summary"}:
        return {
            "action": "infra_retry",
            "next_mode": "retry_same",
            "bucket": "script_failures",
            "instruction": (
                "Previous epoch failed at script/infrastructure level. Retry after preflight; "
                "do not treat it as method failure."
            )
        }

    if decision in {"chain_no_materialized_candidate", "no_depth2_candidate"}:
        return {
            "action": "continue_random_or_retarget",
            "next_mode": "random_first",
            "bucket": "no_materialized_candidate",
            "instruction": (
                "No materialized candidate was produced at Depth1/Depth2 under scoped evidence; "
                "continue random exploration or retarget to a fresh bottleneck instead of manual review."
            )
        }

    return {
        "action": "manual_review",
        "next_mode": "manual_review",
        "bucket": "manual_review",
        "instruction": "Decision is uncommon; avoid blindly repeating the same candidate family."
    }


def update_counters(state: Dict[str, Any], decision: str, repeat_gate: Dict[str, Any] | None = None):
    sched = state["scheduler"]
    repeat_gate = repeat_gate or {}

    repeat_gate_active_unstable = (
        decision == "repeat_gate_no_pass_candidate"
        and to_i(repeat_gate.get("fire_positive_count")) > 0
        and to_i(repeat_gate.get("unstable_count")) > 0
    )

    if decision == "gate_no_firing_candidate" or (
        decision == "repeat_gate_no_pass_candidate" and not repeat_gate_active_unstable
    ):
        sched["consecutive_no_fire"] = sched.get("consecutive_no_fire", 0) + 1
    else:
        sched["consecutive_no_fire"] = 0

    if decision == "active_but_unstable_hang_or_crash" or repeat_gate_active_unstable:
        sched["consecutive_unstable"] = sched.get("consecutive_unstable", 0) + 1
    else:
        sched["consecutive_unstable"] = 0

    if decision in {"active_but_coverage_regressed", "active_but_input_regressed"}:
        sched["consecutive_regression"] = sched.get("consecutive_regression", 0) + 1
    else:
        sched["consecutive_regression"] = 0


def render_feedback_md(state: Dict[str, Any], recent_n: int = 3) -> str:
    lines = []
    lines.append("# NewMultiFuzz Closed-Loop Repair Feedback")
    lines.append("")
    lines.append(f"Case: `{state['case_id']}`")
    lines.append(f"Next mode: `{state['scheduler'].get('next_mode')}`")
    lines.append(f"Last action: `{state['scheduler'].get('last_action')}`")
    lines.append("")

    recent = state["epochs"][-recent_n:]

    if not recent:
        lines.append("No previous epoch feedback. This is the first epoch.")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Recent epoch outcomes")
    lines.append("")

    for ep in recent:
        lines.append(f"### Epoch {ep['epoch']}: `{ep['final_decision']}`")
        lines.append("")
        lines.append(f"- Action: `{ep['action']}`")
        lines.append(f"- Instruction: {ep['instruction']}")

        rg = ep.get("repeat_gate", {})
        if rg:
            lines.append(f"- Repeat-gate candidates: {rg.get('candidate_count')}")
            lines.append(f"- pass_gate_count: {rg.get('pass_gate_count')}")
            lines.append(f"- fire_positive_count: {rg.get('fire_positive_count')}")
            lines.append(f"- unstable_count: {rg.get('unstable_count')}")

            if rg.get("zero_fire_candidate_ids"):
                lines.append("- Candidate families that produced zero fire and should not be repeated:")
                for cid in rg["zero_fire_candidate_ids"][:10]:
                    lines.append(f"  - `{cid}`")

            if rg.get("active_unstable_candidate_ids"):
                lines.append("- Candidate families that fired but were unstable:")
                for cid in rg["active_unstable_candidate_ids"][:10]:
                    lines.append(f"  - `{cid}`")

        lines.append("")

    lines.append("## Required behavior for next LLM plan")
    lines.append("")
    lines.append("- Explicitly state how the new plan differs from failed candidate families.")
    lines.append("- Do not regenerate the same register/field/bit/timing family after no-fire.")
    lines.append("- If stabilizing, reduce aggressiveness: lower frequency, narrower masks, bounded override windows.")
    if state["scheduler"].get("next_mode") in {"force_retarget", "retarget"}:
        lines.append("- Retarget-specific hard constraints:")
        lines.append("  - Select from runtime-observed MMIO read addresses, bottleneck-PC read addresses, or read-after-write dependent status registers.")
        lines.append("  - Do not reuse previous zero-fire address/field/timing families unless the trigger condition is fundamentally different.")
        lines.append("  - Prefer SVD fields named or described as status, ready, done, flag, interrupt, error, or completion fields.")
    if state["scheduler"].get("next_mode") in {"force_stabilize", "stabilize"}:
        lines.append("- Stabilization-specific hard constraints:")
        lines.append("  - Avoid `all_ones` override values unless no narrower field-specific value exists.")
        lines.append("  - Avoid aggressive `w4_first` or persistent ready forcing when prior candidates were unstable.")
        lines.append("  - Prefer delayed or sparse triggers such as `nth8`, `nth16`, or bounded one-shot triggers.")
        lines.append("  - Prefer single-bit or narrow field masks over full-register overrides.")
        lines.append("  - Prefer values that acknowledge/clear transient status rather than permanently forcing ready.")
        lines.append("  - The next plan must explicitly explain how it reduces hang/crash risk relative to previous unstable candidates.")
    lines.append("- If repairing regression, preserve or improve coverage and input count relative to control.")
    lines.append("- Coverage-aware planning constraints:")
    lines.append("  - Prefer candidates expected to increase coverage, not merely fire or reduce one MMIO count.")
    lines.append("  - Avoid broad `all_ones`, full-register permanent override, and early `first` triggers unless strongly justified by binary/manual evidence.")
    lines.append("  - Prefer delayed, `nth`-touch, or after-write triggers with narrow single-bit or field-width masks.")
    lines.append("  - Preserve unrelated bits and explain how the candidate can open a downstream branch rather than only unblocking a spin loop.")
    lines.append("- Prefer candidates that can measurably fire during repeat gate and long validation.")
    lines.append("")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--epoch-root", default="")
    ap.add_argument("--epoch", type=int, default=0)
    ap.add_argument("--out-feedback-md", required=True)
    ap.add_argument("--out-scheduler-json", required=True)
    ap.add_argument("--recent", type=int, default=3)
    args = ap.parse_args()

    state_path = Path(args.state)
    state = load_json(state_path, default_state(args.case_id))

    # If epoch_root is given, ingest this epoch result first.
    state_changed = False

    if args.epoch_root:
        epoch_root = Path(args.epoch_root)
        fs = load_json(epoch_root / "final_summary.json", {})
        decision = fs.get("final_decision", "missing_final_summary")
        repeat_gate = summarize_repeat_gate(epoch_root)
        action = classify_action(decision, repeat_gate)

        entry = {
            "epoch": args.epoch,
            "case_id": args.case_id,
            "epoch_root": str(epoch_root),
            "script_success": fs.get("script_success", False),
            "core_closure_success": fs.get("core_closure_success", False),
            "failed": fs.get("failed", True),
            "failure_reason": fs.get("failure_reason", ""),
            "final_decision": decision,
            "action": action["action"],
            "instruction": action["instruction"],
            "repeat_gate": repeat_gate,
            "final_summary": str(epoch_root / "final_summary.json"),
        }

        state["epochs"].append(entry)
        bucket = action["bucket"]
        state["portfolio"].setdefault(bucket, []).append(entry)

        update_counters(state, decision, repeat_gate)

        state["scheduler"]["last_action"] = action["action"]
        state["scheduler"]["next_mode"] = action["next_mode"]

        # Escalation rule: repeated no-fire means force stronger retarget.
        if state["scheduler"].get("consecutive_no_fire", 0) >= 2:
            state["scheduler"]["next_mode"] = "force_retarget"
            state["scheduler"]["last_action"] = "force_retarget_after_repeated_no_fire"

        if state["scheduler"].get("consecutive_unstable", 0) >= 2:
            state["scheduler"]["next_mode"] = "force_stabilize"
            state["scheduler"]["last_action"] = "force_stabilize_after_repeated_unstable"

        state_changed = True

    # Always save the state file, even for the first epoch where no epoch_root
    # has been ingested yet. This keeps the printed [OK] state path truthful
    # and lets downstream scripts read an initial scheduler/portfolio state.
    save_json(state_path, state)

    feedback_md = Path(args.out_feedback_md)
    scheduler_json = Path(args.out_scheduler_json)

    feedback_md.parent.mkdir(parents=True, exist_ok=True)
    scheduler_json.parent.mkdir(parents=True, exist_ok=True)

    feedback_md.write_text(render_feedback_md(state, args.recent))
    scheduler_json.write_text(json.dumps(state["scheduler"], indent=2))

    print("[OK] state:", state_path)
    print("[OK] feedback:", feedback_md)
    print("[OK] scheduler:", scheduler_json)
    print(feedback_md.read_text())


if __name__ == "__main__":
    main()
