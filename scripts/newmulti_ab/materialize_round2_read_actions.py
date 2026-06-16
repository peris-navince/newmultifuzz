#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def load_json(p, default=None):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def save_json(p, obj):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def norm_hex(x):
    try:
        return f"0X{int(str(x), 0):X}"
    except Exception:
        return str(x).upper()


def safe_name(s):
    return "".join(c if c.isalnum() or c in "._=-" else "_" for c in str(s)).strip("_")


def build_doc(candidate_id, action, rationale, metadata):
    return {
        "schema": "mf_runtime_strategy_v1",
        "plan_name": candidate_id,
        "rationale": rationale,
        "actions": [action],
        "metadata": metadata,
    }


def is_sam_context(ctx):
    manifest = ctx.get("manifest_metadata") or ctx.get("manifest") or {}
    svd = str(manifest.get("svd") or "").lower()
    pdf = str(manifest.get("pdf") or "").lower()
    mcu = str(manifest.get("mcu") or "").lower()
    board = str(manifest.get("board") or "").lower()
    blob = " ".join([svd, pdf, mcu, board])
    return (
        "/sam/" in blob
        or "atsam" in blob
        or "sam3" in blob
        or "sam4" in blob
        or "samd" in blob
        or "same70" in blob
        or "samr" in blob
    )


def emit_empty_index(out_dir, event, target_addr, reason):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    created_at = time.strftime("%Y-%m-%d %H:%M:%S")

    index = {
        "schema": "mf_runtime_guidance_index_v1",
        "compiled": [],
        "skip_reason": reason,
    }
    save_json(out_dir / "guidance_index.json", index)

    manifest = {
        "schema": "multifuzz_round2_read_action_manifest_v1",
        "created_at": created_at,
        "event_dir": str(event),
        "guidance_dir": str(out_dir.resolve()),
        "target_addr": target_addr,
        "candidate_count": 0,
        "compiled": [],
        "skip_reason": reason,
    }
    save_json(out_dir / "round2_read_action_manifest.json", manifest)

    print(f"[SKIP] materialize_round2_read_actions.py: {reason}")
    print("wrote", out_dir / "guidance_index.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--event-dir", required=True)
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--target-addr", default=None)
    ap.add_argument("--repeat", type=int, default=100000)
    ap.add_argument("--max-candidates", type=int, default=24)
    args = ap.parse_args()

    event = Path(args.event_dir)
    ctx = load_json(event / "llm_context.json", {}) or {}
    plan_wrap = load_json(event / "guidance_plan.json", {}) or {}
    feedback = load_json(event / "validation_feedback_round1.json", {}) or {}

    plan = plan_wrap.get("plan", plan_wrap)
    plans = plan.get("plans", [])

    target_addr = args.target_addr
    if not target_addr:
        target_addr = feedback.get("target_hotspot")
    if not target_addr and plans:
        target_addr = plans[0].get("target_addr")
    if not target_addr:
        hotspots = ctx.get("hotspots") or []
        if hotspots:
            target_addr = hotspots[0].get("addr")

    if not target_addr:
        raise SystemExit("cannot infer target addr")

    target_addr = norm_hex(target_addr)

    out_dir = Path(args.out_dir) if args.out_dir else event / "guidance_round2"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not is_sam_context(ctx):
        emit_empty_index(
            out_dir=out_dir,
            event=event,
            target_addr=target_addr,
            reason="round2_read_actions_is_sam_pmc_specific_and_current_case_is_not_sam",
        )
        return

    # These are derived from the SAM/ATSAM PMC_SR Round 1 feedback:
    # - bit_update width=4 under-consumed due to byte-sized reads.
    # - therefore create width=1 low-byte ready-value candidates.
    # - also keep width=4 candidates for full-register reads.
    value_candidates = [
        {
            "name": "low_mckrdy_bit3",
            "width": 1,
            "value": 0x08,
            "reason": "low-byte MCKRDY bit 3 only",
        },
        {
            "name": "low_bits_3_0",
            "width": 1,
            "value": 0x09,
            "reason": "low-byte bits 3 and 0",
        },
        {
            "name": "low_bits_7_3_0",
            "width": 1,
            "value": 0x89,
            "reason": "low-byte bits 7, 3, and 0",
        },
        {
            "name": "low_all_ready_ff",
            "width": 1,
            "value": 0xFF,
            "reason": "aggressive low-byte ready value",
        },
        {
            "name": "word_mckrdy_bit3",
            "width": 4,
            "value": 0x00000008,
            "reason": "word MCKRDY bit 3 only",
        },
        {
            "name": "word_bits_3_0",
            "width": 4,
            "value": 0x00000009,
            "reason": "word bits 3 and 0",
        },
        {
            "name": "word_bits_7_3_0",
            "width": 4,
            "value": 0x00000089,
            "reason": "word bits 7, 3, and 0",
        },
        {
            "name": "word_bits_16_7_3_0",
            "width": 4,
            "value": 0x00010089,
            "reason": "word bits 16, 7, 3, and 0",
        },
        {
            "name": "word_all_ready_ffffffff",
            "width": 4,
            "value": 0xFFFFFFFF,
            "reason": "aggressive full-word ready value",
        },
    ]

    trigger_variants = [
        {
            "name": "first",
            "trigger": {
                "kind": "on_first_touch",
                "addr": target_addr,
                "access": "read",
            },
        },
        {
            "name": "nth2",
            "trigger": {
                "kind": "on_nth_touch",
                "addr": target_addr,
                "n": 2,
                "access": "read",
            },
        },
    ]

    compiled = []

    def emit(candidate_id, action, rationale, metadata):
        if len(compiled) >= args.max_candidates:
            return
        p = out_dir / f"{candidate_id}.guidance.json"
        save_json(p, build_doc(candidate_id, action, rationale, metadata))
        compiled.append({
            "candidate_id": candidate_id,
            "guidance_path": str(p.resolve()),
        })

    created_at = time.strftime("%Y-%m-%d %H:%M:%S")

    for vc in value_candidates:
        for tv in trigger_variants:
            cid = safe_name(f"r2_override_repeat_{vc['name']}_{tv['name']}")
            action = {
                "type": "mmio_read_override_repeat",
                "id": cid,
                "addr": target_addr,
                "width": vc["width"],
                "value": f"0x{vc['value']:X}",
                "repeat": args.repeat,
                "trigger": tv["trigger"],
                "activate_stage": f"{cid}_stage",
                "notes": f"Round2 read_override_repeat: {vc['reason']}",
            }
            metadata = {
                "created_at": created_at,
                "source": "materialize_round2_read_actions.py",
                "round": 2,
                "target_addr": target_addr,
                "action_family": "mmio_read_override_repeat",
                "reason": vc["reason"],
                "feedback_basis": feedback.get("summary", {}),
                "return_to_random_after_success": True,
            }
            emit(
                cid,
                action,
                f"Round2 SAM/PMC: override PMC_SR reads with {vc['reason']} using {tv['name']} trigger.",
                metadata,
            )

    # Sequence candidates: useful when firmware expects progression rather than constant ready.
    sequence_candidates = [
        {
            "name": "seq_low_00_08_89",
            "width": 1,
            "values": [0x00, 0x08, 0x89],
            "reason": "low-byte progression from not-ready to ready",
        },
        {
            "name": "seq_low_00_08_ff",
            "width": 1,
            "values": [0x00, 0x08, 0xFF],
            "reason": "low-byte progression to aggressive ready",
        },
        {
            "name": "seq_word_0_8_10089",
            "width": 4,
            "values": [0x00000000, 0x00000008, 0x00010089],
            "reason": "word progression to multi-ready status",
        },
    ]

    for sc in sequence_candidates:
        for tv in trigger_variants:
            cid = safe_name(f"r2_read_sequence_{sc['name']}_{tv['name']}")
            action = {
                "type": "mmio_read_sequence",
                "id": cid,
                "addr": target_addr,
                "width": sc["width"],
                "values": [f"0x{x:X}" for x in sc["values"]],
                "trigger": tv["trigger"],
                "activate_stage": f"{cid}_stage",
                "notes": f"Round2 read_sequence: {sc['reason']}",
            }
            metadata = {
                "created_at": created_at,
                "source": "materialize_round2_read_actions.py",
                "round": 2,
                "target_addr": target_addr,
                "action_family": "mmio_read_sequence",
                "reason": sc["reason"],
                "feedback_basis": feedback.get("summary", {}),
                "return_to_random_after_success": True,
            }
            emit(
                cid,
                action,
                f"Round2 SAM/PMC: provide PMC_SR read sequence: {sc['reason']} using {tv['name']} trigger.",
                metadata,
            )

    index = {
        "schema": "mf_runtime_guidance_index_v1",
        "compiled": compiled,
    }
    save_json(out_dir / "guidance_index.json", index)

    manifest = {
        "schema": "multifuzz_round2_read_action_manifest_v1",
        "created_at": created_at,
        "event_dir": str(event),
        "guidance_dir": str(out_dir.resolve()),
        "target_addr": target_addr,
        "candidate_count": len(compiled),
        "compiled": compiled,
        "policy": {
            "reason": "Round1 bit_update consumed inconsistently and did not improve coverage; Round2 uses width-aware read overrides/sequences.",
            "repeat": args.repeat,
            "max_candidates": args.max_candidates,
        },
    }
    save_json(out_dir / "materialized_round2_manifest.json", manifest)

    print("guidance_dir:", out_dir)
    print("candidate_count:", len(compiled))
    for c in compiled:
        print(c["candidate_id"], c["guidance_path"])


if __name__ == "__main__":
    main()
