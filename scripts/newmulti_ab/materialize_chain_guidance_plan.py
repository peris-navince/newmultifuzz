#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
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
    return re.sub(r"[^A-Za-z0-9_.=-]+", "_", str(s)).strip("_") or "candidate"


def infer_bits_from_field(field):
    if not field:
        return []

    s = str(field)

    m = re.search(r"P(\d+)\s*\.\.\s*P(\d+)", s)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        lo, hi = min(a, b), max(a, b)
        return list(range(lo, hi + 1))

    bits = []
    for m in re.finditer(r"P(\d+)", s):
        bits.append(int(m.group(1)))

    return sorted(set(bits))


def value_from_bits(bits, width):
    max_bit = width * 8
    v = 0
    for b in bits:
        if 0 <= int(b) < max_bit:
            v |= 1 << int(b)
    return v


def trigger_variants(addr):
    # Coverage-oriented default order: delayed/nth triggers before first-touch.
    # In 12h diagnosis, broad first-touch overrides often fired but caused
    # coverage/input regression or instability. Keep first-touch as a later
    # fallback for targets that only consume early status reads.
    return [
        {
            "name": "nth2",
            "trigger": {"kind": "on_nth_touch", "addr": addr, "n": 2, "access": "read"},
        },
        {
            "name": "nth8",
            "trigger": {"kind": "on_nth_touch", "addr": addr, "n": 8, "access": "read"},
        },
        {
            "name": "nth16",
            "trigger": {"kind": "on_nth_touch", "addr": addr, "n": 16, "access": "read"},
        },
        {
            "name": "first",
            "trigger": {"kind": "on_first_touch", "addr": addr, "access": "read"},
        },
    ]


def width_candidates(bits):
    max_bit = max(bits) if bits else 0
    widths = [1, 4]
    if max_bit >= 8:
        widths = [2, 4]
    if max_bit >= 16:
        widths = [4]
    return widths


def runtime_doc(candidate_id, action, rationale, metadata):
    return {
        "schema": "mf_runtime_strategy_v1",
        "plan_name": candidate_id,
        "rationale": rationale,
        "actions": [action],
        "metadata": metadata,
    }


def emit(out_dir, compiled, candidate_id, action, rationale, metadata, max_candidates):
    if len(compiled) >= max_candidates:
        return
    path = out_dir / f"{candidate_id}.guidance.json"
    save_json(path, runtime_doc(candidate_id, action, rationale, metadata))
    compiled.append({
        "candidate_id": candidate_id,
        "guidance_path": str(path.resolve()),
    })


def materialize_plan(plan, out_dir, compiled, args, created_at):
    if plan.get("materialization_status") not in {"ready_for_materialization", "needs_field_selection"}:
        return

    priority = int(plan.get("priority") or 999)
    if priority > args.priority_max:
        return

    addr = norm_hex(plan.get("target_addr"))
    field = plan.get("target_field")
    bits = [int(x) for x in (plan.get("set_bits") or [])]
    if not bits:
        bits = infer_bits_from_field(field)

    # Fallback portfolio when LLM says uncertain P0..P15 or gives no exact field.
    if not bits:
        bits = [0, 1, 2, 3, 7, 15]

    action_kind = plan.get("action_kind")
    plan_id = safe_name(plan.get("plan_id") or "plan")
    family = plan.get("family")

    metadata_base = {
        "created_at": created_at,
        "source": "materialize_chain_guidance_plan.py",
        "source_plan_id": plan.get("plan_id"),
        "source_family": family,
        "source_priority": priority,
        "target_addr": addr,
        "target_peripheral": plan.get("target_peripheral"),
        "target_register": plan.get("target_register"),
        "target_field": field,
        "return_to_random_after_success": True,
        "short_validation": plan.get("short_validation"),
        "long_validation": plan.get("long_validation"),
        "risk": plan.get("risk"),
        "coverage_oriented_materialization": True,
        "aggressive_full_register_overrides_last": True,
    }

    # 1) bit_update candidates, useful for exact field such as P0.
    if action_kind == "mmio_bit_update":
        for w in width_candidates(bits):
            usable = [b for b in bits if b < w * 8]
            if not usable:
                continue

            # Single-bit variants for low-risk.
            for b in usable[: args.max_single_bits]:
                for tv in trigger_variants(addr):
                    cid = safe_name(f"{plan_id}_bit{b}_w{w}_{tv['name']}")
                    action = {
                        "type": "mmio_bit_update",
                        "id": cid,
                        "addr": addr,
                        "width": w,
                        "set_bits": [b],
                        "clear_bits": [],
                        "trigger": tv["trigger"],
                        "activate_stage": f"{cid}_stage",
                        "notes": f"chain bit_update from {plan.get('plan_id')}",
                    }
                    emit(
                        out_dir, compiled, cid, action,
                        f"Chain guidance: set bit {b} for {addr} {field}.",
                        dict(metadata_base, runtime_action="mmio_bit_update", width=w, bits=[b]),
                        args.max_candidates,
                    )

            # All-listed-bits variant.
            if len(usable) > 1:
                for tv in trigger_variants(addr):
                    cid = safe_name(f"{plan_id}_allbits_w{w}_{tv['name']}")
                    action = {
                        "type": "mmio_bit_update",
                        "id": cid,
                        "addr": addr,
                        "width": w,
                        "set_bits": usable[: args.max_single_bits],
                        "clear_bits": [],
                        "trigger": tv["trigger"],
                        "activate_stage": f"{cid}_stage",
                        "notes": f"chain all-bit update from {plan.get('plan_id')}",
                    }
                    emit(
                        out_dir, compiled, cid, action,
                        f"Chain guidance: set bits {usable[:args.max_single_bits]} for {addr} {field}.",
                        dict(metadata_base, runtime_action="mmio_bit_update", width=w, bits=usable[:args.max_single_bits]),
                        args.max_candidates,
                    )

    # 2) sequence/value style plans become read_override/read_sequence candidates.
    if action_kind in {"mmio_sequence_update", "mmio_value_update", "mmio_read_sequence"}:
        for w in width_candidates(bits):
            usable = [b for b in bits if b < w * 8]
            if not usable:
                continue

            v = value_from_bits(usable, w)
            aggressive = (1 << (w * 8)) - 1

            # 2a) Narrow observed-bit value overrides first. These are the safest
            # value-style candidates and should occupy early candidate slots.
            for tv in trigger_variants(addr):
                cid = safe_name(f"{plan_id}_override_bits_value_w{w}_{tv['name']}")
                action = {
                    "type": "mmio_read_override_repeat",
                    "id": cid,
                    "addr": addr,
                    "width": w,
                    "value": f"0x{v:X}",
                    "repeat": args.repeat,
                    "trigger": tv["trigger"],
                    "activate_stage": f"{cid}_stage",
                    "notes": f"coverage-oriented narrow override from {plan.get('plan_id')}",
                }
                emit(
                    out_dir, compiled, cid, action,
                    f"Chain guidance: narrow override {addr} width={w} value=0x{v:X}.",
                    dict(metadata_base, runtime_action="mmio_read_override_repeat", width=w, value=f"0x{v:X}", bits=usable, risk_level="low"),
                    args.max_candidates,
                )

            # 2b) Progression sequence: not-ready -> target value -> target value.
            # Avoid all-ones in the normal sequence because it often opens wrong
            # error/interrupt states and causes coverage/input regression.
            seq = [0, v, v]
            for tv in trigger_variants(addr):
                cid = safe_name(f"{plan_id}_sequence_bits_w{w}_{tv['name']}")
                action = {
                    "type": "mmio_read_sequence",
                    "id": cid,
                    "addr": addr,
                    "width": w,
                    "values": [f"0x{x:X}" for x in seq],
                    "trigger": tv["trigger"],
                    "activate_stage": f"{cid}_stage",
                    "notes": f"coverage-oriented narrow sequence from {plan.get('plan_id')}",
                }
                emit(
                    out_dir, compiled, cid, action,
                    f"Chain guidance: narrow sequence {seq} for {addr} width={w}.",
                    dict(metadata_base, runtime_action="mmio_read_sequence", width=w, values=[f"0x{x:X}" for x in seq], bits=usable, risk_level="medium"),
                    args.max_candidates,
                )

            # 2c) Aggressive all-ones fallback last. With the default
            # max-candidates this will usually only appear when safer variants
            # are exhausted.
            for tv in trigger_variants(addr):
                cid = safe_name(f"{plan_id}_override_all_ones_w{w}_{tv['name']}")
                action = {
                    "type": "mmio_read_override_repeat",
                    "id": cid,
                    "addr": addr,
                    "width": w,
                    "value": f"0x{aggressive:X}",
                    "repeat": args.repeat,
                    "trigger": tv["trigger"],
                    "activate_stage": f"{cid}_stage",
                    "notes": f"last-resort aggressive override from {plan.get('plan_id')}",
                }
                emit(
                    out_dir, compiled, cid, action,
                    f"Last-resort all-ones override {addr} width={w} value=0x{aggressive:X}.",
                    dict(metadata_base, runtime_action="mmio_read_override_repeat", width=w, value=f"0x{aggressive:X}", bits=usable, risk_level="high", all_ones=True),
                    args.max_candidates,
                )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--event-dir", required=True)
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--priority-max", type=int, default=2)
    ap.add_argument("--max-candidates", type=int, default=32)
    ap.add_argument("--max-single-bits", type=int, default=16)
    ap.add_argument("--repeat", type=int, default=100000)
    args = ap.parse_args()

    event = Path(args.event_dir)
    plan_wrap = load_json(event / "guidance_plan.json", {}) or {}
    plan_obj = plan_wrap.get("plan", plan_wrap)
    plans = plan_obj.get("plans") or []

    out_dir = Path(args.out_dir) if args.out_dir else event / "guidance_chain"
    out_dir.mkdir(parents=True, exist_ok=True)

    compiled = []
    created_at = time.strftime("%Y-%m-%d %H:%M:%S")

    for plan in sorted(plans, key=lambda x: int(x.get("priority") or 999)):
        materialize_plan(plan, out_dir, compiled, args, created_at)

    index = {
        "schema": "mf_runtime_guidance_index_v1",
        "compiled": compiled,
    }
    save_json(out_dir / "guidance_index.json", index)

    manifest = {
        "schema": "multifuzz_chain_guidance_manifest_v1",
        "created_at": created_at,
        "event_dir": str(event),
        "guidance_dir": str(out_dir.resolve()),
        "candidate_count": len(compiled),
        "compiled": compiled,
        "policy": {
            "priority_max": args.priority_max,
            "max_candidates": args.max_candidates,
            "repeat": args.repeat,
            "materialization": "generic_chain_plan_to_runtime_guidance",
        },
    }
    save_json(out_dir / "materialized_chain_guidance_manifest.json", manifest)

    print("guidance_dir:", out_dir)
    print("candidate_count:", len(compiled))
    for c in compiled:
        print(c["candidate_id"], c["guidance_path"])


if __name__ == "__main__":
    main()
