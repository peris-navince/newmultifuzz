from __future__ import annotations

import argparse
import os
from typing import Any, Dict, List

from debug_trace import info, load_json, save_json


SUPPORTED_ACTIONS = {
    "mmio_read_override_once",
    "mmio_read_override_repeat",
    "mmio_read_sequence",
    "mmio_bit_update",
    "mmio_write_observe",
    "mmio_write_then_read_gate",
    "uart_handshake_once",
}
SUPPORTED_TRIGGERS = {
    "after_global_reads",
    "on_first_touch",
    "on_nth_touch",
    "after_write",
    "after_write_value",
    "when_stage_active",
}


def _compile_action(action: Dict[str, Any]) -> Dict[str, Any]:
    kind = str(action.get("type") or "")
    if kind not in SUPPORTED_ACTIONS:
        raise ValueError(f"unsupported action type: {kind}")
    trigger = action.get("trigger") or {}
    trig_kind = str(trigger.get("kind") or "")
    if trig_kind not in SUPPORTED_TRIGGERS:
        raise ValueError(f"unsupported trigger kind: {trig_kind}")
    out = dict(action)
    out["type"] = kind
    out["trigger"] = dict(trigger)
    return out


def compile_plan(plan_path: str, out_dir: str) -> Dict[str, Any]:
    plan = load_json(plan_path)
    os.makedirs(out_dir, exist_ok=True)
    compiled = []

    for idx, cand in enumerate(plan.get("candidates", []) or []):
        actions = [_compile_action(a) for a in (cand.get("actions") or [])]
        guid = {
            "schema": "mf_runtime_strategy_v1",
            "plan_name": cand.get("id") or f"candidate_{idx}",
            "rationale": cand.get("rationale"),
            "actions": actions,
        }
        path = os.path.join(out_dir, f"{guid['plan_name']}.guidance.json")
        save_json(path, guid)
        compiled.append({"candidate_id": guid["plan_name"], "guidance_path": os.path.abspath(path)})

    index = {
        "schema": "mf_runtime_guidance_index_v1",
        "compiled": compiled,
    }
    save_json(os.path.join(out_dir, "guidance_index.json"), index)
    info(f"compiled {len(compiled)} guidance files into {out_dir}")
    return index


def main():
    ap = argparse.ArgumentParser(description="Compile normalized plan JSON into hail-fuzz runtime guidance files")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    compile_plan(args.plan, args.out_dir)


if __name__ == "__main__":
    main()
