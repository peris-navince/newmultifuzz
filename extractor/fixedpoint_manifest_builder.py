from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from debug_trace import info, load_json, save_json
from guidance_compiler import compile_plan


def _abs(path: str) -> str:
    return str(Path(path).expanduser().resolve())


def _ensure_dir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def _compile_direct_candidates(candidates: List[Dict[str, Any]], out_dir: str) -> List[Dict[str, Any]]:
    direct = []
    for cand in candidates:
        if cand.get("actions"):
            direct.append(
                {
                    "id": cand.get("id"),
                    "rationale": cand.get("rationale"),
                    "actions": cand.get("actions") or [],
                }
            )
    if not direct:
        return []
    plan_path = os.path.join(out_dir, "direct_candidates.plan.json")
    save_json(plan_path, {"schema": "mf_runtime_selector_direct_plan_v1", "candidates": direct})
    index = compile_plan(plan_path, os.path.join(out_dir, "direct_guidance"))
    return index.get("compiled") or []


def _compile_sweep_candidates(candidates: List[Dict[str, Any]], out_dir: str) -> List[Dict[str, Any]]:
    compiled: List[Dict[str, Any]] = []
    guidance_root = Path(out_dir) / "sweep_guidance"
    _ensure_dir(str(guidance_root))

    for cand in candidates:
        sweep = cand.get("sweep")
        if not sweep:
            continue
        cid = str(cand.get("id") or "sweep")
        addr = _normalize_hex(sweep.get("addr") or "0x0")
        width = int(sweep.get("width") or 1)
        trigger = sweep.get("trigger") or {"kind": "on_first_touch", "addr": addr, "access": "read"}
        values = sweep.get("values") or []
        for idx, value in enumerate(values):
            value_hex = str(value).upper()
            plan_name = f"{cid}_{value_hex.replace('0X', '').replace('X', '')}"
            guidance = {
                "schema": "mf_runtime_strategy_v1",
                "plan_name": plan_name,
                "rationale": cand.get("rationale"),
                "actions": [
                    {
                        "type": "mmio_read_override_once",
                        "addr": addr,
                        "width": width,
                        "value": value_hex,
                        "trigger": trigger,
                    }
                ],
            }
            path = guidance_root / f"{plan_name}.guidance.json"
            save_json(str(path), guidance)
            compiled.append({"candidate_id": plan_name, "guidance_path": str(path.resolve())})
    if compiled:
        save_json(str(guidance_root / "guidance_index.json"), {"schema": "mf_runtime_guidance_index_v1", "compiled": compiled})
    return compiled


def build_fixedpoint_manifest(
    *,
    selector_plan_path: str,
    input_path: str,
    out_dir: str,
    manifest_out: str,
    summary_out: str,
    continue_icount_delta: int = 200_000,
    include_control: bool = True,
) -> Dict[str, Any]:
    selector_plan = load_json(selector_plan_path)
    _ensure_dir(out_dir)

    compiled_direct = _compile_direct_candidates(selector_plan.get("candidates") or [], out_dir)
    compiled_sweep = _compile_sweep_candidates(selector_plan.get("candidates") or [], out_dir)
    compiled = compiled_direct + compiled_sweep

    manifest_candidates: List[Dict[str, Any]] = []
    if include_control:
        manifest_candidates.append({"id": "control"})
    manifest_candidates.extend(
        {"id": str(item.get("candidate_id") or ""), "guidance_path": _abs(str(item.get("guidance_path") or ""))}
        for item in compiled
    )

    trial = selector_plan.get("trial") or {}
    manifest = {
        "schema": "mf_fixedpoint_sweep_v1",
        "input_path": _abs(input_path),
        "trial": {
            "addr": _normalize_hex(trial.get("addr") or "0x0"),
            "nth_touch": int(trial.get("nth_touch") or 1),
        },
        "continue_icount_delta": int(continue_icount_delta),
        "summary_out": _abs(summary_out),
        "candidates": manifest_candidates,
        "compiled_count": len(manifest_candidates),
        "selector_plan_path": _abs(selector_plan_path),
    }
    save_json(manifest_out, manifest)
    info(f"fixed-point manifest written: {manifest_out}; compiled_candidates={len(manifest_candidates)}")
    return manifest
