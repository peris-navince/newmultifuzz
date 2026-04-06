from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from debug_trace import info, load_json, save_json
from strategy_planner import heuristic_plan


def _hex_u64(value: Any) -> str:
    if isinstance(value, str):
        value = value.strip()
        if value.lower().startswith("0x"):
            return value.upper()
        return f"0x{int(value):X}"
    return f"0x{int(value):X}"


def _first_group(task_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    groups = ((task_context.get("runtime_problem") or {}).get("hotspot_groups")) or []
    return groups[0] if groups else None


def _single_region(group: Dict[str, Any]) -> bool:
    members = group.get("members") or []
    return len(members) <= 1


def _group_summary(group: Dict[str, Any]) -> Dict[str, Any]:
    anchor = group.get("anchor") or {}
    return {
        "group_id": group.get("group_id"),
        "kind": group.get("kind"),
        "instance": group.get("instance"),
        "anchor": {
            "register": anchor.get("register"),
            "addr": anchor.get("addr"),
            "width_bytes": anchor.get("width_bytes"),
            "role": anchor.get("role"),
        },
        "companions": group.get("companions") or [],
        "field_candidates": group.get("field_candidates") or [],
    }


SELECTOR_OUTPUT_SCHEMA: Dict[str, Any] = {
    "schema": "mf_fixedpoint_selector_v1",
    "mode": "single_region | multi_region",
    "trial": {
        "addr": "0x4006A004",
        "nth_touch": 1,
    },
    "candidates": [
        {
            "id": "uart_ready_top_bit_set",
            "rationale": "Set the top-ranked ready-like bit on the anchor register.",
            "actions": [
                {
                    "type": "mmio_bit_update",
                    "addr": "0x4006A004",
                    "width": 1,
                    "set_bits": [5],
                    "trigger": {"kind": "on_first_touch", "addr": "0x4006A004", "access": "read"},
                }
            ],
        },
        {
            "id": "uart_status_full_sweep_fallback",
            "rationale": "Fallback full-value sweep over one byte at the anchor address.",
            "sweep": {
                "addr": "0x4006A004",
                "width": 1,
                "values": ["0x00", "0x20", "0x80", "0xA0", "0xFF"],
                "trigger": {"kind": "on_first_touch", "addr": "0x4006A004", "access": "read"},
            },
        },
    ],
}


def build_fixedpoint_prompt_bundle(
    task_context: Dict[str, Any],
    *,
    max_multi_region_templates: int = 8,
    include_full_sweep_fallback: bool = True,
) -> Dict[str, Any]:
    group = _first_group(task_context)
    if not group:
        return {
            "schema": "mf_fixedpoint_selector_prompt_v1",
            "status": "no_hotspot_group",
            "task_context_target": task_context.get("target") or {},
            "selector_output_schema": SELECTOR_OUTPUT_SCHEMA,
        }

    multi_region_library = heuristic_plan(task_context, max_candidates=max_multi_region_templates)
    bundle = {
        "schema": "mf_fixedpoint_selector_prompt_v1",
        "target": task_context.get("target") or {},
        "primary_group": _group_summary(group),
        "single_region": _single_region(group),
        "multi_region_template_library": multi_region_library.get("candidates") or [],
        "selector_contract": {
            "objective": "Choose a small number of high-priority fixed-point candidates before any broad fallback sweep.",
            "rules": [
                "Prefer evidence-supported values, bit updates, and linked actions before exhaustive sweeps.",
                "For single-region cases, emit direct actions and optionally one fallback sweep candidate.",
                "For multi-region cases, prefer linked candidates from the existing template library and use direct actions only when clearly supported by the evidence.",
                "Only use addresses present in the hotspot group and its companions.",
                "Return JSON only.",
            ],
            "include_full_sweep_fallback": include_full_sweep_fallback,
        },
        "selector_output_schema": SELECTOR_OUTPUT_SCHEMA,
    }
    return bundle


def _heuristic_single_region_plan(
    group: Dict[str, Any],
    *,
    include_full_sweep_fallback: bool,
    full_sweep_values: Optional[List[str]] = None,
) -> Dict[str, Any]:
    anchor = group.get("anchor") or {}
    addr = _hex_u64(anchor.get("addr") or "0")
    width = int(anchor.get("width_bytes") or 1)
    fields = group.get("field_candidates") or []
    top_bits: List[int] = []
    for fld in fields[:4]:
        bits = fld.get("bits") or []
        if bits:
            top_bits.append(int(bits[0]))
    if not top_bits:
        top_bits = [0]

    candidates: List[Dict[str, Any]] = []
    seen = set()
    for bit in top_bits[:4]:
        if bit in seen:
            continue
        seen.add(bit)
        candidates.append(
            {
                "id": f"{group['group_id']}_set_bit_{bit}",
                "rationale": f"Set likely-relevant bit {bit} on the anchor register.",
                "actions": [
                    {
                        "type": "mmio_bit_update",
                        "addr": addr,
                        "width": width,
                        "set_bits": [bit],
                        "trigger": {"kind": "on_first_touch", "addr": addr, "access": "read"},
                    }
                ],
            }
        )
        candidates.append(
            {
                "id": f"{group['group_id']}_clear_bit_{bit}",
                "rationale": f"Clear likely-relevant bit {bit} on the anchor register.",
                "actions": [
                    {
                        "type": "mmio_bit_update",
                        "addr": addr,
                        "width": width,
                        "clear_bits": [bit],
                        "trigger": {"kind": "on_first_touch", "addr": addr, "access": "read"},
                    }
                ],
            }
        )

    if include_full_sweep_fallback and width == 1:
        values = full_sweep_values or [f"0x{i:02X}" for i in range(256)]
        candidates.append(
            {
                "id": f"{group['group_id']}_full_value_sweep",
                "rationale": "Fallback full-value sweep over the single relevant region.",
                "sweep": {
                    "addr": addr,
                    "width": 1,
                    "values": values,
                    "trigger": {"kind": "on_first_touch", "addr": addr, "access": "read"},
                },
            }
        )

    return {
        "schema": "mf_fixedpoint_selector_v1",
        "mode": "single_region",
        "primary_group_id": group.get("group_id"),
        "trial": {"addr": addr, "nth_touch": 1},
        "candidates": candidates,
    }


def _heuristic_multi_region_plan(task_context: Dict[str, Any], group: Dict[str, Any], *, max_candidates: int) -> Dict[str, Any]:
    base = heuristic_plan(task_context, max_candidates=max_candidates)
    return {
        "schema": "mf_fixedpoint_selector_v1",
        "mode": "multi_region",
        "primary_group_id": group.get("group_id"),
        "trial": {"addr": _hex_u64((group.get("anchor") or {}).get("addr") or "0"), "nth_touch": 1},
        "candidates": base.get("candidates") or [],
    }


def normalize_selector_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    if str(plan.get("schema") or "") != "mf_fixedpoint_selector_v1":
        raise ValueError("selector plan schema must be mf_fixedpoint_selector_v1")
    trial = plan.get("trial") or {}
    out = {
        "schema": "mf_fixedpoint_selector_v1",
        "mode": str(plan.get("mode") or "single_region"),
        "primary_group_id": plan.get("primary_group_id"),
        "trial": {
            "addr": _hex_u64(trial.get("addr") or "0"),
            "nth_touch": int(trial.get("nth_touch") or 1),
        },
        "candidates": [],
    }
    for idx, cand in enumerate(plan.get("candidates") or []):
        item = {
            "id": str(cand.get("id") or f"candidate_{idx}"),
            "rationale": str(cand.get("rationale") or ""),
        }
        if cand.get("actions"):
            item["actions"] = cand.get("actions")
        if cand.get("sweep"):
            sweep = dict(cand.get("sweep") or {})
            sweep["addr"] = _hex_u64(sweep.get("addr") or out["trial"]["addr"])
            sweep["width"] = int(sweep.get("width") or 1)
            sweep["values"] = [_hex_u64(v) for v in (sweep.get("values") or [])]
            item["sweep"] = sweep
        out["candidates"].append(item)
    return out


def select_fixedpoint_candidates(
    task_context: Dict[str, Any],
    *,
    llm_json_path: Optional[str] = None,
    include_full_sweep_fallback: bool = True,
    full_sweep_values: Optional[List[str]] = None,
    max_multi_region_candidates: int = 6,
) -> Dict[str, Any]:
    group = _first_group(task_context)
    if not group:
        return {
            "schema": "mf_fixedpoint_selector_v1",
            "mode": "no_group",
            "trial": {"addr": "0x0", "nth_touch": 1},
            "candidates": [],
        }

    if llm_json_path:
        loaded = load_json(llm_json_path)
        normalized = normalize_selector_plan(loaded)
        info(f"loaded fixed-point selector plan from LLM JSON: {llm_json_path}")
        return normalized

    if _single_region(group):
        return _heuristic_single_region_plan(
            group,
            include_full_sweep_fallback=include_full_sweep_fallback,
            full_sweep_values=full_sweep_values,
        )
    return _heuristic_multi_region_plan(task_context, group, max_candidates=max_multi_region_candidates)


def save_fixedpoint_prompt_bundle(task_context_path: str, out_path: str, *, out_text: Optional[str] = None) -> Dict[str, Any]:
    task_context = load_json(task_context_path)
    bundle = build_fixedpoint_prompt_bundle(task_context)
    save_json(out_path, bundle)
    if out_text:
        with open(out_text, "w", encoding="utf-8") as f:
            f.write(json.dumps(bundle, indent=2, ensure_ascii=False))
    info(f"fixed-point prompt bundle saved: {out_path}")
    return bundle


def save_fixedpoint_selector_plan(
    task_context_path: str,
    out_path: str,
    *,
    llm_json_path: Optional[str] = None,
    include_full_sweep_fallback: bool = True,
    full_sweep_values: Optional[List[str]] = None,
    max_multi_region_candidates: int = 6,
) -> Dict[str, Any]:
    task_context = load_json(task_context_path)
    plan = select_fixedpoint_candidates(
        task_context,
        llm_json_path=llm_json_path,
        include_full_sweep_fallback=include_full_sweep_fallback,
        full_sweep_values=full_sweep_values,
        max_multi_region_candidates=max_multi_region_candidates,
    )
    save_json(out_path, plan)
    info(f"fixed-point selector plan saved: {out_path}; candidates={len(plan.get('candidates') or [])}")
    return plan
