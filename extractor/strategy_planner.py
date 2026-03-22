from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional, Set

from debug_trace import info, load_json, save_json, save_text, warn
from strategy_catalog import ACTION_CATALOG, TRIGGER_CATALOG, GROUP_TEMPLATE_CATALOG, llm_visible_schema


ALLOWED_ACTIONS = {x["name"] for x in ACTION_CATALOG}
ALLOWED_TRIGGERS = {x["name"] for x in TRIGGER_CATALOG}


def _allowed_addresses(task_context: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for item in (((task_context.get("evidence_pack") or {}).get("evidence")) or []):
        addr = str(item.get("addr") or "")
        if addr:
            out.add(addr.upper())
        resolved = item.get("svd_resolution") or {}
        ra = str(resolved.get("register_address_hex") or "")
        if ra:
            out.add(ra.upper())
    for group in (((task_context.get("runtime_problem") or {}).get("hotspot_groups")) or []):
        anchor = group.get("anchor") or {}
        a = str(anchor.get("addr") or "")
        if a:
            out.add(a.upper())
        for m in group.get("members", []) or []:
            a = str(m.get("addr") or "")
            if a:
                out.add(a.upper())
    best = task_context.get("best_known_strategy") or {}
    for action in best.get("actions", []) or []:
        for key in ["addr", "read_addr", "write_addr", "s1_addr", "d_addr"]:
            v = str(action.get(key) or "")
            if v:
                out.add(v.upper())
    return out


def _collect_field_bits(task_context: Dict[str, Any]) -> Dict[str, Set[int]]:
    out: Dict[str, Set[int]] = {}
    for item in (((task_context.get("evidence_pack") or {}).get("evidence")) or []):
        resolved = item.get("svd_resolution") or {}
        addr = str(resolved.get("register_address_hex") or item.get("addr") or "").upper()
        if not addr:
            continue
        bits = out.setdefault(addr, set())
        for fld in resolved.get("fields", []) or []:
            bo = fld.get("bitOffset")
            bw = fld.get("bitWidth")
            if isinstance(bo, int) and isinstance(bw, int) and bw > 0:
                for b in range(bo, bo + bw):
                    bits.add(int(b))
    return out


def _template_catalog_by_kind() -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for item in GROUP_TEMPLATE_CATALOG:
        for kind in item.get("group_kinds", []) or []:
            out.setdefault(kind, []).append(item)
    return out


def build_llm_prompt_bundle(task_context: Dict[str, Any]) -> Dict[str, Any]:
    schema = llm_visible_schema()
    groups = ((task_context.get("runtime_problem") or {}).get("hotspot_groups")) or []
    prompt_instructions = {
        "task": "Propose 1-4 staged fuzz strategy candidates by choosing hotspot-group templates, then instantiating them with allowed fields/bits and triggers.",
        "output_requirements": {
            "format": "JSON",
            "top_level_key": "candidates",
            "candidate_fields": ["id", "group_id", "template_id", "rationale", "actions"],
            "action_rules": [
                "action.type must be one of action_catalog.name",
                "action.trigger.kind must be one of trigger_catalog.name",
                "all addresses must appear in allowed_addresses",
                "bit updates must use bits present in allowed_field_bits_by_addr",
                "template_id must be allowed for the selected hotspot group kind",
            ],
        },
        "allowed_addresses": sorted(_allowed_addresses(task_context)),
        "allowed_field_bits_by_addr": {k: sorted(v) for k, v in _collect_field_bits(task_context).items()},
        "hotspot_groups": groups,
    }
    return {
        "task_context": task_context,
        "llm_visible_strategy_schema": schema,
        "prompt_instructions": prompt_instructions,
    }


def _trigger_touch(addr: str, n: int) -> Dict[str, Any]:
    if n <= 1:
        return {"kind": "on_first_touch", "addr": addr, "access": "read"}
    return {"kind": "on_nth_touch", "addr": addr, "n": int(n), "access": "read"}


def _top_bits_for_group(group: Dict[str, Any], allowed_bits: Dict[str, Set[int]]) -> List[int]:
    anchor = group.get("anchor") or {}
    addr = str(anchor.get("addr") or "").upper()
    field_candidates = group.get("field_candidates", []) or []
    out: List[int] = []
    for fld in field_candidates:
        for b in fld.get("bits", []) or []:
            if isinstance(b, int) and b not in out:
                out.append(int(b))
    if out:
        return out
    return sorted(allowed_bits.get(addr, set()))[:4]


def _pick_companion(group: Dict[str, Any], roles: Set[str]) -> Optional[Dict[str, Any]]:
    companions = group.get("companions", []) or []
    filtered = [x for x in companions if str(x.get("role") or "") in roles]
    if not filtered:
        return None
    filtered.sort(key=lambda x: int(x.get("read_count") or 0), reverse=True)
    return filtered[0]


def _candidate_from_group(group: Dict[str, Any], template_id: str, action: Dict[str, Any], rationale: str) -> Dict[str, Any]:
    return {
        "id": f"{group['group_id']}_{template_id}",
        "group_id": group["group_id"],
        "template_id": template_id,
        "rationale": rationale,
        "actions": [action],
    }


def _group_candidates(group: Dict[str, Any], allowed_bits: Dict[str, Set[int]], default_after_reads: int) -> List[Dict[str, Any]]:
    kind = str(group.get("kind") or "")
    anchor = group.get("anchor") or {}
    addr = str(anchor.get("addr") or "").upper()
    width = int(anchor.get("width_bytes") or 4)
    reg = str(anchor.get("register") or "").upper()
    instance = str(group.get("instance") or "").upper()
    bits = _top_bits_for_group(group, allowed_bits)
    candidates: List[Dict[str, Any]] = []

    if not addr or width <= 0:
        return candidates

    if kind in {"polling_group", "status_data_group", "status_config_group"}:
        if bits:
            b = bits[0]
            candidates.append(
                _candidate_from_group(
                    group,
                    "poll_ready_bit_set_touch1",
                    {
                        "type": "mmio_bit_update",
                        "addr": addr,
                        "width": width,
                        "set_bits": [b],
                        "trigger": _trigger_touch(addr, 1),
                        "activate_stage": f"{group['group_id']}_ready_t1",
                    },
                    f"Polling-like anchor {instance}.{reg}: set a top-ranked status bit on first touch.",
                )
            )
            candidates.append(
                _candidate_from_group(
                    group,
                    "poll_ready_bit_set_touch2",
                    {
                        "type": "mmio_bit_update",
                        "addr": addr,
                        "width": width,
                        "set_bits": [b],
                        "trigger": _trigger_touch(addr, 2),
                        "activate_stage": f"{group['group_id']}_ready_t2",
                    },
                    f"Polling-like anchor {instance}.{reg}: set a top-ranked status bit on second touch.",
                )
            )
            candidates.append(
                _candidate_from_group(
                    group,
                    "poll_busy_bit_clear_touch2",
                    {
                        "type": "mmio_bit_update",
                        "addr": addr,
                        "width": width,
                        "clear_bits": [b],
                        "trigger": _trigger_touch(addr, 2),
                        "activate_stage": f"{group['group_id']}_clear_t2",
                    },
                    f"Polling-like anchor {instance}.{reg}: clear a top-ranked status bit on second touch.",
                )
            )
            candidates.append(
                _candidate_from_group(
                    group,
                    "poll_ready_bit_set_after_reads",
                    {
                        "type": "mmio_bit_update",
                        "addr": addr,
                        "width": width,
                        "set_bits": [b],
                        "trigger": {"kind": "after_global_reads", "value": int(default_after_reads)},
                        "activate_stage": f"{group['group_id']}_ready_after_reads",
                    },
                    f"Polling-like anchor {instance}.{reg}: set a top-ranked status bit after a small global-read budget.",
                )
            )

        data_comp = _pick_companion(group, {"data"})
        if data_comp and instance.startswith("UART") and reg in {"S1", "S", "SR", "STAT"}:
            candidates.append(
                {
                    "id": f"{group['group_id']}_status_then_data_touch2",
                    "group_id": group["group_id"],
                    "template_id": "status_then_data",
                    "rationale": f"Use UART status/data pairing for {instance}: pulse the status anchor and open a short data window on {data_comp['register']}.",
                    "actions": [
                        {
                            "type": "uart_handshake_once",
                            "s1_addr": addr,
                            "d_addr": str(data_comp.get("addr") or "").upper(),
                            "s1_value": "0xC0",
                            "data_bytes": ["0x41"],
                            "d_window_accesses": 4,
                            "trigger": _trigger_touch(addr, 2),
                            "activate_stage": f"{group['group_id']}_uart_data",
                        }
                    ],
                }
            )

        ctrl_comp = _pick_companion(group, {"control", "fifo_config"})
        if ctrl_comp:
            candidates.append(
                _candidate_from_group(
                    group,
                    "status_then_config_touch2",
                    {
                        "type": "mmio_bit_update",
                        "addr": addr,
                        "width": width,
                        "set_bits": [bits[0]] if bits else [],
                        "trigger": _trigger_touch(addr, 2),
                        "activate_stage": f"{group['group_id']}_{str(ctrl_comp.get('register') or '').lower()}_follow",
                    },
                    f"Use the polling/status anchor for {instance} and stage a follow-up path for companion {ctrl_comp['register']}.",
                )
            )

    if kind == "config_group":
        candidate_bits = bits or [0]
        b = candidate_bits[0]
        candidates.append(
            _candidate_from_group(
                group,
                "config_bit_set_touch1",
                {
                    "type": "mmio_bit_update",
                    "addr": addr,
                    "width": width,
                    "set_bits": [b],
                    "trigger": _trigger_touch(addr, 1),
                    "activate_stage": f"{group['group_id']}_cfg_set",
                },
                f"Low-priority config fallback for {instance}.{reg}: set one configuration bit on first touch.",
            )
        )
        candidates.append(
            _candidate_from_group(
                group,
                "config_bit_clear_touch2",
                {
                    "type": "mmio_bit_update",
                    "addr": addr,
                    "width": width,
                    "clear_bits": [b],
                    "trigger": _trigger_touch(addr, 2),
                    "activate_stage": f"{group['group_id']}_cfg_clear",
                },
                f"Low-priority config fallback for {instance}.{reg}: clear one configuration bit on second touch.",
            )
        )

    return candidates


def heuristic_plan(task_context: Dict[str, Any], max_candidates: int = 4, default_after_reads: int = 192) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    allowed_bits = _collect_field_bits(task_context)
    groups = ((task_context.get("runtime_problem") or {}).get("hotspot_groups")) or []

    best = task_context.get("best_known_strategy") or {}
    if best.get("actions"):
        candidates.append(
            {
                "id": "best_known_replay",
                "group_id": None,
                "template_id": "best_known_replay",
                "rationale": "Replay the current best-known staged action as a baseline candidate.",
                "actions": best.get("actions"),
            }
        )

    for group in groups:
        candidates.extend(_group_candidates(group, allowed_bits, default_after_reads))
        if len(candidates) >= max_candidates:
            break

    if not candidates and groups:
        group = groups[0]
        anchor = group.get("anchor") or {}
        addr = str(anchor.get("addr") or "").upper()
        width = int(anchor.get("width_bytes") or 4)
        bits = _top_bits_for_group(group, allowed_bits) or [0]
        candidates.append(
            _candidate_from_group(
                group,
                "fallback_anchor_touch1",
                {
                    "type": "mmio_bit_update",
                    "addr": addr,
                    "width": width,
                    "set_bits": [bits[0]],
                    "trigger": _trigger_touch(addr, 1),
                    "activate_stage": f"{group['group_id']}_fallback",
                },
                f"Fallback candidate for {group['group_id']} to ensure the planner is never empty.",
            )
        )

    seen_ids: Set[str] = set()
    deduped = []
    for cand in candidates:
        cid = str(cand.get("id") or "")
        if not cid or cid in seen_ids:
            continue
        seen_ids.add(cid)
        deduped.append(cand)
        if len(deduped) >= max_candidates:
            break

    return {"schema": "llm_strategy_choice_v1", "candidates": deduped}


def _validate_trigger(trigger: Dict[str, Any], allowed_addrs: Set[str]) -> List[str]:
    errs = []
    kind = str(trigger.get("kind") or "")
    if kind not in ALLOWED_TRIGGERS:
        errs.append(f"unknown trigger kind: {kind}")
        return errs
    if kind in {"on_first_touch", "on_nth_touch", "after_write", "after_write_value"}:
        addr = str(trigger.get("addr") or "").upper()
        if addr not in allowed_addrs:
            errs.append(f"trigger addr not allowed: {addr}")
    return errs


def _validate_action(action: Dict[str, Any], allowed_addrs: Set[str], allowed_bits: Dict[str, Set[int]]) -> List[str]:
    errs = []
    kind = str(action.get("type") or "")
    if kind not in ALLOWED_ACTIONS:
        errs.append(f"unknown action type: {kind}")
        return errs
    for key in ["addr", "read_addr", "write_addr", "s1_addr", "d_addr"]:
        if key in action:
            addr = str(action.get(key) or "").upper()
            if addr and addr not in allowed_addrs:
                errs.append(f"{kind}.{key} not allowed: {addr}")
    trigger = action.get("trigger") or {}
    errs.extend(_validate_trigger(trigger, allowed_addrs))
    if kind == "mmio_bit_update":
        addr = str(action.get("addr") or "").upper()
        valid_bits = allowed_bits.get(addr, set())
        for b in (action.get("set_bits") or []) + (action.get("clear_bits") or []):
            if int(b) not in valid_bits:
                errs.append(f"bit {b} not allowed for {addr}")
    return errs


def normalize_llm_plan(task_context: Dict[str, Any], llm_json_path: str) -> Dict[str, Any]:
    raw = load_json(llm_json_path)
    allowed_addrs = _allowed_addresses(task_context)
    allowed_bits = _collect_field_bits(task_context)
    out_candidates = []

    for cand in raw.get("candidates", []) or []:
        candidate_errs = []
        actions = []
        for action in cand.get("actions", []) or []:
            errs = _validate_action(action, allowed_addrs, allowed_bits)
            if errs:
                candidate_errs.extend(errs)
                continue
            actions.append(action)
        if candidate_errs:
            warn(f"candidate {cand.get('id')} rejected: {'; '.join(candidate_errs)}")
            continue
        if actions:
            out_candidates.append(
                {
                    "id": cand.get("id"),
                    "group_id": cand.get("group_id"),
                    "template_id": cand.get("template_id"),
                    "rationale": cand.get("rationale"),
                    "actions": actions,
                }
            )

    return {"schema": "llm_strategy_choice_v1", "candidates": out_candidates}


def main():
    ap = argparse.ArgumentParser(description="LLM prompt builder / heuristic planner / normalizer")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("prompt")
    s1.add_argument("--task-context", required=True)
    s1.add_argument("--out", required=True)
    s1.add_argument("--out-text")

    s2 = sub.add_parser("heuristic")
    s2.add_argument("--task-context", required=True)
    s2.add_argument("--out", required=True)
    s2.add_argument("--max-candidates", type=int, default=4)
    s2.add_argument("--default-after-reads", type=int, default=192)

    s3 = sub.add_parser("normalize")
    s3.add_argument("--task-context", required=True)
    s3.add_argument("--llm-json", required=True)
    s3.add_argument("--out", required=True)

    args = ap.parse_args()
    task_context = load_json(args.task_context)

    if args.cmd == "prompt":
        bundle = build_llm_prompt_bundle(task_context)
        save_json(args.out, bundle)
        if args.out_text:
            save_text(args.out_text, json.dumps(bundle, indent=2, ensure_ascii=False))
        info(f"prompt bundle saved: {args.out}")
    elif args.cmd == "heuristic":
        plan = heuristic_plan(task_context, max_candidates=args.max_candidates, default_after_reads=args.default_after_reads)
        save_json(args.out, plan)
        info(f"heuristic plan saved: {args.out}")
    elif args.cmd == "normalize":
        norm = normalize_llm_plan(task_context, args.llm_json)
        save_json(args.out, norm)
        info(f"normalized plan saved: {args.out}")


if __name__ == "__main__":
    main()
