#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dynamic stuck-function attribution.

Consumes:
- a static contract bundle
- a replay trace / recent-exec trace / text trace

Produces a focused stuck report that combines:
- last-PC localization
- loop repetition signals
- target-peripheral consistency
- target-peripheral MMIO tail-window bonus
- suppression of common helper / libc noise
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


COMMON_HELPER_PATTERNS = [
    r"^_+printf.*$",
    r"^_+scanf.*$",
    r"^i?printf$",
    r"^v?sn?printf$",
    r"^v?ss?canf$",
    r"^puts?$",
    r"^putchar$",
    r"^getchar$",
    r"^__s.+$",
    r"^_+s.+_r$",
    r"^strto.+$",
    r"^strn?cmp$",
    r"^strn?len$",
    r"^strn?cpy$",
    r"^strn?cat$",
    r"^strchr$",
    r"^strrchr$",
    r"^memcmp$",
    r"^memset$",
    r"^memcpy$",
    r"^memmove$",
    r"^mktime$",
    r"^gmtime$",
    r"^localtime$",
    r"^_lseek_r$",
    r"^_fstat_r$",
    r"^_write_r$",
    r"^_read_r$",
    r"^_close_r$",
    r"^_isatty_r$",
    r"^_sbrk_r$",
    r"^_malloc_r$",
    r"^_free_r$",
    r"^_calloc_r$",
    r"^_realloc_r$",
    r"^malloc$",
    r"^free$",
    r"^calloc$",
    r"^realloc$",
    r"^_mutex_.+$",
    r"^sched_.+$",
    r"^context_.+$",
    r"^core_panic$",
    r"^panic$",
    r"^hard_fault_handler$",
    r"^bit_set32$",
    r"^bit_clear32$",
    r"^bit_read32$",
    r"^periph_init$",
]
COMMON_HELPER_RE = re.compile("(?:%s)" % "|".join(COMMON_HELPER_PATTERNS), re.IGNORECASE)

TRACE_LIST_KEYS = ["trace", "events", "bb_trace", "blocks", "pcs", "items", "history"]
PC_RE = re.compile(r"(?:pc|addr|address)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)")
FUNC_RE = re.compile(r"(?:func|function)\s*[:=]\s*([A-Za-z_.$][\w.$]*)")
BLOCK_RE = re.compile(r"(?:bb|block)\s*[:=]\s*([A-Za-z0-9_.$:+\-]+)")
MMIO_RE = re.compile(r"(?:mmio|MMIO).{0,24}?(0x[0-9a-fA-F]+)")


def parse_int_auto(text: Any) -> int:
    s = str(text).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)


def maybe_hex_to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        return None
    try:
        return parse_int_auto(s)
    except Exception:
        return None


def hex_norm(value: int) -> str:
    return f"0x{value:08X}"


def safe_read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_bundle(path: Path) -> Dict[str, Any]:
    data = safe_read_json(path)
    if "program_context" not in data:
        raise ValueError(f"{path} does not look like a contract bundle")
    return data


def normalize_function_name(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _event_from_scalar(item: Any) -> Optional[Dict[str, Any]]:
    pc = maybe_hex_to_int(item)
    if pc is None:
        return None
    return {
        "pc": pc,
        "pc_hex": hex_norm(pc),
        "function": None,
        "block": None,
        "mmio": None,
        "event_type": "exec",
    }


def _event_from_dict(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    pc = (
        maybe_hex_to_int(item.get("pc"))
        or maybe_hex_to_int(item.get("addr"))
        or maybe_hex_to_int(item.get("address"))
        or maybe_hex_to_int(item.get("block_pc"))
        or maybe_hex_to_int(item.get("bb_pc"))
    )
    fn = (
        normalize_function_name(item.get("function"))
        or normalize_function_name(item.get("func"))
        or normalize_function_name(item.get("function_name"))
        or normalize_function_name(item.get("name"))
        or normalize_function_name(item.get("last_function"))
    )
    block = normalize_function_name(item.get("block")) or normalize_function_name(item.get("bb"))
    mmio_addr = maybe_hex_to_int(item.get("mmio_addr")) or maybe_hex_to_int(item.get("mmio_address"))
    mmio_off = maybe_hex_to_int(item.get("mmio_offset")) or maybe_hex_to_int(item.get("offset"))
    mmio_value = maybe_hex_to_int(item.get("mmio_value")) or maybe_hex_to_int(item.get("value"))
    mmio_size = maybe_hex_to_int(item.get("mmio_size")) or maybe_hex_to_int(item.get("size"))
    event_type = item.get("event_type") or item.get("access") or item.get("kind") or item.get("type")
    if pc is None and fn is None and block is None and mmio_addr is None and mmio_off is None:
        return None
    mmio = None
    if mmio_addr is not None or mmio_off is not None:
        mmio = {
            "address": mmio_addr,
            "address_hex": hex_norm(mmio_addr) if mmio_addr is not None else None,
            "offset": mmio_off,
            "offset_hex": hex_norm(mmio_off) if mmio_off is not None else None,
            "value": mmio_value,
            "value_hex": hex_norm(mmio_value) if mmio_value is not None else None,
            "size": mmio_size,
            "access": str(event_type or ""),
        }
    return {
        "pc": pc,
        "pc_hex": hex_norm(pc) if pc is not None else None,
        "function": fn,
        "block": block,
        "mmio": mmio,
        "event_type": str(event_type or "exec"),
    }


def _extract_trace_list(data: Any) -> List[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in TRACE_LIST_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def _choose_exec_container(raw: Any, use_recent_exec: Optional[str]) -> Tuple[List[Any], Dict[str, Any]]:
    if not isinstance(raw, dict):
        return _extract_trace_list(raw), {}

    if use_recent_exec:
        latest_exec = raw.get("latest_exec")
        recent_execs = raw.get("recent_execs") or []
        if use_recent_exec == "latest" and isinstance(latest_exec, dict):
            return _extract_trace_list(latest_exec), {"selected_exec": latest_exec}
        if isinstance(recent_execs, list):
            try:
                idx = int(use_recent_exec)
                if 0 <= idx < len(recent_execs) and isinstance(recent_execs[idx], dict):
                    return _extract_trace_list(recent_execs[idx]), {"selected_exec": recent_execs[idx]}
            except Exception:
                pass

    latest_exec = raw.get("latest_exec")
    if isinstance(latest_exec, dict):
        lst = _extract_trace_list(latest_exec)
        if lst:
            return lst, {"selected_exec": latest_exec}
    return _extract_trace_list(raw), {}


def parse_trace_json(path: Optional[Path], use_recent_exec: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if path is None:
        return [], {}
    raw = safe_read_json(path)
    trace_list, extra_meta = _choose_exec_container(raw, use_recent_exec)
    events: List[Dict[str, Any]] = []
    for item in trace_list:
        ev = _event_from_dict(item) if isinstance(item, dict) else _event_from_scalar(item)
        if ev is not None:
            events.append(ev)
    meta = raw if isinstance(raw, dict) else {}
    meta = {**meta, **extra_meta}
    return events, meta


def parse_trace_text(path: Optional[Path]) -> List[Dict[str, Any]]:
    if path is None:
        return []
    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            pc = None
            fn = None
            block = None
            mmio = None
            m = PC_RE.search(line)
            if m:
                pc = parse_int_auto(m.group(1))
            m = FUNC_RE.search(line)
            if m:
                fn = m.group(1)
            m = BLOCK_RE.search(line)
            if m:
                block = m.group(1)
            m = MMIO_RE.search(line)
            if m:
                mmio_addr = parse_int_auto(m.group(1))
                mmio = {"address": mmio_addr, "address_hex": hex_norm(mmio_addr), "offset": None, "offset_hex": None, "value": None, "value_hex": None, "size": None, "access": None}
            if pc is None and fn is None and block is None and mmio is None:
                continue
            events.append({"pc": pc, "pc_hex": hex_norm(pc) if pc is not None else None, "function": fn, "block": block, "mmio": mmio, "event_type": "exec"})
    return events


def build_function_maps(bundle: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], Dict[int, str]]:
    funcs = bundle.get("program_context", {}).get("functions", []) or []
    anchors = bundle.get("program_context", {}).get("anchor_candidates", []) or []
    anchor_by_name = {str(x.get("function") or ""): x for x in anchors if str(x.get("function") or "")}

    by_name: Dict[str, Dict[str, Any]] = {}
    by_entry: Dict[int, str] = {}
    for f in funcs:
        name = str(f.get("name") or "")
        if not name:
            continue
        merged = dict(f)
        anchor = anchor_by_name.get(name)
        if anchor:
            merged.setdefault("anchor_score", int(anchor.get("final_score") or 0))
            merged.setdefault("is_anchor", bool(anchor.get("is_anchor")))
            merged.setdefault("hot_rel_offsets", anchor.get("rel_hot_offsets") or [])
            merged.setdefault("hot_abs_addresses", anchor.get("abs_hot_addresses") or [])
            merged.setdefault("name_alias_hits", anchor.get("name_alias_hits") or [])
            merged.setdefault("anchor_reasons", anchor.get("reasons") or [])
            merged.setdefault("peripheral", anchor.get("peripheral"))
        by_name[name] = merged
        entry = maybe_hex_to_int(f.get("entry")) or maybe_hex_to_int(f.get("entry_offset"))
        if entry is not None:
            by_entry[entry] = name
    for name, anchor in anchor_by_name.items():
        if name not in by_name:
            by_name[name] = {
                "name": name,
                "anchor_score": int(anchor.get("final_score") or 0),
                "is_anchor": bool(anchor.get("is_anchor")),
                "hot_rel_offsets": anchor.get("rel_hot_offsets") or [],
                "hot_abs_addresses": anchor.get("abs_hot_addresses") or [],
                "name_alias_hits": anchor.get("name_alias_hits") or [],
                "anchor_reasons": anchor.get("reasons") or [],
                "peripheral": anchor.get("peripheral"),
            }
    return by_name, by_entry


def resolve_function_for_event(event: Dict[str, Any], functions_by_name: Dict[str, Dict[str, Any]], entries_by_addr: Dict[int, str]) -> Optional[str]:
    fn = normalize_function_name(event.get("function"))
    if fn:
        return fn
    pc = maybe_hex_to_int(event.get("pc"))
    if pc is None or not entries_by_addr:
        return None
    if pc in entries_by_addr:
        return entries_by_addr[pc]
    best_name = None
    best_entry = None
    best_delta = None
    for entry, name in entries_by_addr.items():
        if entry <= pc:
            delta = pc - entry
            if delta <= 0x2000 and (best_delta is None or delta < best_delta):
                best_delta = delta
                best_entry = entry
                best_name = name
    return best_name


def enrich_trace_events(events: List[Dict[str, Any]], functions_by_name: Dict[str, Dict[str, Any]], entries_by_addr: Dict[int, str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    current_fn: Optional[str] = None
    for ev in events:
        new_ev = dict(ev)
        fn = resolve_function_for_event(new_ev, functions_by_name, entries_by_addr)
        if fn:
            current_fn = fn
        new_ev["resolved_function"] = fn or current_fn
        pc = maybe_hex_to_int(new_ev.get("pc"))
        new_ev["pc_hex"] = hex_norm(pc) if pc is not None else new_ev.get("pc_hex")
        out.append(new_ev)
    return out


def _control_flow_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for ev in events:
        if ev.get("event_type") == "exec":
            out.append(ev)
            continue
        if ev.get("pc") is not None or ev.get("resolved_function") or ev.get("block"):
            out.append(ev)
    return out


def _last_pc_event(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    cf_events = _control_flow_events(events)
    for ev in reversed(cf_events):
        if maybe_hex_to_int(ev.get("pc")) is not None:
            return ev
    return {}


def _last_named_event(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    cf_events = _control_flow_events(events)
    for ev in reversed(cf_events):
        if ev.get("resolved_function") or ev.get("function"):
            return ev
    return {}


def compute_tail_loop_metrics(events: List[Dict[str, Any]], tail_window: int) -> Dict[str, Any]:
    cf_events = _control_flow_events(events)
    tail = cf_events[-tail_window:] if tail_window > 0 else list(cf_events)
    func_counter: Counter[str] = Counter()
    block_counter: Counter[str] = Counter()
    edge_counter: Counter[Tuple[str, str]] = Counter()
    longest_run: Counter[str] = Counter()

    prev_block = None
    run_func = None
    run_len = 0
    for ev in tail:
        fn = ev.get("resolved_function") or ev.get("function")
        block = ev.get("block") or ev.get("pc_hex") or fn
        if fn:
            func_counter[fn] += 1
        if block:
            block_counter[str(block)] += 1
        if prev_block is not None and block is not None:
            edge_counter[(str(prev_block), str(block))] += 1
        prev_block = block
        if fn == run_func and fn is not None:
            run_len += 1
        else:
            if run_func is not None:
                longest_run[run_func] = max(longest_run[run_func], run_len)
            run_func = fn
            run_len = 1 if fn is not None else 0
    if run_func is not None:
        longest_run[run_func] = max(longest_run[run_func], run_len)

    repeated_edges = sum(1 for _, c in edge_counter.items() if c >= 2)
    dominant_loop_functions = []
    for fn, count in func_counter.most_common(16):
        loop_score = count + 2 * longest_run.get(fn, 0)
        dominant_loop_functions.append({
            "function": fn,
            "repeat_blocks": count,
            "repeat_edges": repeated_edges,
            "longest_run": longest_run.get(fn, 0),
            "loop_score": loop_score,
        })
    dominant_loop_blocks = [{"block": blk, "count": cnt} for blk, cnt in block_counter.most_common(16)]
    return {
        "tail_event_count": len(tail),
        "control_flow_event_count": len(cf_events),
        "dominant_loop_functions": dominant_loop_functions,
        "dominant_loop_blocks": dominant_loop_blocks,
        "edge_repetition_count": repeated_edges,
    }


def collect_tail_mmio(events: List[Dict[str, Any]], tail_window: int) -> Dict[str, Any]:
    tail = events[-tail_window:] if tail_window > 0 else list(events)
    addr_counter: Counter[str] = Counter()
    off_counter: Counter[str] = Counter()
    for ev in tail:
        mmio = ev.get("mmio") or {}
        addr_hex = mmio.get("address_hex")
        off_hex = mmio.get("offset_hex")
        if addr_hex:
            addr_counter[str(addr_hex)] += 1
        if off_hex:
            off_counter[str(off_hex)] += 1
    return {
        "addresses": [{"address_hex": a, "count": c} for a, c in addr_counter.most_common(16)],
        "offsets": [{"offset_hex": a, "count": c} for a, c in off_counter.most_common(16)],
    }


def collect_trace_touches(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    addr_counter: Counter[str] = Counter()
    off_counter: Counter[str] = Counter()
    access_counter: Counter[str] = Counter()
    for ev in events:
        mmio = ev.get("mmio") or {}
        addr_hex = str(mmio.get("address_hex") or "").upper().strip()
        off_hex = str(mmio.get("offset_hex") or "").upper().strip()
        access = str(mmio.get("access") or "").strip().lower()
        if addr_hex:
            addr_counter[addr_hex] += 1
        if off_hex:
            off_counter[off_hex] += 1
        if access:
            access_counter[access] += 1
    return {
        "addresses": [{"address_hex": a, "count": c} for a, c in addr_counter.most_common(32)],
        "offsets": [{"offset_hex": a, "count": c} for a, c in off_counter.most_common(32)],
        "access_kinds": [{"kind": k, "count": c} for k, c in access_counter.most_common()],
    }


def build_dynamic_primary_cluster(events: List[Dict[str, Any]], tail_window: int, last_pc_function: Optional[str]) -> Dict[str, Any]:
    tail_mmio = collect_tail_mmio(events, tail_window)
    top_addrs = tail_mmio.get("addresses") or []
    if not top_addrs:
        return {
            "anchor_function": last_pc_function,
            "anchor_address": None,
            "addresses": [],
            "reason": "no_tail_mmio",
        }
    anchor = top_addrs[0]
    anchor_addr = str(anchor.get("address_hex") or "")
    cluster: List[Dict[str, Any]] = []
    anchor_int = maybe_hex_to_int(anchor_addr)
    for item in top_addrs[:8]:
        addr_hex = str(item.get("address_hex") or "")
        count = int(item.get("count") or 0)
        addr_int = maybe_hex_to_int(addr_hex)
        same_page = bool(anchor_int is not None and addr_int is not None and (anchor_int & ~0xFF) == (addr_int & ~0xFF))
        if item is anchor or count >= max(2, int(anchor.get("count") or 0) // 8) or same_page:
            cluster.append({
                "address_hex": addr_hex,
                "count": count,
                "same_page_as_anchor": same_page,
            })
    return {
        "anchor_function": last_pc_function,
        "anchor_address": anchor_addr,
        "addresses": cluster,
        "reason": "tail_mmio_cluster",
    }


def collect_target_touched_registers(bundle: Dict[str, Any], touches: Dict[str, Any], profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    touched_abs = {str(x.get("address_hex") or "").upper() for x in (touches.get("addresses") or []) if str(x.get("address_hex") or "").strip()}
    matched = bundle.get("document_context", {}).get("matched_peripheral_registers", []) or []
    out: List[Dict[str, Any]] = []
    seen = set()
    for doc in matched:
        reg = doc.get("register") or {}
        abs_hex = str(reg.get("absoluteAddress_hex") or "").upper().strip()
        off_hex = str(reg.get("addressOffset_hex") or "").upper().strip()
        key = (doc.get("peripheral"), reg.get("name"), abs_hex)
        if key in seen:
            continue
        if abs_hex and abs_hex in touched_abs:
            out.append({
                "peripheral": doc.get("peripheral"),
                "register": reg.get("name"),
                "absoluteAddress_hex": abs_hex,
                "addressOffset_hex": off_hex or None,
                "touch_count": next((int(x.get("count") or 0) for x in (touches.get("addresses") or []) if str(x.get("address_hex") or "").upper() == abs_hex), 0),
            })
            seen.add(key)
    return out[:16]


def first_divergence(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    a_cf = _control_flow_events(a)
    b_cf = _control_flow_events(b)
    n = min(len(a_cf), len(b_cf))
    for i in range(n):
        pa = a_cf[i].get("pc_hex") or a_cf[i].get("resolved_function")
        pb = b_cf[i].get("pc_hex") or b_cf[i].get("resolved_function")
        if pa != pb:
            return {"index": i, "a": {"pc_hex": a_cf[i].get("pc_hex"), "function": a_cf[i].get("resolved_function")}, "b": {"pc_hex": b_cf[i].get("pc_hex"), "function": b_cf[i].get("resolved_function")}}
    if len(a_cf) != len(b_cf):
        return {"index": n, "a": {"pc_hex": a_cf[n].get("pc_hex"), "function": a_cf[n].get("resolved_function")} if len(a_cf) > n else None, "b": {"pc_hex": b_cf[n].get("pc_hex"), "function": b_cf[n].get("resolved_function")} if len(b_cf) > n else None}
    return None


def extract_target_profile(bundle: Dict[str, Any]) -> Dict[str, Any]:
    matched = bundle.get("document_context", {}).get("matched_peripheral_registers", []) or []
    anchors = bundle.get("program_context", {}).get("anchor_candidates", []) or []
    peripheral_names = Counter()
    abs_addrs = set()
    rel_offsets = set()
    aliases = set()
    for doc in matched:
        periph = str(doc.get("peripheral") or "").strip()
        if periph:
            peripheral_names[periph] += 1
            aliases.add(periph.lower())
        reg = doc.get("register") or {}
        abs_hex = str(reg.get("absoluteAddress_hex") or "").strip()
        off_hex = str(reg.get("addressOffset_hex") or "").strip()
        if abs_hex:
            abs_addrs.add(abs_hex.upper())
        if off_hex:
            rel_offsets.add(off_hex.upper())
    for a in anchors[:24]:
        periph = str(a.get("peripheral") or "").strip()
        if periph:
            peripheral_names[periph] += 1
            aliases.add(periph.lower())
        for hit in a.get("name_alias_hits") or []:
            aliases.add(str(hit).lower())
    target_peripheral = peripheral_names.most_common(1)[0][0] if peripheral_names else None
    return {
        "target_peripheral": target_peripheral,
        "target_abs_addrs": abs_addrs,
        "target_rel_offsets": rel_offsets,
        "target_aliases": {x for x in aliases if x},
    }


def static_offset_bonus(functions_by_name: Dict[str, Dict[str, Any]], fn: str, tail_mmio_offsets: List[str]) -> int:
    f = functions_by_name.get(fn) or {}
    hot_rel_offsets = {str(x).upper() for x in (f.get("hot_rel_offsets") or [])}
    return 15 * len(hot_rel_offsets.intersection({x.upper() for x in tail_mmio_offsets}))


def _function_target_consistency(fn: str, f: Dict[str, Any], profile: Dict[str, Any]) -> Tuple[bool, List[str]]:
    aliases = profile["target_aliases"]
    target_abs = profile["target_abs_addrs"]
    target_rel = profile["target_rel_offsets"]
    reasons: List[str] = []

    fn_lower = fn.lower()
    name_alias_hits = {str(x).lower() for x in (f.get("name_alias_hits") or [])}
    hot_abs = {str(x).upper() for x in (f.get("hot_abs_addresses") or [])}
    hot_rel = {str(x).upper() for x in (f.get("hot_rel_offsets") or [])}
    static_score = int(f.get("anchor_score") or 0)

    name_match = any(alias and alias in fn_lower for alias in aliases) or bool(name_alias_hits.intersection(aliases))
    rel_match = sorted(hot_rel.intersection(target_rel))
    abs_match = sorted(hot_abs.intersection(target_abs))

    if name_match:
        reasons.append("target_name_alias")
    if abs_match:
        reasons.append(f"target_abs_match={abs_match}")
    if rel_match:
        reasons.append(f"target_rel_match={rel_match}")

    consistent = False
    if name_match or abs_match:
        consistent = True
    elif len(rel_match) >= 2 and static_score >= 150:
        consistent = True
    elif len(rel_match) >= 3:
        consistent = True

    return consistent, reasons


def collect_target_mmio_window_bonus(events: List[Dict[str, Any]], tail_window: int, profile: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    tail = events[-tail_window:] if tail_window > 0 else list(events)
    target_abs = {x.upper() for x in profile["target_abs_addrs"]}
    target_rel = {x.upper() for x in profile["target_rel_offsets"]}
    by_fn: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "target_abs_hits": 0,
        "target_rel_hits": 0,
        "target_mmio_bonus": 0,
        "target_mmio_addresses": set(),
        "target_mmio_offsets": set(),
    })

    def nearest_exec_fn(idx: int) -> Optional[str]:
        best_fn: Optional[str] = None
        best_dist: Optional[int] = None
        for radius in range(0, 4):
            for j in (idx - radius, idx + radius):
                if j < 0 or j >= len(tail):
                    continue
                ev = tail[j]
                if ev.get("event_type") != "exec":
                    continue
                if maybe_hex_to_int(ev.get("pc")) is None:
                    continue
                fn = ev.get("resolved_function") or ev.get("function")
                if not fn:
                    continue
                dist = abs(j - idx)
                if best_dist is None or dist < best_dist or (dist == best_dist and j <= idx):
                    best_dist = dist
                    best_fn = fn
            if best_fn is not None:
                return best_fn
        return None

    for idx, ev in enumerate(tail):
        mmio = ev.get("mmio") or {}
        if not mmio:
            continue
        addr_hex = str(mmio.get("address_hex") or "").upper().strip()
        off_hex = str(mmio.get("offset_hex") or "").upper().strip()
        abs_hit = bool(addr_hex and addr_hex in target_abs)
        rel_hit = bool(off_hex and off_hex in target_rel)
        if not abs_hit and not rel_hit:
            continue

        fn = nearest_exec_fn(idx)
        if not fn:
            continue

        slot = by_fn[fn]
        if abs_hit:
            slot["target_abs_hits"] += 1
            slot["target_mmio_addresses"].add(addr_hex)
        if rel_hit:
            slot["target_rel_hits"] += 1
            slot["target_mmio_offsets"].add(off_hex)

    for fn, slot in by_fn.items():
        abs_hits = slot["target_abs_hits"]
        rel_hits = slot["target_rel_hits"]
        abs_unique = len(slot["target_mmio_addresses"])
        rel_unique = len(slot["target_mmio_offsets"])
        bonus = 10 * abs_hits + 6 * rel_hits + 28 * abs_unique + 16 * rel_unique
        slot["target_mmio_bonus"] = min(180, bonus)
        slot["target_mmio_addresses"] = sorted(slot["target_mmio_addresses"])
        slot["target_mmio_offsets"] = sorted(slot["target_mmio_offsets"])
    return by_fn


def build_candidate_scores(bundle: Dict[str, Any], events: List[Dict[str, Any]], tail_window: int, last_pc_function: Optional[str]) -> List[Dict[str, Any]]:
    functions_by_name, _ = build_function_maps(bundle)
    profile = extract_target_profile(bundle)
    metrics = compute_tail_loop_metrics(events, tail_window)
    tail_mmio = collect_tail_mmio(events, tail_window)
    target_mmio_bonus_by_fn = collect_target_mmio_window_bonus(events, tail_window, profile)
    tail_offset_hexes = [x["offset_hex"] for x in tail_mmio["offsets"] if x.get("offset_hex")]

    loop_by_fn = {x["function"]: x for x in metrics["dominant_loop_functions"] if x.get("function")}
    candidate_names = set(loop_by_fn)
    if last_pc_function:
        candidate_names.add(last_pc_function)
    candidate_names.update(bundle.get("program_context", {}).get("anchor_function_names", [])[:16])

    scored = []
    for fn in sorted(candidate_names):
        f = functions_by_name.get(fn) or {}
        loop = loop_by_fn.get(fn, {})
        evidence: List[str] = []

        raw_dynamic_score = 0
        if fn == last_pc_function:
            raw_dynamic_score += 80
            evidence.append("last_pc_in_function")
        repeat_blocks = int(loop.get("repeat_blocks") or 0)
        longest_run = int(loop.get("longest_run") or 0)
        raw_dynamic_score += repeat_blocks
        raw_dynamic_score += 2 * longest_run
        if repeat_blocks:
            evidence.append("dominant_loop_function")

        static_score = int(f.get("anchor_score") or 0)
        helper_noise = bool(COMMON_HELPER_RE.match(fn.lower()))
        target_consistent, target_reasons = _function_target_consistency(fn, f, profile)
        evidence.extend(target_reasons)

        strong_peripheral_signal = bool(
            target_consistent
            or static_score >= 200
            or (f.get("hot_abs_addresses") or [])
            or len(f.get("hot_rel_offsets") or []) >= 2
        )
        if strong_peripheral_signal:
            evidence.append("strong_peripheral_signal")

        dynamic_score = raw_dynamic_score
        if helper_noise:
            penalty = min(260, raw_dynamic_score // 2 + 80)
            if strong_peripheral_signal:
                penalty = min(140, raw_dynamic_score // 3 + 40)
            dynamic_score -= penalty
            evidence.append("dynamic_libc_penalty")

        if fn == last_pc_function and last_pc_function and not target_consistent and profile["target_peripheral"]:
            dynamic_score -= 80
            evidence.append("cross_peripheral_last_pc_penalty")

        target_peripheral_penalty = 0
        if profile["target_peripheral"] and not target_consistent:
            target_peripheral_penalty = 280 if strong_peripheral_signal else 180
            evidence.append("target_peripheral_mismatch")
            evidence.append(f"target_peripheral_penalty={target_peripheral_penalty}")

        static_mmio_bonus = static_offset_bonus(functions_by_name, fn, tail_offset_hexes)
        target_bonus_meta = target_mmio_bonus_by_fn.get(fn, {})
        target_mmio_bonus = int(target_bonus_meta.get("target_mmio_bonus") or 0)
        if not target_consistent:
            target_mmio_bonus = 0
        if target_mmio_bonus:
            evidence.append(f"target_mmio_window_bonus={target_mmio_bonus}")
            if target_bonus_meta.get("target_mmio_addresses"):
                evidence.append(f"target_mmio_addresses={target_bonus_meta['target_mmio_addresses']}")
            if target_bonus_meta.get("target_mmio_offsets"):
                evidence.append(f"target_mmio_offsets={target_bonus_meta['target_mmio_offsets']}")

        mmio_bonus = static_mmio_bonus + target_mmio_bonus
        dynamic_score = max(dynamic_score, 0)
        combined_score = dynamic_score * 2 + static_score + mmio_bonus - target_peripheral_penalty

        if static_score:
            evidence.append(f"static_anchor_score={static_score}")
        if static_mmio_bonus:
            evidence.append(f"tail_mmio_offset_bonus={static_mmio_bonus}")
        if f.get("hot_rel_offsets"):
            evidence.append(f"rel_hot_offsets={f.get('hot_rel_offsets')}")
        if f.get("hot_abs_addresses"):
            evidence.append(f"hot_abs_addresses={f.get('hot_abs_addresses')}")

        scored.append({
            "function": fn,
            "dynamic_score": dynamic_score,
            "raw_dynamic_score": raw_dynamic_score,
            "static_anchor_score": static_score,
            "mmio_bonus": mmio_bonus,
            "combined_score": combined_score,
            "repeat_blocks": repeat_blocks,
            "longest_run": longest_run,
            "common_helper_noise": helper_noise,
            "strong_peripheral_signal": strong_peripheral_signal,
            "target_peripheral_consistent": target_consistent,
            "evidence": evidence,
        })

    scored.sort(key=lambda x: (x["combined_score"], x["dynamic_score"], x["target_peripheral_consistent"], x["static_anchor_score"], x["function"]), reverse=True)
    return scored


def build_stuck_report(bundle: Dict[str, Any], events: List[Dict[str, Any]], trace_meta: Dict[str, Any], seed_path: Optional[str], stop_reason: Optional[str], tail_window: int, baseline_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    functions_by_name, entries_by_addr = build_function_maps(bundle)
    profile = extract_target_profile(bundle)
    events = enrich_trace_events(events, functions_by_name, entries_by_addr)
    baseline_events = enrich_trace_events(baseline_events or [], functions_by_name, entries_by_addr)

    last_event = _last_pc_event(events)
    last_pc = maybe_hex_to_int(last_event.get("pc"))
    last_pc_function = last_event.get("resolved_function") or last_event.get("function")
    if last_pc_function is None:
        last_named = _last_named_event(events)
        last_pc_function = last_named.get("resolved_function") or last_named.get("function")

    loop_metrics = compute_tail_loop_metrics(events, tail_window)
    tail_mmio = collect_tail_mmio(events, tail_window)
    trace_touches = collect_trace_touches(events)
    dynamic_primary_cluster = build_dynamic_primary_cluster(events, tail_window, last_pc_function)
    candidate_scores = build_candidate_scores(bundle, events, tail_window, last_pc_function)

    target_preferred_top = None
    for cand in candidate_scores:
        if cand.get("target_peripheral_consistent"):
            target_preferred_top = cand
            break

    likely_blocking_offsets: List[str] = []
    likely_blocking_registers: List[Dict[str, Any]] = []
    focus_fn = target_preferred_top["function"] if target_preferred_top else (candidate_scores[0]["function"] if candidate_scores else None)
    if focus_fn:
        f = functions_by_name.get(focus_fn) or {}
        likely_blocking_offsets = list(f.get("hot_rel_offsets") or [])
        matched_regs = bundle.get("document_context", {}).get("matched_peripheral_registers", []) or []
        offset_set = {str(x).upper() for x in likely_blocking_offsets}
        hot_mmio_set = {str(x).upper() for x in (f.get("hot_abs_addresses") or [])}
        for doc in matched_regs:
            reg = doc.get("register") or {}
            abs_hex = str(reg.get("absoluteAddress_hex") or "").upper().strip()
            off_hex = str(reg.get("addressOffset_hex") or "").upper().strip()
            if (abs_hex and abs_hex in hot_mmio_set) or (off_hex and off_hex in offset_set):
                likely_blocking_registers.append({
                    "peripheral": doc.get("peripheral"),
                    "register": reg.get("name"),
                    "absoluteAddress_hex": abs_hex or None,
                    "addressOffset_hex": off_hex or None,
                })

    target_touched_registers = collect_target_touched_registers(bundle, trace_touches, profile)
    divergence = first_divergence(events, baseline_events) if baseline_events else None

    still_ambiguous = False
    if not candidate_scores:
        still_ambiguous = True
    else:
        top = candidate_scores[0]
        second = candidate_scores[1] if len(candidate_scores) > 1 else None
        if second and (top["combined_score"] - second["combined_score"] < 30):
            still_ambiguous = True
        if not top.get("target_peripheral_consistent"):
            still_ambiguous = True
        if top.get("raw_dynamic_score", 0) == 0 and top.get("mmio_bonus", 0) == 0:
            still_ambiguous = True
        if target_preferred_top and target_preferred_top is not top and (top["combined_score"] - target_preferred_top["combined_score"] < 120):
            still_ambiguous = True

    selected_exec = trace_meta.get("selected_exec") if isinstance(trace_meta, dict) else None
    return {
        "schema": "stuck_report_v6",
        "seed_path": seed_path,
        "target_peripheral": profile["target_peripheral"],
        "target_abs_addrs": sorted(profile["target_abs_addrs"]),
        "target_rel_offsets": sorted(profile["target_rel_offsets"]),
        "target_aliases": sorted(profile["target_aliases"]),
        "stop_reason": stop_reason or trace_meta.get("stop_reason") or trace_meta.get("reason") or "unknown",
        "trace_event_count": len(events),
        "tail_window": tail_window,
        "selected_exec_index": selected_exec.get("exec_index") if isinstance(selected_exec, dict) else None,
        "last_pc": hex_norm(last_pc) if last_pc is not None else None,
        "last_pc_function": last_pc_function,
        "dominant_loop_functions": loop_metrics["dominant_loop_functions"],
        "dominant_loop_blocks": loop_metrics["dominant_loop_blocks"],
        "tail_mmio": tail_mmio,
        "trace_touches": trace_touches,
        "dynamic_primary_cluster": dynamic_primary_cluster,
        "candidate_stuck_functions": candidate_scores[:12],
        "likely_blocking_offsets": likely_blocking_offsets,
        "likely_blocking_registers": likely_blocking_registers,
        "target_touched_registers": target_touched_registers,
        "trace_divergence": divergence,
        "still_ambiguous": still_ambiguous,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract-bundle", required=True, type=Path)
    ap.add_argument("--trace-json", type=Path, default=None)
    ap.add_argument("--trace-text", type=Path, default=None)
    ap.add_argument("--baseline-trace-json", type=Path, default=None)
    ap.add_argument("--seed-path", default=None)
    ap.add_argument("--stop-reason", default=None)
    ap.add_argument("--tail-window", type=int, default=256)
    ap.add_argument("--use-recent-exec", default=None, help="Use latest_exec or an index from recent_execs (e.g. latest, 0, 1, ...)")
    ap.add_argument("--baseline-use-recent-exec", default=None)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    bundle = load_bundle(args.contract_bundle)
    trace_events, trace_meta = parse_trace_json(args.trace_json, args.use_recent_exec)
    if not trace_events and args.trace_text is not None:
        trace_events = parse_trace_text(args.trace_text)
    baseline_events, _ = parse_trace_json(args.baseline_trace_json, args.baseline_use_recent_exec)

    report = build_stuck_report(
        bundle=bundle,
        events=trace_events,
        trace_meta=trace_meta,
        seed_path=args.seed_path,
        stop_reason=args.stop_reason,
        tail_window=args.tail_window,
        baseline_events=baseline_events,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(json.dumps({
        "out": str(args.out),
        "selected_exec_index": report.get("selected_exec_index"),
        "last_pc": report.get("last_pc"),
        "last_pc_function": report.get("last_pc_function"),
        "candidate_count": len(report.get("candidate_stuck_functions", [])),
        "top_candidates": report.get("candidate_stuck_functions", [])[:5],
        "still_ambiguous": report.get("still_ambiguous"),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
