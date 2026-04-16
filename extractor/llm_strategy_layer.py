
from __future__ import annotations

import copy
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from debug_trace import info, load_json, save_json, save_text, warn
from strategy_planner import normalize_llm_plan


def _ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def _read_json(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = load_json(str(p))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _walk(obj: Any):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for it in obj:
            yield from _walk(it)


def _parse_int_auto(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return int(v)
    s = str(v).strip().replace("_", "")
    if not s:
        return None
    try:
        return int(s, 0)
    except Exception:
        try:
            return int(s, 16)
        except Exception:
            return None


def _normalize_hex(v: Any) -> Optional[str]:
    i = _parse_int_auto(v)
    if i is None:
        return None
    return f"0x{i:08X}"


def _read_json_path_safe(path: Optional[str]) -> Any:
    if not path:
        return None
    try:
        p = Path(path)
        if not p.exists():
            return None
        return json.loads(p.read_text())
    except Exception:
        try:
            return load_json(str(path))
        except Exception:
            return None


def _register_role(name: Any) -> str:
    n = str(name or "").upper()
    if n in {"S1", "S2", "SR", "ISR", "STAT", "STATUS"} or n.startswith("S"):
        return "status"
    if n in {"C1", "C2", "C3", "C4", "C5", "CR", "CR1", "CR2", "CTRL", "CONTROL"} or n.startswith("C"):
        return "control"
    if n in {"D", "DR", "RDR", "TDR", "DATA"}:
        return "data"
    if "FIFO" in n:
        return "fifo"
    if "BD" in n or "BR" in n or "BAUD" in n:
        return "baud"
    return "other"


def _ready_like(field_name: str) -> bool:
    n = str(field_name or "").upper()
    keywords = [
        "READY", "RDRF", "TDRE", "TC", "RX", "TX", "COUNT", "WATER", "EMPTY",
        "FULL", "EMPT", "UF", "OF", "IDLE",
    ]
    return any(k in n for k in keywords)


def _build_field_candidates(fields: List[Dict[str, Any]], role: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in fields or []:
        name = str(f.get("name") or f.get("field") or "").strip()
        if not name:
            continue
        bit_offset = _parse_int_auto(f.get("bitOffset") or f.get("bit_offset"))
        bit_width = _parse_int_auto(f.get("bitWidth") or f.get("bit_width")) or 1
        if bit_offset is None:
            bits = f.get("bits")
            if isinstance(bits, list) and bits:
                bit_list = [int(x) for x in bits]
            else:
                continue
        else:
            bit_list = list(range(bit_offset, bit_offset + bit_width))
        tags = []
        if role == "status":
            tags.append("status_register")
        elif role == "control":
            tags.append("control_register")
        elif role == "data":
            tags.append("data_register")
        elif role == "fifo":
            tags.append("fifo_register")
        else:
            tags.append("register")
        if _ready_like(name):
            tags.append("ready_like")
        out.append({
            "field": name,
            "bits": bit_list,
            "score": 0.8,
            "tags": tags,
        })
    return out


def _generic_field_candidates_for_register(reg: str, width_bytes: Any, role: str) -> List[Dict[str, Any]]:
    width = _parse_int_auto(width_bytes) or 1
    bit_max = max(1, width * 8)
    return [{
        "field": f"{reg}_BITS",
        "bits": list(range(bit_max)),
        "score": 0.3,
        "tags": [f"{role}_register" if role != "other" else "register", "generic_fallback"],
    }]


def _extract_evidence_items(evidence_pack: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not evidence_pack:
        return []
    for key in ("evidence", "top_items", "items"):
        items = evidence_pack.get(key)
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def _primary_from_evidence(evidence_pack: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    items = _extract_evidence_items(evidence_pack)
    if not items:
        return {}
    item = items[0]
    svd = item.get("svd_resolution") or item.get("resolved") or {}
    pdf = item.get("pdf_evidence") or {}
    width_bits = _parse_int_auto(svd.get("width_bits"))
    return {
        "addr": _normalize_hex(
            svd.get("register_address_hex")
            or svd.get("register_address")
            or svd.get("absoluteAddress_hex")
            or svd.get("absolute_address_hex")
            or item.get("addr")
        ),
        "instance": svd.get("instance") or pdf.get("resolved_instance") or "",
        "family": svd.get("family") or pdf.get("resolved_family") or "",
        "register": svd.get("register") or svd.get("register_name") or pdf.get("register") or "",
        "base": _normalize_hex(svd.get("base_address_hex") or svd.get("base_address")),
        "width": svd.get("width_bytes") or (max(1, width_bits // 8) if width_bits else 1),
        "access": svd.get("access") or svd.get("svd_access"),
        "artifact_paths": pdf.get("artifact_paths") or {},
        "pdf_snippets": (pdf.get("source_page_snippets") or []) + (pdf.get("nearby_page_snippets") or []),
    }


def _dedup_registers(regs: List[Dict[str, Any]], limit: int = 16) -> List[Dict[str, Any]]:
    role_priority = {"status": 0, "control": 1, "data": 2, "fifo": 3, "baud": 4, "other": 9}
    cleaned: List[Dict[str, Any]] = []
    seen = set()
    for r in regs:
        addr = _normalize_hex(r.get("addr") or r.get("address") or r.get("absoluteAddress_hex"))
        reg = str(r.get("register") or r.get("name") or r.get("register_name") or "").split(".")[-1]
        if not addr or not reg:
            continue
        rr = dict(r)
        rr["addr"] = addr
        rr["register"] = reg
        rr.setdefault("role", _register_role(reg))
        rr.setdefault("field_candidates", [])
        key = (addr, reg.upper())
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(rr)
    cleaned.sort(key=lambda x: (
        role_priority.get(str(x.get("role") or "other"), 9),
        _parse_int_auto(x.get("addr")) or 0xFFFFFFFF,
    ))
    return cleaned[:limit]


def _collect_registers_from_mmio_map(mmio_map_path: Optional[str], primary_instance: str, primary_base: Optional[str]) -> List[Dict[str, Any]]:
    data = _read_json_path_safe(mmio_map_path)
    if data is None:
        return []
    base_i = _parse_int_auto(primary_base)
    regs: List[Dict[str, Any]] = []
    for node in _walk(data):
        addr = _normalize_hex(
            node.get("absoluteAddress_hex")
            or node.get("absolute_address_hex")
            or node.get("register_address_hex")
            or node.get("addr")
            or node.get("address")
        )
        if not addr:
            continue
        addr_i = _parse_int_auto(addr)
        if base_i is not None and addr_i is not None and not (base_i <= addr_i < base_i + 0x100):
            continue
        inst = str(node.get("instance") or node.get("peripheral") or node.get("peripheral_name") or primary_instance or "")
        if primary_instance and inst and primary_instance.upper() not in inst.upper() and inst.upper() not in primary_instance.upper():
            continue
        reg = str(node.get("register") or node.get("name") or node.get("register_name") or "").split(".")[-1]
        if not reg:
            continue
        width = node.get("width_bytes")
        if width is None:
            bits = _parse_int_auto(node.get("width") or node.get("size") or node.get("width_bits"))
            width = max(1, bits // 8) if bits else 1
        role = _register_role(reg)
        fields = node.get("fields") or []
        regs.append({
            "addr": addr,
            "instance": primary_instance or inst,
            "register": reg,
            "width": width,
            "access": node.get("access") or node.get("svd_access"),
            "role": role,
            "field_candidates": _build_field_candidates(fields, role) if fields else [],
            "source": "mmio_map",
        })
    return regs


def _collect_registers_from_register_merged(register_merged_path: Optional[str], primary_instance: str, primary_base: Optional[str]) -> List[Dict[str, Any]]:
    data = _read_json_path_safe(register_merged_path)
    if data is None:
        return []
    base_i = _parse_int_auto(primary_base)
    regs: List[Dict[str, Any]] = []
    for node in _walk(data):
        addr = _normalize_hex(
            node.get("absoluteAddress_hex")
            or node.get("absolute_address_hex")
            or node.get("register_address_hex")
            or node.get("addr")
            or node.get("address")
        )
        reg = str(node.get("name") or node.get("register") or node.get("register_name") or "").split(".")[-1]
        if not addr or not reg:
            continue
        addr_i = _parse_int_auto(addr)
        if base_i is not None and addr_i is not None and not (base_i <= addr_i < base_i + 0x100):
            continue
        role = _register_role(reg)
        width = node.get("size")
        if width is not None:
            width = max(1, (_parse_int_auto(width) or 8) // 8)
        else:
            width = 1
        regs.append({
            "addr": addr,
            "instance": primary_instance,
            "register": reg,
            "width": width,
            "access": node.get("svd_access") or node.get("access"),
            "role": role,
            "field_candidates": _build_field_candidates(node.get("fields") or [], role),
            "source": "register_merged",
        })
    return regs


def _collect_registers_from_pdf_snippets(snippets: List[Any], primary_instance: str, primary_base: Optional[str]) -> List[Dict[str, Any]]:
    if not primary_instance:
        return []
    regs: List[Dict[str, Any]] = []
    inst_re = re.escape(primary_instance)
    pat = re.compile(
        r"(?P<addr>[0-9A-Fa-f]{4}_[0-9A-Fa-f]{4})\s+"
        r"(?P<label>[A-Za-z0-9]+).*?"
        r"\((?P<full>" + inst_re + r"_(?P<reg>[A-Za-z0-9_]+))\)\s+"
        r"(?P<width>\d+)\s+"
        r"(?P<access>R/W|R|W)",
        re.M,
    )
    base_i = _parse_int_auto(primary_base)
    for snip in snippets or []:
        text = snip.get("text") if isinstance(snip, dict) else str(snip)
        for m in pat.finditer(text or ""):
            addr = _normalize_hex("0x" + m.group("addr").replace("_", ""))
            addr_i = _parse_int_auto(addr)
            if base_i is not None and addr_i is not None and not (base_i <= addr_i < base_i + 0x100):
                continue
            reg = m.group("reg")
            width_bits = _parse_int_auto(m.group("width")) or 8
            role = _register_role(reg)
            regs.append({
                "addr": addr,
                "instance": primary_instance,
                "register": reg,
                "width": max(1, width_bits // 8),
                "access": m.group("access"),
                "role": role,
                "field_candidates": [],
                "source": "pdf_memory_map",
            })
    return regs


def _merge_register_records(regs: List[Dict[str, Any]], limit: int = 16) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    source_priority = {"register_merged": 0, "mmio_map": 1, "task_context": 2, "pdf_memory_map": 3, "primary_hotspot": 4}
    for r in regs:
        addr = _normalize_hex(r.get("addr"))
        reg = str(r.get("register") or "").strip()
        if not addr or not reg:
            continue
        key = f"{addr}|{reg.upper()}"
        cur = merged.get(key)
        if cur is None:
            merged[key] = dict(r)
            continue
        for field in ("instance", "access", "width", "role"):
            if not cur.get(field) and r.get(field):
                cur[field] = r.get(field)
        if not cur.get("field_candidates") and r.get("field_candidates"):
            cur["field_candidates"] = r.get("field_candidates")
        cur_src = source_priority.get(str(cur.get("source") or ""), 99)
        new_src = source_priority.get(str(r.get("source") or ""), 99)
        if new_src < cur_src:
            cur["source"] = r.get("source")
    out = _dedup_registers(list(merged.values()), limit=limit)
    for r in out:
        if not r.get("field_candidates"):
            r["field_candidates"] = _generic_field_candidates_for_register(
                r.get("register"),
                r.get("width"),
                r.get("role"),
            )
    return out[:limit]


def _extract_primary_hotspot(task_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    runtime = task_context.get("runtime_problem") or {}
    hs = runtime.get("hotspots_summary") or []
    if isinstance(hs, list) and hs:
        first = hs[0]
        if isinstance(first, dict):
            out = dict(first)
            out.setdefault("instance", first.get("resolved_instance"))
            out.setdefault("register", first.get("resolved_register"))
            return out
    groups = runtime.get("hotspot_groups") or []
    if isinstance(groups, list) and groups:
        first = groups[0]
        if isinstance(first, dict):
            anchor = first.get("anchor") or {}
            out = dict(first)
            out.setdefault("addr", anchor.get("addr"))
            out.setdefault("instance", first.get("instance") or anchor.get("instance"))
            out.setdefault("register", anchor.get("register"))
            out.setdefault("kind", first.get("kind"))
            out.setdefault("read_count", anchor.get("read_count"))
            out.setdefault("width", anchor.get("width_bytes"))
            return out
    return None


def _extract_hotspot_register_cluster(task_context: Dict[str, Any], evidence_pack: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the set of addresses the LLM is allowed to use.

    The strategy layer should not be trapped at the primary status register.
    It expands the allowed set to same-peripheral registers using cached PDF/SVD
    artifacts and memory-map snippets, while still enforcing an address whitelist.
    """
    primary = _extract_primary_hotspot(task_context) or {}
    ev_primary = _primary_from_evidence(evidence_pack)

    primary_addr = (
        _normalize_hex(primary.get("addr") or primary.get("address_hex") or primary.get("anchor_addr"))
        or ev_primary.get("addr")
    )
    primary_instance = str(
        primary.get("instance")
        or primary.get("resolved_instance")
        or ev_primary.get("instance")
        or ""
    ).strip()
    primary_register = str(
        primary.get("register")
        or primary.get("resolved_register")
        or primary.get("anchor_register")
        or ev_primary.get("register")
        or ""
    ).strip()
    primary_base = ev_primary.get("base")

    regs: List[Dict[str, Any]] = []
    artifact_paths = ev_primary.get("artifact_paths") or {}
    regs.extend(_collect_registers_from_register_merged(artifact_paths.get("register_merged"), primary_instance, primary_base))
    regs.extend(_collect_registers_from_mmio_map(artifact_paths.get("mmio_map"), primary_instance, primary_base))
    regs.extend(_collect_registers_from_pdf_snippets(ev_primary.get("pdf_snippets") or [], primary_instance, primary_base))

    for node in _walk(task_context):
        addr = _normalize_hex(
            node.get("addr")
            or node.get("address_hex")
            or node.get("absolute_addr_hex")
            or node.get("absoluteAddress_hex")
        )
        reg = str(node.get("register") or node.get("register_name") or node.get("name") or "").strip()
        inst = str(node.get("instance") or node.get("peripheral") or "").strip()
        if not addr or not reg:
            continue
        same_primary = primary_addr and addr == primary_addr
        same_instance = primary_instance and inst and inst.upper() == primary_instance.upper()
        if not same_primary and not same_instance:
            continue
        role = _register_role(reg)
        regs.append({
            "addr": addr,
            "register": reg,
            "instance": inst or primary_instance,
            "width": int(node.get("width_bytes") or node.get("width") or 1),
            "access": node.get("access") or node.get("svd_access"),
            "role": role,
            "kind": node.get("kind"),
            "field_candidates": node.get("field_candidates") or [],
            "source": "task_context",
        })

    if primary_addr:
        regs.append({
            "addr": primary_addr,
            "instance": primary_instance,
            "register": primary_register,
            "width": ev_primary.get("width") or primary.get("width") or primary.get("width_bytes") or 1,
            "access": ev_primary.get("access") or "read-only",
            "role": _register_role(primary_register),
            "field_candidates": primary.get("field_candidates") or [],
            "source": "primary_hotspot",
        })

    regs = _merge_register_records(regs, limit=16)

    if primary_addr:
        primary_regs = [r for r in regs if _normalize_hex(r.get("addr")) == primary_addr]
        other_regs = [r for r in regs if _normalize_hex(r.get("addr")) != primary_addr]
        regs = primary_regs[:1] + other_regs

    return {
        "primary_addr": primary_addr,
        "primary_instance": primary_instance,
        "primary_register": primary_register,
        "primary_base": primary_base,
        "registers": regs[:16],
    }


def _build_prompt_payload(task_context: Dict[str, Any], evidence_pack: Optional[Dict[str, Any]], max_candidates: int) -> Dict[str, Any]:
    primary = _extract_primary_hotspot(task_context) or {}
    cluster = _extract_hotspot_register_cluster(task_context, evidence_pack)
    runtime = task_context.get("runtime_problem") or {}
    schema = {
        "top_level_key": "candidates",
        "candidate_fields": ["id", "group_id", "template_id", "rationale", "actions"],
        "supported_action_types": [
            "mmio_read_override_once",
            "mmio_read_override_repeat",
            "mmio_read_sequence",
            "mmio_bit_update",
            "mmio_write_observe",
            "mmio_write_then_read_gate",
            "uart_handshake_once",
        ],
        "supported_trigger_kinds": [
            "after_global_reads",
            "on_first_touch",
            "on_nth_touch",
            "after_write",
            "after_write_value",
            "when_stage_active",
        ],
        "requirements": [
            "Use only addresses from allowed_register_cluster.",
            "Prefer state-advancing strategies over pure read shaping.",
            "At least two candidates should use more than one register if multiple allowed registers exist.",
            "Prefer one control/status gating candidate, one status/data pairing candidate, and one write-followed-by-read candidate when supported by allowed registers.",
            "Avoid returning only repeated reads of the primary status register.",
            "Return 1 to max_candidates candidates.",
            "Keep candidate IDs stable and descriptive.",
            "Do not return prose outside JSON.",
        ],
    }
    return {
        "task": "Generate generic MMIO runtime strategy candidates that can advance execution beyond the current primary hotspot.",
        "max_candidates": int(max_candidates),
        "primary_hotspot": {
            "addr": cluster.get("primary_addr") or _normalize_hex(primary.get("addr") or primary.get("address_hex") or primary.get("anchor_addr")),
            "instance": cluster.get("primary_instance") or primary.get("instance") or primary.get("resolved_instance") or primary.get("peripheral"),
            "register": cluster.get("primary_register") or primary.get("register") or primary.get("resolved_register") or primary.get("anchor_register"),
            "kind": primary.get("kind"),
            "read_count": primary.get("read_count"),
            "width": primary.get("width") or primary.get("width_bytes"),
        },
        "allowed_register_cluster": cluster,
        "runtime_problem": {
            "hotspots_summary": runtime.get("hotspots_summary") or [],
            "hotspot_groups": runtime.get("hotspot_groups") or [],
            "best_known_strategy": task_context.get("best_known_strategy") or {},
        },
        "previous_failure_summary": {
            "heuristic_candidates": [
                "ready_bit_set_touch1",
                "ready_bit_set_touch2",
                "busy_bit_clear_touch2",
                "ready_bit_set_after_reads",
            ],
            "observed_problem": (
                "Prior heuristic strategies mostly performed read-only status shaping. "
                "In the 100-window long-horizon run, the primary hotspot stayed at the same "
                "status register in most windows. New candidates should prefer cross-register "
                "state advancement such as control/status gating, status/data pairing, or "
                "write-followed-by-read effects."
            ),
        },
        "evidence": {
            "top_items": _extract_evidence_items(evidence_pack)[:6],
        },
        "output_schema": schema,
    }


def build_llm_strategy_prompt(*, task_context_path: str, evidence_pack_path: Optional[str], out_dir: str, max_candidates: int = 4) -> Dict[str, Any]:
    task_context = load_json(task_context_path)
    evidence_pack = _read_json(evidence_pack_path)
    payload = _build_prompt_payload(task_context, evidence_pack, max_candidates=max_candidates)
    _ensure_dir(out_dir)

    prompt_text = (
        "You are generating executable MMIO fuzzing strategies in strict JSON.\n"
        "Focus on the current primary hotspot and nearby same-peripheral registers.\n"
        "Prefer strategies that can advance state, such as status/data pairing, enable-then-ready gating, or write-followed-by-read effects.\n"
        "Only use allowed addresses and supported action/trigger kinds.\n"
        "Return JSON only, with top-level key 'candidates'.\n\n"
        + json.dumps(payload, indent=2, ensure_ascii=False)
    )

    save_json(str(Path(out_dir) / "llm_strategy_prompt.json"), payload)
    save_text(str(Path(out_dir) / "llm_strategy_prompt.txt"), prompt_text)
    return {"payload": payload, "prompt_text": prompt_text}


def _extract_text_from_response(obj: Dict[str, Any]) -> str:
    if isinstance(obj.get("output_text"), str) and obj.get("output_text").strip():
        return obj["output_text"]
    texts: List[str] = []
    for item in obj.get("output") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "message":
            for c in item.get("content") or []:
                if isinstance(c, dict):
                    if c.get("type") in {"output_text", "text"} and c.get("text"):
                        texts.append(str(c["text"]))
                    elif c.get("type") == "input_text" and c.get("text"):
                        texts.append(str(c["text"]))
    return "\n".join(t for t in texts if t)


def _extract_json_candidate(text: str) -> Dict[str, Any]:
    s = text.strip()
    if not s:
        raise ValueError("empty LLM response text")
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", s, flags=re.S)
    if fence:
        return json.loads(fence.group(1))
    try:
        return json.loads(s)
    except Exception:
        pass
    start = s.find("{")
    end = s.rfind("}")
    if start >= 0 and end > start:
        return json.loads(s[start:end + 1])
    raise ValueError("could not locate JSON object in LLM response")


def _call_openai_responses_api(*, prompt_text: str, model: Optional[str], max_output_tokens: int, reasoning_effort: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    body: Dict[str, Any] = {
        "model": model or os.environ.get("OPENAI_MODEL") or "gpt-5.4",
        "input": prompt_text,
        "max_output_tokens": int(max_output_tokens),
    }
    eff = str(reasoning_effort or "none").strip().lower()
    if eff and eff != "none":
        body["reasoning"] = {"effort": eff}
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {e.code}: {detail}") from e


def _normalize_action_addresses(action: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(action)
    for key in ("addr", "write_addr", "read_addr"):
        if key in out:
            out[key] = _normalize_hex(out.get(key))
    trig = out.get("trigger")
    if isinstance(trig, dict):
        trig = dict(trig)
        if "addr" in trig:
            trig["addr"] = _normalize_hex(trig.get("addr"))
        if not trig.get("addr"):
            if out.get("write_addr"):
                trig["addr"] = out.get("write_addr")
            elif out.get("addr"):
                trig["addr"] = out.get("addr")
            elif out.get("read_addr"):
                trig["addr"] = out.get("read_addr")
        out["trigger"] = trig
    return out



def _candidate_ids(plan: Dict[str, Any]) -> List[str]:
    ids: List[str] = []
    for cand in plan.get("candidates") or []:
        if isinstance(cand, dict) and cand.get("id"):
            ids.append(str(cand.get("id")))
    return ids


def _cluster_allowed_bits(cluster: Dict[str, Any]) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    for reg in cluster.get("registers") or []:
        if not isinstance(reg, dict):
            continue
        addr = _normalize_hex(reg.get("addr"))
        if not addr:
            continue
        bits = set()
        for fc in reg.get("field_candidates") or []:
            if not isinstance(fc, dict):
                continue
            for b in fc.get("bits") or []:
                bi = _parse_int_auto(b)
                if bi is not None:
                    bits.add(bi)
        out[addr] = sorted(bits)
    return out


def _cluster_widths(cluster: Dict[str, Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for reg in cluster.get("registers") or []:
        if not isinstance(reg, dict):
            continue
        addr = _normalize_hex(reg.get("addr"))
        if not addr:
            continue
        out[addr] = max(1, _parse_int_auto(reg.get("width")) or 1)
    return out


def _full_mask_hex(width_bytes: int) -> str:
    width_bytes = max(1, min(int(width_bytes or 1), 8))
    return f"0x{((1 << (width_bytes * 8)) - 1):X}"


def _normalize_value_hex(v: Any, width_bytes: int = 1) -> Optional[str]:
    i = _parse_int_auto(v)
    if i is None:
        return None
    width_bytes = max(1, min(int(width_bytes or 1), 8))
    return f"0x{i:0{width_bytes * 2}X}"


def _action_width_for(action: Dict[str, Any], widths: Dict[str, int]) -> int:
    for key in ("addr", "write_addr", "read_addr", "status_addr", "s1_addr", "data_addr", "d_addr"):
        addr = _normalize_hex(action.get(key))
        if addr and addr in widths:
            return int(widths[addr])
    return 1


def _cluster_register_map(cluster: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for reg in cluster.get("registers") or []:
        if not isinstance(reg, dict):
            continue
        addr = _normalize_hex(reg.get("addr"))
        if not addr:
            continue
        out[addr] = reg
    return out


def _default_read_value_for_addr(addr: Any, width_bytes: int, cluster_regs: Dict[str, Dict[str, Any]]) -> str:
    a = _normalize_hex(addr)
    width_bytes = max(1, int(width_bytes or 1))
    reg = cluster_regs.get(a or "", {})
    role = str(reg.get("role") or "")
    fcs = reg.get("field_candidates") or []

    bits = []
    for fc in fcs:
        if not isinstance(fc, dict):
            continue
        tags = [str(t) for t in (fc.get("tags") or [])]
        if "ready_like" in tags or role == "data":
            for b in fc.get("bits") or []:
                bi = _parse_int_auto(b)
                if bi is not None and bi not in bits:
                    bits.append(int(bi))
    if bits:
        value = 0
        for b in bits:
            value |= (1 << b)
        return _normalize_value_hex(value, width_bytes) or _full_mask_hex(width_bytes)

    if role == "data":
        return _normalize_value_hex(0x41, width_bytes) or "0x41"

    return _full_mask_hex(width_bytes)


def _expand_repeat_override(action: Dict[str, Any], widths: Dict[str, int], cluster_regs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    addr = _normalize_hex(action.get("addr"))
    width = widths.get(addr or "", _action_width_for(action, widths))
    value = action.get("value")
    if value is None:
        value = _default_read_value_for_addr(addr, width, cluster_regs)
    value_hex = _normalize_value_hex(value, width) or _default_read_value_for_addr(addr, width, cluster_regs)
    count = int(_parse_int_auto(action.get("count") or action.get("repeat") or action.get("n") or 1) or 1)
    count = max(1, min(count, 32))
    out = dict(action)
    out["type"] = "mmio_read_sequence"
    out["addr"] = addr
    out["width"] = width
    out["values"] = [value_hex] * count
    out["repeat"] = count
    out.pop("value", None)
    out.pop("count", None)
    return out


def _inject_action_widths(action: Dict[str, Any], widths: Dict[str, int], cluster_regs: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    out = dict(action)
    kind = str(out.get("type") or "")
    width = _action_width_for(out, widths)
    cluster_regs = cluster_regs or {}

    if kind in {
        "mmio_bit_update",
        "mmio_read_override_once",
        "mmio_read_override_repeat",
        "mmio_read_sequence",
        "mmio_write_observe",
        "mmio_write_then_read_gate",
    }:
        out.setdefault("width", width)

    if kind == "mmio_write_observe":
        if out.get("value") is not None:
            hv = _normalize_value_hex(out.get("value"), width)
            if hv is not None:
                out["value"] = hv

    if kind == "mmio_write_then_read_gate":
        waddr = _normalize_hex(out.get("write_addr"))
        raddr = _normalize_hex(out.get("read_addr"))
        wwidth = widths.get(waddr, width) if waddr else width
        rwidth = widths.get(raddr, width) if raddr else width
        out.setdefault("write_mask", _full_mask_hex(wwidth))
        out.setdefault("read_mask", _full_mask_hex(rwidth))
        if out.get("write_value") is None:
            out["write_value"] = _normalize_value_hex(0, wwidth)
        else:
            out["write_value"] = _normalize_value_hex(out.get("write_value"), wwidth)
        if out.get("read_value") is None:
            out["read_value"] = _default_read_value_for_addr(raddr, rwidth, cluster_regs)
        else:
            out["read_value"] = _normalize_value_hex(out.get("read_value"), rwidth)
        if out.get("read_mask") is not None:
            out["read_mask"] = _normalize_value_hex(out.get("read_mask"), rwidth)
        if out.get("match_mask") is not None:
            out["match_mask"] = _normalize_value_hex(out.get("match_mask"), wwidth)
        if out.get("match_value") is not None:
            out["match_value"] = _normalize_value_hex(out.get("match_value"), wwidth)
        if out.get("count") is None and out.get("read_count") is not None:
            out["count"] = int(_parse_int_auto(out.get("read_count")) or 0)

    if kind in {"mmio_read_override_once", "mmio_read_override_repeat"}:
        if out.get("value") is None:
            out["value"] = _default_read_value_for_addr(out.get("addr"), width, cluster_regs)
        else:
            hv = _normalize_value_hex(out.get("value"), width)
            if hv is not None:
                out["value"] = hv
        if kind == "mmio_read_override_repeat":
            repeat = int(_parse_int_auto(out.get("repeat") or out.get("count") or 1) or 1)
            out["repeat"] = max(1, repeat)

    if kind == "mmio_read_sequence":
        vals = []
        for v in out.get("values") or []:
            hv = _normalize_value_hex(v, width)
            if hv is not None:
                vals.append(hv)
        out["values"] = vals

    if kind == "uart_handshake_once":
        swidth = widths.get(_normalize_hex(out.get("status_addr") or out.get("s1_addr")) or "", 1)
        dwidth = widths.get(_normalize_hex(out.get("data_addr") or out.get("d_addr")) or "", 1)
        out.setdefault("status_width", swidth)
        out.setdefault("data_width", dwidth)
        if out.get("status_value") is not None:
            out["status_value"] = _normalize_value_hex(out.get("status_value"), swidth)
        if out.get("status_mask") is not None:
            out["status_mask"] = _normalize_value_hex(out.get("status_mask"), swidth)
        if out.get("data_value") is not None:
            out["data_value"] = _normalize_value_hex(out.get("data_value"), dwidth)
    return out


def _canonicalize_trigger(trigger: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
    trig = dict(trigger or {})
    kind = str(trig.get("kind") or "")

    primary_addr = (
        action.get("write_addr")
        or action.get("addr")
        or action.get("read_addr")
        or action.get("status_addr")
        or action.get("s1_addr")
        or action.get("data_addr")
        or action.get("d_addr")
    )
    if primary_addr:
        primary_addr = _normalize_hex(primary_addr)

    if kind in {"on_first_touch", "on_nth_touch", "after_write", "after_write_value"}:
        trig.setdefault("addr", primary_addr)

    if kind == "after_global_reads":
        if "value" not in trig:
            if "count" in trig:
                trig["value"] = int(_parse_int_auto(trig.get("count")) or 0)
            elif "n" in trig:
                trig["value"] = int(_parse_int_auto(trig.get("n")) or 0)
        trig.pop("count", None)
        trig.pop("n", None)
        trig.setdefault("addr", primary_addr)

    if trig.get("addr"):
        trig["addr"] = _normalize_hex(trig.get("addr"))
    return trig


def _expand_uart_handshake_action(action: Dict[str, Any]) -> List[Dict[str, Any]]:
    status_addr = _normalize_hex(action.get("status_addr") or action.get("s1_addr"))
    data_addr = _normalize_hex(action.get("data_addr") or action.get("d_addr"))
    if not status_addr or not data_addr:
        return []

    trigger = action.get("trigger") if isinstance(action.get("trigger"), dict) else {}
    trigger = _canonicalize_trigger(trigger, {"addr": status_addr})

    status_value = action.get("status_value")
    if status_value is None:
        status_value = action.get("s1_value")
    if status_value is None:
        status_value = "0x20"

    data_value = action.get("data_value")
    if data_value is None:
        db = action.get("data_bytes") or []
        if db:
            data_value = db[0]
    if data_value is None:
        data_value = "0x41"

    d_count = int(_parse_int_auto(action.get("d_window_accesses")) or 4)

    return [
        {
            "type": "mmio_read_sequence",
            "addr": status_addr,
            "trigger": trigger,
            "values": [_normalize_value_hex(status_value, 1) or "0x20"] * max(1, min(d_count, 16)),
            "activate_stage": "__auto_stage__",
        },
        {
            "type": "mmio_read_override_once",
            "addr": data_addr,
            "trigger": {"kind": "when_stage_active"},
            "value": data_value,
        },
    ]


def _lint_candidates(plan: Dict[str, Any], cluster: Dict[str, Any]) -> Dict[str, Any]:
    allowed_addrs = {_normalize_hex(r.get("addr")) for r in cluster.get("registers") or [] if isinstance(r, dict)}
    allowed_bits = _cluster_allowed_bits(cluster)
    out: List[Dict[str, Any]] = []
    for cand in plan.get("candidates") or []:
        if not isinstance(cand, dict):
            continue
        issues: List[str] = []
        cid = str(cand.get("id") or cand.get("candidate_id") or "")
        stage_refs = 0
        stage_activations = 0
        action_summaries = []
        for idx, act in enumerate(cand.get("actions") or []):
            if not isinstance(act, dict):
                issues.append(f"action[{idx}] not dict")
                continue
            at = str(act.get("type") or "")
            trig = act.get("trigger") if isinstance(act.get("trigger"), dict) else {}
            if trig.get("kind") == "when_stage_active":
                stage_refs += 1
                if not trig.get("stage"):
                    issues.append(f"action[{idx}] when_stage_active missing stage")
            if act.get("activate_stage"):
                stage_activations += 1
            for key in ("addr", "write_addr", "read_addr"):
                if act.get(key):
                    addr = _normalize_hex(act.get(key))
                    if addr not in allowed_addrs:
                        issues.append(f"action[{idx}] {key} not allowed: {addr}")
            if isinstance(trig, dict) and trig.get("addr"):
                taddr = _normalize_hex(trig.get("addr"))
                if taddr not in allowed_addrs:
                    issues.append(f"action[{idx}] trigger.addr not allowed: {taddr}")
            if at == "mmio_bit_update":
                addr = _normalize_hex(act.get("addr"))
                allowed = set(allowed_bits.get(addr) or [])
                for field_name in ("set_bits", "clear_bits"):
                    for b in act.get(field_name) or []:
                        bi = _parse_int_auto(b)
                        if bi is None:
                            issues.append(f"action[{idx}] invalid bit in {field_name}: {b}")
                        elif allowed and bi not in allowed:
                            issues.append(f"action[{idx}] bit {bi} not allowed for {addr}")
            action_summaries.append({
                "index": idx,
                "type": at,
                "addr": _normalize_hex(act.get("addr")) if act.get("addr") else None,
                "write_addr": _normalize_hex(act.get("write_addr")) if act.get("write_addr") else None,
                "read_addr": _normalize_hex(act.get("read_addr")) if act.get("read_addr") else None,
                "trigger": trig,
                "activate_stage": act.get("activate_stage"),
            })
        if stage_refs and not stage_activations:
            issues.append("candidate has when_stage_active but no activate_stage producer")
        out.append({
            "id": cid,
            "issue_count": len(issues),
            "issues": issues,
            "action_summaries": action_summaries,
        })
    return {"candidates": out}


def _primary_action_addr(action: Dict[str, Any]) -> Optional[str]:
    for key in ("addr", "write_addr", "read_addr", "status_addr", "s1_addr", "data_addr", "d_addr"):
        if action.get(key):
            return _normalize_hex(action.get(key))
    return None


def _make_stage_name(candidate_id: str, idx: int, label: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", str(candidate_id or "cand")).strip("_") or "cand"
    return f"{safe}_{label}_{idx}"



def _expand_gate_to_primitives(
    action: Dict[str, Any],
    *,
    candidate_id: str,
    idx: int,
    widths: Dict[str, int],
    cluster_regs: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    a = dict(action)
    waddr = _normalize_hex(a.get("write_addr"))
    raddr = _normalize_hex(a.get("read_addr"))
    if not waddr or not raddr:
        return [a]

    wwidth = widths.get(waddr, _action_width_for({"addr": waddr}, widths))
    rwidth = widths.get(raddr, _action_width_for({"addr": raddr}, widths))
    stage = _make_stage_name(candidate_id, idx, "write_stage")

    trig = a.get("trigger") if isinstance(a.get("trigger"), dict) else {}
    trig = _canonicalize_trigger(trig, {"addr": waddr, "write_addr": waddr, "read_addr": raddr})
    kind = str(trig.get("kind") or "")
    observe_trigger: Dict[str, Any]
    if kind in {"after_write", "after_write_value", "when_stage_active"}:
        observe_trigger = {"kind": "on_first_touch", "addr": waddr}
    else:
        observe_trigger = dict(trig or {"kind": "on_first_touch", "addr": waddr})
        observe_trigger.setdefault("addr", waddr)

    observe: Dict[str, Any] = {
        "type": "mmio_write_observe",
        "addr": waddr,
        "width": wwidth,
        "trigger": observe_trigger,
        "activate_stage": stage,
    }
    write_value = a.get("write_value")
    if write_value is None:
        write_value = a.get("value")
    if write_value is not None:
        observe["value"] = _normalize_value_hex(write_value, wwidth) or _normalize_value_hex(0, wwidth)

    read_value = a.get("read_value")
    if read_value is None:
        read_value = _default_read_value_for_addr(raddr, rwidth, cluster_regs)
    read_value = _normalize_value_hex(read_value, rwidth) or _default_read_value_for_addr(raddr, rwidth, cluster_regs)
    count = int(_parse_int_auto(a.get("count") or a.get("read_count") or a.get("repeat") or 1) or 1)
    count = max(1, min(count, 32))
    read_seq: Dict[str, Any] = {
        "type": "mmio_read_sequence",
        "addr": raddr,
        "width": rwidth,
        "values": [read_value] * count,
        "repeat": count,
        "trigger": {"kind": "when_stage_active", "stage": stage, "addr": raddr},
    }
    return [observe, read_seq]



def _rewrite_after_write_trigger(
    action: Dict[str, Any],
    *,
    candidate_id: str,
    idx: int,
    widths: Dict[str, int],
) -> List[Dict[str, Any]]:
    a = dict(action)
    trig = a.get("trigger") if isinstance(a.get("trigger"), dict) else {}
    trig = _canonicalize_trigger(trig, a)
    kind = str(trig.get("kind") or "")
    if kind not in {"after_write", "after_write_value"}:
        a["trigger"] = trig
        return [a]

    observed_addr = _normalize_hex(trig.get("addr")) or _primary_action_addr(a)
    if not observed_addr:
        a["trigger"] = trig
        return [a]

    stage = _make_stage_name(candidate_id, idx, "after_write")
    width = widths.get(observed_addr, _action_width_for({"addr": observed_addr}, widths))
    observe: Dict[str, Any] = {
        "type": "mmio_write_observe",
        "addr": observed_addr,
        "width": width,
        "trigger": {"kind": "on_first_touch", "addr": observed_addr},
        "activate_stage": stage,
    }
    if kind == "after_write_value" and trig.get("value") is not None:
        observe["value"] = _normalize_value_hex(trig.get("value"), width) or _normalize_value_hex(0, width)

    a["trigger"] = {"kind": "when_stage_active", "stage": stage, "addr": _primary_action_addr(a) or observed_addr}
    return [observe, a]



def _sanitize_extracted_plan(extracted: Dict[str, Any], cluster: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {_normalize_hex(x.get("addr")) for x in cluster.get("registers") or [] if isinstance(x, dict)}
    allowed_bits = _cluster_allowed_bits(cluster)
    widths = _cluster_widths(cluster)
    cluster_regs = _cluster_register_map(cluster)
    out = {"candidates": []}
    for cand in extracted.get("candidates") or []:
        if not isinstance(cand, dict):
            continue
        c = dict(cand)
        c["id"] = str(c.get("id") or c.get("candidate_id") or "").strip()
        if not c["id"]:
            continue

        actions_seed: List[Dict[str, Any]] = []
        for action in (c.get("actions") or []):
            if not isinstance(action, dict):
                continue
            at = str(action.get("type") or "")
            if at == "uart_handshake_once":
                actions_seed.extend(_expand_uart_handshake_action(action))
            else:
                actions_seed.append(action)

        actions_in = [a for a in actions_seed if isinstance(a, dict)]
        actions: List[Dict[str, Any]] = []
        for idx, act in enumerate(actions_in):
            a = _normalize_action_addresses(act)
            at = str(a.get("type") or "")

            for key in ("addr", "write_addr", "read_addr", "status_addr", "s1_addr", "data_addr", "d_addr"):
                if a.get(key):
                    a[key] = _normalize_hex(a.get(key))

            trig = a.get("trigger") if isinstance(a.get("trigger"), dict) else {}
            trig = _canonicalize_trigger(trig, a)
            a = _inject_action_widths(a, widths, cluster_regs)
            a["trigger"] = trig

            if at == "mmio_bit_update":
                addr = _normalize_hex(a.get("addr"))
                allowed_for_addr = set(allowed_bits.get(addr) or [])
                for field_name in ("set_bits", "clear_bits"):
                    bits = []
                    for b in a.get(field_name) or []:
                        bi = _parse_int_auto(b)
                        if bi is None:
                            continue
                        if allowed_for_addr and bi not in allowed_for_addr:
                            continue
                        bits.append(bi)
                    a[field_name] = sorted(set(bits))
                if not a.get("set_bits") and not a.get("clear_bits"):
                    width = widths.get(addr) or 1
                    a["set_bits"] = [0] if width >= 1 else []

            expanded_actions: List[Dict[str, Any]]
            if str(a.get("type") or "") == "mmio_read_override_repeat":
                a = _expand_repeat_override(a, widths, cluster_regs)
                a["trigger"] = _canonicalize_trigger(a.get("trigger") if isinstance(a.get("trigger"), dict) else {}, a)
                expanded_actions = [a]
            elif str(a.get("type") or "") == "mmio_write_then_read_gate":
                expanded_actions = _expand_gate_to_primitives(a, candidate_id=c["id"], idx=idx, widths=widths, cluster_regs=cluster_regs)
            else:
                expanded_actions = [a]

            rewritten: List[Dict[str, Any]] = []
            for sub_idx, ex in enumerate(expanded_actions):
                ex = _normalize_action_addresses(ex)
                ex = _inject_action_widths(ex, widths, cluster_regs)
                ex["trigger"] = _canonicalize_trigger(ex.get("trigger") if isinstance(ex.get("trigger"), dict) else {}, ex)
                rewritten.extend(_rewrite_after_write_trigger(ex, candidate_id=c["id"], idx=(idx * 10) + sub_idx, widths=widths))

            for final_action in rewritten:
                addrs = [
                    final_action.get("addr"),
                    final_action.get("write_addr"),
                    final_action.get("read_addr"),
                    final_action.get("status_addr"),
                    final_action.get("s1_addr"),
                    final_action.get("data_addr"),
                    final_action.get("d_addr"),
                    (final_action.get("trigger") or {}).get("addr") if isinstance(final_action.get("trigger"), dict) else None,
                ]
                if any(x for x in addrs if x and x in allowed):
                    actions.append(final_action)

        if any(str(a.get("type") or "") == "uart_handshake_once" for a in actions):
            c["template_id"] = "uart_handshake_once"
        elif c.get("template_id") == "uart_handshake_once":
            c["template_id"] = "status_data_pair_primitive"

        c["actions"] = actions
        out["candidates"].append(c)
    return out


def _inject_llm_register_nodes(task_context: Dict[str, Any], cluster: Dict[str, Any]) -> Dict[str, Any]:
    aug = copy.deepcopy(task_context)
    regs = [dict(r) for r in cluster.get("registers") or []]
    addrs = [_normalize_hex(r.get("addr")) for r in regs if _normalize_hex(r.get("addr"))]
    aug["llm_strategy_allowed_addrs"] = addrs
    aug["llm_strategy_register_nodes"] = regs

    runtime = aug.setdefault("runtime_problem", {})
    runtime["llm_strategy_allowed_addrs"] = addrs
    runtime["llm_strategy_register_nodes"] = regs

    hs = runtime.setdefault("hotspots_summary", [])
    existing_hs = {_normalize_hex(x.get("addr")) for x in hs if isinstance(x, dict)}
    for r in regs:
        addr = _normalize_hex(r.get("addr"))
        if not addr or addr in existing_hs:
            continue
        hs.append({
            "addr": addr,
            "status": "ok",
            "read_count": 0,
            "executions_seen": 0,
            "interesting_executions_seen": 0,
            "resolved_register": r.get("register"),
            "resolved_instance": r.get("instance"),
            "field_candidates": r.get("field_candidates") or [],
        })

    groups = runtime.setdefault("hotspot_groups", [])
    if not groups:
        groups.append({
            "group_id": "llm_strategy_register_group",
            "instance": cluster.get("primary_instance"),
            "kind": "llm_strategy_group",
            "anchor": {
                "instance": cluster.get("primary_instance"),
                "register": cluster.get("primary_register"),
                "addr": cluster.get("primary_addr"),
                "role": "status",
                "width_bytes": 1,
                "read_count": 0,
                "executions_seen": 0,
            },
            "members": [],
            "companions": [],
            "signals": {},
            "field_candidates": [],
        })

    g = groups[0]
    g.setdefault("members", [])
    g.setdefault("companions", [])
    member_addrs = {_normalize_hex(x.get("addr")) for x in g["members"] if isinstance(x, dict)}
    companion_addrs = {_normalize_hex(x.get("addr")) for x in g["companions"] if isinstance(x, dict)}

    for r in regs:
        node = {
            "instance": r.get("instance"),
            "register": r.get("register"),
            "addr": _normalize_hex(r.get("addr")),
            "role": r.get("role"),
            "width_bytes": r.get("width") or 1,
            "read_count": 0,
            "executions_seen": 0,
            "field_candidates": r.get("field_candidates") or [],
        }
        if node["addr"] == _normalize_hex(cluster.get("primary_addr")):
            if node["addr"] not in member_addrs:
                g["members"].append(node)
        else:
            if node["addr"] not in companion_addrs:
                g["companions"].append(node)

    roles = {str(r.get("role")) for r in regs}
    signals = g.setdefault("signals", {})
    signals["has_data_companion"] = "data" in roles
    signals["has_control_companion"] = "control" in roles
    signals["has_fifo_companion"] = "fifo" in roles
    signals["anchor_read_count"] = signals.get("anchor_read_count") or 0
    return aug


def _merge_candidates(base_plan: Dict[str, Any], extra_plan: Dict[str, Any]) -> Dict[str, Any]:
    merged = list(base_plan.get("candidates") or [])
    seen = {str(c.get("id") or "") for c in merged if str(c.get("id") or "")}
    added = []
    for cand in extra_plan.get("candidates") or []:
        cid = str(cand.get("id") or "").strip()
        if not cid:
            continue
        if cid in seen:
            cand = dict(cand)
            cand["id"] = f"llm_{cid}"
            cid = cand["id"]
        seen.add(cid)
        merged.append(cand)
        added.append(cid)
    return {"schema": base_plan.get("schema") or "llm_strategy_choice_v1", "candidates": merged, "_llm_added_ids": added}


def _mask_key(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    if len(v) <= 8:
        return "***"
    return v[:12] + "..." + v[-4:]


def augment_plan_with_llm_strategies(
    *,
    plan_path: str,
    task_context_path: str,
    evidence_pack_path: Optional[str],
    out_dir: str,
    mode: str = "prompt-only",
    model: Optional[str] = None,
    llm_json_path: Optional[str] = None,
    max_candidates: int = 4,
    max_output_tokens: int = 4000,
    max_attempts: int = 2,
    reasoning_effort: str = "none",
    strategy_version: str = "v1",
) -> Dict[str, Any]:
    _ensure_dir(out_dir)
    plan = load_json(plan_path)
    prompt_info = build_llm_strategy_prompt(
        task_context_path=task_context_path,
        evidence_pack_path=evidence_pack_path,
        out_dir=out_dir,
        max_candidates=max_candidates,
    )
    prompt_text = prompt_info["prompt_text"]
    prompt_payload = prompt_info["payload"]
    api_key = os.environ.get("OPENAI_API_KEY")
    cluster = prompt_payload.get("allowed_register_cluster") or {}

    report: Dict[str, Any] = {
        "schema": "mf_llm_strategy_layer_v3",
        "mode": mode,
        "strategy_version": strategy_version,
        "prompt_json": str(Path(out_dir) / "llm_strategy_prompt.json"),
        "prompt_text": str(Path(out_dir) / "llm_strategy_prompt.txt"),
        "raw_response_json": None,
        "raw_response_text": None,
        "normalized_json": None,
        "augmented_task_context_json": None,
        "merge_report_json": str(Path(out_dir) / "llm_strategy_merge_report.json"),
        "added_candidate_ids": [],
        "added_candidate_count": 0,
        "error": None,
        "env_has_openai_api_key": bool(api_key),
        "env_openai_api_key_masked": _mask_key(api_key),
        "python_executable": sys.executable,
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "model": model or os.environ.get("OPENAI_MODEL") or "gpt-5.4",
        "prompt_chars": len(prompt_text),
        "allowed_register_count": len(cluster.get("registers") or []),
        "allowed_addrs": [_normalize_hex(r.get("addr")) for r in cluster.get("registers") or []],
        "api_attempt_errors": [],
        "raw_response_preview": None,
        "normalized_candidate_ids": [],
        "normalized_candidate_count": 0,
        "raw_candidate_ids": [],
        "sanitized_candidate_ids": [],
        "raw_candidate_count": 0,
        "sanitized_candidate_count": 0,
        "lint_raw_json": None,
        "lint_sanitized_json": None,
        "rejection_debug_json": None,
    }

    if mode == "prompt-only":
        save_json(str(Path(out_dir) / "llm_strategy_merge_report.json"), report)
        return report

    raw_obj: Optional[Dict[str, Any]] = None
    raw_text: str = ""

    try:
        if mode == "json-file":
            if not llm_json_path:
                raise ValueError("llm_strategy_mode=json-file requires llm_json_path")
            raw_obj = load_json(llm_json_path)
            raw_text = json.dumps(raw_obj, indent=2, ensure_ascii=False)
        elif mode == "api":
            last_err = None
            for attempt in range(1, max(1, int(max_attempts)) + 1):
                try:
                    raw_resp = _call_openai_responses_api(
                        prompt_text=prompt_text,
                        model=model,
                        max_output_tokens=max_output_tokens,
                        reasoning_effort=reasoning_effort,
                        api_key=api_key,
                    )
                    raw_obj = raw_resp
                    raw_text = _extract_text_from_response(raw_resp)
                    break
                except Exception as e:
                    last_err = e
                    msg = f"attempt {attempt}: {e}"
                    report["api_attempt_errors"].append(msg)
                    warn(f"LLM strategy attempt {attempt} failed: {e}")
                    time.sleep(min(3 * attempt, 10))
            if raw_obj is None:
                raise RuntimeError(f"LLM strategy API failed after {max_attempts} attempts: {last_err}")
        else:
            raise ValueError(f"unsupported llm strategy mode: {mode}")

        save_json(str(Path(out_dir) / "llm_strategy_raw.json"), raw_obj)
        save_text(str(Path(out_dir) / "llm_strategy_raw.txt"), raw_text or json.dumps(raw_obj, indent=2, ensure_ascii=False))
        report["raw_response_json"] = str(Path(out_dir) / "llm_strategy_raw.json")
        report["raw_response_text"] = str(Path(out_dir) / "llm_strategy_raw.txt")
        report["raw_response_preview"] = (raw_text or "")[:1200]

        extracted_raw = raw_obj if (isinstance(raw_obj, dict) and "candidates" in raw_obj) else _extract_json_candidate(raw_text)
        report["raw_candidate_ids"] = _candidate_ids(extracted_raw)
        report["raw_candidate_count"] = len(report["raw_candidate_ids"])
        lint_raw = _lint_candidates(extracted_raw, cluster)
        save_json(str(Path(out_dir) / "llm_strategy_lint_raw.json"), lint_raw)
        report["lint_raw_json"] = str(Path(out_dir) / "llm_strategy_lint_raw.json")

        extracted = _sanitize_extracted_plan(extracted_raw, cluster)
        report["sanitized_candidate_ids"] = _candidate_ids(extracted)
        report["sanitized_candidate_count"] = len(report["sanitized_candidate_ids"])
        lint_sanitized = _lint_candidates(extracted, cluster)
        save_json(str(Path(out_dir) / "llm_strategy_lint_sanitized.json"), lint_sanitized)
        report["lint_sanitized_json"] = str(Path(out_dir) / "llm_strategy_lint_sanitized.json")
        save_json(str(Path(out_dir) / "llm_strategy_extracted.json"), extracted)

        augmented_context = _inject_llm_register_nodes(load_json(task_context_path), cluster)
        augmented_context_path = str(Path(out_dir) / "llm_strategy_augmented_task_context.json")
        save_json(augmented_context_path, augmented_context)
        report["augmented_task_context_json"] = augmented_context_path

        normalized = normalize_llm_plan(augmented_context, str(Path(out_dir) / "llm_strategy_extracted.json"))
        save_json(str(Path(out_dir) / "llm_strategy_normalized.json"), normalized)
        report["normalized_json"] = str(Path(out_dir) / "llm_strategy_normalized.json")
        norm_ids = [str(c.get("id")) for c in normalized.get("candidates") or [] if isinstance(c, dict) and c.get("id")]
        report["normalized_candidate_ids"] = norm_ids
        report["normalized_candidate_count"] = len(norm_ids)
        rejection_debug = {
            "raw_candidate_ids": report["raw_candidate_ids"],
            "sanitized_candidate_ids": report["sanitized_candidate_ids"],
            "normalized_candidate_ids": report["normalized_candidate_ids"],
            "raw_candidate_count": report["raw_candidate_count"],
            "sanitized_candidate_count": report["sanitized_candidate_count"],
            "normalized_candidate_count": report["normalized_candidate_count"],
            "lint_raw_json": report["lint_raw_json"],
            "lint_sanitized_json": report["lint_sanitized_json"],
        }
        save_json(str(Path(out_dir) / "llm_strategy_rejection_debug.json"), rejection_debug)
        report["rejection_debug_json"] = str(Path(out_dir) / "llm_strategy_rejection_debug.json")

        merged = _merge_candidates(plan, normalized)
        added_ids = list(merged.pop("_llm_added_ids", []))
        save_json(plan_path, merged)
        report["added_candidate_ids"] = added_ids
        report["added_candidate_count"] = len(added_ids)
        save_json(str(Path(out_dir) / "llm_strategy_merge_report.json"), report)
        info(f"LLM strategy layer added {len(added_ids)} candidates into {plan_path}")
        return report
    except Exception as e:
        report["error"] = str(e)
        save_json(str(Path(out_dir) / "llm_strategy_merge_report.json"), report)
        warn(f"LLM strategy layer failed; keeping original heuristic plan: {e}")
        return report
