from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_MODEL = os.getenv("EXTRACTOR_LLM_MODEL", "gpt-5.4")
DEFAULT_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
DEFAULT_TIMEOUT = int(os.getenv("EXTRACTOR_LLM_TIMEOUT", "120"))
DEFAULT_API_KEY_ENV = os.getenv("EXTRACTOR_LLM_API_KEY_ENV", "OPENAI_API_KEY")

ALLOWED_FIELD_RELATIONS = {
    "affects",
    "enables",
    "disables",
    "clears",
    "sets",
    "triggers",
    "selects",
    "indicates",
    "requires",
    "gates",
    "configures",
    "depends_on",
    "interrupt_enable_for",
    "reports_status_of",
    "uses",
    "references",
}

ALLOWED_REGISTER_RELATIONS = {
    "references_register",
    "configures_register",
    "depends_on_register",
    "interrupt_enable_in_register",
    "status_latched_in_register",
    "data_path_uses_register",
}

ALLOWED_PERIPHERAL_RELATIONS = {
    "interacts_with_peripheral",
    "dma_request_enable",
    "interrupt_route_to_peripheral",
    "controller_affects_peripheral",
    "clock_gate_enable",
    "clock_gate_disable",
    "reset_control",
    "low_power_clock_enable",
    "power_control",
    "bus_gate",
    "peripheral_enable",
    "peripheral_disable",
    "interrupt_domain_enable",
    "interrupt_domain_disable",
    "pinmux_gate",
    "dma_domain_enable",
}

CONTROL_FIELD_SUFFIX_HINTS = (
    "LPEN",
    "SMEN",
    "CLKEN",
    "CKEN",
    "PWRDN",
    "PWRDWN",
    "PWR",
    "RST",
    "EN",
)

MAX_SOURCE_ITEMS_PER_REGISTER = 16
MAX_CANDIDATES_PER_SOURCE = 18
SNIPPET_RADIUS = 220
SNIPPET_MAX_MATCHES = 3


def debug(msg: str):
    print(f"[DEBUG][llm-rel] {msg}")


class LLMRelationError(RuntimeError):
    pass


def _norm_base_url(base_url: str) -> str:
    base_url = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
    if not base_url:
        base_url = DEFAULT_BASE_URL
    if not base_url.endswith("/v1"):
        if base_url.endswith("/chat/completions"):
            base_url = base_url[: -len("/chat/completions")]
        elif base_url.endswith("/chat"):
            base_url = base_url[:-len("/chat")]
        elif not re.search(r"/v\d+$", base_url):
            base_url += "/v1"
    return base_url


def _extract_json_object(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise LLMRelationError("empty LLM response")

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            data = json.loads(text[start : end + 1])
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    raise LLMRelationError("failed to parse JSON object from LLM response")


def _http_chat_json(
    messages: List[Dict[str, str]],
    *,
    model: str,
    api_key: str,
    base_url: str,
    timeout: int,
) -> Dict[str, Any]:
    url = _norm_base_url(base_url) + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise LLMRelationError(f"HTTP {e.code}: {body[:400]}")
    except Exception as e:
        raise LLMRelationError(str(e))

    data = json.loads(raw)
    try:
        content = data["choices"][0]["message"]["content"]
    except Exception as e:
        raise LLMRelationError(f"unexpected response shape: {e}")
    return _extract_json_object(content)


def _clamp_confidence(v: Any, default: float = 0.72) -> float:
    try:
        x = float(v)
    except Exception:
        x = default
    x = max(0.01, min(0.99, x))
    return round(x, 4)


def _normalize_name(name: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (name or "").upper())


def _normalize_relation(name: Any, fallback: str) -> str:
    rel = re.sub(r"[^a-z0-9_]+", "_", str(name or "").strip().lower()).strip("_")
    return rel or fallback


def _token_patterns(token: str) -> List[re.Pattern]:
    tok = (token or "").strip()
    if not tok:
        return []
    esc = re.escape(tok)
    pats = [re.compile(rf"\b{esc}\b", re.IGNORECASE)]
    # Tolerate glued PDF text like TXEIEbit or USART_CR2register.
    pats.append(re.compile(rf"\b{esc}(?=[A-Za-z])", re.IGNORECASE))
    return pats


def _contains_token(text: str, token: str) -> bool:
    if not text or not token:
        return False
    for pat in _token_patterns(token):
        if pat.search(text):
            return True
    # Fall back to compact matching for glued PDF text.
    return _normalize_name(token) in _normalize_name(text)


def _find_token_positions(text: str, token: str, max_matches: int = SNIPPET_MAX_MATCHES) -> List[int]:
    if not text or not token:
        return []
    positions: List[int] = []
    for pat in _token_patterns(token):
        for m in pat.finditer(text):
            positions.append(m.start())
            if len(positions) >= max_matches:
                return sorted(set(positions))
    # Compact fallback: use raw substring when possible.
    idx = text.upper().find(token.upper())
    if idx >= 0:
        positions.append(idx)
    return sorted(set(positions))[:max_matches]


def _snippet_around_positions(text: str, positions: List[int], radius: int = SNIPPET_RADIUS) -> str:
    text = str(text or "")
    if not text:
        return ""
    if not positions:
        return text[: min(len(text), radius * 2)].strip()

    spans: List[Tuple[int, int]] = []
    for pos in positions:
        start = max(0, pos - radius)
        end = min(len(text), pos + radius)
        spans.append((start, end))
    spans.sort()

    merged: List[Tuple[int, int]] = []
    for start, end in spans:
        if not merged or start > merged[-1][1] + 24:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))

    chunks = []
    for start, end in merged[:SNIPPET_MAX_MATCHES]:
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
    return "\n...\n".join(dict.fromkeys(chunks))[:1200]


def _is_controller_like_target(name: str) -> bool:
    n = (name or "").upper()
    controller_roots = {
        "RCC", "PMC", "SYSCON", "SIM", "PCC", "CLKCTRL", "RSTC", "RESET",
        "CLOCK", "CCM", "CMU", "MCG", "OSCCTRL", "SYSCTL",
    }
    if n in controller_roots:
        return True
    return any(n.startswith(root) for root in controller_roots)


def _compact_field(field: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": field.get("name"),
        "bitRange": field.get("bitRange"),
        "svd_description": field.get("svd_description"),
        "pdf_description": field.get("pdf_description"),
    }


def _register_addr_hex(reg: Dict[str, Any]) -> Optional[str]:
    return reg.get("absoluteAddress_hex")


def _build_indexes(merged_view: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], Dict[Tuple[str, str], Dict[str, Any]], Dict[str, set]]:
    reg_map: Dict[str, Dict[str, Any]] = {}
    reg_field_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    reg_to_fields: Dict[str, set] = {}
    for reg in merged_view.get("registers") or []:
        rn = (reg.get("name") or "").upper()
        if not rn:
            continue
        reg_map[rn] = reg
        reg_to_fields[rn] = set()
        for field in reg.get("fields") or []:
            fn = (field.get("name") or "").upper()
            if not fn:
                continue
            reg_to_fields[rn].add(fn)
            reg_field_map[(rn, fn)] = field
    return reg_map, reg_field_map, reg_to_fields


def _build_field_catalog(merged_view: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    target_peripheral = merged_view.get("keyword") or merged_view.get("template_instance") or "PERIPH"
    for reg in merged_view.get("registers") or []:
        rn = (reg.get("name") or "").upper()
        if not rn:
            continue
        for field in reg.get("fields") or []:
            fn = (field.get("name") or "").upper()
            if not fn:
                continue
            out.append(
                {
                    "peripheral": target_peripheral,
                    "register": rn,
                    "field": fn,
                    "field_id": f"{target_peripheral}:{rn}.{fn}",
                }
            )
    return out


def _field_name_candidates(field_name: str) -> List[str]:
    base = _normalize_name(field_name)
    out = [base]
    for suf in sorted(CONTROL_FIELD_SUFFIX_HINTS, key=len, reverse=True):
        if base.endswith(suf) and len(base) > len(suf):
            out.append(base[: -len(suf)])
    return list(dict.fromkeys([x for x in out if x]))


def _match_known_peripheral(name: str, known_peripherals: List[str]) -> Optional[str]:
    nu = (name or "").strip().upper()
    if not nu:
        return None
    exact = {p.upper(): p for p in known_peripherals}
    if nu in exact:
        return exact[nu]

    nn = _normalize_name(nu)
    for p in known_peripherals:
        pn = _normalize_name(p)
        if nn == pn:
            return p
    return None


def _controller_field_name_candidates(src_field: str, known_peripherals: List[str], target_peripheral: str) -> List[Dict[str, Any]]:
    target_u = (target_peripheral or "").upper()
    norm_map = {_normalize_name(p): p for p in known_peripherals if p and p.upper() != target_u}
    out: List[Dict[str, Any]] = []
    seen = set()
    for cand in _field_name_candidates(src_field):
        for np_norm, np_real in norm_map.items():
            if cand == np_norm or cand.startswith(np_norm) or np_norm.startswith(cand):
                if np_real in seen:
                    continue
                seen.add(np_real)
                out.append(
                    {
                        "kind": "peripheral",
                        "name": np_real,
                        "match_text": src_field,
                        "mention_basis": "field_name_inference",
                    }
                )
    return out


def _source_text_variants(reg: Dict[str, Any], field: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    src_field = (field.get("name") or "").upper()
    page = (reg.get("source_pages") or [None])[0]

    field_pdf = str(field.get("pdf_description") or "").strip()
    if field_pdf:
        out.append({"source": "field_pdf", "text": field_pdf, "page": page})

    field_svd = str(field.get("svd_description") or "").strip()
    if field_svd:
        out.append({"source": "field_svd", "text": field_svd, "page": page})

    reg_pdf = str(reg.get("pdf_description") or "").strip()
    if reg_pdf and src_field:
        positions = _find_token_positions(reg_pdf, src_field)
        if positions:
            snippet = _snippet_around_positions(reg_pdf, positions)
            if snippet:
                out.append({"source": "register_pdf", "text": snippet, "page": page})

    uniq: List[Dict[str, Any]] = []
    seen = set()
    for x in out:
        key = (x["source"], x["text"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(x)
    return uniq


def _detect_mention_candidates(
    text: str,
    *,
    src_reg: str,
    src_field: str,
    field_catalog: List[Dict[str, Any]],
    reg_names: List[str],
    known_peripherals: List[str],
    target_peripheral: str,
) -> List[Dict[str, Any]]:
    text_u = (text or "").upper()
    out: List[Dict[str, Any]] = []
    seen = set()

    def add_candidate(item: Dict[str, Any]):
        key = (item.get("kind"), item.get("name"), item.get("register"), item.get("field"), item.get("mention_basis"))
        if key in seen:
            return
        seen.add(key)
        out.append(item)

    for entry in field_catalog:
        dst_reg = entry["register"]
        dst_field = entry["field"]
        if dst_reg == src_reg and dst_field == src_field:
            continue
        if len(dst_field) <= 2:
            # Very short field names are too noisy in raw PDF text. Let LLM infer them from richer snippets.
            continue
        if _contains_token(text_u, dst_field):
            add_candidate(
                {
                    "kind": "field",
                    "name": dst_field,
                    "register": dst_reg,
                    "peripheral": target_peripheral,
                    "match_text": dst_field,
                    "mention_basis": "text_mention",
                }
            )

    for reg_name in reg_names:
        if reg_name == src_reg:
            continue
        if len(reg_name) <= 2:
            continue
        if _contains_token(text_u, reg_name):
            add_candidate(
                {
                    "kind": "register",
                    "name": reg_name,
                    "register": reg_name,
                    "peripheral": target_peripheral,
                    "match_text": reg_name,
                    "mention_basis": "text_mention",
                }
            )

    target_u = (target_peripheral or "").upper()
    for p in known_peripherals:
        pu = (p or "").upper()
        if not pu or pu == target_u:
            continue
        if len(pu) <= 2:
            continue
        if _contains_token(text_u, pu):
            add_candidate(
                {
                    "kind": "peripheral",
                    "name": p,
                    "peripheral": p,
                    "match_text": pu,
                    "mention_basis": "text_mention",
                }
            )

    return out[:MAX_CANDIDATES_PER_SOURCE]


def _build_source_items_for_register(
    merged_view: Dict[str, Any],
    reg: Dict[str, Any],
    *,
    known_peripherals: List[str],
    field_catalog: List[Dict[str, Any]],
    reg_names: List[str],
    is_controller_like: bool,
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    target_peripheral = merged_view.get("keyword") or merged_view.get("template_instance") or "PERIPH"
    src_reg = (reg.get("name") or "").upper()

    for field in reg.get("fields") or []:
        src_field = (field.get("name") or "").upper()
        if not src_field:
            continue

        source_variants = _source_text_variants(reg, field)
        candidates: List[Dict[str, Any]] = []
        for sv in source_variants:
            found = _detect_mention_candidates(
                sv.get("text") or "",
                src_reg=src_reg,
                src_field=src_field,
                field_catalog=field_catalog,
                reg_names=reg_names,
                known_peripherals=known_peripherals,
                target_peripheral=target_peripheral,
            )
            for cand in found:
                candidates.append(cand)

        if is_controller_like:
            candidates.extend(_controller_field_name_candidates(src_field, known_peripherals, target_peripheral))

        # Stable de-dup.
        uniq: List[Dict[str, Any]] = []
        seen = set()
        for cand in candidates:
            key = (cand.get("kind"), cand.get("name"), cand.get("register"), cand.get("field"), cand.get("mention_basis"))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(cand)
        candidates = uniq[:MAX_CANDIDATES_PER_SOURCE]

        if not candidates:
            continue

        # Pick the richest source text first.
        source_variants.sort(key=lambda x: (0 if x["source"] == "field_pdf" else 1 if x["source"] == "register_pdf" else 2, -len(x["text"] or "")))
        chosen = source_variants[0] if source_variants else {"source": "field_name_inference", "text": src_field, "page": (reg.get("source_pages") or [None])[0]}

        item = {
            "source_item_id": f"{src_reg}.{src_field}",
            "src_register": src_reg,
            "src_field": src_field,
            "source_kind": chosen.get("source") or "field_pdf",
            "source_page": chosen.get("page"),
            "source_text": chosen.get("text") or src_field,
            "mention_candidates": candidates,
        }
        items.append(item)

    # Prefer items with richer source texts and more candidates.
    items.sort(key=lambda x: (0 if x["source_kind"] == "field_pdf" else 1 if x["source_kind"] == "register_pdf" else 2, -len(x["mention_candidates"]), x["src_field"]))
    return items[:MAX_SOURCE_ITEMS_PER_REGISTER]


def _build_messages_for_source_item(
    merged_view: Dict[str, Any],
    reg: Dict[str, Any],
    source_item: Dict[str, Any],
    *,
    is_controller_like: bool,
) -> List[Dict[str, str]]:
    target_peripheral = merged_view.get("keyword") or merged_view.get("template_instance") or "PERIPH"
    payload = {
        "task": "mention_driven_hardware_relation_extraction",
        "target_peripheral": target_peripheral,
        "template_instance": merged_view.get("template_instance"),
        "is_controller_like_target": is_controller_like,
        "current_register": {
            "name": reg.get("name"),
            "svd_description": reg.get("svd_description"),
            "pdf_description": reg.get("pdf_description"),
            "fields": [_compact_field(f) for f in (reg.get("fields") or [])],
        },
        "current_source_item": source_item,
        "allowed_edge_types": [
            "field_to_field",
            "field_to_register",
            "field_to_peripheral",
            "controller_field_to_peripheral",
        ],
        "notes": {
            "mention_driven": True,
            "single_source_item_only": True,
            "do_not_require_fixed_predicates": True,
            "mere_bit_table_cooccurrence_is_not_enough": True,
            "for_controller_like_targets_field_name_inference_is_allowed": bool(is_controller_like),
        },
    }

    system = (
        "You extract hardware dependency edges from MCU manual text using mention-driven reasoning. "
        "The caller has already preselected exactly one source field description or nearby register snippet that mentions other entities. "
        "Judge only this one source item. Do not use information from other fields or other parts of the manual. "
        "Do not rely on fixed verbs only; infer relation from the local context around the mention. "
        "However, do NOT create an edge from mere table co-occurrence, register layout adjacency, or unrelated name overlap. "
        "For controller-like peripherals such as RCC/PMC/SYSCON, field-name inference is allowed for names like USART1EN, SPI2RST, I2C1LPEN. "
        "Return JSON with a single key 'edges'. If nothing is grounded for this source item, return {\"edges\": []}."
    )

    user = (
        "You are given exactly one source item. Every returned edge must use that same source_item_id.\n"
        "Use only entities listed in current_source_item.mention_candidates.\n"
        "If none of the candidates are actually related, return an empty list.\n"
        "JSON schema for each edge:\n"
        "{\n"
        "  \"source_item_id\": string,\n"
        "  \"edge_type\": \"field_to_field\" | \"field_to_register\" | \"field_to_peripheral\" | \"controller_field_to_peripheral\",\n"
        "  \"dst_register\": string | null,\n"
        "  \"dst_field\": string | null,\n"
        "  \"dst_peripheral\": string | null,\n"
        "  \"relation\": short lowercase label,\n"
        "  \"confidence\": number between 0 and 1,\n"
        "  \"evidence_type\": \"field_pdf\" | \"register_pdf\" | \"field_svd\" | \"field_name_inference\",\n"
        "  \"evidence_text\": exact substring copied from source_text, or the exact source field name for field_name_inference,\n"
        "  \"notes\": short string\n"
        "}\n\n"
        f"Input:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _validate_evidence_text(evidence_text: str, source_item: Dict[str, Any]) -> bool:
    ev = str(evidence_text or "").strip()
    if not ev:
        return False
    if source_item.get("source_kind") == "field_name_inference":
        return ev.upper() == str(source_item.get("src_field") or "").upper()
    return ev.lower() in str(source_item.get("source_text") or "").lower()


def _candidate_index(source_item: Dict[str, Any]) -> Dict[Tuple[str, Optional[str], Optional[str]], Dict[str, Any]]:
    out: Dict[Tuple[str, Optional[str], Optional[str]], Dict[str, Any]] = {}
    for c in source_item.get("mention_candidates") or []:
        key = (c.get("kind"), (c.get("register") or c.get("name")), c.get("field"))
        out[key] = c
    return out


def extract_relation_edges_with_llm(
    merged_view: Dict[str, Any],
    *,
    known_peripherals: List[str],
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    timeout: Optional[int] = None,
    api_key_env: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    model = model or DEFAULT_MODEL
    base_url = base_url or DEFAULT_BASE_URL
    timeout = int(timeout or DEFAULT_TIMEOUT)
    api_key_env = api_key_env or DEFAULT_API_KEY_ENV
    api_key = os.getenv(api_key_env, "").strip()
    if not api_key:
        raise LLMRelationError(f"missing API key in env var {api_key_env}")

    target_peripheral = merged_view.get("keyword") or merged_view.get("template_instance") or "PERIPH"
    is_controller_like = _is_controller_like_target(target_peripheral)
    reg_map, _reg_field_map, reg_to_fields = _build_indexes(merged_view)
    reg_names = list(reg_map.keys())
    field_catalog = _build_field_catalog(merged_view)

    edges: List[Dict[str, Any]] = []
    stats = {
        "mode": "llm",
        "model": model,
        "calls": 0,
        "registers_considered": 0,
        "registers_with_llm_edges": 0,
        "source_items_considered": 0,
        "target_is_controller_like": is_controller_like,
        "latency_sec": 0.0,
    }

    edge_id = 1
    t0 = time.time()

    for reg in merged_view.get("registers") or []:
        if (reg.get("documentation_status") or "") != "documented_in_pdf":
            continue

        source_items = _build_source_items_for_register(
            merged_view,
            reg,
            known_peripherals=known_peripherals,
            field_catalog=field_catalog,
            reg_names=reg_names,
            is_controller_like=is_controller_like,
        )
        if not source_items:
            continue

        stats["registers_considered"] += 1
        stats["source_items_considered"] += len(source_items)
        valid_count_for_reg = 0

        for source_item in source_items:
            messages = _build_messages_for_source_item(
                merged_view,
                reg,
                source_item,
                is_controller_like=is_controller_like,
            )
            stats["calls"] += 1
            response = _http_chat_json(
                messages,
                model=model,
                api_key=api_key,
                base_url=base_url,
                timeout=timeout,
            )
            raw_edges = response.get("edges") or []
            if not isinstance(raw_edges, list):
                continue

            item_valid_count = 0
            src_reg = str(source_item.get("src_register") or "").upper()
            src_field = str(source_item.get("src_field") or "").upper()
            if src_field not in reg_to_fields.get(src_reg, set()):
                continue
            src_reg_obj = reg_map.get(src_reg, {})

            for raw in raw_edges:
                if not isinstance(raw, dict):
                    continue

                sid = str(raw.get("source_item_id") or "").strip()
                if sid != str(source_item.get("source_item_id") or ""):
                    continue

                edge_type = str(raw.get("edge_type") or "").strip()
                relation = _normalize_relation(raw.get("relation"), "affects")
                confidence = _clamp_confidence(raw.get("confidence"), default=0.74)
                evidence_type = str(raw.get("evidence_type") or source_item.get("source_kind") or "register_pdf").strip()
                evidence_text = str(raw.get("evidence_text") or "").strip()
                notes = str(raw.get("notes") or "").strip()

                if not _validate_evidence_text(evidence_text, source_item):
                    continue

                evidence = [
                    {
                        "source": evidence_type,
                        "page": source_item.get("source_page"),
                        "text": evidence_text[:800],
                    }
                ]

                if edge_type == "field_to_field":
                    dst_reg = str(raw.get("dst_register") or "").strip().upper()
                    dst_field = str(raw.get("dst_field") or "").strip().upper()
                    if not dst_reg or not dst_field:
                        continue
                    if dst_field not in reg_to_fields.get(dst_reg, set()):
                        continue
                    if relation not in ALLOWED_FIELD_RELATIONS:
                        relation = "affects"
                    dst_reg_obj = reg_map.get(dst_reg, {})
                    edges.append(
                        {
                            "edge_id": f"e_f2f_llm_{edge_id:06d}",
                            "edge_type": "field_to_field",
                            "src": {
                                "peripheral": target_peripheral,
                                "register": src_reg,
                                "register_addr_hex": _register_addr_hex(src_reg_obj),
                                "field": src_field,
                                "field_id": f"{target_peripheral}:{src_reg}.{src_field}",
                            },
                            "dst": {
                                "peripheral": target_peripheral,
                                "register": dst_reg,
                                "register_addr_hex": _register_addr_hex(dst_reg_obj),
                                "field": dst_field,
                                "field_id": f"{target_peripheral}:{dst_reg}.{dst_field}",
                            },
                            "relation": relation,
                            "confidence": confidence,
                            "evidence": evidence,
                            "notes": [notes] if notes else [],
                        }
                    )
                    edge_id += 1
                    item_valid_count += 1
                    valid_count_for_reg += 1

                elif edge_type == "field_to_register":
                    dst_reg = str(raw.get("dst_register") or "").strip().upper()
                    if not dst_reg or dst_reg not in reg_map:
                        continue
                    if relation not in ALLOWED_REGISTER_RELATIONS:
                        relation = "references_register"
                    dst_reg_obj = reg_map.get(dst_reg, {})
                    edges.append(
                        {
                            "edge_id": f"e_f2r_llm_{edge_id:06d}",
                            "edge_type": "field_to_register",
                            "src": {
                                "peripheral": target_peripheral,
                                "register": src_reg,
                                "register_addr_hex": _register_addr_hex(src_reg_obj),
                                "register_id": f"{target_peripheral}:{src_reg}",
                                "field": src_field,
                                "field_id": f"{target_peripheral}:{src_reg}.{src_field}",
                            },
                            "dst": {
                                "peripheral": target_peripheral,
                                "register": dst_reg,
                                "register_addr_hex": _register_addr_hex(dst_reg_obj),
                                "register_id": f"{target_peripheral}:{dst_reg}",
                            },
                            "relation": relation,
                            "confidence": confidence,
                            "evidence": evidence,
                            "notes": [notes] if notes else [],
                        }
                    )
                    edge_id += 1
                    item_valid_count += 1
                    valid_count_for_reg += 1

                elif edge_type in {"field_to_peripheral", "controller_field_to_peripheral"}:
                    dst_periph = _match_known_peripheral(raw.get("dst_peripheral") or "", known_peripherals)
                    if not dst_periph:
                        continue
                    final_type = edge_type
                    if edge_type == "controller_field_to_peripheral":
                        if not is_controller_like:
                            continue
                        if relation not in ALLOWED_PERIPHERAL_RELATIONS:
                            relation = "controller_affects_peripheral"
                    else:
                        if relation not in ALLOWED_PERIPHERAL_RELATIONS:
                            relation = "interacts_with_peripheral"
                        final_type = "field_to_peripheral"
                    edges.append(
                        {
                            "edge_id": f"e_{'cf2p' if final_type == 'controller_field_to_peripheral' else 'f2p'}_llm_{edge_id:06d}",
                            "edge_type": final_type,
                            "src": {
                                "peripheral": target_peripheral,
                                "register": src_reg,
                                "register_addr_hex": _register_addr_hex(src_reg_obj),
                                "register_id": f"{target_peripheral}:{src_reg}",
                                "field": src_field,
                                "field_id": f"{target_peripheral}:{src_reg}.{src_field}",
                            },
                            "dst": {
                                "peripheral": dst_periph,
                                "target_kind": "peripheral",
                            },
                            "relation": relation,
                            "confidence": confidence,
                            "evidence": evidence,
                            "notes": [notes] if notes else [],
                        }
                    )
                    edge_id += 1
                    item_valid_count += 1
                    valid_count_for_reg += 1

            debug(f"source item {source_item.get('source_item_id')} produced {item_valid_count} llm edges")

        if valid_count_for_reg:
            stats["registers_with_llm_edges"] += 1

    stats["latency_sec"] = round(time.time() - t0, 3)
    return edges, stats
