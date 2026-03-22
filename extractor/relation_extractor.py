from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from llm_relation_extractor import extract_relation_edges_with_llm, LLMRelationError
except Exception:  # pragma: no cover
    extract_relation_edges_with_llm = None
    class LLMRelationError(RuntimeError):
        pass


def debug(msg: str):
    print(f"[DEBUG][relation] {msg}")


FIELD_REL_CUES = {
    "gates": ["only when", "when", "if", "requires", "must be", "dependent on"],
    "enables": ["enable", "enabled", "set to 1 enables", "activates", "allow"],
    "disables": ["disable", "disabled", "set to 0 disables", "prevent"],
    "clears": ["clear", "cleared", "write 1 to clear"],
    "sets": ["is set", "becomes set", "set when", "sets"],
    "triggers": ["trigger", "triggers", "starts", "causes", "generates"],
    "affects": ["affect", "controls", "determines", "influences", "selects"],
}

CTRL_REG_TO_PERIPH_REL = {
    "clock_gate_enable": ["clock enable", "peripheral clock", "clock is enabled", "enable clock"],
    "clock_gate_disable": ["clock disable", "disable clock"],
    "reset_control": ["reset", "software reset"],
    "power_control": ["power", "powered", "power-down", "power down"],
    "interrupt_domain_enable": ["interrupt enable", "interrupt is enabled", "unmask"],
    "interrupt_domain_disable": ["interrupt disable", "mask"],
    "pinmux_gate": ["pin", "io line", "multiplex", "mux", "pinsel", "pio"],
    "dma_domain_enable": ["dma", "pdc", "transfer"],
    "controller_affects_peripheral": ["controls", "affects", "related to"],
}

CTRL_REG_TO_REG_REL = {
    "interrupt_gate_register": ["interrupt enable", "interrupt mask", "interrupt source"],
    "clock_controls_register": ["clock", "clocked"],
    "pinmux_controls_register": ["pin", "mux", "pio"],
    "dma_controls_register": ["dma", "pdc", "transfer"],
    "controller_affects_register": ["controls", "affects", "determines"],
}

CONTROL_REGISTER_NAME_HINTS = [
    "PCER", "PCDR", "ENR", "RSTR", "ISER", "ICER", "IMR", "IER", "IDR",
    "PCR", "PMR", "MUX", "PDR", "PER", "CHER", "CHDR", "PTCR",
]

INTERRUPT_FAMILY = {"IER", "IDR", "IMR", "SR", "CSR", "ISR", "ICR"}
CONTROL_FAMILY = {"CR", "MR", "BRGR", "FIDI", "TTGR"}
STATUS_FAMILY = {"SR", "CSR", "ISR", "IMR"}

TABLE_MARKERS = [
    "address", "offset", "read", "write", "reset", "table continues", "access",
    "width", "value", "default", "bit", "bits",
]


def _text_has_any(text: str, phrases: List[str]) -> bool:
    t = (text or "").lower()
    return any(p.lower() in t for p in phrases)


def _infer_relation(text: str, mapping: Dict[str, List[str]], fallback: str) -> str:
    for rel, phrases in mapping.items():
        if _text_has_any(text, phrases):
            return rel
    return fallback


def _confidence_from_text(text: str, base: float = 0.55) -> float:
    t = (text or "").strip().lower()
    score = base
    if "enable" in t or "disable" in t:
        score += 0.08
    if "interrupt" in t:
        score += 0.06
    if "clock" in t:
        score += 0.06
    if len(t) > 80:
        score += 0.05
    return min(0.98, round(score, 4))


def _split_lines(text: str) -> List[str]:
    return [ln.strip() for ln in str(text or "").splitlines() if ln.strip()]


def _looks_table_like(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return True

    low = t.lower()
    lines = _split_lines(t)

    if "table continues" in low:
        return True
    if re.search(r"\baddress\b.*\boffset\b", low):
        return True
    if re.search(r"\bbit\s+\d+(?:\s+\d+){3,}", low):
        return True
    if "read" in low and "write" in low and "reset" in low:
        return True
    if len(re.findall(r"\b[01]\b", t)) >= 6 and len(lines) >= 2:
        return True

    short_caps = re.findall(r"\b[A-Z][A-Z0-9_]{0,4}\b", t)
    if len(short_caps) >= 8 and len(t) <= 240:
        return True

    table_hits = sum(1 for ln in lines if any(m in ln.lower() for m in TABLE_MARKERS))
    if len(lines) >= 3 and table_hits >= 2:
        return True

    return False


def _has_field_relation_signal(text: str) -> bool:
    t = (text or "").lower()
    if not t or _looks_table_like(text):
        return False
    signal_words = [
        "enable", "disable", "clear", "set when", "cleared by", "trigger", "cause",
        "when", "if", "require", "must", "only when", "is set", "becomes set",
        "depends on", "controls", "determines", "selects", "generates",
    ]
    return any(w in t for w in signal_words)


def _has_strong_field_relation_signal(text: str) -> bool:
    t = (text or "").lower()
    if not t or _looks_table_like(text):
        return False
    strong_words = [
        "cleared by", "set when", "only when", "must be", "enabled by",
        "disabled by", "depends on", "requires", "controls", "determines",
        "selects", "causes", "generates", "triggers",
    ]
    return any(w in t for w in strong_words)


def _has_controller_signal(text: str) -> bool:
    t = (text or "").lower()
    if not t:
        return False
    signal_words = [
        "clock", "interrupt", "dma", "pdc", "pin", "mux", "reset",
        "enable", "disable", "mask", "unmask", "power", "control",
    ]
    return any(w in t for w in signal_words)


def _field_id(periph: str, reg: str, field: str) -> str:
    return f"{periph}:{reg}.{field}"


def _reg_id(periph: str, reg: str) -> str:
    return f"{periph}:{reg}"


def _page_num(p: Dict[str, Any]) -> Optional[int]:
    v = p.get("page_num", p.get("page"))
    return int(v) if isinstance(v, int) else None


def _page_lines(p: Dict[str, Any]) -> List[str]:
    lines = p.get("lines")
    if isinstance(lines, list) and lines:
        out = []
        for x in lines:
            if isinstance(x, dict):
                s = str(x.get("text", "")).strip()
            else:
                s = str(x).strip()
            if s:
                out.append(s)
        if out:
            return out
    text = p.get("text") or ""
    return [ln.strip() for ln in str(text).splitlines() if ln.strip()]


def normalize_field_variants(candidate: str) -> set:
    base, _, bit = candidate.upper().partition(".")
    return set(filter(None, {candidate.upper(), f"{base}.{bit}", f"{base}_{bit}", bit}))


def _variant_regex(variant: str) -> Optional[re.Pattern]:
    v = variant.strip().upper()
    if not v or "." in v or len(v) < 3:
        return None
    return re.compile(rf"\b{re.escape(v)}\b", re.IGNORECASE)


def extract_field_cross_references(
    text: str,
    known_fields: List[str],
    current_field: str,
    current_reg: str,
    known_regs: List[str],
    field_to_register: Dict[str, str],
    allowed_fields: set,
    allow_same_register: bool = True,
):
    relations = []
    upper_text = (text or "").upper()
    current_reg_prefix = current_reg.upper()

    for candidate in known_fields:
        if candidate == current_field:
            continue

        candidate_reg = field_to_register.get(candidate, "")
        if (not allow_same_register) and candidate_reg == current_reg_prefix:
            continue
        if candidate not in allowed_fields:
            continue

        variants = normalize_field_variants(candidate)
        matched = []
        for v in variants:
            rgx = _variant_regex(v)
            if rgx and rgx.search(upper_text):
                matched.append(v)

        if matched:
            relations.append((current_field, "refers", candidate, matched))

    tokens = set(re.findall(r"\b[A-Z0-9_]+\b", upper_text))
    for reg in known_regs:
        if reg != current_reg_prefix and reg in tokens:
            relations.append((current_field, "refers_reg", reg, [reg]))

    return relations


def _field_anchor_patterns(field_name_only: str, all_field_names=None):
    field_pattern = re.escape(field_name_only)
    start_pattern = re.compile(
        rf"(?i)^[\u2022•\-–\s]*"
        rf"(?:bit\s*\d+(?:\s*[-:]?\s*)?)?"
        rf"(?:\b|(?<=\d))"
        rf"{field_pattern}"
        rf"\b\s*[:：\-–]"
    )

    next_field_names = []
    if all_field_names:
        for name in all_field_names:
            if name and name.upper() != field_name_only.upper():
                next_field_names.append(name)

    next_field_pattern = None
    if next_field_names:
        next_field_pattern = re.compile(
            r"(?i)^[\u2022•\-–\s]*"
            r"(?:bit\s*\d+(?:\s*[-:]?\s*)?)?"
            r"(?:\b|(?<=\d))"
            r"(?:" + "|".join(re.escape(f) for f in next_field_names) + r")"
            r"\b\s*[:：\-–]"
        )
    return start_pattern, next_field_pattern


def _extract_field_snippets_from_lines(field_name: str, lines: List[str], all_field_names=None, *, max_lines=18):
    field_name_only = field_name.split(".")[-1]
    start_pattern, next_field_pattern = _field_anchor_patterns(field_name_only, all_field_names)
    snippets = []

    i = 0
    while i < len(lines):
        line = lines[i]
        if start_pattern.search(line):
            start = i
            end = i + 1
            while end < len(lines) and (end - start) < max_lines:
                nl = lines[end]
                if next_field_pattern and next_field_pattern.search(nl):
                    break
                if (end - start) >= 3 and re.match(r"^[\u2022•\-–]\s*", nl):
                    break
                end += 1
            text = "\n".join(lines[start:end]).strip()
            snippets.append({"method": "anchor", "text": text})
            i = end
            continue
        i += 1

    if not snippets:
        fuzzy_pattern = re.compile(rf"\b{re.escape(field_name_only)}(?:[0-9A-Za-z]|\[\d+:\d+\])?", re.IGNORECASE)
        for i, line in enumerate(lines):
            if fuzzy_pattern.search(line):
                start = i
                end = min(len(lines), i + 4)
                text = "\n".join(lines[start:end]).strip()
                snippets.append({"method": "fuzzy", "text": text})

    return snippets


def extract_field_paragraphs(field_name: str, pages: List[Dict[str, Any]], all_field_names=None, *, max_lines=18):
    snippets = []
    matched_pages = []
    for p in pages:
        page_no = _page_num(p)
        lines = _page_lines(p)
        if not lines:
            continue
        local = _extract_field_snippets_from_lines(field_name, lines, all_field_names, max_lines=max_lines)
        for snip in local:
            snip = dict(snip)
            snip["page"] = page_no
            snippets.append(snip)
            if page_no is not None and page_no not in matched_pages:
                matched_pages.append(page_no)
    return snippets, matched_pages


def _build_register_addr_lookup(merged: Dict[str, Any]) -> Dict[str, Optional[str]]:
    out = {}
    for reg in merged.get("registers") or []:
        rname = (reg.get("name") or "").upper()
        if rname:
            out[rname] = reg.get("absoluteAddress_hex")
    return out


def _build_register_index_for_controllers(controller_index: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out = {}
    for per_name, per in (controller_index or {}).items():
        base = per.get("baseAddress")
        for reg in per.get("registers") or []:
            rname = reg.get("name")
            if not rname:
                continue
            if not any(h in rname.upper() for h in CONTROL_REGISTER_NAME_HINTS):
                continue
            off = reg.get("addressOffset")
            abs_addr = None
            if base is not None and off is not None:
                abs_addr = int(base) + int(off)
            out[_reg_id(per_name, rname)] = {
                "peripheral": per_name,
                "register": rname,
                "register_id": _reg_id(per_name, rname),
                "register_addr_hex": f"0x{abs_addr:08X}" if abs_addr is not None else None,
                "description": reg.get("description") or "",
            }
    return out


def _aggregate_edges(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped = {}
    for e in edges:
        et = e.get("edge_type")
        if et == "field_to_field":
            key = (et, e["src"]["field_id"], e["dst"]["field_id"], e["relation"])
        elif et == "field_to_register":
            key = (et, e["src"]["field_id"], e["dst"]["register_id"], e["relation"])
        elif et in {"field_to_peripheral", "controller_register_to_peripheral", "controller_field_to_peripheral"}:
            src_key = e["src"].get("field_id") or e["src"].get("register_id")
            key = (et, src_key, e["dst"]["peripheral"], e["relation"])
        else:
            key = (et, e["src"]["register_id"], e["dst"]["register_id"], e["relation"])

        if key not in grouped:
            grouped[key] = dict(e)
            grouped[key]["evidence"] = list(e.get("evidence", []))
        else:
            grouped[key]["evidence"].extend(e.get("evidence", []))
            grouped[key]["confidence"] = round(max(grouped[key]["confidence"], e["confidence"]), 4)
            if e.get("notes"):
                grouped[key].setdefault("notes", [])
                grouped[key]["notes"].extend(e.get("notes", []))

    out = []
    for e in grouped.values():
        seen = set()
        ev2 = []
        for x in e.get("evidence", []):
            k = (x.get("source"), x.get("page"), x.get("text"))
            if k in seen:
                continue
            seen.add(k)
            ev2.append(x)
        e["evidence"] = ev2
        if e.get("notes"):
            e["notes"] = list(dict.fromkeys([n for n in e.get("notes", []) if n]))
        out.append(e)

    out.sort(key=lambda x: x["edge_id"])
    return out


def _is_documented_reg(reg: Dict[str, Any]) -> bool:
    return (reg.get("documentation_status") or "") == "documented_in_pdf"


def _same_name_relation_allowed(src_reg: str, dst_reg: str, src_field: str, dst_field: str) -> bool:
    if src_field != dst_field:
        return True

    s = src_reg.upper()
    d = dst_reg.upper()

    if s in INTERRUPT_FAMILY and d in INTERRUPT_FAMILY:
        return True
    if s in CONTROL_FAMILY and d in STATUS_FAMILY:
        return True

    return False


def _directed_pair_allowed(src_reg: str, dst_reg: str) -> bool:
    s = src_reg.upper()
    d = dst_reg.upper()

    if s == "IER" and d in {"IMR", "SR", "ISR"}:
        return True
    if s == "IDR" and d in {"IMR", "SR", "ISR"}:
        return True
    if s == "ICR" and d in {"SR", "ISR"}:
        return True
    if s in CONTROL_FAMILY and d in STATUS_FAMILY:
        return True
    if s == d:
        return True
    return False


def _field_source_snippets(field: Dict[str, Any], reg: Dict[str, Any], pages: List[Dict[str, Any]], all_field_names: List[str]):
    snippets = []
    source_pages = reg.get("source_pages") or []
    page_hint = source_pages[0] if source_pages else None

    field_pdf = str(field.get("pdf_description") or "").strip()
    if field_pdf and not _looks_table_like(field_pdf):
        snippets.append({"page": page_hint, "method": "field_pdf", "text": field_pdf})
        return snippets

    reg_pdf = str(reg.get("pdf_description") or "").strip()
    if reg_pdf:
        local = _extract_field_snippets_from_lines(field.get("name") or "", _split_lines(reg_pdf), all_field_names)
        for sn in local:
            txt = sn.get("text", "")
            if txt and not _looks_table_like(txt):
                snippets.append({"page": page_hint, "method": f"reg_{sn.get('method', 'anchor')}", "text": txt})
        if snippets:
            return snippets

    raw_snippets, _ = extract_field_paragraphs(field.get("name") or "", pages, all_field_names=all_field_names)
    for sn in raw_snippets:
        txt = sn.get("text", "")
        if txt and not _looks_table_like(txt):
            snippets.append(sn)
    return snippets


def _extract_field_to_field_edges(
    merged: Dict[str, Any],
    pages: List[Dict[str, Any]],
    allow_same_register_fields: bool = True,
) -> List[Dict[str, Any]]:
    periph = merged.get("keyword") or merged.get("template_instance") or "PERIPH"

    known_regs = []
    known_fields = []
    field_to_register = {}
    allowed_fields = set()
    reg_addr_lookup = _build_register_addr_lookup(merged)
    documented_reg_names = set()

    for reg in merged.get("registers") or []:
        rname = (reg.get("name") or "").upper()
        if not rname:
            continue
        known_regs.append(rname)

        if _is_documented_reg(reg):
            documented_reg_names.add(rname)

        for field in reg.get("fields") or []:
            fname = (field.get("name") or "").upper()
            if not fname:
                continue
            fid = f"{rname}.{fname}"
            known_fields.append(fid)
            field_to_register[fid] = rname
            if _is_documented_reg(reg):
                allowed_fields.add(fid)

    edge_id = 1
    edges = []

    for reg in merged.get("registers") or []:
        rname = (reg.get("name") or "").upper()
        if rname not in documented_reg_names:
            continue

        field_names_only = [
            (f.get("name") or "").upper()
            for f in (reg.get("fields") or [])
            if f.get("name")
        ]

        for field in reg.get("fields") or []:
            fname = (field.get("name") or "").upper()
            if not fname:
                continue
            if (field.get("documentation_status") or "") == "svd_only":
                continue

            full_name = f"{rname}.{fname}"
            snippets = _field_source_snippets(field, reg, pages, field_names_only)
            if not snippets:
                continue

            for snip in snippets:
                snippet_text = snip.get("text", "")
                if not _has_field_relation_signal(snippet_text):
                    continue

                refs = extract_field_cross_references(
                    snippet_text,
                    known_fields,
                    full_name,
                    rname,
                    known_regs,
                    field_to_register,
                    allowed_fields,
                    allow_same_register=allow_same_register_fields,
                )

                for _, _, dst, matched in refs:
                    dst_reg, _, dst_field = dst.partition(".")
                    if dst_reg not in documented_reg_names:
                        continue

                    rel = _infer_relation(snippet_text, FIELD_REL_CUES, "affects")

                    if dst_field == fname and dst_reg != rname:
                        if not _same_name_relation_allowed(rname, dst_reg, fname, dst_field):
                            continue
                        if not _directed_pair_allowed(rname, dst_reg):
                            continue
                        if rel == "affects" and not _has_strong_field_relation_signal(snippet_text):
                            continue

                    if dst_field != fname and rel == "affects" and not _has_strong_field_relation_signal(snippet_text):
                        continue

                    edges.append(
                        {
                            "edge_id": f"e_f2f_{edge_id:06d}",
                            "edge_type": "field_to_field",
                            "src": {
                                "peripheral": periph,
                                "register": rname,
                                "register_addr_hex": reg_addr_lookup.get(rname),
                                "field": fname,
                                "field_id": _field_id(periph, rname, fname),
                            },
                            "dst": {
                                "peripheral": periph,
                                "register": dst_reg,
                                "register_addr_hex": reg_addr_lookup.get(dst_reg),
                                "field": dst_field,
                                "field_id": _field_id(periph, dst_reg, dst_field),
                            },
                            "relation": rel,
                            "confidence": _confidence_from_text(snippet_text, base=0.62),
                            "evidence": [
                                {
                                    "source": snip.get("method", "field_snippet"),
                                    "page": snip.get("page"),
                                    "text": snippet_text[:600],
                                }
                            ],
                            "notes": [f"matched_variants={matched}"] if matched else [],
                        }
                    )
                    edge_id += 1

    edges = _aggregate_edges(edges)
    debug(f"field_to_field edges: {len(edges)}")
    return edges


def _page_lines_with_num(pages: List[Dict[str, Any]]) -> List[Tuple[Optional[int], str]]:
    out = []
    for p in pages:
        pno = _page_num(p)
        for ln in _page_lines(p):
            out.append((pno, ln))
    return out


def _build_target_register_index(merged: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    periph = merged.get("keyword") or merged.get("template_instance") or "PERIPH"
    out = {}
    for reg in merged.get("registers") or []:
        rname = reg.get("name")
        if not rname:
            continue
        out[_reg_id(periph, rname)] = {
            "peripheral": periph,
            "register": rname,
            "register_id": _reg_id(periph, rname),
            "register_addr_hex": reg.get("absoluteAddress_hex"),
            "documentation_status": reg.get("documentation_status"),
        }
    return out


def _target_register_patterns(periph: str, reg: str) -> List[re.Pattern]:
    p = re.escape(periph.upper())
    r = re.escape(reg.upper())
    return [
        re.compile(rf"\b{p}_{r}\b", re.IGNORECASE),
        re.compile(rf"\b{p}[0-9A-Z]+_{r}\b", re.IGNORECASE),
        re.compile(rf"\b{p}\s+{r}\b", re.IGNORECASE),
    ]


def _extract_controller_edges(
    merged: Dict[str, Any],
    pages: List[Dict[str, Any]],
    controller_index: Dict[str, Any],
) -> List[Dict[str, Any]]:
    target_periph = merged.get("keyword") or merged.get("template_instance") or "PERIPH"
    controller_regs = _build_register_index_for_controllers(controller_index)
    target_regs = _build_target_register_index(merged)
    lines = _page_lines_with_num(pages)

    edges = []
    edge_id = 1
    target_periph_u = target_periph.upper()

    target_reg_pats: List[re.Pattern] = []
    for r in target_regs.values():
        target_reg_pats.extend(_target_register_patterns(target_periph, r["register"]))

    for pno, line in lines:
        u = line.upper()

        if (re.search(rf"\b{re.escape(target_periph_u)}\b", u) is None) and (not any(p.search(u) for p in target_reg_pats)):
            continue
        if not _has_controller_signal(line):
            continue

        for src_reg in controller_regs.values():
            src_name = src_reg["register"].upper()
            if re.search(rf"\b{re.escape(src_name)}\b", u) is None:
                continue

            rel1 = _infer_relation(line, CTRL_REG_TO_PERIPH_REL, "controller_affects_peripheral")
            edges.append(
                {
                    "edge_id": f"e_c2p_{edge_id:06d}",
                    "edge_type": "controller_register_to_peripheral",
                    "src": {
                        "peripheral": src_reg["peripheral"],
                        "register": src_reg["register"],
                        "register_addr_hex": src_reg["register_addr_hex"],
                        "register_id": src_reg["register_id"],
                    },
                    "dst": {
                        "peripheral": target_periph,
                        "target_kind": "peripheral",
                    },
                    "relation": rel1,
                    "confidence": _confidence_from_text(line, base=0.66),
                    "evidence": [{"source": "pdf_line", "page": pno, "text": line[:600]}],
                    "notes": [],
                }
            )
            edge_id += 1

            for dst_reg in target_regs.values():
                if (dst_reg.get("documentation_status") or "") != "documented_in_pdf":
                    continue

                dst_name = dst_reg["register"].upper()
                pats = _target_register_patterns(target_periph, dst_name)
                if not any(p.search(u) for p in pats):
                    continue

                rel2 = _infer_relation(line, CTRL_REG_TO_REG_REL, "controller_affects_register")
                edges.append(
                    {
                        "edge_id": f"e_c2r_{edge_id:06d}",
                        "edge_type": "controller_register_to_register",
                        "src": {
                            "peripheral": src_reg["peripheral"],
                            "register": src_reg["register"],
                            "register_addr_hex": src_reg["register_addr_hex"],
                            "register_id": src_reg["register_id"],
                        },
                        "dst": {
                            "peripheral": dst_reg["peripheral"],
                            "register": dst_reg["register"],
                            "register_addr_hex": dst_reg["register_addr_hex"],
                            "register_id": dst_reg["register_id"],
                        },
                        "relation": rel2,
                        "confidence": _confidence_from_text(line, base=0.70),
                        "evidence": [{"source": "pdf_line", "page": pno, "text": line[:600]}],
                        "notes": [],
                    }
                )
                edge_id += 1

    edges = _aggregate_edges(edges)
    debug(f"controller edges: {len(edges)}")
    return edges


def extract_relation_edges(
    merged_view: Dict[str, Any],
    selected_pages: List[Dict[str, Any]],
    controller_index: Optional[Dict[str, Any]] = None,
    allow_same_register_fields: bool = True,
    known_peripherals: Optional[List[str]] = None,
    relation_mode: str = "hybrid",
    llm_model: Optional[str] = None,
    llm_base_url: Optional[str] = None,
    llm_timeout: Optional[int] = None,
    llm_api_key_env: Optional[str] = None,
) -> Dict[str, Any]:
    relation_mode = (relation_mode or "hybrid").strip().lower()
    if relation_mode not in {"llm", "hybrid", "heuristic"}:
        relation_mode = "hybrid"

    known_peripherals = list(known_peripherals or [])
    llm_meta: Dict[str, Any] = {"attempted": False, "used": False}
    edges: List[Dict[str, Any]] = []

    if relation_mode in {"llm", "hybrid"}:
        if extract_relation_edges_with_llm is None:
            llm_meta = {
                "attempted": True,
                "used": False,
                "error": "llm_relation_extractor import failed",
            }
            if relation_mode == "llm":
                raise RuntimeError("LLM relation extraction requested but llm_relation_extractor.py is unavailable")
        else:
            try:
                llm_meta["attempted"] = True
                llm_edges, stats = extract_relation_edges_with_llm(
                    merged_view,
                    known_peripherals=known_peripherals,
                    model=llm_model,
                    base_url=llm_base_url,
                    timeout=llm_timeout,
                    api_key_env=llm_api_key_env,
                )
                edges = _aggregate_edges(llm_edges)
                llm_meta.update(stats)
                llm_meta["used"] = True
                debug(f"LLM relation edges: {len(edges)}")
            except LLMRelationError as e:
                llm_meta = {"attempted": True, "used": False, "error": str(e)}
                if relation_mode == "llm":
                    raise RuntimeError(f"LLM relation extraction failed: {e}")

    if not edges and relation_mode in {"hybrid", "heuristic"}:
        field_edges = _extract_field_to_field_edges(
            merged_view,
            selected_pages,
            allow_same_register_fields=allow_same_register_fields,
        )
        ctrl_edges = _extract_controller_edges(
            merged_view,
            selected_pages,
            controller_index or {},
        )
        edges = _aggregate_edges(field_edges + ctrl_edges)
        debug(f"heuristic fallback relation edges: {len(edges)}")

    debug(f"total relation edges: {len(edges)}")

    return {
        "schema": "relation_edges_v2",
        "peripheral": merged_view.get("keyword"),
        "template_instance": merged_view.get("template_instance"),
        "relation_mode": relation_mode,
        "llm": llm_meta,
        "edges": edges,
    }
