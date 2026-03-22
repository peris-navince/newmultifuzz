from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


def _fmt_hex(v: Optional[int], bits: int = 32) -> Optional[str]:
    if v is None:
        return None
    width = max(1, bits // 4)
    return "0x" + format(int(v) & ((1 << bits) - 1), f"0{width}X")


def _iter_lines(pages: List[dict]) -> List[Tuple[int, str]]:
    out = []
    for p in pages:
        pno = p.get("page_num")
        for ln in p.get("lines", []):
            if isinstance(ln, dict):
                s = str(ln.get("text", "")).strip()
            else:
                s = str(ln).strip()
            if s:
                out.append((pno, s))
    return out


def _normalize_text(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    text = re.sub(r"\s+([,.;:])", r"\1", text)
    return text


def _cleanup_block(block: str) -> str:
    block = re.sub(r"\n{2,}", "\n", block or "").strip()
    lines = []
    seen = set()
    for ln in block.splitlines():
        s = _normalize_text(ln)
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        lines.append(s)
    return "\n".join(lines)


def _derive_base_variants(peripheral_keyword: str, template_instance: Optional[str]) -> List[str]:
    """Build likely base-name variants that may appear in the manual.

    Keep only safe structural variants:
    - exact instance name from SVD (e.g. SPI1 / I2C1 / UART4)
    - trailing-digit-stripped family base (e.g. SPI / I2C / UART)

    IMPORTANT: do not mix semantically different peripherals such as UART and USART.
    """

    raw = [template_instance or "", peripheral_keyword or ""]
    bases: List[str] = []
    for x in raw:
        x = str(x or "").strip()
        if not x:
            continue
        xu = x.upper()
        bases.append(xu)
        stripped = re.sub(r"\d+$", "", xu)
        if stripped:
            bases.append(stripped)

    out: List[str] = []
    seen = set()
    for b in bases:
        b = b.strip().upper()
        if not b or b in seen:
            continue
        seen.add(b)
        out.append(b)
    return out


def _token_patterns(token: str) -> List[re.Pattern]:
    """Return patterns that tolerate common PDF text-join artifacts.

    pdfplumber sometimes returns tokens glued to following words
    (e.g. USART_CR2register), which breaks strict \b...\b matching.
    """

    tok = (token or "").strip()
    if not tok:
        return []
    esc = re.escape(tok)
    pats = [re.compile(rf"\b{esc}\b", re.IGNORECASE)]

    # Allow the token to be immediately followed by letters (glued headings)
    if len(tok) >= 4 or "_" in tok or any(c.isdigit() for c in tok):
        pats.append(re.compile(rf"\b{esc}(?=[A-Za-z])", re.IGNORECASE))
    return pats


def _build_name_patterns(base_variants_u: List[str], reg_u: str) -> List[re.Pattern]:
    pats: List[re.Pattern] = []

    # 1) exact register name, as a standalone token
    pats += _token_patterns(reg_u)

    # 2) allow matches like USART_CR2 / SPI_CR1 (suffix after underscore)
    #    ("CR2" inside "USART_CR2" has no word-boundary on the left because '_' is a word char)
    pats.append(re.compile(rf"(?<=_)\s*{re.escape(reg_u)}\b", re.IGNORECASE))
    pats.append(re.compile(rf"(?<=_)\s*{re.escape(reg_u)}(?=[A-Za-z])", re.IGNORECASE))

    # 3) instance/peripheral-prefixed tokens
    for base_u in base_variants_u or []:
        if not base_u:
            continue
        toks = [
            f"{base_u}_{reg_u}",
            f"{base_u}{reg_u}",
            f"{base_u} {reg_u}",
            f"{base_u}0_{reg_u}",
            f"{base_u}1_{reg_u}",
            f"{base_u}X_{reg_u}",
        ]
        for tok in toks:
            pats += _token_patterns(tok)

    uniq: List[re.Pattern] = []
    seen = set()
    for p in pats:
        if p.pattern in seen:
            continue
        seen.add(p.pattern)
        uniq.append(p)
    return uniq


def _title_score(line_u: str, base_variants_u: List[str], reg_u: str) -> int:
    score = 0
    if any(p.search(line_u) for p in _build_name_patterns(base_variants_u, reg_u)):
        score += 5
    if "REGISTER" in line_u:
        score += 2
    if "OFFSET" in line_u or "ADDRESS" in line_u:
        score += 1
    return score


def _extract_field_descriptions(block_text: str, field_list: List[dict]) -> Dict[str, str]:
    if not block_text:
        return {}

    lines = [ln.strip() for ln in block_text.splitlines() if ln.strip()]
    fields = [
        str(f.get("name") or "").strip()
        for f in field_list
        if str(f.get("name") or "").strip()
    ]
    fields_u = {f.upper(): f for f in fields}
    out: Dict[str, List[str]] = {}

    i = 0
    while i < len(lines):
        ln = lines[i]
        # Tolerate common manual formatting: "Bit15SWRST: ..." or "Bit 15 SWRST: ..."
        m = re.match(r"^(?:BIT\s*\d+)?\s*([A-Z][A-Z0-9_]{1,63})\b\s*[:-]?\s*(.*)$", ln.upper())
        if m and m.group(1) in fields_u:
            fname = fields_u[m.group(1)]
            buf = [ln]
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                m2 = re.match(r"^(?:BIT\s*\d+)?\s*([A-Z][A-Z0-9_]{1,63})\b\s*[:-]?", nxt.upper())
                if m2 and m2.group(1) in fields_u:
                    break
                if "REGISTER" in nxt.upper() and len(nxt) < 100:
                    break
                buf.append(nxt)
                j += 1
            out[fname] = [_cleanup_block("\n".join(buf))]
            i = j
        else:
            i += 1

    return {k: "\n".join(v) for k, v in out.items()}


def extract_register_pdf_descriptions(
    pages: List[dict],
    peripheral_keyword: str,
    svd_registers: List[dict],
    base_address: Optional[int] = None,
    template_instance: Optional[str] = None,
) -> Dict[str, Any]:
    base_variants_u = _derive_base_variants(peripheral_keyword, template_instance)
    lines = _iter_lines(pages)
    line_texts_u = [ln.upper() for _, ln in lines]

    reg_names = [
        str(r.get("name") or "").strip().upper()
        for r in svd_registers
        if str(r.get("name") or "").strip()
    ]

    anchors: List[Tuple[int, str, int]] = []
    for idx, u in enumerate(line_texts_u):
        for reg_u in reg_names:
            score = _title_score(u, base_variants_u, reg_u)
            if score >= 5:
                anchors.append((idx, reg_u, score))

    best_by_reg: Dict[str, List[int]] = {r: [] for r in reg_names}
    for idx, reg_u, score in anchors:
        best_by_reg[reg_u].append(idx)

    out: Dict[str, Any] = {}
    for r in svd_registers:
        reg_name = str(r.get("name") or "").strip()
        if not reg_name:
            continue

        reg_u = reg_name.upper()
        idxs = sorted(set(best_by_reg.get(reg_u, [])))

        blocks = []
        hit_pages = []

        for idx in idxs[:3]:
            start = idx
            end = min(len(lines), idx + 30)

            for j in range(idx + 1, min(len(lines), idx + 60)):
                u = line_texts_u[j]
                if any(
                    _title_score(u, base_variants_u, other) >= 5
                    for other in reg_names
                    if other != reg_u
                ):
                    end = j
                    break

            block_lines = [ln for _, ln in lines[start:end]]
            block = _cleanup_block("\n".join(block_lines))
            if block:
                blocks.append(block)
                hit_pages.extend([pno for pno, _ in lines[start:end] if pno is not None])

        merged_block = "\n\n".join(dict.fromkeys(blocks))
        field_desc = _extract_field_descriptions(merged_block, r.get("fields") or [])

        out[reg_name] = {
            "register_pdf_description": merged_block,
            "field_pdf_descriptions": field_desc,
            "source_pages": sorted(set(hit_pages)),
        }

    return out


def build_merged_register_view(
    svd_registers: List[dict],
    reg_pdf_map: Dict[str, Any],
    base_address: Optional[int] = None,
    include_fields: bool = True,
) -> List[Dict[str, Any]]:
    out = []

    for r in svd_registers:
        name = str(r.get("name") or "").strip()
        if not name:
            continue

        off = r.get("addressOffset")
        abs_addr = None
        if base_address is not None and off is not None:
            abs_addr = int(base_address) + int(off)

        pdf_info = reg_pdf_map.get(name, {}) if isinstance(reg_pdf_map, dict) else {}
        pdf_desc = pdf_info.get("register_pdf_description", "") or ""
        doc_status = "documented_in_pdf" if pdf_desc.strip() else "svd_only"

        entry = {
            "name": name,
            "addressOffset": off,
            "addressOffset_hex": _fmt_hex(off),
            "absoluteAddress": abs_addr,
            "absoluteAddress_hex": _fmt_hex(abs_addr),
            "size": r.get("size") or 32,
            "resetValue": r.get("resetValue"),
            "resetValue_hex": _fmt_hex(r.get("resetValue")) if r.get("resetValue") is not None else None,
            "svd_access": r.get("access"),
            "svd_description": r.get("description"),
            "pdf_description": pdf_desc,
            "source_pages": pdf_info.get("source_pages", []),
            "documentation_status": doc_status,
            "fields": [],
        }

        if include_fields:
            pdf_field_map = pdf_info.get("field_pdf_descriptions", {}) or {}
            for f in (r.get("fields") or []):
                bo = f.get("bitOffset")
                bw = f.get("bitWidth")
                bit_range = None
                if bo is not None and bw is not None and int(bw) > 0:
                    bit_range = f"[{int(bo) + int(bw) - 1}:{int(bo)}]"

                f_pdf_desc = pdf_field_map.get(f.get("name"), "") or ""
                f_doc_status = "documented_in_pdf" if f_pdf_desc.strip() else ("documented_in_pdf" if doc_status == "documented_in_pdf" else "svd_only")

                entry["fields"].append(
                    {
                        "name": f.get("name"),
                        "bitOffset": bo,
                        "bitWidth": bw,
                        "bitRange": bit_range,
                        "svd_access": f.get("access"),
                        "svd_description": f.get("description"),
                        "pdf_description": f_pdf_desc,
                        "documentation_status": f_doc_status,
                        "enumeratedValues": f.get("enumeratedValues") or [],
                    }
                )

        out.append(entry)

    return out