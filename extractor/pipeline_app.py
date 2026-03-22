from __future__ import annotations

import argparse
import copy
import json
import math
import os
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import pdfplumber

from svd_parser import parse_svd, extract_base_metadata
from pdf_register_extractor import extract_register_pdf_descriptions, build_merged_register_view
from pdf_text import extract_pages
from mmio_export import export_mmio_map_from_merged_view
from relation_extractor import extract_relation_edges
from stream_group_builder import build_stream_groups
from utils import ensure_output_dir, save_json

try:
    from chunk_postprocess import build_chunks
except Exception as _e:
    build_chunks = None
    print(f"[!] chunk_postprocess import failed: {_e}")

TOOL_VERSION = "manual_pdf_svd_extractor_v2_debug"

DEFAULT_CONTROLLERS = [
    "PMC", "RCC", "SYSCON", "NVIC", "GIC", "PIO", "GPIO", "IOCON",
    "PDC", "DMAC", "DMA", "DMAMUX", "RSTC", "PM",
]


def debug(msg: str):
    print(f"[DEBUG] {msg}")


def stage(msg: str):
    print(f"\n[STAGE] {msg}")


def _fmt_hex(v, bits=32):
    if v is None:
        return None
    try:
        v_i = int(v)
    except Exception:
        return None
    width = max(1, int(math.ceil(bits / 4)))
    if bits <= 64:
        mask = (1 << bits) - 1 if bits < 64 else (1 << 64) - 1
        v_i &= mask
    return "0x" + format(v_i, f"0{width}X")


def _get_page_num(p: Dict[str, Any]) -> Optional[int]:
    if not isinstance(p, dict):
        return None
    v = p.get("page_num", p.get("page"))
    return int(v) if isinstance(v, int) else None


def compile_keyword_pattern(keyword: str) -> re.Pattern:
    kw = (keyword or "").strip().upper()
    if not kw:
        return re.compile(r"(?!)")
    if re.fullmatch(r"[A-Z]{1,3}", kw):
        return re.compile(rf"\b{re.escape(kw)}(?:\d+|_[A-Z0-9_]+)?\b")
    return re.compile(rf"\b{re.escape(kw)}[A-Z0-9_]*\b")


def _is_safe_instance_match(name: str, target: str) -> bool:
    name_u = str(name or "").strip().upper()
    target_u = str(target or "").strip().upper()
    if not name_u or not target_u:
        return False
    if name_u == target_u:
        return True

    # Explicit, conservative aliases only. Do NOT mix UART and USART.
    alias_map = {
        'I2C': ['TWI'],
        'TWI': ['I2C'],
        'GPIO': ['PIO'],
        'PIO': ['GPIO'],
    }
    for alt in alias_map.get(target_u, []):
        if name_u == alt or re.fullmatch(rf"{re.escape(alt)}(?:\d+|[A-Z]|[A-Z]\d+)$", name_u):
            return True

    if not name_u.startswith(target_u):
        return False
    suffix = name_u[len(target_u):]
    if not suffix:
        return True
    return re.fullmatch(r"(?:\d+|[A-Z]|[A-Z]\d+)$", suffix) is not None


def find_matching_peripherals(svd_data, target):
    return [name for name in svd_data.get("peripherals", {}) if _is_safe_instance_match(name, target)]


def parse_toc(pdf_path, max_pages=30):
    pattern = re.compile(r"^(\d+)\s+(.*?)\s+(\d+)$")
    results = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages[:max_pages]:
            text = page.extract_text() or ""
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            for line in lines:
                match = pattern.match(line)
                if match:
                    chapter, title, page_str = match.groups()
                    results.append(
                        {
                            "chapter": chapter,
                            "title": title,
                            "start_page": int(page_str),
                        }
                    )
    return sorted(results, key=lambda x: x["start_page"])


def fill_end_pages(toc_list, total_pages):
    for i, entry in enumerate(toc_list):
        entry["end_page"] = (
            toc_list[i + 1]["start_page"] - 1 if i < len(toc_list) - 1 else total_pages
        )
    return toc_list


def scan_pdf_for_keyword_pages(pdf_path, keyword, start_page=None, end_page=None):
    keyword_upper = (keyword or "").strip().upper()
    register_keywords = {"REGISTER", "REGISTERS"}
    freq_dict = defaultdict(int)
    register_pages = set()
    kw_pat = compile_keyword_pattern(keyword_upper)

    with pdfplumber.open(pdf_path) as pdf:
        n_pages = len(pdf.pages)
        s = 1 if start_page is None else max(1, int(start_page))
        e = n_pages if end_page is None else min(n_pages, int(end_page))

        for i in range(s - 1, e):
            page = pdf.pages[i]
            text = page.extract_text() or ""
            upper = text.upper()

            count = len(kw_pat.findall(upper))
            freq_dict[i + 1] = count

            if any(k in upper for k in register_keywords):
                register_pages.add(i + 1)

            if count > 0:
                print(
                    f"[📄 Page {i+1:>3}] {keyword_upper} count: {count} | "
                    f"REGISTER found: {any(k in upper for k in register_keywords)}"
                )

    return freq_dict, register_pages


def scan_pdf_for_register_pages(pdf_path, base_name, register_names, scan_start=1, scan_end=None):
    """
    只在目标外设已定位页段附近进一步收缩“寄存器说明页”。
    修正点：
    - 支持 UART_CR / UART_MR / UART_SR
    - 也支持 UART0_CR / UART1_CR / UARTX_CR
    - 不再要求 UART 后面必须多一个字符
    """
    base_u = (base_name or "").strip().upper()
    regs_u = sorted({str(r).strip().upper() for r in (register_names or []) if str(r).strip()})
    freq_dict = defaultdict(int)
    register_pages = set()

    if not base_u or not regs_u:
        return freq_dict, register_pages

    token_patterns = []
    for reg in regs_u:
        token_patterns.append(re.compile(rf"\b{re.escape(base_u)}_{re.escape(reg)}\b", re.IGNORECASE))
        token_patterns.append(re.compile(rf"\b{re.escape(base_u)}[0-9A-Z]+_{re.escape(reg)}\b", re.IGNORECASE))
        token_patterns.append(re.compile(rf"\b{re.escape(base_u)}\s+{re.escape(reg)}\b", re.IGNORECASE))

    heading_re = re.compile(
        rf"\b{re.escape(base_u)}\s+REGISTERS?\b|\bREGISTER\s+MAP\b|\bREGISTER\s+DESCRIPTION\b",
        re.IGNORECASE,
    )
    generic_register_word = re.compile(r"\bREGISTERS?\b", re.IGNORECASE)

    with pdfplumber.open(pdf_path) as pdf:
        total_pages = len(pdf.pages)
        if scan_end is None:
            scan_end = total_pages
        scan_start = max(1, int(scan_start))
        scan_end = min(total_pages, int(scan_end))

        for pno in range(scan_start, scan_end + 1):
            page = pdf.pages[pno - 1]
            text = page.extract_text() or ""
            upper = text.upper()

            count = 0
            for pat in token_patterns:
                count += len(pat.findall(upper))

            if count:
                print(f"[📄 Page {pno:>3}] {base_u} register-token count: {count}")
            freq_dict[pno] = count

            if count and (heading_re.search(upper) or generic_register_word.search(upper)):
                register_pages.add(pno)

    return freq_dict, register_pages


def merge_consecutive_pages(freq_dict, register_pages, keyword, pdf_path, max_gap=2, min_total=5):
    pages = sorted([p for p, c in freq_dict.items() if c > 0])
    ranges = []
    current = []
    for p in pages:
        if not current or p - current[-1] <= max_gap:
            current.append(p)
        else:
            ranges.append(current)
            current = [p]
    if current:
        ranges.append(current)

    print("\n[🔍 Merge Phase] Candidate page groups (before filtering):")
    for g in ranges:
        print(f"  Pages {g[0]}–{g[-1]} → Count = {sum(freq_dict[p] for p in g)}")

    kw_l = str(keyword or "").strip().lower()
    ctx_re = re.compile(re.escape(kw_l) + r".{0,80}register", re.I | re.S)

    merged = []
    with pdfplumber.open(pdf_path) as pdf:
        n_pages = len(pdf.pages)
        for group in ranges:
            start, end = group[0], group[-1]
            total = sum(freq_dict[p] for p in group)

            has_register_here = any(p in register_pages for p in range(start, end + 1))

            window = 2
            s = max(1, start - window)
            e = min(n_pages, end + window)
            has_register_nearby = any(p in register_pages for p in range(s, e + 1))

            has_context = False
            if not has_register_here:
                for pno in range(start, end + 1):
                    txt = (pdf.pages[pno - 1].extract_text() or "").lower()
                    if ctx_re.search(txt):
                        has_context = True
                        break

            print(
                f"  ▶ Evaluating group {start}–{end} | count={total} | "
                f"has_register_here={has_register_here} | "
                f"has_register_nearby={has_register_nearby} | "
                f"has_context={has_context}"
            )

            accept = False
            if total >= min_total:
                if has_register_here or has_context:
                    accept = True
                elif has_register_nearby and (end - start + 1) >= 3:
                    accept = True

            if accept:
                merged.append({"start_page": start, "end_page": end, "count": total})
            else:
                print("    ❌ Rejected this group")

    return merged


def select_best_range(merged_ranges, freq_dict, max_merge_gap=5, top_k: int = 1):
    if not merged_ranges:
        print("[✗] No merged keyword regions found.")
        return []

    print("\n[📊 Selecting best keyword region...]")

    merged_groups = []
    current = [merged_ranges[0]]
    for r in merged_ranges[1:]:
        prev = current[-1]
        if r["start_page"] - prev["end_page"] <= max_merge_gap:
            current.append(r)
        else:
            merged_groups.append(current)
            current = [r]
    if current:
        merged_groups.append(current)

    total_ranges = []
    for group in merged_groups:
        start = group[0]["start_page"]
        end = group[-1]["end_page"]
        count = sum(x["count"] for x in group)
        total_ranges.append({"start_page": start, "end_page": end, "count": count})
        print(f"  ➕ Merged {start}–{end} | Total Count = {count}")

    def _len(r):
        return r["end_page"] - r["start_page"] + 1

    def _avg(r):
        return r["count"] / max(1, _len(r))

    if top_k and top_k > 1:
        ranked = sorted(
            total_ranges,
            key=lambda r: (r["count"], _len(r), _avg(r), -r["start_page"]),
            reverse=True,
        )
        picked = ranked[: max(1, int(top_k))]
        print("[✓] Multi-range mode picked:")
        for r in picked:
            print(
                f"  Pages {r['start_page']}–{r['end_page']} | "
                f"total={r['count']} | avg={_avg(r):.2f}"
            )
        return picked

    continuity = max(total_ranges, key=lambda r: (r["count"], _len(r), _avg(r), -r["start_page"]))

    print(
        f"[✓] Selected continuity winner: "
        f"Pages {continuity['start_page']}–{continuity['end_page']}"
    )
    return [continuity]


def extract_pages_by_ranges(pdf_path, ranges, strategy="layout"):
    seen_pages = set()
    result = []
    for r in ranges:
        start = int(r.get("start_page") or 1)
        for p in extract_pages(pdf_path, r["start_page"], r["end_page"], strategy=strategy):
            pn = _get_page_num(p)
            if pn is None:
                pn = start + len(result)
            if isinstance(p, dict) and p.get("page_num") is None:
                p["page_num"] = pn
            if pn in seen_pages:
                continue
            seen_pages.add(pn)
            result.append(p)

    result.sort(key=lambda x: (_get_page_num(x) or 0))
    return result


def build_controller_index(svd_info: Dict[str, Any], controller_names: List[str]) -> Dict[str, Any]:
    out = {}
    per_map = svd_info.get("peripherals", {}) or {}
    for want in controller_names:
        matches = [n for n in per_map if _is_safe_instance_match(n, want)]
        if not matches:
            continue
        chosen = sorted(matches, key=lambda x: (len(x), x))[0]
        out[chosen] = per_map[chosen]
    return out


def process_peripheral_pdf_only(args, keyword: str):
    pdf_stem = os.path.splitext(os.path.basename(args.pdf))[0]
    page_cache_path = os.path.join(args.outdir, f"{pdf_stem.lower()}_{keyword.lower()}_pages.json")
    range_cache_path = os.path.join(args.outdir, f"{keyword.lower()}_ranges.json")

    if os.path.exists(page_cache_path) and not args.force:
        debug(f"Using cached pages from {page_cache_path}")
        with open(page_cache_path, "r", encoding="utf-8") as f:
            extracted = json.load(f)
        ranges = None
        if os.path.exists(range_cache_path):
            with open(range_cache_path, "r", encoding="utf-8") as f:
                ranges = json.load(f)
        return extracted, ranges or [], None

    toc = parse_toc(args.pdf)
    with pdfplumber.open(args.pdf) as _pdf:
        total_pages = len(_pdf.pages)
    toc = fill_end_pages(toc, total_pages)
    save_json(os.path.join(args.outdir, "toc.json"), toc)

    toc_hit = None
    pat = compile_keyword_pattern(keyword)
    for entry in toc:
        title_u = str(entry.get("title") or "").upper()
        if pat.search(title_u):
            toc_hit = entry
            break

    if toc_hit:
        hint_start = int(toc_hit.get("start_page") or 1)
        hint_end = int(toc_hit.get("end_page") or hint_start)
        scan_start = max(1, hint_start - 30)
        scan_end = min(total_pages, hint_end + 30)
        debug(
            f"TOC hit for {keyword}: {toc_hit.get('title')} | "
            f"hint={hint_start}-{hint_end} | scan={scan_start}-{scan_end}"
        )
        freq_dict, reg_pages = scan_pdf_for_keyword_pages(args.pdf, keyword, scan_start, scan_end)
    else:
        debug(f"No TOC hit for {keyword}; fallback to full scan")
        freq_dict, reg_pages = scan_pdf_for_keyword_pages(args.pdf, keyword)

    merged_ranges = merge_consecutive_pages(
        freq_dict,
        reg_pages,
        keyword,
        args.pdf,
        min_total=args.min_total,
    )
    final_ranges = select_best_range(merged_ranges, freq_dict, top_k=1)

    if not final_ranges and toc_hit:
        debug("TOC-guided scan failed; retrying full-document keyword scan")
        freq_dict, reg_pages = scan_pdf_for_keyword_pages(args.pdf, keyword)
        merged_ranges = merge_consecutive_pages(
            freq_dict,
            reg_pages,
            keyword,
            args.pdf,
            min_total=args.min_total,
        )
        final_ranges = select_best_range(merged_ranges, freq_dict, top_k=1)

    if not final_ranges:
        raise RuntimeError(f"No keyword-heavy region found for {keyword}")

    save_json(range_cache_path, final_ranges)

    extracted = extract_pages_by_ranges(args.pdf, final_ranges, strategy=args.extract_strategy)
    save_json(page_cache_path, extracted)
    return extracted, final_ranges, toc_hit


def process_peripheral_with_svd(svd_info: Dict[str, Any], args, keyword: str):
    matched_instances = find_matching_peripherals(svd_info, keyword)
    if not matched_instances:
        raise RuntimeError(f"Peripheral '{keyword}' not found in SVD")

    # 这里仍然保留结构锚点加载，但它不参与主页面定位。
    base_meta = extract_base_metadata(svd_info, keyword)
    template = base_meta.get("template") or matched_instances[0]
    save_json(os.path.join(args.outdir, f"{keyword.lower()}_svd_meta.json"), base_meta)

    target_per = (svd_info.get("peripherals", {}) or {}).get(template, {}) or {}
    raw_regs_tpl = target_per.get("registers", [])
    base_addr = target_per.get("baseAddress")

    debug(f"matched target instances: {matched_instances}")
    debug(f"selected template instance: {template}")
    debug(f"target register count: {len(raw_regs_tpl)}")

    controller_index = build_controller_index(svd_info, args.controllers)
    debug(f"controller peripherals found: {sorted(controller_index.keys())}")

    stage("1. Locate target peripheral pages (PDF-first)")
    extracted, final_ranges, toc_hit = process_peripheral_pdf_only(args, keyword)
    debug(f"peripheral ranges: {final_ranges}")
    debug(f"extracted peripheral pages: {[ _get_page_num(p) for p in extracted ]}")

    stage("2. Register-page refinement (still target-only)")
    register_region_pages = extracted

    if args.scan_registers:
        reg_names = [r.get("name") for r in raw_regs_tpl if r.get("name")]
        debug(f"register-scan enabled with {len(reg_names)} SVD registers")

        if reg_names:
            base_pages = [pn for pn in (_get_page_num(p) for p in extracted) if pn is not None]
            base_start = min(base_pages) if base_pages else 1
            base_end = max(base_pages) if base_pages else None

            pad = int(args.periph_pad or 0)
            base_start = max(1, base_start - pad)

            with pdfplumber.open(args.pdf) as pdf:
                total_pages = len(pdf.pages)
            base_end = min(total_pages, (base_end or total_pages) + pad)

            freq_dict, register_pages = scan_pdf_for_register_pages(
                args.pdf,
                keyword,
                reg_names,
                scan_start=base_start,
                scan_end=base_end,
            )

            merged_ranges = merge_consecutive_pages(
                freq_dict,
                register_pages,
                keyword,
                args.pdf,
                max_gap=args.reg_max_gap,
                min_total=args.reg_min_total,
            )

            reg_final_ranges = select_best_range(merged_ranges, freq_dict, top_k=1)
            debug(f"register ranges: {reg_final_ranges}")

            if reg_final_ranges:
                pad2 = 1
                selected_pages = set()
                for r in reg_final_ranges:
                    s = max(base_start, int(r["start_page"]) - pad2)
                    e = min(base_end, int(r["end_page"]) + pad2)
                    for pg in range(s, e + 1):
                        selected_pages.add(pg)

                reg_pages_extra = (
                    extract_pages_by_ranges(
                        args.pdf,
                        [
                            {
                                "start_page": min(selected_pages),
                                "end_page": max(selected_pages),
                                "count": len(selected_pages),
                            }
                        ],
                        strategy=args.extract_strategy,
                    )
                    if selected_pages
                    else []
                )

                merged_union = []
                seen = set()

                for p in extracted:
                    pn = _get_page_num(p)
                    if pn not in seen:
                        merged_union.append(p)
                        seen.add(pn)

                for p in reg_pages_extra:
                    pn = _get_page_num(p)
                    if pn not in seen and pn in selected_pages:
                        merged_union.append(p)
                        seen.add(pn)

                merged_union.sort(key=lambda x: _get_page_num(x) or 0)
                register_region_pages = merged_union
            else:
                debug("register scan found no confident sub-region; keep peripheral pages")

    selected_pages_path = os.path.join(args.outdir, f"{keyword.lower()}_selected_pages.json")
    save_json(selected_pages_path, register_region_pages)
    debug(f"analysis pages: {[ _get_page_num(p) for p in register_region_pages ]}")

    stage("3. Extract register descriptions from PDF")
    reg_pdf_map = extract_register_pdf_descriptions(
        register_region_pages,
        keyword,
        raw_regs_tpl,
        base_address=base_addr,
        template_instance=template,
    )
    reg_pdf_path = os.path.join(args.outdir, f"{keyword.lower()}_register_pdf_descriptions.json")
    save_json(reg_pdf_path, reg_pdf_map)

    found_blocks = sum(1 for _, v in reg_pdf_map.items() if v.get("register_pdf_description"))
    debug(f"registers with extracted pdf blocks: {found_blocks}")

    stage("4. Build merged register view")
    merged_regs = build_merged_register_view(
        raw_regs_tpl,
        reg_pdf_map,
        base_address=base_addr,
        include_fields=True,
    )

    instances_meta_hex = []
    for inst in matched_instances:
        per = (svd_info.get("peripherals", {}) or {}).get(inst, {}) or {}
        ba = per.get("baseAddress")
        try:
            ba_i = int(ba) if ba is not None else None
        except Exception:
            ba_i = None

        instances_meta_hex.append(
            {
                "name": inst,
                "baseAddress": ba_i,
                "baseAddress_hex": _fmt_hex(ba_i, 32) if ba_i is not None else None,
                "description": (per.get("description") or "").strip(),
            }
        )

    merged_view = {
        "keyword": keyword,
        "template_instance": template,
        "baseAddress": base_addr,
        "baseAddress_hex": _fmt_hex(base_addr, 32),
        "instances": instances_meta_hex,
        "registers": merged_regs,
        "tool_version": TOOL_VERSION,
    }

    merged_path = os.path.join(args.outdir, f"{keyword.lower()}_register_merged.json")
    save_json(merged_path, merged_view)
    debug(f"merged register count: {len(merged_regs)}")

    stage("5. Export MMIO map")
    mmio_map = export_mmio_map_from_merged_view(merged_view)
    mmio_path = os.path.join(args.outdir, f"{keyword.lower()}_mmio_map.json")
    save_json(mmio_path, mmio_map)
    debug(f"mmio register count: {len(mmio_map.get('registers', []))}")

    stage("6. Extract relation edges")
    relation_edges = extract_relation_edges(
        merged_view=merged_view,
        selected_pages=register_region_pages,
        controller_index=controller_index,
        allow_same_register_fields=True,
        known_peripherals=sorted((svd_info.get("peripherals", {}) or {}).keys()),
        relation_mode=args.relation_mode,
        llm_model=args.llm_model,
        llm_base_url=args.llm_base_url,
        llm_timeout=args.llm_timeout,
        llm_api_key_env=args.llm_api_key_env,
    )
    relation_path = os.path.join(args.outdir, f"{keyword.lower()}_relation_edges.json")
    save_json(relation_path, relation_edges)
    debug(f"relation edge count: {len(relation_edges.get('edges', []))}")

    stage("7. Build stream groups")
    groups = build_stream_groups(relation_edges, mmio_map)
    groups_path = os.path.join(args.outdir, f"{keyword.lower()}_stream_groups.json")
    save_json(groups_path, groups)
    debug(f"stream group count: {len(groups.get('groups', []))}")

    chunk_outputs = []
    if not args.no_chunks and build_chunks is not None:
        stage("8. Chunk post-process")
        chunks_path = os.path.join(args.outdir, f"{keyword.lower()}_chunks.jsonl")
        build_chunks(
            merged_path,
            relation_path,
            chunks_path,
        )
        chunk_outputs = [chunks_path]
        debug(f"chunk outputs: {chunk_outputs}")

    manifest = {
        "tool_version": TOOL_VERSION,
        "pdf": os.path.abspath(args.pdf),
        "svd": os.path.abspath(args.svd),
        "peripheral": keyword,
        "matched_instances": matched_instances,
        "template_instance": template,
        "controller_peripherals_found": sorted(controller_index.keys()),
        "ranges": final_ranges,
        "relation_mode": args.relation_mode,
        "llm_model": args.llm_model,
        "artifacts": {
            "selected_pages": selected_pages_path,
            "register_pdf_descriptions": reg_pdf_path,
            "register_merged": merged_path,
            "mmio_map": mmio_path,
            "relation_edges": relation_path,
            "stream_groups": groups_path,
            "chunk_outputs": chunk_outputs,
        },
    }

    manifest_path = os.path.join(args.outdir, f"{keyword.lower()}_debug_manifest.json")
    save_json(manifest_path, manifest)

    print("\n[OK] Pipeline finished.")
    print(f"[OK] Manifest: {manifest_path}")
    return manifest


def build_argparser():
    ap = argparse.ArgumentParser(
        description="PDF+SVD extraction pipeline for MultiFuzz semantics"
    )
    ap.add_argument("--pdf", required=True, help="Path to target PDF manual")
    ap.add_argument("--svd", required=True, help="Path to SVD file")
    ap.add_argument("--outdir", default="output", help="Output directory")
    ap.add_argument(
        "--extract-strategy",
        default="layout",
        choices=["layout", "plain"],
        help="PDF text extraction strategy",
    )
    ap.add_argument("--peripheral", default=None, help="Single peripheral keyword, e.g. UART")
    ap.add_argument("--peripherals", nargs="*", default=None, help="Multiple peripheral keywords")
    ap.add_argument("--force", action="store_true", help="Force re-extraction even if cache exists")

    ap.add_argument("--min-total", type=int, default=5)
    ap.add_argument("--periph-pad", type=int, default=20)

    ap.add_argument(
        "--scan-registers",
        dest="scan_registers",
        action="store_true",
        default=True,
        help="Refine pages using SVD register names (default on)",
    )
    ap.add_argument(
        "--no-scan-registers",
        dest="scan_registers",
        action="store_false",
        help="Disable register page refinement",
    )

    ap.add_argument("--reg-min-total", type=int, default=4)
    ap.add_argument("--reg-max-gap", type=int, default=2)

    ap.add_argument(
        "--controllers",
        default=",".join(DEFAULT_CONTROLLERS),
        help="Comma-separated controller peripheral prefixes",
    )

    ap.add_argument(
        "--relation-mode",
        choices=["llm", "hybrid", "heuristic"],
        default=os.getenv("EXTRACTOR_RELATION_MODE", "hybrid"),
        help="Relation extraction mode: llm, hybrid, or heuristic",
    )
    ap.add_argument(
        "--llm-model",
        default=os.getenv("EXTRACTOR_LLM_MODEL", "gpt-5"),
        help="LLM model name for relation extraction",
    )
    ap.add_argument(
        "--llm-base-url",
        default=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        help="OpenAI-compatible base URL for relation extraction",
    )
    ap.add_argument(
        "--llm-timeout",
        type=int,
        default=int(os.getenv("EXTRACTOR_LLM_TIMEOUT", "120")),
        help="HTTP timeout for the LLM relation extractor",
    )
    ap.add_argument(
        "--llm-api-key-env",
        default=os.getenv("EXTRACTOR_LLM_API_KEY_ENV", "OPENAI_API_KEY"),
        help="Environment variable containing the API key for the LLM relation extractor",
    )

    ap.add_argument("--no-chunks", action="store_true")
    return ap


def main():
    ap = build_argparser()
    args = ap.parse_args()

    ensure_output_dir(args.outdir)
    args.controllers = [x.strip() for x in (args.controllers or "").split(",") if x.strip()]

    # 统一收集外设列表
    if args.peripheral:
        per_list = [args.peripheral]
    elif args.peripherals:
        per_list = []
        for x in args.peripherals:
            per_list.extend([y.strip() for y in str(x).split(",") if y.strip()])
    else:
        raise SystemExit("[!] Please provide --peripheral UART or --peripherals UART SPI ...")

    # 去重，同时保持顺序
    seen = set()
    final_per_list = []
    for kw in per_list:
        kw_u = kw.strip().upper()
        if not kw_u or kw_u in seen:
            continue
        seen.add(kw_u)
        final_per_list.append(kw_u)

    debug(f"requested peripherals: {final_per_list}")

    svd_info = parse_svd(args.svd)

    for kw in final_per_list:
        print("\n" + "=" * 80)
        print(f"[RUN] Peripheral: {kw}")
        print("=" * 80)

        # 每个外设单独一个子目录
        sub_args = copy.deepcopy(args)
        sub_args.outdir = os.path.join(args.outdir, kw.lower())
        ensure_output_dir(sub_args.outdir)

        process_peripheral_with_svd(svd_info, sub_args, kw)


if __name__ == "__main__":
    main()