#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build a compact contract bundle for hotspot-guided stuck attribution.

This version is backward-compatible with the v5 bundle shape used earlier,
but adds relative-offset rarity / IDF weighting so that common offsets such as
RTC 0x0 / 0x8 / 0x14 / 0x1c do not dominate the ranking.

Inputs
------
- ghidra_export.json from Ghidra headless export.
- hot MMIO addresses observed from fuzzing / hotspot plateau.
- optional extractor/.shared_pdf_svd_cache root for PDF+SVD evidence.

Output
------
A bundle JSON with:
- hot MMIO address to document matches
- anchor candidates with scoring evidence
- selected neighborhood functions with excerpts and MMIO summaries
- offset rarity statistics for debugging / regression checks
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# -----------------------------
# Helpers
# -----------------------------

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


def safe_read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def truncate_text(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"


def compact_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def excerpt_around_keywords(text: str, keywords: Iterable[str], window: int = 2200) -> str:
    text = text or ""
    if not text:
        return text
    low = text.lower()
    positions: List[int] = []
    for kw in keywords:
        kw = (kw or "").lower()
        if not kw:
            continue
        idx = low.find(kw)
        if idx >= 0:
            positions.append(idx)
    if not positions:
        return truncate_text(text, window)
    start = max(0, min(positions) - window // 3)
    end = min(len(text), start + window)
    return text[start:end]


def dedup_preserve(seq: Iterable[Any]) -> List[Any]:
    seen: Set[str] = set()
    out: List[Any] = []
    for item in seq:
        try:
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        except Exception:
            key = repr(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def acc_addr_int(acc: Dict[str, Any]) -> Optional[int]:
    return maybe_hex_to_int(acc.get("address")) or maybe_hex_to_int(acc.get("address_hex"))


def relative_offset_int(acc: Dict[str, Any]) -> Optional[int]:
    return maybe_hex_to_int(acc.get("offset")) or maybe_hex_to_int(acc.get("offset_hex"))


def acc_base_int(acc: Dict[str, Any]) -> Optional[int]:
    return maybe_hex_to_int(acc.get("base")) or maybe_hex_to_int(acc.get("base_hex"))


def boolish(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y"}


# -----------------------------
# Cache loading
# -----------------------------

@dataclass
class PeripheralCache:
    cache_dir: Path
    peripheral: str
    mmio_map: Dict[str, Any]
    svd_meta: Optional[Dict[str, Any]]
    register_pdf_descriptions: Optional[Dict[str, Any]]
    relation_edges: Optional[Dict[str, Any]]
    chunks: List[Dict[str, Any]]
    registers_by_addr: List[Dict[str, Any]]


@dataclass
class PeripheralSpan:
    cache_dir: Path
    peripheral: str
    base_address: Optional[int]
    min_reg_addr: int
    max_reg_end: int
    register_count: int


class CacheRegistry:
    def __init__(self, root: Optional[Path]) -> None:
        self.root = root
        self.caches: List[PeripheralCache] = []
        if root and root.exists():
            self.caches = self._discover(root)

    def _discover(self, root: Path) -> List[PeripheralCache]:
        caches: List[PeripheralCache] = []
        for sub in sorted(p for p in root.iterdir() if p.is_dir()):
            mmio_map_files = list(sub.glob("*_mmio_map.json"))
            if not mmio_map_files:
                continue
            mmio_map = safe_read_json(mmio_map_files[0])
            svd_meta_file = next(iter(sub.glob("*_svd_meta.json")), None)
            reg_pdf_file = next(iter(sub.glob("*_register_pdf_descriptions.json")), None)
            relation_file = next(iter(sub.glob("*_relation_edges.json")), None)
            chunks_file = next(iter(sub.glob("*_chunks.jsonl")), None)
            registers = list(mmio_map.get("registers", []))
            registers_by_addr = sorted(
                registers,
                key=lambda r: maybe_hex_to_int(r.get("absoluteAddress"))
                or maybe_hex_to_int(r.get("absoluteAddress_hex"))
                or 0,
            )
            caches.append(
                PeripheralCache(
                    cache_dir=sub,
                    peripheral=str(mmio_map.get("peripheral") or sub.name),
                    mmio_map=mmio_map,
                    svd_meta=safe_read_json(svd_meta_file) if svd_meta_file else None,
                    register_pdf_descriptions=safe_read_json(reg_pdf_file) if reg_pdf_file else None,
                    relation_edges=safe_read_json(relation_file) if relation_file else None,
                    chunks=safe_read_jsonl(chunks_file) if chunks_file else [],
                    registers_by_addr=registers_by_addr,
                )
            )
        return caches

    def match_address(self, addr: int) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for cache in self.caches:
            for reg in cache.registers_by_addr:
                reg_addr = maybe_hex_to_int(reg.get("absoluteAddress"))
                if reg_addr is None:
                    reg_addr = maybe_hex_to_int(reg.get("absoluteAddress_hex"))
                if reg_addr is None:
                    continue
                size_bytes = reg.get("size_bytes")
                if size_bytes is None:
                    size_bits = reg.get("size_bits")
                    size_bytes = max(1, int(size_bits or 8) // 8)
                reg_end = reg_addr + int(size_bytes)
                if reg_addr <= addr < reg_end:
                    matches.append(self._build_register_match(cache, reg, addr))
        return matches

    def get_spans_for_address(self, addr: int) -> List[PeripheralSpan]:
        spans: List[PeripheralSpan] = []
        seen: Set[Tuple[str, int, int]] = set()
        for cache in self.caches:
            ranges: List[Tuple[int, int]] = []
            contains = False
            for reg in cache.registers_by_addr:
                reg_addr = maybe_hex_to_int(reg.get("absoluteAddress"))
                if reg_addr is None:
                    reg_addr = maybe_hex_to_int(reg.get("absoluteAddress_hex"))
                if reg_addr is None:
                    continue
                size_bytes = reg.get("size_bytes")
                if size_bytes is None:
                    size_bits = reg.get("size_bits")
                    size_bytes = max(1, int(size_bits or 8) // 8)
                reg_end = reg_addr + int(size_bytes)
                ranges.append((reg_addr, reg_end))
                if reg_addr <= addr < reg_end:
                    contains = True
            if not contains or not ranges:
                continue
            min_reg_addr = min(x[0] for x in ranges)
            max_reg_end = max(x[1] for x in ranges)
            base_address = maybe_hex_to_int(cache.mmio_map.get("baseAddress")) or maybe_hex_to_int(
                cache.mmio_map.get("baseAddress_hex")
            )
            key = (str(cache.cache_dir), min_reg_addr, max_reg_end)
            if key in seen:
                continue
            seen.add(key)
            spans.append(
                PeripheralSpan(
                    cache_dir=cache.cache_dir,
                    peripheral=cache.peripheral,
                    base_address=base_address,
                    min_reg_addr=min_reg_addr,
                    max_reg_end=max_reg_end,
                    register_count=len(ranges),
                )
            )
        return spans

    def _build_register_match(self, cache: PeripheralCache, reg: Dict[str, Any], addr: int) -> Dict[str, Any]:
        reg_addr = maybe_hex_to_int(reg.get("absoluteAddress"))
        if reg_addr is None:
            reg_addr = maybe_hex_to_int(reg.get("absoluteAddress_hex")) or 0
        fields = reg.get("fields", [])
        reg_name = str(reg.get("name") or "")
        chunk_matches = self._select_relevant_chunks(cache, reg_name, addr, fields)
        relation_matches = self._select_relation_edges(cache, reg_name, fields)
        span_summary = []
        for sp in self.get_spans_for_address(addr):
            if sp.cache_dir != cache.cache_dir:
                continue
            span_summary.append(
                {
                    "peripheral": sp.peripheral,
                    "base_address_hex": hex_norm(sp.base_address) if sp.base_address is not None else None,
                    "min_reg_addr_hex": hex_norm(sp.min_reg_addr),
                    "max_reg_end_hex": hex_norm(sp.max_reg_end),
                    "register_count": sp.register_count,
                }
            )
        return {
            "cache_dir": str(cache.cache_dir),
            "peripheral": cache.peripheral,
            "register": {
                "name": reg_name,
                "absoluteAddress_hex": reg.get("absoluteAddress_hex") or hex_norm(reg_addr),
                "addressOffset_hex": reg.get("addressOffset_hex"),
                "size_bits": reg.get("size_bits"),
                "size_bytes": reg.get("size_bytes"),
                "svd_access": reg.get("svd_access"),
                "svd_description": reg.get("svd_description"),
                "pdf_description": truncate_text(str(reg.get("pdf_description") or ""), 3000),
                "documentation_status": reg.get("documentation_status"),
                "fields": [
                    {
                        "name": f.get("name"),
                        "bitOffset": f.get("bitOffset"),
                        "bitWidth": f.get("bitWidth"),
                        "bitRange": f.get("bitRange"),
                        "mask_hex": f.get("mask_hex"),
                        "svd_access": f.get("svd_access"),
                        "svd_description": f.get("svd_description"),
                        "pdf_description": truncate_text(str(f.get("pdf_description") or ""), 600),
                        "documentation_status": f.get("documentation_status"),
                    }
                    for f in fields
                ],
            },
            "mmio_map_summary": {
                "baseAddress_hex": cache.mmio_map.get("baseAddress_hex"),
                "template_instance": cache.mmio_map.get("template_instance"),
                "status_register_candidates": cache.mmio_map.get("status_register_candidates", []),
            },
            "svd_meta_summary": {
                "template": (cache.svd_meta or {}).get("template"),
                "template_description": (cache.svd_meta or {}).get("template_description"),
                "matched_instances": (cache.svd_meta or {}).get("matched_instances"),
            },
            "peripheral_span_summary": span_summary,
            "pdf_chunk_matches": chunk_matches,
            "relation_edge_matches": relation_matches,
        }

    def _select_relevant_chunks(
        self,
        cache: PeripheralCache,
        reg_name: str,
        addr: int,
        fields: List[Dict[str, Any]],
        max_chunks: int = 6,
    ) -> List[Dict[str, Any]]:
        reg_addr_hex = hex_norm(addr)
        field_names = {str(f.get("name") or "").lower() for f in fields if f.get("name")}
        scored: List[Tuple[int, Dict[str, Any]]] = []
        for chunk in cache.chunks:
            try:
                text = json.dumps(chunk, ensure_ascii=False).lower()
            except Exception:
                text = str(chunk).lower()
            score = 0
            if str(chunk.get("chunk_type") or "") == "register" and str(chunk.get("register") or "").lower() == reg_name.lower():
                score += 5
            if reg_name and reg_name.lower() in text:
                score += 3
            if reg_addr_hex.lower() in text:
                score += 3
            for fn in field_names:
                if fn and fn in text:
                    score += 1
            if score > 0:
                scored.append((score, chunk))
        scored.sort(key=lambda x: x[0], reverse=True)
        out: List[Dict[str, Any]] = []
        for score, chunk in scored[:max_chunks]:
            entry = {"score": score, **chunk}
            if "pdf_description" in entry:
                entry["pdf_description"] = truncate_text(str(entry.get("pdf_description") or ""), 1200)
            out.append(entry)
        return out

    def _select_relation_edges(
        self,
        cache: PeripheralCache,
        reg_name: str,
        fields: List[Dict[str, Any]],
        max_edges: int = 8,
    ) -> List[Dict[str, Any]]:
        rel = cache.relation_edges
        if rel is None:
            return []
        if isinstance(rel, dict):
            raw_edges = rel.get("edges", [])
        elif isinstance(rel, list):
            raw_edges = rel
        else:
            raw_edges = []
        reg_name_low = reg_name.lower()
        field_names = {str(f.get("name") or "").lower() for f in fields if f.get("name")}
        scored: List[Tuple[int, Dict[str, Any]]] = []
        for edge in raw_edges:
            try:
                text = json.dumps(edge, ensure_ascii=False).lower()
            except Exception:
                text = str(edge).lower()
            score = 0
            if reg_name_low and reg_name_low in text:
                score += 3
            for fn in field_names:
                if fn and fn in text:
                    score += 1
            if score > 0:
                scored.append((score, edge))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"score": s, **e} for s, e in scored[:max_edges]]


# -----------------------------
# Ghidra export helpers
# -----------------------------

def load_ghidra_export(path: Path) -> Dict[str, Any]:
    data = safe_read_json(path)
    if "functions" not in data:
        raise ValueError(f"{path} does not look like a ghidra_export.json")
    return data


def build_reverse_callers(functions: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    callers: Dict[str, Set[str]] = defaultdict(set)
    names = {str(f.get("name")) for f in functions}
    for f in functions:
        src = str(f.get("name"))
        for callee in f.get("calls", []) or []:
            callee = str(callee)
            if callee in names:
                callers[callee].add(src)
    return callers


# -----------------------------
# Scoring and selection
# -----------------------------

LIBC_NOISE_PATTERNS = [
    r"^_printf",
    r"^_scanf",
    r"^__s",
    r"^_vfprintf",
    r"^_puts",
    r"^write$",
    r"^read$",
    r"^_malloc",
    r"^_free",
    r"^mktime$",
    r"^gmtime",
    r"^_tz",
    r"^clist_",
    r"^list_",
    r"^validate_structure$",
    r"^phydat_dump$",
    r"^memcmp$",
    r"^memcpy$",
    r"^memset$",
]


def is_likely_libc_noise(name: str) -> bool:
    low = name.lower()
    return any(re.search(pat, low) for pat in LIBC_NOISE_PATTERNS)


def peripheral_aliases(peripheral: str) -> List[str]:
    p = peripheral.lower()
    aliases = {p}
    aliases.add(re.sub(r"\d+$", "", p))
    aliases.add(re.sub(r"[^a-z0-9]+", "", p))
    if p.startswith("uart"):
        aliases.update({"uart", "uart0", "uart_stdio"})
    if p == "rtc":
        aliases.update({"rtc", "rtt"})
    if p.startswith("spi"):
        aliases.update({"spi"})
    if p.startswith("i2c"):
        aliases.update({"i2c", "twi"})
    if p.startswith("twi"):
        aliases.update({"i2c", "twi"})
    if p.startswith("gpio") or p.startswith("pio"):
        aliases.update({"gpio", "port", "pio"})
    if p.startswith("timer") or p.startswith("tc"):
        aliases.update({"timer", "tc"})
    return sorted(a for a in aliases if a)


def build_offset_targets(doc_matches: List[Dict[str, Any]]) -> Tuple[Set[int], Dict[int, List[str]]]:
    offsets: Set[int] = set()
    offset_to_regs: Dict[int, List[str]] = defaultdict(list)
    for doc in doc_matches:
        reg = doc.get("register") or {}
        off = maybe_hex_to_int(reg.get("addressOffset_hex"))
        if off is None:
            abs_addr = maybe_hex_to_int(reg.get("absoluteAddress_hex"))
            base_hex = maybe_hex_to_int((doc.get("mmio_map_summary") or {}).get("baseAddress_hex"))
            if abs_addr is not None and base_hex is not None:
                off = abs_addr - base_hex
        if off is None:
            continue
        offsets.add(off)
        rn = str(reg.get("name") or "")
        if rn:
            offset_to_regs[off].append(rn)
    return offsets, {k: sorted(set(v)) for k, v in offset_to_regs.items()}


@dataclass
class HotPeripheralSpec:
    peripheral: str
    aliases: List[str]
    hot_addresses: Set[int]
    target_offsets: Set[int]
    offset_to_registers: Dict[int, List[str]]
    spans: List[PeripheralSpan]
    span_bases: Set[int]
    doc_matches_by_addr: Dict[int, List[Dict[str, Any]]]


def infer_hot_peripheral_specs(hot_mmio: Set[int], cache_registry: CacheRegistry) -> List[HotPeripheralSpec]:
    periph_to_addrs: Dict[str, Set[int]] = defaultdict(set)
    periph_to_docs: Dict[str, Dict[int, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    periph_to_spans: Dict[str, List[PeripheralSpan]] = defaultdict(list)
    for addr in hot_mmio:
        docs = cache_registry.match_address(addr)
        spans = cache_registry.get_spans_for_address(addr)
        for doc in docs:
            p = str(doc.get("peripheral") or "")
            if not p:
                continue
            periph_to_addrs[p].add(addr)
            periph_to_docs[p][addr].append(doc)
        for sp in spans:
            periph_to_spans[sp.peripheral].append(sp)
            if sp.peripheral not in periph_to_addrs:
                periph_to_addrs[sp.peripheral] = set()
    specs: List[HotPeripheralSpec] = []
    for periph in sorted(set(periph_to_addrs) | set(periph_to_spans)):
        docs_by_addr = periph_to_docs.get(periph, {})
        flattened_docs = [doc for addr in docs_by_addr for doc in docs_by_addr[addr]]
        target_offsets, offset_to_regs = build_offset_targets(flattened_docs)
        spans = dedup_spans(periph_to_spans.get(periph, []))
        span_bases = {sp.base_address for sp in spans if sp.base_address is not None}
        specs.append(
            HotPeripheralSpec(
                peripheral=periph,
                aliases=peripheral_aliases(periph),
                hot_addresses=set(periph_to_addrs.get(periph, set())),
                target_offsets=target_offsets,
                offset_to_registers=offset_to_regs,
                spans=spans,
                span_bases=span_bases,
                doc_matches_by_addr=dict(docs_by_addr),
            )
        )
    return specs


def dedup_spans(spans: List[PeripheralSpan]) -> List[PeripheralSpan]:
    seen: Set[Tuple[str, int, int]] = set()
    out: List[PeripheralSpan] = []
    for sp in spans:
        key = (sp.peripheral, sp.min_reg_addr, sp.max_reg_end)
        if key in seen:
            continue
        seen.add(key)
        out.append(sp)
    return out


def text_related_for_peripheral(func: Dict[str, Any], aliases: List[str], target_offsets: Set[int]) -> Tuple[List[str], List[int]]:
    text = "\n".join(
        [
            str(func.get("name") or ""),
            str(func.get("signature") or ""),
            str(func.get("decompile") or ""),
            str(func.get("disassembly") or ""),
        ]
    ).lower()
    alias_hits = [a for a in aliases if a and a.lower() in text]
    offset_hits: List[int] = []
    for off in sorted(target_offsets):
        off_hex = hex_norm(off).lower()
        short_hex = hex(off).lower()
        if off_hex in text or short_hex in text:
            offset_hits.append(off)
    return sorted(set(alias_hits)), sorted(set(offset_hits))


def access_in_spans(acc: Dict[str, Any], spans: List[PeripheralSpan]) -> bool:
    addr = acc_addr_int(acc)
    if addr is None:
        return False
    for sp in spans:
        if sp.min_reg_addr <= addr < sp.max_reg_end:
            return True
    return False


def relative_access_matches_spec(acc: Dict[str, Any], spec: HotPeripheralSpec) -> bool:
    off = relative_offset_int(acc)
    if off is None or off not in spec.target_offsets:
        return False
    base = acc_base_int(acc)
    if base is None:
        return True
    if not spec.span_bases:
        return True
    return base in spec.span_bases


def compute_relative_offset_df(functions: List[Dict[str, Any]]) -> Dict[int, int]:
    df: Counter[int] = Counter()
    for func in functions:
        seen_offsets: Set[int] = set()
        for acc in func.get("relative_mmio_accesses", []) or []:
            off = relative_offset_int(acc)
            if off is not None:
                seen_offsets.add(off)
        for off in seen_offsets:
            df[off] += 1
    return dict(df)


def compute_relative_offset_idf(df: Dict[int, int], function_count: int) -> Dict[int, float]:
    idf: Dict[int, float] = {}
    n = max(1, function_count)
    for off, freq in df.items():
        idf[off] = math.log((n + 1.0) / (freq + 1.0)) + 1.0
    return idf


def callgraph_distance_map(functions: List[Dict[str, Any]], anchor_names: Set[str]) -> Dict[str, int]:
    by_name = {str(f.get("name")): f for f in functions}
    callers = build_reverse_callers(functions)
    q = deque((name, 0) for name in anchor_names if name in by_name)
    dist: Dict[str, int] = {name: 0 for name in anchor_names if name in by_name}
    while q:
        name, depth = q.popleft()
        f = by_name.get(name)
        if f is None:
            continue
        for callee in f.get("calls", []) or []:
            callee = str(callee)
            if callee in by_name and callee not in dist:
                dist[callee] = depth + 1
                q.append((callee, depth + 1))
        for caller in callers.get(name, set()):
            if caller in by_name and caller not in dist:
                dist[caller] = depth + 1
                q.append((caller, depth + 1))
    return dist


def score_function_against_spec(
    func: Dict[str, Any],
    spec: HotPeripheralSpec,
    offset_df: Dict[int, int],
    offset_idf: Dict[int, float],
) -> Dict[str, Any]:
    name = str(func.get("name") or "")
    mmio_accesses = list(func.get("mmio_accesses", []) or [])
    rel_accesses = list(func.get("relative_mmio_accesses", []) or [])

    abs_hot_hits = [acc for acc in mmio_accesses if acc_addr_int(acc) in spec.hot_addresses]
    span_hot_hits = [acc for acc in mmio_accesses if access_in_spans(acc, spec.spans)]
    rel_hot_hits = [acc for acc in rel_accesses if relative_access_matches_spec(acc, spec)]
    rel_hot_offsets = sorted({relative_offset_int(acc) for acc in rel_hot_hits if relative_offset_int(acc) is not None})
    rel_span_hits = [
        acc
        for acc in rel_accesses
        if (acc_base_int(acc) in spec.span_bases) or (not spec.span_bases and relative_offset_int(acc) is not None)
    ]

    name_alias_hits = [a for a in spec.aliases if a and a.lower() in name.lower()]
    text_alias_hits, text_offset_hits = text_related_for_peripheral(func, spec.aliases, spec.target_offsets)

    rel_offset_counts: Counter[int] = Counter(
        relative_offset_int(acc) for acc in rel_hot_hits if relative_offset_int(acc) is not None
    )
    unique_rel_idf = sum(offset_idf.get(off, 1.0) for off in rel_hot_offsets)
    weighted_rel_hit_score = sum(
        offset_idf.get(off, 1.0) * math.log1p(cnt) for off, cnt in sorted(rel_offset_counts.items())
    )
    raw_weighted_rel_hit_score = sum(offset_idf.get(relative_offset_int(acc) or -1, 1.0) for acc in rel_hot_hits)
    weighted_text_offset_score = sum(offset_idf.get(off, 1.0) for off in text_offset_hits)

    has_identity_signal = bool(abs_hot_hits or name_alias_hits or text_alias_hits or boolish(func.get("is_isr")))
    should_score_text_offsets = bool(text_offset_hits) and has_identity_signal

    score = 0.0
    reasons: List[str] = []

    if abs_hot_hits:
        score += 160.0 * len(abs_hot_hits)
        reasons.append(f"abs_hot_hits={len(abs_hot_hits)}")
    if span_hot_hits:
        score += 7.5 * len(span_hot_hits)
        reasons.append(f"span_hot_hits={len(span_hot_hits)}")
    if rel_hot_hits:
        score += 10.0 * weighted_rel_hit_score
        reasons.append(f"rel_hot_offset_hits={len(rel_hot_hits)}")
    if len(rel_hot_offsets) >= 2:
        score += 120.0 + 40.0 * (len(rel_hot_offsets) - 2)
        reasons.append(f"multi_hot_offsets={[hex_norm(x) for x in rel_hot_offsets]}")
    elif len(rel_hot_offsets) == 1:
        reasons.append(f"single_hot_offset={hex_norm(rel_hot_offsets[0])}")

    if unique_rel_idf > 0:
        score += 16.0 * unique_rel_idf
        reasons.append(f"offset_rarity_score={unique_rel_idf:.3f}")

    if name_alias_hits:
        score += 110.0 + 10.0 * len(name_alias_hits)
        reasons.append(f"name_alias_hits={sorted(set(name_alias_hits))}")
    if text_alias_hits:
        score += 70.0 + 8.0 * len(text_alias_hits)
        reasons.append(f"text_alias_hits={sorted(set(text_alias_hits))}")
    if should_score_text_offsets:
        score += 6.0 * weighted_text_offset_score
        reasons.append(f"text_offset_hits={[hex_norm(x) for x in text_offset_hits]}")
    elif text_offset_hits:
        reasons.append(f"text_offset_hits_suppressed={[hex_norm(x) for x in text_offset_hits]}")

    if boolish(func.get("is_isr")):
        if rel_hot_hits or abs_hot_hits or name_alias_hits:
            score += 35.0
            reasons.append("isr_bonus")

    is_libc_noise = is_likely_libc_noise(name)
    libc_hard_gate = False
    libc_penalty = 0.0
    if is_libc_noise:
        libc_penalty = 260.0
        if len(rel_hot_offsets) <= 1 and not name_alias_hits:
            libc_penalty += 220.0
        if not abs_hot_hits and not name_alias_hits and not text_alias_hits:
            libc_penalty += 120.0
        if not abs_hot_hits and not name_alias_hits and not boolish(func.get("is_isr")):
            libc_hard_gate = True
            libc_penalty += 320.0
        score -= libc_penalty
        reasons.append("libc_noise_penalty")
        if libc_hard_gate:
            reasons.append("libc_hard_gate")

    gate_ok = False
    if libc_hard_gate:
        gate_ok = False
    elif abs_hot_hits:
        gate_ok = True
    elif len(rel_hot_offsets) >= 2 and has_identity_signal:
        gate_ok = True
    elif name_alias_hits and (rel_hot_hits or text_offset_hits):
        gate_ok = True
    elif boolish(func.get("is_isr")) and (rel_hot_hits or abs_hot_hits or text_offset_hits):
        gate_ok = True

    is_anchor = gate_ok and score >= 90.0
    if not is_anchor:
        reasons.append("failed_gate")

    offset_rarity_stats = {
        hex_norm(off): {
            "df": int(offset_df.get(off, 0)),
            "idf": round(float(offset_idf.get(off, 1.0)), 6),
            "count": int(rel_offset_counts.get(off, 0)),
            "registers": spec.offset_to_registers.get(off, []),
        }
        for off in rel_hot_offsets
    }

    return {
        "function": name,
        "peripheral": spec.peripheral,
        "final_score": int(round(score)),
        "score_float": score,
        "is_anchor": is_anchor,
        "reasons": reasons,
        "callgraph_distance": 0,
        "is_isr": boolish(func.get("is_isr")),
        "name_alias_hits": sorted(set(name_alias_hits)),
        "match_stats": {
            "abs_hot_hits": len(abs_hot_hits),
            "span_hot_hits": len(span_hot_hits),
            "rel_hot_offset_hits": len(rel_hot_hits),
            "rel_hot_offsets": [hex_norm(x) for x in rel_hot_offsets],
            "rel_offset_counts": {hex_norm(k): int(v) for k, v in sorted(rel_offset_counts.items())},
            "rel_span_hits": len(rel_span_hits),
            "text_alias_hits": sorted(set(text_alias_hits)),
            "text_offset_hits": [hex_norm(x) for x in sorted(set(text_offset_hits))],
            "weighted_rel_hit_score": round(weighted_rel_hit_score, 6),
            "raw_weighted_rel_hit_score": round(raw_weighted_rel_hit_score, 6),
            "weighted_rel_unique_score": round(unique_rel_idf, 6),
            "weighted_text_offset_score": round(weighted_text_offset_score, 6),
            "text_offset_scored": should_score_text_offsets,
            "identity_signal": has_identity_signal,
            "libc_hard_gate": libc_hard_gate,
        },
        "offset_rarity_stats": offset_rarity_stats,
        "abs_hot_addresses": [hex_norm(acc_addr_int(acc)) for acc in abs_hot_hits if acc_addr_int(acc) is not None],
        "rel_hot_offsets": [hex_norm(x) for x in rel_hot_offsets],
        "matched_keywords": sorted(
            set(
                [name]
                + [hex_norm(a) for a in spec.hot_addresses]
                + [hex_norm(x) for x in rel_hot_offsets]
                + spec.aliases
                + [r for regs in spec.offset_to_registers.values() for r in regs]
            )
        ),
    }


def select_anchor_candidates(
    functions: List[Dict[str, Any]],
    hot_specs: List[HotPeripheralSpec],
    call_depth: int,
) -> Tuple[List[Dict[str, Any]], Set[str], Dict[str, int], Dict[int, int], Dict[int, float]]:
    offset_df = compute_relative_offset_df(functions)
    offset_idf = compute_relative_offset_idf(offset_df, len(functions))

    best_by_function: Dict[str, Dict[str, Any]] = {}
    for func in functions:
        name = str(func.get("name") or "")
        best: Optional[Dict[str, Any]] = None
        for spec in hot_specs:
            cand = score_function_against_spec(func, spec, offset_df, offset_idf)
            if best is None or cand["score_float"] > best["score_float"]:
                best = cand
        if best is not None:
            best_by_function[name] = best

    anchor_candidates = sorted(
        best_by_function.values(), key=lambda x: (x.get("score_float", 0.0), x.get("function", "")), reverse=True
    )
    anchor_names = {c["function"] for c in anchor_candidates if c.get("is_anchor")}
    dist = callgraph_distance_map(functions, anchor_names)
    for cand in anchor_candidates:
        cand["callgraph_distance"] = dist.get(cand["function"], 0 if cand.get("is_anchor") else -1)
    return anchor_candidates, anchor_names, dist, offset_df, offset_idf


def expand_function_neighborhood(functions: List[Dict[str, Any]], anchor_names: Set[str], call_depth: int) -> Set[str]:
    by_name = {str(f.get("name")): f for f in functions}
    callers = build_reverse_callers(functions)
    visited: Set[str] = set(anchor_names)
    q = deque((name, 0) for name in anchor_names)
    while q:
        name, depth = q.popleft()
        if depth >= call_depth:
            continue
        f = by_name.get(name)
        if f is not None:
            for callee in f.get("calls", []) or []:
                callee = str(callee)
                if callee in by_name and callee not in visited:
                    visited.add(callee)
                    q.append((callee, depth + 1))
        for caller in callers.get(name, set()):
            if caller in by_name and caller not in visited:
                visited.add(caller)
                q.append((caller, depth + 1))
    return visited


def build_selected_call_edges(functions_by_name: Dict[str, Dict[str, Any]], selected_names: Set[str]) -> List[Dict[str, str]]:
    edges = []
    for name in sorted(selected_names):
        f = functions_by_name[name]
        for callee in f.get("calls", []) or []:
            callee = str(callee)
            if callee in selected_names:
                edges.append({"caller": name, "callee": callee})
    return edges


# -----------------------------
# Bundle construction
# -----------------------------

def function_summary(
    func: Dict[str, Any],
    candidate: Dict[str, Any],
    callers: Set[str],
    max_code_chars: int,
) -> Dict[str, Any]:
    keywords = list(candidate.get("matched_keywords", []))
    return {
        "name": func.get("name"),
        "entry": func.get("entry"),
        "entry_offset": func.get("entry_offset"),
        "signature": func.get("signature"),
        "is_isr": func.get("is_isr"),
        "anchor_score": candidate.get("final_score"),
        "anchor_peripheral": candidate.get("peripheral"),
        "anchor_reasons": candidate.get("reasons", []),
        "callgraph_distance": candidate.get("callgraph_distance"),
        "is_anchor": candidate.get("is_anchor"),
        "hot_abs_addresses": candidate.get("abs_hot_addresses", []),
        "hot_rel_offsets": candidate.get("rel_hot_offsets", []),
        "offset_rarity_stats": candidate.get("offset_rarity_stats", {}),
        "calls": func.get("calls", []),
        "callers": sorted(callers),
        "mmio_accesses": func.get("mmio_accesses", []),
        "relative_mmio_accesses": func.get("relative_mmio_accesses", []),
        "decompile_excerpt": truncate_text(
            excerpt_around_keywords(str(func.get("decompile") or ""), keywords, window=max_code_chars),
            max_code_chars,
        ),
        "disassembly_excerpt": truncate_text(
            excerpt_around_keywords(str(func.get("disassembly") or ""), keywords, window=max_code_chars),
            max_code_chars,
        ),
    }


def build_contract_bundle(
    ghidra_export: Dict[str, Any],
    hot_mmio: Set[int],
    cache_registry: CacheRegistry,
    call_depth: int,
    max_code_chars: int,
) -> Dict[str, Any]:
    functions = list(ghidra_export.get("functions", []))
    functions_by_name = {str(f.get("name")): f for f in functions}
    reverse_callers = build_reverse_callers(functions)

    hot_specs = infer_hot_peripheral_specs(hot_mmio, cache_registry)
    anchor_candidates, anchor_names, dist, offset_df, offset_idf = select_anchor_candidates(
        functions, hot_specs, call_depth=call_depth
    )
    selected_names = expand_function_neighborhood(functions, anchor_names, call_depth=call_depth)
    cand_by_func = {c["function"]: c for c in anchor_candidates}

    hot_doc_matches: Dict[int, List[Dict[str, Any]]] = {addr: cache_registry.match_address(addr) for addr in hot_mmio}
    hot_spans: Dict[int, List[PeripheralSpan]] = {addr: cache_registry.get_spans_for_address(addr) for addr in hot_mmio}

    mmio_entries: List[Dict[str, Any]] = []
    for addr in sorted(hot_mmio):
        addr_hex = hex_norm(addr)
        doc_matches = hot_doc_matches[addr]
        spans = hot_spans[addr]
        periph_names = {m.get("peripheral") for m in doc_matches if m.get("peripheral")}
        target_offsets, _ = build_offset_targets(doc_matches)

        exact_accessors = []
        related_accessors = []
        text_related_accessors = []

        for name in sorted(selected_names):
            func = functions_by_name[name]
            candidate = cand_by_func.get(name, {})
            abs_hits = []
            rel_hits = []
            span_hits = []
            for acc in func.get("mmio_accesses", []) or []:
                a = acc_addr_int(acc)
                if a == addr:
                    abs_hits.append(acc)
                elif any(sp.min_reg_addr <= (a or -1) < sp.max_reg_end for sp in spans if a is not None):
                    span_hits.append(acc)
            for acc in func.get("relative_mmio_accesses", []) or []:
                off = relative_offset_int(acc)
                if off is not None and off in target_offsets:
                    rel_hits.append(acc)

            text_alias_hits, text_offset_hits = text_related_for_peripheral(
                func,
                sorted({alias for spec in hot_specs if spec.peripheral in periph_names for alias in spec.aliases}),
                target_offsets,
            )

            if abs_hits:
                exact_accessors.append(
                    {
                        "function": name,
                        "signature": func.get("signature"),
                        "entry": func.get("entry"),
                        "accesses": abs_hits,
                        "score": candidate.get("final_score"),
                    }
                )
            if rel_hits or span_hits:
                related_accessors.append(
                    {
                        "function": name,
                        "signature": func.get("signature"),
                        "entry": func.get("entry"),
                        "accesses": rel_hits + span_hits,
                        "score": candidate.get("final_score"),
                    }
                )
            if text_alias_hits or text_offset_hits:
                text_related_accessors.append(
                    {
                        "function": name,
                        "signature": func.get("signature"),
                        "entry": func.get("entry"),
                        "text_alias_hits": text_alias_hits,
                        "text_offset_hits": [hex_norm(x) for x in text_offset_hits],
                        "score": candidate.get("final_score"),
                    }
                )

        mmio_entries.append(
            {
                "address_hex": addr_hex,
                "address": addr,
                "program_accessors": dedup_preserve(exact_accessors),
                "program_related_accessors": dedup_preserve(related_accessors),
                "program_text_related_accessors": dedup_preserve(text_related_accessors),
                "document_matches": doc_matches,
                "document_inferred_spans": [
                    {
                        "peripheral": sp.peripheral,
                        "base_address_hex": hex_norm(sp.base_address) if sp.base_address is not None else None,
                        "min_reg_addr_hex": hex_norm(sp.min_reg_addr),
                        "max_reg_end_hex": hex_norm(sp.max_reg_end),
                        "register_count": sp.register_count,
                    }
                    for sp in spans
                ],
            }
        )

    selected_functions = []
    for name in sorted(selected_names):
        func = functions_by_name[name]
        candidate = cand_by_func.get(
            name,
            {
                "final_score": 0,
                "peripheral": None,
                "reasons": [],
                "callgraph_distance": dist.get(name, -1),
                "is_anchor": False,
                "abs_hot_addresses": [],
                "rel_hot_offsets": [],
                "offset_rarity_stats": {},
                "matched_keywords": [name],
            },
        )
        selected_functions.append(
            function_summary(
                func=func,
                candidate=candidate,
                callers=reverse_callers.get(name, set()),
                max_code_chars=max_code_chars,
            )
        )

    peripheral_docs: List[Dict[str, Any]] = []
    seen_regs: Set[Tuple[Optional[str], Optional[str], Optional[str]]] = set()
    for mmio in mmio_entries:
        for doc in mmio["document_matches"]:
            key = (
                doc.get("peripheral"),
                (doc.get("register") or {}).get("name"),
                (doc.get("register") or {}).get("absoluteAddress_hex"),
            )
            if key in seen_regs:
                continue
            seen_regs.add(key)
            peripheral_docs.append(doc)

    bundle = {
        "schema": "contract_bundle_v6",
        "build_info": {
            "generator": "build_contract_bundle.py",
            "program_name": ghidra_export.get("program_name"),
            "executable_path": ghidra_export.get("executable_path"),
            "language_id": ghidra_export.get("language_id"),
            "compiler_spec": ghidra_export.get("compiler_spec"),
            "image_base": ghidra_export.get("image_base"),
            "offset_rarity_enabled": True,
        },
        "hot_mmio": [hex_norm(x) for x in sorted(hot_mmio)],
        "hot_peripheral_specs": [
            {
                "peripheral": spec.peripheral,
                "aliases": spec.aliases,
                "hot_addresses": [hex_norm(x) for x in sorted(spec.hot_addresses)],
                "target_offsets": [hex_norm(x) for x in sorted(spec.target_offsets)],
                "offset_to_registers": {hex_norm(k): v for k, v in sorted(spec.offset_to_registers.items())},
                "span_bases": [hex_norm(x) for x in sorted(spec.span_bases)],
                "spans": [
                    {
                        "peripheral": sp.peripheral,
                        "base_address_hex": hex_norm(sp.base_address) if sp.base_address is not None else None,
                        "min_reg_addr_hex": hex_norm(sp.min_reg_addr),
                        "max_reg_end_hex": hex_norm(sp.max_reg_end),
                        "register_count": sp.register_count,
                    }
                    for sp in spec.spans
                ],
            }
            for spec in hot_specs
        ],
        "program_context": {
            "anchor_function_names": sorted(anchor_names),
            "selected_function_names": sorted(selected_names),
            "call_depth": call_depth,
            "anchor_candidates": anchor_candidates,
            "call_edges": build_selected_call_edges(functions_by_name, selected_names),
            "functions": selected_functions,
            "offset_document_frequency": {hex_norm(k): int(v) for k, v in sorted(offset_df.items())},
            "offset_idf": {hex_norm(k): round(float(v), 6) for k, v in sorted(offset_idf.items())},
        },
        "mmio_context": mmio_entries,
        "document_context": {
            "cache_root": str(cache_registry.root) if cache_registry.root else None,
            "matched_peripheral_registers": peripheral_docs,
        },
    }
    return bundle


# -----------------------------
# CLI
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-export", required=True, type=Path, help="Path to ghidra_export.json")
    ap.add_argument("--hot-mmio", nargs="+", required=True, help="Hot MMIO addresses, e.g. 0x4006A004 0x4006A007")
    ap.add_argument("--pdf-svd-cache-root", type=Path, default=None, help="Root like extractor/.shared_pdf_svd_cache")
    ap.add_argument("--call-depth", type=int, default=1, help="Caller/callee expansion depth around anchor functions")
    ap.add_argument("--max-code-chars", type=int, default=2400, help="Max chars kept per decompile/disassembly excerpt")
    ap.add_argument("--out", required=True, type=Path, help="Output contract_bundle.json")
    args = ap.parse_args()

    ghidra_export = load_ghidra_export(args.ghidra_export)
    hot_mmio = {parse_int_auto(x) for x in args.hot_mmio}
    cache_registry = CacheRegistry(args.pdf_svd_cache_root)

    bundle = build_contract_bundle(
        ghidra_export=ghidra_export,
        hot_mmio=hot_mmio,
        cache_registry=cache_registry,
        call_depth=args.call_depth,
        max_code_chars=args.max_code_chars,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)

    matched_reg_count = len(bundle["document_context"]["matched_peripheral_registers"])
    exact_access_func_count = sum(1 for mm in bundle["mmio_context"] for x in mm["program_accessors"] if x.get("function"))
    related_access_func_count = sum(1 for mm in bundle["mmio_context"] for x in mm["program_related_accessors"] if x.get("function"))
    text_related_func_count = sum(1 for mm in bundle["mmio_context"] for x in mm["program_text_related_accessors"] if x.get("function"))

    print(
        json.dumps(
            {
                "out": str(args.out),
                "hot_mmio_count": len(bundle["hot_mmio"]),
                "anchor_function_count": len(bundle["program_context"]["anchor_function_names"]),
                "selected_function_count": len(bundle["program_context"]["selected_function_names"]),
                "matched_peripheral_register_count": matched_reg_count,
                "exact_program_accessor_entries": exact_access_func_count,
                "related_program_accessor_entries": related_access_func_count,
                "text_related_program_accessor_entries": text_related_func_count,
                "top_anchor_candidates": [c for c in bundle["program_context"]["anchor_candidates"] if c.get("is_anchor")][:12] or bundle["program_context"]["anchor_candidates"][:12],
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
