from __future__ import annotations

import re
from typing import Any, Dict, Optional


def _fmt_hex(v: Optional[int], bits: int = 32) -> Optional[str]:
    if v is None:
        return None
    width = max(1, bits // 4)
    return "0x" + format(int(v) & ((1 << bits) - 1), f"0{width}X")


def _field_mask(bit_offset, bit_width, reg_size_bits=32):
    if bit_offset is None or bit_width is None:
        return None
    bo = int(bit_offset)
    bw = int(bit_width)
    if bw <= 0 or bo < 0:
        return None
    raw = (1 << bw) - 1 if bw < 64 else (1 << 64) - 1
    m = raw << bo
    if 0 < reg_size_bits <= 64:
        m &= (1 << reg_size_bits) - 1
    return int(m)


def export_mmio_map_from_merged_view(merged_view: Dict[str, Any]) -> Dict[str, Any]:
    keyword = (merged_view.get("keyword") or "").strip()
    template_instance = merged_view.get("template_instance")
    base_addr = merged_view.get("baseAddress")
    instances = merged_view.get("instances") or []

    regs_out = []
    addr_list = []
    reg_by_addr_hex = {}
    status_candidates = []

    status_pat = re.compile(
        r"(?:^|_)(SR|ISR|STATUS|STAT|INTFLAG|IFR|IMR|IER|IDR|ICR)$",
        re.IGNORECASE,
    )

    for r in merged_view.get("registers") or []:
        name = (r.get("name") or "").strip()
        if not name:
            continue

        abs_addr = r.get("absoluteAddress")
        off = r.get("addressOffset")
        size_bits = int(r.get("size") or 32)
        size_bytes = (size_bits + 7) // 8

        if abs_addr is None and base_addr is not None and off is not None:
            abs_addr = int(base_addr) + int(off)
        if abs_addr is None:
            continue

        abs_i = int(abs_addr)
        addr_list.append(abs_i)

        fields_out = []
        for f in r.get("fields") or []:
            m = _field_mask(f.get("bitOffset"), f.get("bitWidth"), reg_size_bits=size_bits)
            fields_out.append(
                {
                    "name": f.get("name"),
                    "bitOffset": f.get("bitOffset"),
                    "bitWidth": f.get("bitWidth"),
                    "bitRange": f.get("bitRange"),
                    "mask": m,
                    "mask_hex": _fmt_hex(m, bits=size_bits) if m is not None else None,
                    "svd_access": f.get("svd_access"),
                    "svd_description": f.get("svd_description"),
                    "pdf_description": f.get("pdf_description"),
                    "documentation_status": f.get("documentation_status"),
                    "enumeratedValues": f.get("enumeratedValues") or [],
                }
            )

        reg_entry = {
            "name": name,
            "addressOffset": off,
            "addressOffset_hex": r.get("addressOffset_hex") or _fmt_hex(off),
            "absoluteAddress": abs_i,
            "absoluteAddress_hex": r.get("absoluteAddress_hex") or _fmt_hex(abs_i),
            "size_bits": size_bits,
            "size_bytes": size_bytes,
            "resetValue": r.get("resetValue"),
            "resetValue_hex": r.get("resetValue_hex"),
            "svd_access": r.get("svd_access"),
            "svd_description": r.get("svd_description"),
            "pdf_description": r.get("pdf_description"),
            "documentation_status": r.get("documentation_status"),
            "fields": fields_out,
        }

        regs_out.append(reg_entry)

        reg_by_addr_hex[reg_entry["absoluteAddress_hex"]] = {
            "name": name,
            "size_bits": size_bits,
            "size_bytes": size_bytes,
            "addressOffset_hex": reg_entry["addressOffset_hex"],
            "documentation_status": reg_entry["documentation_status"],
        }

        if status_pat.search(name):
            status_candidates.append(name)

    mmio_ranges = []
    if regs_out:
        start = min(addr_list)
        end = max(r["absoluteAddress"] + r["size_bytes"] - 1 for r in regs_out)
        mmio_ranges.append(
            {
                "name": keyword or template_instance or "PERIPH",
                "start": start,
                "start_hex": _fmt_hex(start),
                "end": end,
                "end_hex": _fmt_hex(end),
            }
        )

    return {
        "schema": "mmio_map_v1",
        "peripheral": keyword,
        "template_instance": template_instance,
        "baseAddress": base_addr,
        "baseAddress_hex": merged_view.get("baseAddress_hex") or _fmt_hex(base_addr),
        "instances": instances,
        "mmio_ranges": mmio_ranges,
        "status_register_candidates": status_candidates,
        "registers": regs_out,
        "reg_by_addr_hex": reg_by_addr_hex,
    }