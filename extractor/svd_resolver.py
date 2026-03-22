from __future__ import annotations

import argparse
import os
import re
from typing import Any, Dict, List, Optional

from debug_trace import debug, info, load_json, save_json
from svd_parser import parse_svd


def _int_auto(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except Exception:
        return None


def _fmt_hex(v: Optional[int], bits: int = 32) -> Optional[str]:
    if v is None:
        return None
    width = max(1, bits // 4)
    return "0x" + format(int(v) & ((1 << bits) - 1), f"0{width}X")


def _family_name(instance: str) -> str:
    s = str(instance or "").strip().upper()
    if not s:
        return s
    # 只去掉实例编号，如 UART0 -> UART, I2C1 -> I2C
    # 不要删掉末尾字母，避免 GPIOA -> GPI、UART0 -> UAR 这类过裁剪
    return re.sub(r"\d+$", "", s)


def resolve_address(svd_data: Dict[str, Any], addr: int) -> Optional[Dict[str, Any]]:
    debug(f"resolve_address: addr={_fmt_hex(addr)}")
    peripherals = svd_data.get("peripherals", {}) or {}
    candidates: List[Dict[str, Any]] = []

    for per_name, per in peripherals.items():
        base = _int_auto(per.get("baseAddress"))
        if base is None:
            continue
        for reg in per.get("registers", []) or []:
            off = _int_auto(reg.get("addressOffset"))
            if off is None:
                continue
            width_bits = _int_auto(reg.get("size")) or 32
            reg_addr = base + off
            if reg_addr != addr:
                continue
            fields = []
            for fld in reg.get("fields", []) or []:
                fields.append(
                    {
                        "name": fld.get("name"),
                        "bitOffset": fld.get("bitOffset"),
                        "bitWidth": fld.get("bitWidth"),
                        "access": fld.get("access"),
                        "description": fld.get("description"),
                        "enumeratedValues": fld.get("enumeratedValues") or [],
                    }
                )
            candidates.append(
                {
                    "instance": per_name,
                    "family": _family_name(per_name),
                    "peripheral_description": per.get("description"),
                    "base_address": base,
                    "base_address_hex": _fmt_hex(base),
                    "register": reg.get("name"),
                    "register_description": reg.get("description"),
                    "register_address": reg_addr,
                    "register_address_hex": _fmt_hex(reg_addr),
                    "address_offset": off,
                    "address_offset_hex": _fmt_hex(off),
                    "width_bits": width_bits,
                    "width_bytes": max(1, width_bits // 8),
                    "access": reg.get("access"),
                    "reset_value": reg.get("resetValue"),
                    "reset_value_hex": _fmt_hex(_int_auto(reg.get("resetValue"))) if reg.get("resetValue") is not None else None,
                    "fields": fields,
                }
            )

    if not candidates:
        return None

    # Prefer the shortest instance name (e.g. RTC over RTC0-like aliases) for stability.
    candidates.sort(key=lambda x: (len(str(x.get("instance") or "")), str(x.get("instance") or "")))
    chosen = candidates[0]
    chosen["candidate_count"] = len(candidates)
    chosen["candidates"] = [
        {
            "instance": x["instance"],
            "register": x["register"],
            "register_address_hex": x["register_address_hex"],
        }
        for x in candidates
    ]
    debug(
        f"resolve_address hit: addr={chosen['register_address_hex']} instance={chosen['instance']} register={chosen['register']} fields={len(chosen['fields'])}"
    )
    return chosen


def resolve_many(svd_path: str, addresses: List[int]) -> Dict[str, Any]:
    svd_data = parse_svd(svd_path)
    out = {
        "svd": os.path.abspath(svd_path),
        "results": [],
    }
    for addr in addresses:
        result = resolve_address(svd_data, addr)
        out["results"].append(
            {
                "addr": _fmt_hex(addr),
                "resolved": result,
            }
        )
    return out


def _parse_addr_list(values: List[str]) -> List[int]:
    out = []
    for x in values:
        out.append(int(str(x), 0))
    return out


def main():
    ap = argparse.ArgumentParser(description="Direct SVD MMIO address resolver")
    ap.add_argument("--svd", required=True)
    ap.add_argument("--addr", nargs="+", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()

    addrs = _parse_addr_list(args.addr)
    data = resolve_many(args.svd, addrs)
    if args.out:
        save_json(args.out, data)
    else:
        import json
        print(json.dumps(data, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
