from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def _nsmap(root: ET.Element) -> Dict[str, str]:
    if "}" in root.tag:
        return {"ns": root.tag.split("}")[0].strip("{")}
    return {}


def _qualify(path: str, ns: Dict[str, str]) -> str:
    if not ns:
        return path
    return "/".join(f"ns:{p}" for p in path.split("/"))


def _find(elem: ET.Element, path: str, ns: Dict[str, str]):
    return elem.find(_qualify(path, ns), ns)


def _findall(elem: ET.Element, path: str, ns: Dict[str, str]):
    return list(elem.findall(_qualify(path, ns), ns))


def _text(elem, default: str = "") -> str:
    if elem is None or elem.text is None:
        return default
    return str(elem.text).strip()


def _parse_int(x: Any) -> Optional[int]:
    if x is None:
        return None
    if isinstance(x, int):
        return x
    s = str(x).strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except Exception:
        m = re.search(r"0x[0-9a-fA-F]+", s)
        if m:
            return int(m.group(0), 0)
    return None


def parse_svd(path: str) -> Dict[str, Any]:
    tree = ET.parse(path)
    root = tree.getroot()
    ns = _nsmap(root)
    peripherals: Dict[str, Any] = {}

    for per in _findall(root, ".//peripheral", ns):
        name = _text(_find(per, "name", ns))
        if not name:
            continue

        p: Dict[str, Any] = {
            "name": name,
            "description": _text(_find(per, "description", ns)),
            "baseAddress": _parse_int(_text(_find(per, "baseAddress", ns))),
            "registers": [],
        }

        reg_defaults = {
            "size": _parse_int(_text(_find(per, "size", ns))),
            "resetValue": _parse_int(_text(_find(per, "resetValue", ns))),
            "access": _text(_find(per, "access", ns)) or None,
        }

        regs_block = _find(per, "registers", ns)
        if regs_block is not None:
            for reg in _findall(regs_block, "register", ns):
                reg_name = _text(_find(reg, "name", ns))
                if not reg_name:
                    continue

                r: Dict[str, Any] = {
                    "name": reg_name,
                    "description": _text(_find(reg, "description", ns)),
                    "addressOffset": _parse_int(_text(_find(reg, "addressOffset", ns))),
                    "size": _parse_int(_text(_find(reg, "size", ns))) or reg_defaults["size"],
                    "resetValue": (
                        _parse_int(_text(_find(reg, "resetValue", ns)))
                        if _text(_find(reg, "resetValue", ns))
                        else reg_defaults["resetValue"]
                    ),
                    "access": _text(_find(reg, "access", ns)) or reg_defaults["access"],
                    "fields": [],
                }

                fields_block = _find(reg, "fields", ns)
                if fields_block is not None:
                    for fld in _findall(fields_block, "field", ns):
                        bit_offset = _parse_int(_text(_find(fld, "bitOffset", ns)))
                        bit_width = _parse_int(_text(_find(fld, "bitWidth", ns)))

                        if bit_offset is None:
                            lsb = _parse_int(_text(_find(fld, "lsb", ns)))
                            msb = _parse_int(_text(_find(fld, "msb", ns)))
                            if lsb is not None and msb is not None and msb >= lsb:
                                bit_offset = lsb
                                bit_width = msb - lsb + 1

                        f: Dict[str, Any] = {
                            "name": _text(_find(fld, "name", ns)),
                            "description": _text(_find(fld, "description", ns)),
                            "bitOffset": bit_offset,
                            "bitWidth": bit_width,
                            "access": _text(_find(fld, "access", ns)) or r["access"],
                            "enumeratedValues": [],
                        }

                        for evs in _findall(fld, "enumeratedValues", ns):
                            for ev in _findall(evs, "enumeratedValue", ns):
                                f["enumeratedValues"].append(
                                    {
                                        "name": _text(_find(ev, "name", ns)),
                                        "description": _text(_find(ev, "description", ns)),
                                        "value": _parse_int(_text(_find(ev, "value", ns))),
                                    }
                                )

                        r["fields"].append(f)

                p["registers"].append(r)

        peripherals[name] = p

    return {"peripherals": peripherals}


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

    # Safe family-instance suffixes only. Examples: SPI0, I2C1, UART4, GPIOA, GPIOA1.
    return re.fullmatch(r"(?:\d+|[A-Z]|[A-Z]\d+)$", suffix) is not None


def find_matching_peripherals(svd_data: Dict[str, Any], target: str) -> List[str]:
    return [
        name
        for name in (svd_data.get("peripherals", {}) or {})
        if _is_safe_instance_match(name, target)
    ]


def get_peripheral(svd_data: Dict[str, Any], name: str) -> Dict[str, Any]:
    return (svd_data.get("peripherals", {}) or {}).get(name, {}) or {}


def _fmt_hex32(v: Optional[int]) -> Optional[str]:
    if v is None:
        return None
    return "0x" + format(int(v) & 0xFFFFFFFF, "08X")


def extract_base_metadata(svd_data: Dict[str, Any], target: str) -> Dict[str, Any]:
    """
    为目标外设抽取结构元数据。
    这不是语义主源，只是给 PDF 抽取后的对齐/补全用。
    """
    matched = find_matching_peripherals(svd_data, target)
    if not matched:
        return {
            "target": target,
            "template": None,
            "matched_instances": [],
            "instances": [],
            "register_names": [],
            "field_names": [],
        }

    template = sorted(matched, key=lambda n: (len(str(n)), str(n)))[0]
    per_map = svd_data.get("peripherals", {}) or {}
    template_per = per_map.get(template, {}) or {}

    register_names: List[str] = []
    field_names: List[str] = []
    registers_meta: List[Dict[str, Any]] = []

    for reg in template_per.get("registers", []) or []:
        rname = reg.get("name")
        if not rname:
            continue
        register_names.append(rname)

        reg_fields = []
        for fld in reg.get("fields", []) or []:
            fname = fld.get("name")
            if fname:
                field_names.append(fname)
            reg_fields.append(
                {
                    "name": fname,
                    "bitOffset": fld.get("bitOffset"),
                    "bitWidth": fld.get("bitWidth"),
                    "access": fld.get("access"),
                    "description": fld.get("description"),
                    "enumeratedValues": fld.get("enumeratedValues") or [],
                }
            )

        registers_meta.append(
            {
                "name": rname,
                "description": reg.get("description"),
                "addressOffset": reg.get("addressOffset"),
                "addressOffset_hex": _fmt_hex32(reg.get("addressOffset")),
                "size": reg.get("size"),
                "resetValue": reg.get("resetValue"),
                "resetValue_hex": _fmt_hex32(reg.get("resetValue"))
                if reg.get("resetValue") is not None
                else None,
                "access": reg.get("access"),
                "fields": reg_fields,
            }
        )

    instances = []
    for inst in matched:
        p = per_map.get(inst, {}) or {}
        ba = p.get("baseAddress")
        instances.append(
            {
                "name": inst,
                "description": p.get("description"),
                "baseAddress": ba,
                "baseAddress_hex": _fmt_hex32(ba),
            }
        )

    return {
        "target": target,
        "template": template,
        "template_description": template_per.get("description"),
        "template_baseAddress": template_per.get("baseAddress"),
        "template_baseAddress_hex": _fmt_hex32(template_per.get("baseAddress")),
        "matched_instances": matched,
        "instances": instances,
        "register_names": register_names,
        "field_names": sorted(set(field_names)),
        "registers": registers_meta,
    }


def build_controller_index(
    svd_data: Dict[str, Any],
    controller_names: List[str],
) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    per_map = svd_data.get("peripherals", {}) or {}
    for want in controller_names:
        matches = [n for n in per_map if _is_safe_instance_match(n, want)]
        if not matches:
            continue
        chosen = sorted(matches, key=lambda x: (len(x), x))[0]
        out[chosen] = per_map[chosen]
    return out


def resolve_peripheral_mentions(svd_data: Dict[str, Any], text: str) -> List[str]:
    """Resolve explicit peripheral-instance mentions from free text conservatively."""
    text_u = str(text or "").upper()
    per_map = svd_data.get("peripherals", {}) or {}
    hits: List[str] = []
    alias_map = {"I2C": ["TWI"], "TWI": ["I2C"], "GPIO": ["PIO"], "PIO": ["GPIO"]}
    for name in sorted(per_map, key=lambda x: (-len(str(x)), str(x))):
        n_u = str(name).upper()
        if re.search(rf"\b{re.escape(n_u)}\b", text_u):
            hits.append(name)
            continue
        m = re.match(r"^([A-Z]+)(\d+|[A-Z]|[A-Z]\d+)$", n_u)
        if not m:
            continue
        fam, suffix = m.group(1), m.group(2)
        for alt in alias_map.get(fam, []):
            alt_name = f"{alt}{suffix}"
            if re.search(rf"\b{re.escape(alt_name)}\b", text_u):
                hits.append(name)
                break
    return list(dict.fromkeys(hits))
