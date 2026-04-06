#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


DATA_NAMES = {"D", "DR", "RDR", "DATA", "DAT", "RXD", "DL", "DLH", "RDRT"}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def child_text(elem: ET.Element, child_name: str) -> Optional[str]:
    for child in list(elem):
        if strip_ns(child.tag) == child_name:
            return (child.text or "").strip()
    return None


def parse_int(text: Optional[str]) -> Optional[int]:
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    return int(text, 0)


def collect_observed_addrs(observer_json: Optional[Path]) -> Set[int]:
    out: Set[int] = set()
    if observer_json is None or not observer_json.exists():
        return out
    arr = load_json(observer_json)
    if isinstance(arr, list):
        for item in arr:
            try:
                out.add(int(str(item.get("addr")), 0))
            except Exception:
                pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--svd", required=True)
    ap.add_argument("--observer-json", default=None,
                    help="latest_window_discovered_streams.json")
    ap.add_argument("--out", default=None,
                    help="optional JSON output path")
    args = ap.parse_args()

    svd_path = Path(args.svd)
    observer_json = Path(args.observer_json) if args.observer_json else None
    observed_addrs = collect_observed_addrs(observer_json)

    tree = ET.parse(svd_path)
    root = tree.getroot()

    groups: List[Dict[str, Any]] = []

    for periph in root.findall(".//{*}peripheral"):
        pname = child_text(periph, "name")
        base_text = child_text(periph, "baseAddress")
        base_addr = parse_int(base_text)
        if pname is None or base_addr is None:
            continue

        registers_parent = None
        for child in list(periph):
            if strip_ns(child.tag) == "registers":
                registers_parent = child
                break
        if registers_parent is None:
            continue

        regs: List[Dict[str, Any]] = []
        for reg in registers_parent.findall(".//{*}register"):
            rname = child_text(reg, "name")
            roff = parse_int(child_text(reg, "addressOffset"))
            if rname is None or roff is None:
                continue
            regs.append({
                "name": rname,
                "offset": roff,
                "abs_addr": base_addr + roff,
            })

        s1_regs = [r for r in regs if r["name"] == "S1"]
        if not s1_regs:
            continue

        data_regs = [r for r in regs if r["name"] in DATA_NAMES]

        for s1 in s1_regs:
            group = {
                "peripheral": pname,
                "base_addr": hex(base_addr),
                "s1_addr": hex(s1["abs_addr"]),
                "s1_offset": hex(s1["offset"]),
                "s1_hot": s1["abs_addr"] in observed_addrs,
                "data_regs": [],
            }
            for d in data_regs:
                group["data_regs"].append({
                    "name": d["name"],
                    "addr": hex(d["abs_addr"]),
                    "offset": hex(d["offset"]),
                    "hot": d["abs_addr"] in observed_addrs,
                })
            groups.append(group)

    # 简单排序：先把 S1 热、并且 data 里有热点的组放前面
    def score(g: Dict[str, Any]) -> tuple:
        data_hot = any(x["hot"] for x in g["data_regs"])
        return (int(g["s1_hot"]), int(data_hot), g["peripheral"])

    groups.sort(key=score, reverse=True)

    print(json.dumps(groups, indent=2, ensure_ascii=False))

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(groups, f, indent=2, ensure_ascii=False)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())