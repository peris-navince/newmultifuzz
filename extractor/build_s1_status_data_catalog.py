#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def hs_candidate(group_id: str, s1_addr: str, d_addr: str,
                 s1_value: str, data_byte: str, nth: int, window: int) -> Dict[str, Any]:
    cid = f"{group_id}__hs_{s1_value}_{data_byte}_t{nth}_w{window}"
    stage = cid.replace("-", "_")
    return {
        "id": cid,
        "rationale": f"{group_id}: status+data handshake, s1={s1_value}, data={data_byte}, nth={nth}, window={window}",
        "actions": [
            {
                "type": "uart_handshake_once",
                "id": stage,
                "s1_addr": s1_addr,
                "d_addr": d_addr,
                "s1_value": s1_value,
                "data_bytes": [data_byte],
                "d_window_accesses": window,
                "trigger": {
                    "kind": "on_nth_touch",
                    "addr": s1_addr,
                    "n": nth,
                    "access": "read"
                },
                "activate_stage": stage
            }
        ]
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selected-groups", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    obj = load_json(Path(args.selected_groups))
    groups = obj.get("groups") or []

    candidates: List[Dict[str, Any]] = []

    # 这轮先固定一小族，不加 bit5 了；专测 status+data
    family = [
        ("0x20", "0x41", 2, 4),
        ("0x20", "0x41", 4, 4),
        ("0x20", "0x41", 4, 8),
        ("0x20", "0x00", 4, 8),
        ("0xE0", "0x41", 2, 4),
        ("0xE0", "0x41", 4, 4),
    ]

    for g in groups:
        mode = str(g.get("mode") or "")
        if mode != "uart_status_data":
            continue

        group_id = str(g["group_id"])
        s1_addr = str(g["s1_addr"])
        d_addr = str(g["d_addr"])

        for s1_value, data_byte, nth, window in family:
            candidates.append(
                hs_candidate(
                    group_id=group_id,
                    s1_addr=s1_addr,
                    d_addr=d_addr,
                    s1_value=s1_value,
                    data_byte=data_byte,
                    nth=nth,
                    window=window,
                )
            )

    out = {
        "schema": "mf_manual_strategy_catalog_v1",
        "target": {
            "benchmark": "P2IM-Console",
            "kind": "manual_s1_status_data_groups"
        },
        "candidates": candidates
    }
    save_json(Path(args.out), out)
    print(f"[OK] wrote {args.out} with {len(candidates)} candidates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())