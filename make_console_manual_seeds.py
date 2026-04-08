#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate minimal UART-only MultiFuzz seeds for:
    /home/MultiFuzz/benchmarks/P2IM/Console/config.yml

Grounded directly in the observed assembly constraints:
- irq_handler_uart reads 0x4006A004 and requires bit 0x20
- then reads 0x4006A007 as input byte stream
- readline consumes bytes until '\\n' or '\\r'
- handle_input_line splits on any char <= 0x20

Output:
    /home/MultiFuzz/manual_seeds_console/*.bin
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Dict, List, Tuple

MAGIC = b"mul\x01"

UART0_S1 = 0x4006A004
UART0_D = 0x4006A007

DEFAULT_OUTDIR = Path("/home/MultiFuzz/manual_seeds_console")


def save_multistream(streams: Dict[int, bytes], path: Path) -> None:
    """
    MultiStream v1 format used by hail-fuzz/src/input.rs
      magic: 4 bytes = b"mul\\x01"
      num_streams: u32 LE
      headers[num_streams]:
          addr: u64 LE
          len : u64 LE
      payloads concatenated in sorted addr order
    """
    items = [(addr, data) for addr, data in streams.items() if data]
    items.sort(key=lambda x: x[0])

    out = bytearray()
    out += MAGIC
    out += struct.pack("<I", len(items))

    for addr, data in items:
        out += struct.pack("<QQ", addr, len(data))

    for _, data in items:
        out += data

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(out)


def build_seed(command_bytes: bytes, s1_byte: int, s1_len: int) -> Dict[int, bytes]:
    return {
        UART0_S1: bytes([s1_byte]) * s1_len,
        UART0_D: command_bytes,
    }


def hex_preview(bs: bytes) -> str:
    out = []
    for b in bs:
        if 32 <= b < 127:
            out.append(chr(b))
        elif b == 0x0A:
            out.append("\\n")
        elif b == 0x0D:
            out.append("\\r")
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def make_command_variants() -> List[Tuple[str, bytes]]:
    """
    Multi-token commands are generated in both:
      - normal ASCII space form
      - 0x18-separated form
    because handle_input_line treats <= 0x20 as separators,
    and your existing corpus often showed control-char separators.
    """
    cmds: List[Tuple[str, bytes]] = []

    # single-token
    cmds.append(("help_lf", b"help\n"))
    cmds.append(("ps_lf", b"ps\n"))
    cmds.append(("reboot_lf", b"reboot\n"))

    # space-separated
    space_cmds = {
        "rtc_gettime_space_lf": b"rtc gettime\n",
        "rtc_getalarm_space_lf": b"rtc getalarm\n",
        "rtc_clearalarm_space_lf": b"rtc clearalarm\n",
        "rtc_poweron_space_lf": b"rtc poweron\n",
        "rtc_poweroff_space_lf": b"rtc poweroff\n",
        "rtc_settime_valid_space_lf": b"rtc settime 2024-01-02 03:04:05\n",
        "rtc_setalarm_valid_space_lf": b"rtc setalarm 2024-01-02 03:04:05\n",
        "saul_read_all_space_lf": b"saul read all\n",
        "saul_read_0_space_lf": b"saul read 0\n",
        "saul_write_0_1_space_lf": b"saul write 0 1\n",
    }
    cmds.extend(space_cmds.items())

    # ctrl-0x18-separated
    ctrl18_cmds = {
        "rtc_gettime_ctrl18_lf": b"rtc\x18gettime\n",
        "rtc_getalarm_ctrl18_lf": b"rtc\x18getalarm\n",
        "rtc_clearalarm_ctrl18_lf": b"rtc\x18clearalarm\n",
        "rtc_poweron_ctrl18_lf": b"rtc\x18poweron\n",
        "rtc_poweroff_ctrl18_lf": b"rtc\x18poweroff\n",
        "rtc_settime_valid_ctrl18_lf": b"rtc\x18settime\x182024-01-02\x1803:04:05\n",
        "rtc_setalarm_valid_ctrl18_lf": b"rtc\x18setalarm\x182024-01-02\x1803:04:05\n",
        "saul_read_all_ctrl18_lf": b"saul\x18read\x18all\n",
        "saul_read_0_ctrl18_lf": b"saul\x18read\x180\n",
        "saul_write_0_1_ctrl18_lf": b"saul\x18write\x180\x181\n",
    }
    cmds.extend(ctrl18_cmds.items())

    return cmds


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", type=Path, default=DEFAULT_OUTDIR)
    ap.add_argument("--s1-len", type=int, default=2048)
    ap.add_argument(
        "--s1-bytes",
        nargs="+",
        default=["0x20", "0xA0", "0xE0"],
        help="Repeat-byte candidates for UART0.S1, e.g. 0x20 0xA0 0xE0",
    )
    args = ap.parse_args()

    s1_values: List[int] = []
    for x in args.s1_bytes:
        x = x.strip().lower()
        if x.startswith("0x"):
            v = int(x, 16)
        else:
            v = int(x, 10)
        if not (0 <= v <= 0xFF):
            raise ValueError(f"invalid S1 byte: {x}")
        s1_values.append(v)

    commands = make_command_variants()
    manifest = {
        "schema": "console-minimal-manual-seeds-v1",
        "uart0_s1_addr": hex(UART0_S1),
        "uart0_d_addr": hex(UART0_D),
        "s1_len": args.s1_len,
        "entries": [],
    }

    args.outdir.mkdir(parents=True, exist_ok=True)

    for s1 in s1_values:
        tag = f"s1_{s1:02x}"
        for name, cmd in commands:
            fname = f"{name}_{tag}.bin"
            path = args.outdir / fname
            streams = build_seed(cmd, s1, args.s1_len)
            save_multistream(streams, path)

            manifest["entries"].append({
                "file": str(path),
                "name": name,
                "s1_byte": hex(s1),
                "uart_d_preview": hex_preview(cmd),
                "uart_d_len": len(cmd),
            })
            print(f"[+] wrote {path.name:<45}  s1={hex(s1):<6}  cmd={hex_preview(cmd)}")

    (args.outdir / "manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8"
    )
    print()
    print(f"[done] seeds written to: {args.outdir}")
    print(f"[done] manifest: {args.outdir / 'manifest.json'}")


if __name__ == "__main__":
    main()