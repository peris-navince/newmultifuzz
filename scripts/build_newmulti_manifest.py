#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build a per-benchmark manifest for the local newMulti A/B experiment.

The script discovers benchmark cases under <repo>/benchmarks, attaches existing
Ghidra/KG artifacts under <repo>/analysis/out/baseline_all when present, and
adds a best-effort PDF/SVD mapping for the materialization stage used by
extractor/closed_loop.py.

It never contacts external hosts and never executes a benchmark. It only writes
manifest files.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def repo_path(p: str | Path) -> Path:
    return Path(p).expanduser().resolve()


def safe_id(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "__", text.strip().strip("/"))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""


def load_mapping_file(path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {}
    path = path.expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".json", ".jsonc"}:
        return json.loads(text)
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        return data or {}
    except Exception as exc:
        raise RuntimeError(
            f"Failed to parse mapping file {path}. Install PyYAML or provide JSON. Error: {exc}"
        ) from exc


def first_existing(root: Path, rels: Iterable[str]) -> Optional[Path]:
    for rel in rels:
        p = (root / rel).resolve()
        if p.exists():
            return p
    return None


def manual_paths(repo: Path) -> Dict[str, Optional[Path]]:
    return {
        "k64_pdf": first_existing(repo, ["extractor/text/K64.pdf"]),
        "k64_svd": first_existing(repo, ["extractor/svd/NXP/NXP-FRDM-K64F/MK64F12.xml"]),
        "stm32f10_pdf": first_existing(repo, ["extractor/text/stm32f10.pdf"]),
        "stm32f103_svd": first_existing(repo, ["extractor/svd/STM/STM32F103xx.svd"]),
        "stm32f405_pdf": first_existing(repo, ["extractor/text/stm32f405.pdf"]),
        "stm32f40x_svd": first_existing(repo, ["extractor/svd/STM/STM32F40x.svd"]),
        "stm32l151_pdf": first_existing(repo, ["extractor/text/stm32l151.pdf"]),
        "stm32l152_svd": first_existing(repo, ["extractor/svd/STM/STM32L152.svd"]),
        "stm32l4_pdf": first_existing(repo, ["extractor/text/stm32l4.pdf"]),
        "stm32l476_svd": first_existing(repo, ["extractor/svd/STM/STM32L476.svd"]),
        "sam3_pdf": first_existing(repo, ["extractor/text/SAM3X-SAM3A_Datasheet.pdf"]),
        "sam3_svd": first_existing(repo, ["extractor/svd/SAM/ATSAM3X8E.svd"]),
        "sam4l_pdf": first_existing(repo, ["extractor/text/ATSAM4LC4C.pdf"]),
        "sam4l_svd": first_existing(repo, ["extractor/svd/SAM/ATSAM4LC4C.svd"]),
        "samr21_pdf": first_existing(repo, ["extractor/text/SAMR21E.pdf"]),
        "samd20_svd": first_existing(repo, ["extractor/svd/SAM/ATSAMD20J18.svd"]),
    }


def apply_override(
    overrides: Dict[str, Any], *, rel_dir: str, case_id: str, repo: Path
) -> Optional[Dict[str, Any]]:
    if not overrides:
        return None
    cases = overrides.get("cases") if isinstance(overrides, dict) else None
    if isinstance(cases, dict):
        raw = cases.get(rel_dir) or cases.get(case_id)
        if isinstance(raw, dict):
            out = dict(raw)
            for key in ("pdf", "svd", "ghidra_summary_json", "ghidra_export_json"):
                if out.get(key):
                    out[key] = str((repo / str(out[key])).resolve()) if not os.path.isabs(str(out[key])) else str(Path(out[key]).resolve())
            return out
    return None


def pick_manual_mapping(repo: Path, rel_dir: str, elf_name: str, config_text: str, overrides: Dict[str, Any]) -> Dict[str, Any]:
    case_id = safe_id(rel_dir)
    override = apply_override(overrides, rel_dir=rel_dir, case_id=case_id, repo=repo)
    if override:
        return {
            "pdf": override.get("pdf"),
            "svd": override.get("svd"),
            "board": override.get("board") or override.get("mcu") or "override",
            "mcu": override.get("mcu") or override.get("board") or "override",
            "manual_mapping_source": "override",
            "manual_mapping_confidence": override.get("confidence", "override"),
            "manual_mapping_note": override.get("note", "Provided by user override mapping."),
        }

    lower = f"{rel_dir} {elf_name} {config_text[:20000]}".lower()
    paths = manual_paths(repo)

    def pack(pdf_key: str, svd_key: str, board: str, mcu: str, source: str, confidence: str, note: str) -> Dict[str, Any]:
        pdf = paths.get(pdf_key)
        svd = paths.get(svd_key)
        return {
            "pdf": str(pdf) if pdf else None,
            "svd": str(svd) if svd else None,
            "board": board,
            "mcu": mcu,
            "manual_mapping_source": source,
            "manual_mapping_confidence": confidence,
            "manual_mapping_note": note,
        }

    if "stm32429" in lower or "stm32f4" in lower or "stm324" in lower:
        return pack("stm32f405_pdf", "stm32f40x_svd", "STM32F4", "STM32F4xx", "heuristic", "high", "Name/config indicates STM32F4-family firmware.")
    if "stm32l4" in lower:
        return pack("stm32l4_pdf", "stm32l476_svd", "STM32L4", "STM32L4xx", "heuristic", "high", "Name/config indicates STM32L4-family firmware.")
    if "stm32l1" in lower or "stm32l151" in lower:
        return pack("stm32l151_pdf", "stm32l152_svd", "STM32L1", "STM32L1xx", "heuristic", "high", "Name/config indicates STM32L1-family firmware.")
    if "stm32f10" in lower or "filesystem" in lower or "gnrc_networking" in lower or "xml_parser" in lower:
        return pack("stm32f10_pdf", "stm32f103_svd", "STM32F1", "STM32F103", "heuristic", "medium", "RIOT/WYCINWYC cases commonly use STM32-style layout; override if your local dataset metadata is more precise.")
    if "samr" in lower or "6lowpan" in lower or "atmel" in lower:
        return pack("samr21_pdf", "samd20_svd", "ATSAMR21/SAMD", "ATSAMD20-compatible", "heuristic", "low", "PDF is SAMR21; closest bundled SVD is ATSAMD20J18. Provide override for exact device.")
    if "sam3" in lower or "sam3x" in lower:
        return pack("sam3_pdf", "sam3_svd", "SAM3X", "ATSAM3X8E", "heuristic", "high", "Name/config indicates SAM3X-family firmware.")
    if "atsam4l" in lower or "sam4l" in lower:
        return pack("sam4l_pdf", "sam4l_svd", "ATSAM4L", "ATSAM4LC4C", "heuristic", "high", "Name/config indicates SAM4L-family firmware.")
    if "p2im/" in lower or "p2im\\" in lower or "k64" in lower or "zephyr" in lower or "utasker_modbus" in lower:
        return pack("k64_pdf", "k64_svd", "FRDM-K64F", "MK64F12", "heuristic", "medium", "Default mapping for P2IM/Kinetis-like benchmark cases; override if needed.")
    if "gps" in lower and "0x80000" in lower:
        return pack("sam3_pdf", "sam3_svd", "SAM3X", "ATSAM3X8E", "heuristic", "low", "Flash base resembles SAM-style layout; override if needed.")
    if "0x8000000" in lower or "0x08000000" in lower:
        return pack("stm32f10_pdf", "stm32f103_svd", "STM32F1", "STM32F103", "fallback", "low", "Generic STM32-style flash-base fallback. Override for exact device.")
    return pack("k64_pdf", "k64_svd", "FRDM-K64F", "MK64F12", "fallback", "low", "Generic fallback used only so all cases can enter the same local A/B pipeline. Override for exact device.")


def find_ghidra_artifacts(repo: Path, rel_dir: str, elf_stem: str) -> Dict[str, Any]:
    # Expected existing layout: analysis/out/baseline_all/<rel_dir>/<elf_stem>/summary.json
    outdir = (repo / "analysis" / "out" / "baseline_all" / rel_dir / elf_stem).resolve()
    summary = outdir / "summary.json"
    export = outdir / "ghidra_export.json"
    return {
        "ghidra_outdir": str(outdir),
        "ghidra_summary_json": str(summary) if summary.exists() else None,
        "ghidra_export_json": str(export) if export.exists() else None,
        "ghidra_artifacts_present": bool(summary.exists() and export.exists()),
    }


def discover_cases(repo: Path, overrides: Dict[str, Any]) -> List[Dict[str, Any]]:
    bench_root = repo / "benchmarks"
    if not bench_root.exists():
        raise FileNotFoundError(f"benchmarks directory not found: {bench_root}")
    rows: List[Dict[str, Any]] = []
    for cfg in sorted(bench_root.glob("*/*/config.yml")):
        case_dir = cfg.parent
        rel_dir = case_dir.relative_to(bench_root).as_posix()
        elfs = sorted(case_dir.glob("*.elf"))
        bins = sorted(case_dir.glob("*.bin"))
        if not elfs:
            continue
        elf = elfs[0]
        bin_file = bins[0] if bins else None
        config_text = read_text(cfg)
        case_id = safe_id(rel_dir)
        mapping = pick_manual_mapping(repo, rel_dir, elf.name, config_text, overrides)
        gh = find_ghidra_artifacts(repo, rel_dir, elf.stem)
        row: Dict[str, Any] = {
            "case_id": case_id,
            "dataset": rel_dir.split("/", 1)[0],
            "benchmark": rel_dir.split("/", 1)[1] if "/" in rel_dir else rel_dir,
            "relative_dir": rel_dir,
            "case_dir": str(case_dir.resolve()),
            "config": str(cfg.resolve()),
            "elf": str(elf.resolve()),
            "bin": str(bin_file.resolve()) if bin_file else None,
            "valid_basic_blocks": str((case_dir / "valid_basic_blocks.txt").resolve()) if (case_dir / "valid_basic_blocks.txt").exists() else None,
            "syms_yml": str((case_dir / "syms.yml").resolve()) if (case_dir / "syms.yml").exists() else None,
        }
        row.update(mapping)
        row.update(gh)
        row["guided_materialization_ready"] = bool(row.get("pdf") and row.get("svd"))
        rows.append(row)
    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "case_id", "dataset", "benchmark", "relative_dir", "config", "elf", "pdf", "svd",
        "board", "mcu", "manual_mapping_source", "manual_mapping_confidence",
        "guided_materialization_ready", "ghidra_artifacts_present", "ghidra_summary_json", "ghidra_export_json",
        "manual_mapping_note",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fields})


def main() -> None:
    ap = argparse.ArgumentParser(description="Build newMulti local A/B experiment manifest.")
    ap.add_argument("--repo", default=".", help="MultiFuzz/newMulti repository root")
    ap.add_argument("--out", default="workdir/newmulti_ab/manifest.jsonl", help="Output JSONL manifest")
    ap.add_argument("--csv-out", default=None, help="Optional CSV summary path")
    ap.add_argument("--mapping", default=None, help="Optional JSON/YAML override mapping")
    ap.add_argument("--case-filter", default=None, help="Regex over relative_dir/case_id")
    args = ap.parse_args()

    repo = repo_path(args.repo)
    overrides = load_mapping_file(Path(args.mapping)) if args.mapping else {}
    rows = discover_cases(repo, overrides)
    if args.case_filter:
        rx = re.compile(args.case_filter)
        rows = [r for r in rows if rx.search(r["relative_dir"]) or rx.search(r["case_id"])]

    out = repo_path(args.out) if os.path.isabs(args.out) else (repo / args.out).resolve()
    write_jsonl(out, rows)
    csv_out = Path(args.csv_out) if args.csv_out else out.with_suffix(".csv")
    if not csv_out.is_absolute():
        csv_out = (repo / csv_out).resolve()
    write_csv(csv_out, rows)

    summary = {
        "repo": str(repo),
        "manifest": str(out),
        "csv": str(csv_out),
        "total_cases": len(rows),
        "guided_materialization_ready": sum(1 for r in rows if r.get("guided_materialization_ready")),
        "ghidra_artifacts_present": sum(1 for r in rows if r.get("ghidra_artifacts_present")),
        "low_confidence_manual_mapping": sum(1 for r in rows if r.get("manual_mapping_confidence") == "low"),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
