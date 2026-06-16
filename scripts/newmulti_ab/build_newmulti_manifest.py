#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build a per-case manifest for the local newMulti A/B experiment.

Default layout, relative to repo root:
  benchmarks/                 benchmark cases
  analysis/out/baseline_all/  static result cache
  extractor/text/             PDF directory
  extractor/svd/              SVD directory

All four roots can be overridden by CLI flags. Relative paths are resolved under
--repo, so the same script works when the repository is moved.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def repo_path(p: str | Path) -> Path:
    return Path(p).expanduser().resolve()


def resolve_under_repo(repo: Path, value: Optional[str], default: str) -> Path:
    raw = Path(value or default).expanduser()
    return raw.resolve() if raw.is_absolute() else (repo / raw).resolve()


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


def manual_paths(pdf_root: Path, svd_root: Path) -> Dict[str, Optional[Path]]:
    """Known bundled documentation names. Supports both the uploaded bundle and the PELSE-style copy."""
    return {
        # NXP / Kinetis
        "k22_svd": first_existing(svd_root, ["NXP/NXP-FRDM-K22F/MK22F51212.xml"]),
        "k64_pdf": first_existing(pdf_root, ["K64.pdf"]),
        "k64_svd": first_existing(svd_root, ["NXP/NXP-FRDM-K64F/MK64F12.xml"]),
        "k82_svd": first_existing(svd_root, ["NXP/NXP-FRDM-K82F/MK82F25615.xml"]),
        "kl25_svd": first_existing(svd_root, ["NXP/NXP-FRDM-KL25Z/MKL25Z4.xml"]),
        "lpc51_svd": first_existing(svd_root, ["NXP/NXP-LPCXpresso51U68/LPC51U68.xml"]),

        # STM32
        "stm32f0_pdf": first_existing(pdf_root, ["stm32f0.pdf"]),
        "stm32f072_svd": first_existing(svd_root, ["STM/STM32F072x.svd"]),
        "stm32f10_pdf": first_existing(pdf_root, ["stm32f10.pdf"]),
        "stm32f103_svd": first_existing(svd_root, ["STM/STM32F103xx.svd"]),
        "stm32f405_pdf": first_existing(pdf_root, ["stm32f405.pdf"]),
        "stm32f40x_svd": first_existing(svd_root, ["STM/STM32F40x.svd"]),
        "stm32f76_pdf": first_existing(pdf_root, ["stm32f76xxx.pdf"]),
        "stm32f769_svd": first_existing(svd_root, ["STM/STM32F769.svd"]),
        "stm32l0_pdf": first_existing(pdf_root, ["stm32l0.pdf"]),
        "stm32l07_svd": first_existing(svd_root, ["STM/STM32L07x.svd"]),
        "stm32l151_pdf": first_existing(pdf_root, ["stm32l151.pdf"]),
        "stm32l152_svd": first_existing(svd_root, ["STM/STM32L152.svd"]),
        "stm32l4_pdf": first_existing(pdf_root, ["stm32l4.pdf"]),
        "stm32l476_svd": first_existing(svd_root, ["STM/STM32L476.svd"]),

        # SAM / Atmel
        "sam3_pdf": first_existing(pdf_root, ["SAM3X-SAM3A_Datasheet.pdf"]),
        "sam3_svd": first_existing(svd_root, ["SAM/ATSAM3X8E.svd"]),
        "sam4e_pdf": first_existing(pdf_root, ["SAM4E.pdf"]),
        "sam4e_svd": first_existing(svd_root, ["SAM/ATSAM4E16E.svd"]),
        "sam4lc_pdf": first_existing(pdf_root, ["SAM4LC4C.pdf", "ATSAM4LC4C.pdf"]),
        "sam4lc_svd": first_existing(svd_root, ["SAM/ATSAM4LC4C.svd"]),
        "sam4s_pdf": first_existing(pdf_root, ["SAM4S.pdf"]),
        "sam4s_svd": first_existing(svd_root, ["SAM/ATSAM4S16C.svd"]),
        "same70_pdf": first_existing(pdf_root, ["SAME70.pdf"]),
        "same70_svd": first_existing(svd_root, ["SAM/ATSAME70Q21B.svd"]),
        "samv71_svd": first_existing(svd_root, ["SAM/ATSAMV71Q21B.svd"]),
        "samr21_pdf": first_existing(pdf_root, ["SAMR21E.pdf"]),
        "samd20_svd": first_existing(svd_root, ["SAM/ATSAMD20J18.svd"]),
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
                    p = Path(str(out[key])).expanduser()
                    out[key] = str(p.resolve() if p.is_absolute() else (repo / p).resolve())
            return out
    return None


def pack_mapping(
    paths: Dict[str, Optional[Path]],
    pdf_key: str,
    svd_key: str,
    board: str,
    mcu: str,
    source: str,
    confidence: str,
    note: str,
    *,
    fallback_pdf_key: str = "k64_pdf",
    fallback_svd_key: str = "k64_svd",
) -> Dict[str, Any]:
    pdf = paths.get(pdf_key) or paths.get(fallback_pdf_key)
    svd = paths.get(svd_key) or paths.get(fallback_svd_key)
    if (paths.get(pdf_key) is None or paths.get(svd_key) is None) and confidence != "override":
        confidence = "low"
        note = note + " Exact pair not fully present; using bundled fallback so the case remains runnable."
    return {
        "pdf": str(pdf) if pdf else None,
        "svd": str(svd) if svd else None,
        "board": board,
        "mcu": mcu,
        "manual_mapping_source": source,
        "manual_mapping_confidence": confidence,
        "manual_mapping_note": note,
    }


def pick_manual_mapping(
    repo: Path,
    pdf_root: Path,
    svd_root: Path,
    rel_dir: str,
    elf_name: str,
    config_text: str,
    overrides: Dict[str, Any],
) -> Dict[str, Any]:
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
    paths = manual_paths(pdf_root, svd_root)

    def pack(pdf_key: str, svd_key: str, board: str, mcu: str, source: str, confidence: str, note: str) -> Dict[str, Any]:
        return pack_mapping(paths, pdf_key, svd_key, board, mcu, source, confidence, note)

    # Explicit names first.
    if "stm32429" in lower or "stm32f429" in lower:
        return pack("stm32f405_pdf", "stm32f40x_svd", "STM32F4", "STM32F429-compatible", "heuristic", "high", "Name indicates STM32F4-family firmware.")
    if "stm32f769" in lower or "stm32f7" in lower:
        return pack("stm32f76_pdf", "stm32f769_svd", "STM32F7", "STM32F769", "heuristic", "high", "Name indicates STM32F7-family firmware.")
    if "stm32f0" in lower or "stm32f072" in lower:
        return pack("stm32f0_pdf", "stm32f072_svd", "STM32F0", "STM32F072", "heuristic", "high", "Name indicates STM32F0-family firmware.")
    if "stm32l4" in lower or "stm32l476" in lower:
        return pack("stm32l4_pdf", "stm32l476_svd", "STM32L4", "STM32L476", "heuristic", "high", "Name indicates STM32L4-family firmware.")
    if "stm32l1" in lower or "stm32l151" in lower or "stm32l152" in lower:
        return pack("stm32l151_pdf", "stm32l152_svd", "STM32L1", "STM32L152-compatible", "heuristic", "high", "Name indicates STM32L1-family firmware.")
    if "stm32" in lower or "0x8000000" in lower or "0x08000000" in lower:
        if "3dprinter" in lower or "stm32f4" in lower:
            return pack("stm32f405_pdf", "stm32f40x_svd", "STM32F4", "STM32F4xx", "heuristic", "medium", "Name/base address indicates STM32F4-style layout.")
        return pack("stm32f10_pdf", "stm32f103_svd", "STM32F1", "STM32F103", "heuristic", "medium", "Name/base address indicates STM32F1-style layout.")

    if "6lowpan" in lower or "samr" in lower or "atmel_6lowpan" in lower:
        return pack("samr21_pdf", "samd20_svd", "ATSAMR21/SAMD", "ATSAMD20-compatible", "heuristic", "medium", "Name indicates SAMR21/SAMD-style case.")
    if "sam3" in lower or "sam3x" in lower or "gps" in lower or "0x80000" in lower or "0x00080000" in lower:
        return pack("sam3_pdf", "sam3_svd", "SAM3X", "ATSAM3X8E", "heuristic", "medium", "Name/base address indicates SAM3X-style layout.")
    if "sam4e" in lower:
        return pack("sam4e_pdf", "sam4e_svd", "SAM4E", "ATSAM4E16E", "heuristic", "high", "Name indicates SAM4E-family firmware.")
    if "atsam4l" in lower or "sam4l" in lower:
        return pack("sam4lc_pdf", "sam4lc_svd", "SAM4L", "ATSAM4LC4C", "heuristic", "high", "Name indicates SAM4L-family firmware.")
    if "sam4s" in lower:
        return pack("sam4s_pdf", "sam4s_svd", "SAM4S", "ATSAM4S16C", "heuristic", "high", "Name indicates SAM4S-family firmware.")
    if "same70" in lower:
        return pack("same70_pdf", "same70_svd", "SAME70", "ATSAME70Q21B", "heuristic", "high", "Name indicates SAME70-family firmware.")

    if "k64" in lower or "frdm" in lower or "zephyr" in lower or "utasker_modbus" in lower or "p2im/" in lower or "p2im\\" in lower:
        return pack("k64_pdf", "k64_svd", "FRDM-K64F", "MK64F12", "heuristic", "medium", "Default bundled mapping for Kinetis-like cases; override if needed.")

    return pack("k64_pdf", "k64_svd", "FRDM-K64F", "MK64F12", "fallback", "low", "Generic bundled fallback; override for exact device when available.")


def find_static_artifacts(analysis_root: Path, rel_dir: str, elf_stem: str) -> Dict[str, Any]:
    outdir = (analysis_root / "out" / "baseline_all" / rel_dir / elf_stem).resolve()
    summary = outdir / "summary.json"
    export = outdir / "ghidra_export.json"
    return {
        "ghidra_outdir": str(outdir),
        "ghidra_summary_json": str(summary) if summary.exists() else None,
        "ghidra_export_json": str(export) if export.exists() else None,
        "ghidra_artifacts_present": bool(summary.exists() and export.exists()),
    }


def infer_architecture(config_text: str, elf_name: str) -> str:
    lower = f"{elf_name} {config_text[:20000]}".lower()
    if "nvic" in lower or "irq_ret" in lower or "0xe0000000" in lower:
        return "ARM Cortex-M"
    if "thumb" in lower:
        return "ARM Thumb"
    return "unknown"


def discover_cases(
    repo: Path,
    bench_root: Path,
    pdf_root: Path,
    svd_root: Path,
    analysis_root: Path,
    overrides: Dict[str, Any],
) -> List[Dict[str, Any]]:
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
        mapping = pick_manual_mapping(repo, pdf_root, svd_root, rel_dir, elf.name, config_text, overrides)
        static_info = find_static_artifacts(analysis_root, rel_dir, elf.stem)
        row: Dict[str, Any] = {
            "target_id": case_id,
            "case_id": case_id,
            "dataset": rel_dir.split("/", 1)[0],
            "benchmark": rel_dir.split("/", 1)[1] if "/" in rel_dir else rel_dir,
            "relative_dir": rel_dir,
            "case_dir": str(case_dir.resolve()),
            "config": str(cfg.resolve()),
            "binary_path": str(elf.resolve()),
            "elf": str(elf.resolve()),
            "bin": str(bin_file.resolve()) if bin_file else None,
            "architecture": infer_architecture(config_text, elf.name),
            "valid_basic_blocks": str((case_dir / "valid_basic_blocks.txt").resolve()) if (case_dir / "valid_basic_blocks.txt").exists() else None,
            "syms_yml": str((case_dir / "syms.yml").resolve()) if (case_dir / "syms.yml").exists() else None,
        }
        row.update(mapping)
        row.update(static_info)
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
        "target_id", "binary_path", "architecture", "platform", "svd_or_manual_mapping",
        "case_id", "dataset", "benchmark", "relative_dir", "config", "elf", "pdf", "svd",
        "board", "mcu", "manual_mapping_source", "manual_mapping_confidence",
        "guided_materialization_ready", "ghidra_artifacts_present", "ghidra_summary_json", "ghidra_export_json",
        "manual_mapping_note",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            out = {k: row.get(k) for k in fields}
            out["platform"] = row.get("board") or row.get("mcu")
            out["svd_or_manual_mapping"] = row.get("svd") or row.get("manual_mapping_source")
            writer.writerow(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="Build newMulti local A/B experiment manifest.")
    ap.add_argument("--repo", default=".", help="Repository root")
    ap.add_argument("--bench-root", default="benchmarks", help="Case directory, relative to --repo unless absolute")
    ap.add_argument("--analysis-root", default="analysis", help="Static-result root, relative to --repo unless absolute")
    ap.add_argument("--pdf-root", default="extractor/text", help="PDF directory, relative to --repo unless absolute")
    ap.add_argument("--svd-root", default="extractor/svd", help="SVD directory, relative to --repo unless absolute")
    ap.add_argument("--out", default="workdir/newmulti_ab/manifest.jsonl", help="Output JSONL manifest")
    ap.add_argument("--csv-out", default=None, help="Optional CSV summary path")
    ap.add_argument("--mapping", default=None, help="Optional JSON/YAML override mapping")
    ap.add_argument("--case-filter", default=None, help="Regex over relative_dir/case_id")
    args = ap.parse_args()

    repo = repo_path(args.repo)
    bench_root = resolve_under_repo(repo, args.bench_root, "benchmarks")
    analysis_root = resolve_under_repo(repo, args.analysis_root, "analysis")
    pdf_root = resolve_under_repo(repo, args.pdf_root, "extractor/text")
    svd_root = resolve_under_repo(repo, args.svd_root, "extractor/svd")
    overrides = load_mapping_file(Path(args.mapping)) if args.mapping else {}
    rows = discover_cases(repo, bench_root, pdf_root, svd_root, analysis_root, overrides)
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
        "bench_root": str(bench_root),
        "analysis_root": str(analysis_root),
        "pdf_root": str(pdf_root),
        "svd_root": str(svd_root),
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
