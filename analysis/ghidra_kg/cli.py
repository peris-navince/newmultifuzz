from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .ghidra_export import export_with_ghidra
from .kg_schema import GraphBuilder, function_node_id, mmio_node_id, peripheral_node_id, register_node_id
from .kg_writer import write_graph
from .llm_code_analyzer import analyze_functions_with_llm
from .manual_map import ManualMMIOIndex


BATCH_SUMMARY_NAME = "batch_summary.json"


def _add_base_graph(export_data: Dict[str, Any], graph: GraphBuilder, manual_index: ManualMMIOIndex | None) -> Dict[str, int]:
    func_count = 0
    mmio_edge_count = 0
    call_edge_count = 0
    resolved_mmio_count = 0

    for func in export_data.get("functions") or []:
        name = str(func.get("name") or "")
        entry = str(func.get("entry") or "0x0")
        if not name:
            continue
        func_count += 1
        func_id = graph.add_node(
            function_node_id(name, entry),
            "function",
            name=name,
            entry=entry,
            is_isr=bool(func.get("is_isr")),
            signature=str(func.get("signature") or ""),
        )

        for callee in func.get("calls") or []:
            callee = str(callee or "").strip()
            if not callee:
                continue
            callee_id = graph.add_node(f"func:{callee}", "function", name=callee)
            graph.add_edge(func_id, "calls", callee_id, source="ghidra")
            call_edge_count += 1

        for item in func.get("mmio_accesses") or []:
            addr_hex = str(item.get("address_hex") or "")
            addr_val = item.get("address")
            if not addr_hex:
                continue
            kind = str(item.get("kind") or "mmio_access")
            mmio_id = graph.add_node(mmio_node_id(addr_hex), "mmio", address_hex=addr_hex, address=addr_val)
            graph.add_edge(func_id, kind, mmio_id, instruction=str(item.get("instruction_text") or ""), source="ghidra")
            mmio_edge_count += 1

            if manual_index and addr_val is not None:
                match = manual_index.resolve(int(addr_val))
                if match:
                    periph_id = graph.add_node(peripheral_node_id(match.peripheral), "peripheral", name=match.peripheral)
                    reg_id = graph.add_node(
                        register_node_id(match.peripheral, match.register),
                        "register",
                        name=match.register,
                        peripheral=match.peripheral,
                        absolute_address=match.absolute_address,
                        absolute_address_hex=match.absolute_address_hex,
                    )
                    graph.add_edge(mmio_id, "belongs_to_register", reg_id, source="manual_map")
                    graph.add_edge(reg_id, "belongs_to_peripheral", periph_id, source="manual_map")
                    graph.add_edge(func_id, "touches_register", reg_id, source="manual_map")
                    graph.add_edge(func_id, "touches_peripheral", periph_id, source="manual_map")
                    resolved_mmio_count += 1

    return {
        "function_count": func_count,
        "ghidra_mmio_edge_count": mmio_edge_count,
        "ghidra_call_edge_count": call_edge_count,
        "resolved_mmio_count": resolved_mmio_count,
    }


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Ghidra -> LLM -> code KG prototype for MultiFuzz")
    p.add_argument("--binary", default=None, help="Path to a single target firmware binary")
    p.add_argument("--binary-root", default=None, help="Root directory to recursively scan for firmware binaries")
    p.add_argument("--binary-pattern", default="*.elf", help="Glob pattern used under --binary-root (default: *.elf)")
    p.add_argument("--ghidra-export-json", default=None, help="Use an existing ghidra_export.json instead of rerunning Ghidra")
    p.add_argument("--outdir", required=True, help="Output directory (single-run outdir or batch output root)")
    p.add_argument("--ghidra-home", default=None, help="Ghidra install dir (optional if auto-detected)")
    p.add_argument("--processor", default=None, help="Optional Ghidra processor spec")
    p.add_argument("--language-id", default=None, help="Optional exact Ghidra language id")
    p.add_argument("--manual-mmio-map", default=None, help="Optional extractor mmio_map_v1 JSON")
    p.add_argument("--relation-mode", choices=["off", "llm"], default="llm")
    p.add_argument("--llm-model", default="gpt-5.4")
    p.add_argument("--max-functions", type=int, default=0, help="Optional cap on Ghidra-exported functions")
    p.add_argument("--max-candidates", type=int, default=0, help="Optional cap on LLM-analyzed candidate functions")
    p.add_argument("--fail-fast", action="store_true", help="In batch mode, stop at the first failed binary")
    return p


def _validate_args(args: argparse.Namespace) -> None:
    if args.ghidra_export_json and args.binary_root:
        raise SystemExit("--ghidra-export-json cannot be used together with --binary-root")
    if args.binary and args.binary_root:
        raise SystemExit("Use either --binary or --binary-root, not both")
    if not args.binary and not args.binary_root and not args.ghidra_export_json:
        raise SystemExit("Either --binary, --binary-root, or --ghidra-export-json is required")
    if args.ghidra_export_json and args.binary:
        raise SystemExit("Use either --binary or --ghidra-export-json, not both")


def _discover_binaries(binary_root: Path, pattern: str) -> List[Path]:
    if not binary_root.exists():
        raise SystemExit(f"--binary-root does not exist: {binary_root}")
    if not binary_root.is_dir():
        raise SystemExit(f"--binary-root is not a directory: {binary_root}")

    files = sorted(p.resolve() for p in binary_root.rglob(pattern) if p.is_file())
    if not files:
        raise SystemExit(f"No files matching pattern '{pattern}' found under: {binary_root}")
    return files


def _single_export_data(args: argparse.Namespace, outdir: Path, binary: str | None, ghidra_export_json: str | None) -> Dict[str, Any]:
    export_json = outdir / "ghidra_export.json"
    if ghidra_export_json:
        src = Path(ghidra_export_json).resolve()
        export_json.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        export_data = json.loads(export_json.read_text(encoding="utf-8"))
    else:
        export_data = export_with_ghidra(
            binary=binary,
            out_json=str(export_json),
            ghidra_home=args.ghidra_home,
            processor=args.processor,
            language_id=args.language_id,
            max_functions=args.max_functions,
        )
    return export_data


def _run_one(args: argparse.Namespace, *, binary: str | None, ghidra_export_json: str | None, outdir: Path, batch_relative_path: str | None = None) -> Dict[str, Any]:
    outdir.mkdir(parents=True, exist_ok=True)
    export_data = _single_export_data(args, outdir, binary, ghidra_export_json)

    manual_index = ManualMMIOIndex.from_path(args.manual_mmio_map)
    graph = GraphBuilder()
    base_stats = _add_base_graph(export_data, graph, manual_index)

    llm_stats: Dict[str, Any] = {"candidate_function_count": 0, "llm_edge_count": 0, "llm_finding_count": 0}
    if args.relation_mode == "llm":
        llm_stats = analyze_functions_with_llm(
            export_data=export_data,
            graph=graph,
            outdir=str(outdir),
            manual_index=manual_index,
            model=args.llm_model,
            relation_mode=args.relation_mode,
            max_candidates=args.max_candidates,
        )

    summary = {
        "binary": str(Path(binary).resolve()) if binary else None,
        "ghidra_export_json": str((outdir / "ghidra_export.json").resolve()),
        "outdir": str(outdir),
        "relation_mode": args.relation_mode,
        "llm_model": args.llm_model,
        "batch_relative_path": batch_relative_path,
        "ghidra_runtime": export_data.get("_ghidra_runtime"),
        "ghidra_cmd": export_data.get("_ghidra_cmd"),
        **base_stats,
        **llm_stats,
        "node_count": len(graph.materialize_nodes()),
        "edge_count": len(graph.materialize_edges()),
        "finding_count": len(graph.findings),
    }
    write_graph(str(outdir), graph.materialize_nodes(), graph.materialize_edges(), graph.findings, summary)
    return summary


def _relative_outdir_for_binary(binary_root: Path, out_root: Path, binary_path: Path) -> Tuple[Path, str]:
    rel = binary_path.resolve().relative_to(binary_root.resolve())
    # Preserve relative path and strip suffix so each ELF gets its own output directory.
    rel_no_suffix = rel.with_suffix("")
    return out_root / rel_no_suffix, str(rel)


def _run_batch(args: argparse.Namespace, out_root: Path) -> Dict[str, Any]:
    binary_root = Path(args.binary_root).resolve()
    binaries = _discover_binaries(binary_root, args.binary_pattern)
    out_root.mkdir(parents=True, exist_ok=True)

    items: List[Dict[str, Any]] = []
    success = 0
    failed = 0

    for idx, binary_path in enumerate(binaries, start=1):
        per_outdir, rel = _relative_outdir_for_binary(binary_root, out_root, binary_path)
        print(f"[{idx}/{len(binaries)}] {rel}")
        try:
            summary = _run_one(args, binary=str(binary_path), ghidra_export_json=None, outdir=per_outdir, batch_relative_path=rel)
            items.append({
                "status": "ok",
                "binary": str(binary_path),
                "relative_binary": rel,
                "outdir": str(per_outdir),
                "summary": summary,
            })
            success += 1
        except Exception as e:
            item = {
                "status": "error",
                "binary": str(binary_path),
                "relative_binary": rel,
                "outdir": str(per_outdir),
                "error": f"{type(e).__name__}: {e}",
            }
            items.append(item)
            failed += 1
            print(json.dumps(item, ensure_ascii=False))
            if args.fail_fast:
                break

    batch_summary = {
        "mode": "batch",
        "binary_root": str(binary_root),
        "outdir_root": str(out_root),
        "binary_pattern": args.binary_pattern,
        "total": len(items),
        "succeeded": success,
        "failed": failed,
        "relation_mode": args.relation_mode,
        "llm_model": args.llm_model,
        "items": items,
    }
    (out_root / BATCH_SUMMARY_NAME).write_text(json.dumps(batch_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return batch_summary


def main() -> None:
    args = build_argparser().parse_args()
    _validate_args(args)

    outdir = Path(args.outdir).resolve()

    if args.binary_root:
        result = _run_batch(args, outdir)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    outdir.mkdir(parents=True, exist_ok=True)
    summary = _run_one(
        args,
        binary=args.binary,
        ghidra_export_json=args.ghidra_export_json,
        outdir=outdir,
        batch_relative_path=None,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
