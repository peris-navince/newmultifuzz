from __future__ import annotations

import argparse
import json
import threading
import time
import traceback
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .ghidra_export import export_with_ghidra
from .kg_schema import GraphBuilder, function_node_id, mmio_node_id, peripheral_node_id, register_node_id
from .kg_writer import write_graph
from .llm_code_analyzer import analyze_functions_with_llm
from .manual_map import ManualMMIOIndex


BATCH_SUMMARY_NAME = "batch_summary.json"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _json_dump(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _path_info(path: str | Path | None) -> Dict[str, Any]:
    if not path:
        return {"path": None, "exists": False}
    p = Path(path).expanduser()
    try:
        rp = p.resolve()
    except Exception:
        rp = p
    info: Dict[str, Any] = {"path": str(rp), "exists": rp.exists()}
    if rp.exists():
        info["is_file"] = rp.is_file()
        info["is_dir"] = rp.is_dir()
        try:
            info["size_bytes"] = rp.stat().st_size
        except Exception:
            pass
    return info


def _snapshot_dir(path: Path, max_items: int = 30) -> Dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "exists": False, "file_count": 0, "items": []}
    items: List[Dict[str, Any]] = []
    file_count = 0
    try:
        for p in sorted(path.rglob("*")):
            if p.is_file():
                file_count += 1
                if len(items) < max_items:
                    try:
                        rel = str(p.relative_to(path))
                    except Exception:
                        rel = str(p)
                    try:
                        size = p.stat().st_size
                    except Exception:
                        size = None
                    items.append({"relative_path": rel, "size_bytes": size})
    except Exception as e:
        return {"path": str(path), "exists": True, "error": repr(e), "file_count": file_count, "items": items}
    return {"path": str(path), "exists": True, "file_count": file_count, "items": items}


class DebugRun:
    """File-backed progress logger for long Ghidra runs."""

    def __init__(self, *, outdir: Path, args: argparse.Namespace, label: str = "single") -> None:
        self.outdir = outdir.resolve()
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.label = label
        self.started_at = time.time()
        self.stage = "init"
        self.stage_started_at = self.started_at
        self.extra: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.heartbeat_interval = max(1, int(getattr(args, "heartbeat_interval", 30) or 30))
        self.debug_log = Path(getattr(args, "debug_log", None) or (self.outdir / "run_ghidra_kg.debug.log")).resolve()
        self.status_json = Path(getattr(args, "status_json", None) or (self.outdir / "run_ghidra_kg.status.json")).resolve()
        self.verbose = bool(getattr(args, "verbose", False))
        self.args = args

    def log(self, message: str, **fields: Any) -> None:
        rec = {
            "ts": _utc_now(),
            "label": self.label,
            "stage": self.stage,
            "elapsed_sec": round(time.time() - self.started_at, 3),
            "message": message,
        }
        if fields:
            rec.update(fields)
        line = json.dumps(rec, ensure_ascii=False)
        self.debug_log.parent.mkdir(parents=True, exist_ok=True)
        with self.debug_log.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        if self.verbose:
            print(line, flush=True)

    def set_stage(self, stage: str, **extra: Any) -> None:
        with self._lock:
            self.stage = stage
            self.stage_started_at = time.time()
            self.extra = dict(extra)
        self.log(f"stage -> {stage}", **extra)
        self.write_status(event="stage_change")

    def write_status(self, *, event: str = "heartbeat", error: str | None = None) -> None:
        with self._lock:
            stage = self.stage
            stage_started = self.stage_started_at
            extra = dict(self.extra)
        data: Dict[str, Any] = {
            "event": event,
            "timestamp": _utc_now(),
            "label": self.label,
            "stage": stage,
            "started_at": datetime.fromtimestamp(self.started_at, UTC).isoformat().replace("+00:00", "Z"),
            "elapsed_sec": round(time.time() - self.started_at, 3),
            "stage_elapsed_sec": round(time.time() - stage_started, 3),
            "outdir": str(self.outdir),
            "debug_log": str(self.debug_log),
            "extra": extra,
            "inputs": {
                "binary": _path_info(getattr(self.args, "binary", None)),
                "binary_root": _path_info(getattr(self.args, "binary_root", None)),
                "ghidra_export_json": _path_info(getattr(self.args, "ghidra_export_json", None)),
                "ghidra_home": _path_info(getattr(self.args, "ghidra_home", None)),
                "manual_mmio_map": _path_info(getattr(self.args, "manual_mmio_map", None)),
            },
            "outdir_snapshot": _snapshot_dir(self.outdir, max_items=25),
        }
        if error:
            data["error"] = error
        _json_dump(self.status_json, data)

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.heartbeat_interval):
            self.log("heartbeat", status_json=str(self.status_json))
            self.write_status(event="heartbeat")

    def start(self) -> None:
        self.log("debug run started", status_json=str(self.status_json), heartbeat_interval=self.heartbeat_interval)
        self.write_status(event="start")
        self._thread = threading.Thread(target=self._heartbeat_loop, name="run-ghidra-kg-heartbeat", daemon=True)
        self._thread.start()

    def stop(self, *, ok: bool, error: str | None = None) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.log("debug run finished", ok=ok, error=error)
        self.write_status(event="finished" if ok else "error", error=error)


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
    p.add_argument("--debug-log", default=None, help="Write JSONL debug/progress logs here")
    p.add_argument("--status-json", default=None, help="Write latest progress/status JSON here")
    p.add_argument("--heartbeat-interval", type=int, default=30, help="Seconds between heartbeat status updates")
    p.add_argument("--verbose", action="store_true", help="Also print debug JSONL records to stdout")
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


def _single_export_data(args: argparse.Namespace, outdir: Path, binary: str | None, ghidra_export_json: str | None, dbg: DebugRun) -> Dict[str, Any]:
    export_json = outdir / "ghidra_export.json"
    if ghidra_export_json:
        dbg.set_stage("load_existing_ghidra_export", ghidra_export_json=str(Path(ghidra_export_json).resolve()))
        src = Path(ghidra_export_json).resolve()
        export_json.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        export_data = json.loads(export_json.read_text(encoding="utf-8"))
        dbg.log("loaded existing ghidra export", function_count=len(export_data.get("functions") or []), export_json=str(export_json))
    else:
        dbg.set_stage(
            "ghidra_export",
            binary=str(Path(binary).resolve()) if binary else None,
            ghidra_home=str(Path(args.ghidra_home).resolve()) if args.ghidra_home else None,
            processor=args.processor,
            language_id=args.language_id,
            max_functions=args.max_functions,
            out_json=str(export_json),
        )
        dbg.log("calling export_with_ghidra", binary_info=_path_info(binary), ghidra_home_info=_path_info(args.ghidra_home), out_json=str(export_json))
        t0 = time.time()
        export_data = export_with_ghidra(
            binary=binary,
            out_json=str(export_json),
            ghidra_home=args.ghidra_home,
            processor=args.processor,
            language_id=args.language_id,
            max_functions=args.max_functions,
        )
        dbg.log(
            "export_with_ghidra returned",
            duration_sec=round(time.time() - t0, 3),
            function_count=len(export_data.get("functions") or []),
            ghidra_runtime=export_data.get("_ghidra_runtime"),
            ghidra_cmd=export_data.get("_ghidra_cmd"),
            export_json_info=_path_info(export_json),
        )
    return export_data


def _run_one(args: argparse.Namespace, *, binary: str | None, ghidra_export_json: str | None, outdir: Path, batch_relative_path: str | None = None) -> Dict[str, Any]:
    outdir.mkdir(parents=True, exist_ok=True)
    dbg = DebugRun(outdir=outdir, args=args, label=batch_relative_path or (Path(binary).name if binary else "single"))
    dbg.start()
    try:
        dbg.set_stage("start_run_one", binary=binary, ghidra_export_json=ghidra_export_json, outdir=str(outdir), batch_relative_path=batch_relative_path)
        export_data = _single_export_data(args, outdir, binary, ghidra_export_json, dbg)

        dbg.set_stage("manual_index_load", manual_mmio_map=args.manual_mmio_map)
        manual_index = ManualMMIOIndex.from_path(args.manual_mmio_map)
        graph = GraphBuilder()

        dbg.set_stage("build_base_graph", function_count=len(export_data.get("functions") or []))
        t0 = time.time()
        base_stats = _add_base_graph(export_data, graph, manual_index)
        dbg.log("base graph built", duration_sec=round(time.time() - t0, 3), **base_stats)

        llm_stats: Dict[str, Any] = {"candidate_function_count": 0, "llm_edge_count": 0, "llm_finding_count": 0}
        if args.relation_mode == "llm":
            dbg.set_stage("llm_code_analysis", model=args.llm_model, max_candidates=args.max_candidates)
            t0 = time.time()
            llm_stats = analyze_functions_with_llm(
                export_data=export_data,
                graph=graph,
                outdir=str(outdir),
                manual_index=manual_index,
                model=args.llm_model,
                relation_mode=args.relation_mode,
                max_candidates=args.max_candidates,
            )
            dbg.log("llm code analysis finished", duration_sec=round(time.time() - t0, 3), **llm_stats)
        else:
            dbg.log("llm code analysis skipped", relation_mode=args.relation_mode)

        summary = {
            "binary": str(Path(binary).resolve()) if binary else None,
            "ghidra_export_json": str((outdir / "ghidra_export.json").resolve()),
            "outdir": str(outdir),
            "relation_mode": args.relation_mode,
            "llm_model": args.llm_model,
            "batch_relative_path": batch_relative_path,
            "ghidra_runtime": export_data.get("_ghidra_runtime"),
            "ghidra_cmd": export_data.get("_ghidra_cmd"),
            "debug_log": str(dbg.debug_log),
            "status_json": str(dbg.status_json),
            **base_stats,
            **llm_stats,
            "node_count": len(graph.materialize_nodes()),
            "edge_count": len(graph.materialize_edges()),
            "finding_count": len(graph.findings),
        }
        dbg.set_stage("write_graph", node_count=summary["node_count"], edge_count=summary["edge_count"], finding_count=summary["finding_count"])
        write_graph(str(outdir), graph.materialize_nodes(), graph.materialize_edges(), graph.findings, summary)
        dbg.stop(ok=True)
        return summary
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        dbg.log("run failed", error=err, traceback=traceback.format_exc())
        dbg.stop(ok=False, error=err)
        raise


def _relative_outdir_for_binary(binary_root: Path, out_root: Path, binary_path: Path) -> Tuple[Path, str]:
    rel = binary_path.resolve().relative_to(binary_root.resolve())
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
        print(f"[{idx}/{len(binaries)}] {rel}", flush=True)
        try:
            summary = _run_one(args, binary=str(binary_path), ghidra_export_json=None, outdir=per_outdir, batch_relative_path=rel)
            items.append({"status": "ok", "binary": str(binary_path), "relative_binary": rel, "outdir": str(per_outdir), "summary": summary})
            success += 1
        except Exception as e:
            item = {
                "status": "error",
                "binary": str(binary_path),
                "relative_binary": rel,
                "outdir": str(per_outdir),
                "error": f"{type(e).__name__}: {e}",
                "debug_log": str((per_outdir / "run_ghidra_kg.debug.log").resolve()),
                "status_json": str((per_outdir / "run_ghidra_kg.status.json").resolve()),
            }
            items.append(item)
            failed += 1
            print(json.dumps(item, ensure_ascii=False), flush=True)
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
    summary = _run_one(args, binary=args.binary, ghidra_export_json=args.ghidra_export_json, outdir=outdir, batch_relative_path=None)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
