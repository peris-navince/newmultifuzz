from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# This script is meant to live at: <repo>/analysis/run_ghidra_kg.py
# It supports both direct execution (python3 analysis/run_ghidra_kg.py)
# and package-style imports.
try:  # Preferred when running from <repo>/analysis/run_ghidra_kg.py
    from ghidra_kg.ghidra_export import export_with_ghidra
    from ghidra_kg.kg_schema import GraphBuilder, function_node_id, mmio_node_id, peripheral_node_id, register_node_id
    from ghidra_kg.kg_writer import write_graph
    from ghidra_kg.llm_code_analyzer import analyze_functions_with_llm
    from ghidra_kg.manual_map import ManualMMIOIndex
except ImportError:  # Fallback for package-relative placement
    try:
        from .ghidra_export import export_with_ghidra  # type: ignore
        from .kg_schema import GraphBuilder, function_node_id, mmio_node_id, peripheral_node_id, register_node_id  # type: ignore
        from .kg_writer import write_graph  # type: ignore
        from .llm_code_analyzer import analyze_functions_with_llm  # type: ignore
        from .manual_map import ManualMMIOIndex  # type: ignore
    except ImportError:
        here = Path(__file__).resolve().parent
        sys.path.insert(0, str(here))
        sys.path.insert(0, str(here / "ghidra_kg"))
        from ghidra_export import export_with_ghidra  # type: ignore
        from kg_schema import GraphBuilder, function_node_id, mmio_node_id, peripheral_node_id, register_node_id  # type: ignore
        from kg_writer import write_graph  # type: ignore
        from llm_code_analyzer import analyze_functions_with_llm  # type: ignore
        from manual_map import ManualMMIOIndex  # type: ignore


BATCH_SUMMARY_NAME = "batch_summary.json"
DEFAULT_GHIDRA_TIMEOUT_SEC = 1800


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _file_info(path: str | Path | None) -> Dict[str, Any] | None:
    if not path:
        return None
    p = Path(path).expanduser().resolve()
    info: Dict[str, Any] = {
        "path": str(p),
        "exists": p.exists(),
        "is_file": p.is_file(),
        "is_dir": p.is_dir(),
    }
    try:
        if p.exists():
            info["size_bytes"] = p.stat().st_size
    except OSError as exc:
        info["stat_error"] = f"{type(exc).__name__}: {exc}"
    return info


class DebugRunLogger:
    def __init__(self, outdir: Path, *, label: str, heartbeat_interval: int = 30, verbose: bool = False) -> None:
        self.outdir = outdir.resolve()
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.label = label
        self.heartbeat_interval = max(1, int(heartbeat_interval or 30))
        self.verbose = bool(verbose)
        self.debug_log = self.outdir / "run_ghidra_kg.debug.log"
        self.status_json = self.outdir / "run_ghidra_kg.status.json"
        self.start = time.monotonic()
        self.stage = "init"
        self.stage_start = self.start
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._heartbeat_thread: Optional[threading.Thread] = None

    def elapsed(self) -> float:
        return round(time.monotonic() - self.start, 3)

    def stage_elapsed(self) -> float:
        return round(time.monotonic() - self.stage_start, 3)

    def emit(self, message: str, **extra: Any) -> None:
        rec: Dict[str, Any] = {
            "ts": _now(),
            "label": self.label,
            "stage": self.stage,
            "elapsed_sec": self.elapsed(),
            "message": message,
        }
        rec.update(extra)
        line = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            with self.debug_log.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._write_status(extra=extra)
        if self.verbose:
            print(line, flush=True)

    def _write_status(self, *, extra: Dict[str, Any] | None = None) -> None:
        status = {
            "ts": _now(),
            "label": self.label,
            "stage": self.stage,
            "elapsed_sec": self.elapsed(),
            "stage_elapsed_sec": self.stage_elapsed(),
            "debug_log": str(self.debug_log),
            "status_json": str(self.status_json),
        }
        if extra:
            status["extra"] = extra
        tmp = self.status_json.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.status_json)

    def set_stage(self, stage: str, **extra: Any) -> None:
        self.stage = stage
        self.stage_start = time.monotonic()
        self.emit(f"stage -> {stage}", **extra)

    def start_heartbeat(self) -> None:
        if self._heartbeat_thread:
            return
        self._stop.clear()

        def _loop() -> None:
            while not self._stop.wait(self.heartbeat_interval):
                self.emit("heartbeat", status_json=str(self.status_json))

        self._heartbeat_thread = threading.Thread(target=_loop, name="run-ghidra-kg-heartbeat", daemon=True)
        self._heartbeat_thread.start()

    def stop_heartbeat(self) -> None:
        self._stop.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)
            self._heartbeat_thread = None


def _parse_java_major(version_output: str) -> int | None:
    # Handles both: openjdk version "21.0.10" and openjdk version "1.8.0_..."
    m = re.search(r'version\s+"([^"]+)"', version_output)
    if not m:
        return None
    version = m.group(1)
    if version.startswith("1."):
        parts = version.split(".")
        if len(parts) > 1 and parts[1].isdigit():
            return int(parts[1])
        return None
    first = version.split(".", 1)[0]
    return int(first) if first.isdigit() else None


def _run_cmd_capture(cmd: List[str], *, timeout: int = 20) -> Tuple[int, str]:
    try:
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        return proc.returncode, proc.stdout or ""
    except FileNotFoundError as exc:
        return 127, f"{type(exc).__name__}: {exc}"
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or "") + f"\nTIMEOUT: {exc}"


def _preflight_ghidra(args: argparse.Namespace, log: DebugRunLogger) -> None:
    """Fail fast with actionable messages instead of letting pyghidraRun wait interactively."""
    if args.ghidra_export_json:
        log.emit("preflight skipped: using existing ghidra_export_json")
        return

    binary_info = _file_info(args.binary)
    ghidra_home_info = _file_info(args.ghidra_home)
    log.emit("preflight inputs", binary_info=binary_info, ghidra_home_info=ghidra_home_info, java_home=os.environ.get("JAVA_HOME"))

    if args.binary and not Path(args.binary).expanduser().resolve().is_file():
        raise RuntimeError(f"Binary does not exist or is not a file: {args.binary}")

    if args.ghidra_home:
        ghidra_home = Path(args.ghidra_home).expanduser().resolve()
        pyghidra_run = ghidra_home / "support" / "pyghidraRun"
        analyze_headless = ghidra_home / "support" / "analyzeHeadless"
        if not pyghidra_run.exists():
            raise RuntimeError(f"pyghidraRun not found: {pyghidra_run}")
        if not analyze_headless.exists():
            raise RuntimeError(f"analyzeHeadless not found: {analyze_headless}")

    rc, java_out = _run_cmd_capture(["java", "-version"], timeout=20)
    major = _parse_java_major(java_out)
    log.emit("java preflight", returncode=rc, major=major, output=java_out.strip())
    if rc != 0 or major is None or major < 21:
        raise RuntimeError(
            "Ghidra 12.x requires JDK 21+. Current java is not usable.\n"
            f"Detected output:\n{java_out}\n"
            "Fix example:\n"
            "  export JAVA_HOME=/home/wgh/tools/jdk-21\n"
            "  export PATH=\"$JAVA_HOME/bin:$PATH\"\n"
            "  java -version\n"
        )

    rc, py_out = _run_cmd_capture([sys.executable, "-c", "import pyghidra, jpype; print('pyghidra ok')"], timeout=20)
    log.emit("pyghidra preflight", returncode=rc, output=py_out.strip(), python=sys.executable)
    if rc != 0:
        raise RuntimeError(
            "PyGhidra is not installed in the active Python environment.\n"
            f"Python: {sys.executable}\n"
            f"Import output:\n{py_out}\n"
            "Fix example:\n"
            "  source extractor/.venv/bin/activate\n"
            "  pip install -r requirements-ghidra.txt\n"
            "or:\n"
            "  pip install pyghidra jpype1 packaging\n"
        )


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

    # Hardened/debug controls.
    p.add_argument("--heartbeat-interval", type=int, default=30, help="Seconds between heartbeat status updates")
    p.add_argument("--verbose", action="store_true", help="Print JSONL debug events to terminal")
    p.add_argument("--ghidra-timeout-sec", type=int, default=DEFAULT_GHIDRA_TIMEOUT_SEC, help="Timeout for the Ghidra export subprocess")
    p.add_argument("--print-ghidra-output", action="store_true", help="Also stream Ghidra subprocess output to terminal")
    p.add_argument("--skip-preflight", action="store_true", help="Skip Java/PyGhidra preflight checks")
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


def _call_export_with_ghidra(args: argparse.Namespace, *, binary: str, export_json: Path, outdir: Path) -> Dict[str, Any]:
    """Call export_with_ghidra while remaining compatible with older ghidra_export.py signatures."""
    subprocess_log = outdir / "ghidra_export.subprocess.log"
    sig = inspect.signature(export_with_ghidra)
    kwargs: Dict[str, Any] = {
        "binary": binary,
        "out_json": str(export_json),
        "ghidra_home": args.ghidra_home,
        "processor": args.processor,
        "language_id": args.language_id,
        "max_functions": args.max_functions,
    }
    optional = {
        "timeout_sec": args.ghidra_timeout_sec,
        "log_path": str(subprocess_log),
        "print_output": bool(args.print_ghidra_output),
        "stdin_devnull": True,
        "noninteractive": True,
    }
    for key, value in optional.items():
        if key in sig.parameters:
            kwargs[key] = value
    return export_with_ghidra(**kwargs)


def _single_export_data(args: argparse.Namespace, outdir: Path, binary: str | None, ghidra_export_json: str | None, log: DebugRunLogger) -> Dict[str, Any]:
    export_json = outdir / "ghidra_export.json"
    if ghidra_export_json:
        src = Path(ghidra_export_json).expanduser().resolve()
        log.emit("using existing ghidra export json", source=str(src), source_info=_file_info(src))
        export_json.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        export_data = json.loads(export_json.read_text(encoding="utf-8"))
    else:
        if not binary:
            raise RuntimeError("binary is required when --ghidra-export-json is not provided")
        bin_path = str(Path(binary).expanduser().resolve())
        log.emit(
            "calling export_with_ghidra",
            binary_info=_file_info(bin_path),
            ghidra_home_info=_file_info(args.ghidra_home),
            out_json=str(export_json),
        )
        t0 = time.monotonic()
        export_data = _call_export_with_ghidra(args, binary=bin_path, export_json=export_json, outdir=outdir)
        log.emit(
            "export_with_ghidra returned",
            duration_sec=round(time.monotonic() - t0, 3),
            function_count=len(export_data.get("functions") or []),
            ghidra_runtime=export_data.get("_ghidra_runtime"),
            ghidra_cmd=export_data.get("_ghidra_cmd"),
            export_json_info=_file_info(export_json),
        )
    return export_data


def _run_one(args: argparse.Namespace, *, binary: str | None, ghidra_export_json: str | None, outdir: Path, batch_relative_path: str | None = None) -> Dict[str, Any]:
    outdir.mkdir(parents=True, exist_ok=True)
    label = Path(binary).name if binary else (Path(ghidra_export_json).name if ghidra_export_json else "run")
    log = DebugRunLogger(outdir, label=label, heartbeat_interval=args.heartbeat_interval, verbose=args.verbose)
    log.start_heartbeat()
    log.emit("debug run started", status_json=str(log.status_json), heartbeat_interval=args.heartbeat_interval)

    try:
        log.set_stage("start_run_one", binary=binary, ghidra_export_json=ghidra_export_json, outdir=str(outdir), batch_relative_path=batch_relative_path)
        if not args.skip_preflight:
            log.set_stage("preflight")
            _preflight_ghidra(args, log)

        log.set_stage(
            "ghidra_export",
            binary=str(Path(binary).expanduser().resolve()) if binary else None,
            ghidra_home=str(Path(args.ghidra_home).expanduser().resolve()) if args.ghidra_home else None,
            processor=args.processor,
            language_id=args.language_id,
            max_functions=args.max_functions,
            out_json=str(outdir / "ghidra_export.json"),
        )
        export_data = _single_export_data(args, outdir, binary, ghidra_export_json, log)

        log.set_stage("manual_index_load", manual_mmio_map=args.manual_mmio_map)
        manual_index = ManualMMIOIndex.from_path(args.manual_mmio_map)

        log.set_stage("build_base_graph", function_count=len(export_data.get("functions") or []))
        graph = GraphBuilder()
        t0 = time.monotonic()
        base_stats = _add_base_graph(export_data, graph, manual_index)
        log.emit("base graph built", duration_sec=round(time.monotonic() - t0, 3), **base_stats)

        llm_stats: Dict[str, Any] = {"candidate_function_count": 0, "llm_edge_count": 0, "llm_finding_count": 0}
        if args.relation_mode == "llm":
            log.set_stage("llm_code_analysis", model=args.llm_model, max_candidates=args.max_candidates)
            t0 = time.monotonic()
            llm_stats = analyze_functions_with_llm(
                export_data=export_data,
                graph=graph,
                outdir=str(outdir),
                manual_index=manual_index,
                model=args.llm_model,
                relation_mode=args.relation_mode,
                max_candidates=args.max_candidates,
            )
            log.emit("llm analysis finished", duration_sec=round(time.monotonic() - t0, 3), **llm_stats)
        else:
            log.emit("llm code analysis skipped", relation_mode=args.relation_mode)

        summary = {
            "binary": str(Path(binary).expanduser().resolve()) if binary else None,
            "ghidra_export_json": str((outdir / "ghidra_export.json").resolve()),
            "outdir": str(outdir),
            "relation_mode": args.relation_mode,
            "llm_model": args.llm_model,
            "batch_relative_path": batch_relative_path,
            "ghidra_runtime": export_data.get("_ghidra_runtime"),
            "ghidra_cmd": export_data.get("_ghidra_cmd"),
            "debug_log": str(log.debug_log),
            "status_json": str(log.status_json),
            **base_stats,
            **llm_stats,
            "node_count": len(graph.materialize_nodes()),
            "edge_count": len(graph.materialize_edges()),
            "finding_count": len(graph.findings),
        }
        log.set_stage("write_graph", node_count=summary["node_count"], edge_count=summary["edge_count"], finding_count=summary["finding_count"])
        write_graph(str(outdir), graph.materialize_nodes(), graph.materialize_edges(), graph.findings, summary)
        log.emit("debug run finished", ok=True, error=None)
        return summary
    except Exception as exc:
        log.emit("debug run failed", ok=False, error=f"{type(exc).__name__}: {exc}", traceback=traceback.format_exc())
        raise
    finally:
        log.stop_heartbeat()


def _relative_outdir_for_binary(binary_root: Path, out_root: Path, binary_path: Path) -> Tuple[Path, str]:
    rel = binary_path.resolve().relative_to(binary_root.resolve())
    rel_no_suffix = rel.with_suffix("")
    return out_root / rel_no_suffix, str(rel)


def _run_batch(args: argparse.Namespace, out_root: Path) -> Dict[str, Any]:
    binary_root = Path(args.binary_root).expanduser().resolve()
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

    outdir = Path(args.outdir).expanduser().resolve()

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


if __name__ == "__main__":
    main()
