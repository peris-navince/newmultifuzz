#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
except Exception as e:  # pragma: no cover
    raise SystemExit("PyYAML is required: pip install pyyaml") from e


DEFAULT_BATCH_SUBDIR = Path("workdir") / "batch_runs"


@dataclass
class BenchRecord:
    bench_id: str
    data: Dict[str, Any]


class ManifestError(RuntimeError):
    pass


def _now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _load_manifest(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise ManifestError(f"manifest not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ManifestError("manifest top-level must be a mapping")
    return data


def _resolve_path(repo_root: Path, value: Optional[str]) -> Optional[Path]:
    if not value:
        return None
    p = Path(value)
    if p.is_absolute():
        return p
    return (repo_root / p).resolve()


def _as_rel(repo_root: Path, p: Path) -> str:
    try:
        return str(p.resolve().relative_to(repo_root.resolve()))
    except Exception:
        return str(p.resolve())


def _read_benches(manifest: Dict[str, Any]) -> List[BenchRecord]:
    benches = manifest.get("benchmarks")
    if not isinstance(benches, list):
        raise ManifestError("manifest key 'benchmarks' must be a list")
    out: List[BenchRecord] = []
    for idx, item in enumerate(benches):
        if not isinstance(item, dict):
            raise ManifestError(f"benchmark entry #{idx} must be a mapping")
        bench_id = item.get("bench_id")
        if not isinstance(bench_id, str) or not bench_id.strip():
            raise ManifestError(f"benchmark entry #{idx} missing valid 'bench_id'")
        out.append(BenchRecord(bench_id=bench_id.strip(), data=item))
    return out


def _infer_run_mode(rec: BenchRecord, repo_root: Path) -> str:
    contract = _resolve_path(repo_root, rec.data.get("contract_bundle"))
    pdf = _resolve_path(repo_root, rec.data.get("pdf"))
    svd = _resolve_path(repo_root, rec.data.get("svd"))
    board = rec.data.get("board")
    mcu = rec.data.get("mcu")
    bench_name = rec.data.get("benchmark_name") or rec.bench_id

    if contract and contract.exists():
        return "bundle_first"
    if pdf and pdf.exists() and svd and svd.exists() and board and mcu and bench_name:
        return "materialize_if_missing"
    return "incomplete"


def _eligible(rec: BenchRecord, args: argparse.Namespace) -> bool:
    enabled = bool(rec.data.get("enabled", True))
    confidence = str(rec.data.get("mapping_confidence", "exact"))
    if not enabled and not args.include_disabled:
        return False
    if confidence == "unsupported" and not args.include_unsupported:
        return False
    if confidence == "provisional" and not args.include_provisional:
        return False
    return True


def _archive_dir(path: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_root = path.parent / "_archive"
    archive_root.mkdir(parents=True, exist_ok=True)
    return archive_root / f"{path.name}_{ts}"


def _prepare_outdir(outdir: Path, args: argparse.Namespace) -> Dict[str, Any]:
    info: Dict[str, Any] = {"outdir": str(outdir)}
    if outdir.exists():
        if args.archive_existing:
            dest = _archive_dir(outdir)
            shutil.move(str(outdir), str(dest))
            info["archived_to"] = str(dest)
        elif args.clean_run:
            shutil.rmtree(outdir, ignore_errors=True)
            info["cleaned"] = True
    outdir.mkdir(parents=True, exist_ok=True)
    return info


def _build_cmd(repo_root: Path, manifest_path: Path, rec: BenchRecord) -> Dict[str, Any]:
    cfg = rec.data
    root_dir = _resolve_path(repo_root, cfg.get("repo_root") or ".") or repo_root

    python_bin = _resolve_path(root_dir, cfg.get("python_bin") or "extractor/.venv/bin/python3")
    closed_loop = _resolve_path(root_dir, cfg.get("closed_loop") or "extractor/closed_loop.py")
    fuzzer_manifest = _resolve_path(root_dir, cfg.get("fuzzer_manifest") or "hail-fuzz/Cargo.toml")
    firmware_config = _resolve_path(root_dir, cfg.get("firmware_config") or cfg.get("config"))
    ghidra_src = _resolve_path(root_dir, cfg.get("ghidra_src") or "tools/ghidra")
    import_dir = _resolve_path(root_dir, cfg.get("import_dir"))
    contract_bundle = _resolve_path(root_dir, cfg.get("contract_bundle"))
    pdf = _resolve_path(root_dir, cfg.get("pdf"))
    svd = _resolve_path(root_dir, cfg.get("svd"))
    binary = _resolve_path(root_dir, cfg.get("binary") or cfg.get("elf"))

    if not python_bin or not python_bin.exists():
        raise ManifestError(f"{rec.bench_id}: python_bin missing: {python_bin}")
    if not closed_loop or not closed_loop.exists():
        raise ManifestError(f"{rec.bench_id}: closed_loop missing: {closed_loop}")
    if not fuzzer_manifest or not fuzzer_manifest.exists():
        raise ManifestError(f"{rec.bench_id}: fuzzer_manifest missing: {fuzzer_manifest}")
    if not firmware_config or not firmware_config.exists():
        raise ManifestError(f"{rec.bench_id}: firmware_config missing: {firmware_config}")
    if not ghidra_src or not ghidra_src.exists():
        raise ManifestError(f"{rec.bench_id}: ghidra_src missing: {ghidra_src}")

    out_root = _resolve_path(root_dir, cfg.get("out_root") or str(DEFAULT_BATCH_SUBDIR / rec.bench_id))
    if out_root is None:
        raise ManifestError(f"{rec.bench_id}: could not determine out_root")

    mode = _infer_run_mode(rec, root_dir)
    if mode == "incomplete":
        raise ManifestError(
            f"{rec.bench_id}: needs either an existing contract_bundle or pdf+svd+board+mcu(+benchmark_name)"
        )

    cmd: List[str] = [
        str(python_bin),
        str(closed_loop),
        "adaptive-mmio-loop",
        "--fuzzer-manifest", str(fuzzer_manifest),
        "--firmware-config", str(firmware_config),
        "--ghidra-src", str(ghidra_src),
        "--out-root", str(out_root),
        "--warmup-run-for", str(cfg.get("warmup_run_for", "300s")),
        "--warmup-restarts", str(cfg.get("warmup_restarts", 1)),
        "--main-window-count", str(cfg.get("main_window_count", 10)),
        "--main-window-run-for", str(cfg.get("main_window_run_for", "120s")),
        "--adaptive-period-windows", str(cfg.get("adaptive_period_windows", 3)),
        "--adaptive-plateau-windows", str(cfg.get("adaptive_plateau_windows", 2)),
        "--probe-run-for", str(cfg.get("probe_run_for", "45s")),
        "--followup-run-for", str(cfg.get("followup_run_for", "45s")),
        "--portfolio-run-for", str(cfg.get("portfolio_run_for", "20s")),
        "--strategy-control-every-windows", str(cfg.get("strategy_control_every_windows", 5)),
        "--strategy-pool-max-size", str(cfg.get("strategy_pool_max_size", 4)),
        "--strategy-trial-windows", str(cfg.get("strategy_trial_windows", 1)),
        "--portfolio-intervention-coverage-slack", str(cfg.get("portfolio_intervention_coverage_slack", 64)),
        "--use-recent-exec", str(cfg.get("use_recent_exec", "latest")),
        "--max-llm-cycles", str(cfg.get("max_llm_cycles", 1)),
        "--llm-max-output-tokens", str(cfg.get("llm_max_output_tokens", 4000)),
        "--llm-max-attempts", str(cfg.get("llm_max_attempts", 1)),
    ]

    if import_dir:
        cmd.extend(["--import-dir", str(import_dir)])
    if binary:
        cmd.extend(["--binary", str(binary)])

    if mode == "bundle_first":
        cmd.extend(["--contract-bundle", str(contract_bundle)])
    else:
        board = str(cfg.get("board"))
        mcu = str(cfg.get("mcu"))
        benchmark_name = str(cfg.get("benchmark_name") or rec.bench_id)
        materialization_mode = str(cfg.get("materialization_mode", "staged-loop"))
        if not pdf or not pdf.exists():
            raise ManifestError(f"{rec.bench_id}: pdf missing for materialization: {pdf}")
        if not svd or not svd.exists():
            raise ManifestError(f"{rec.bench_id}: svd missing for materialization: {svd}")
        cmd.extend([
            "--pdf", str(pdf),
            "--svd", str(svd),
            "--board", board,
            "--mcu", mcu,
            "--benchmark-name", benchmark_name,
            "--materialization-mode", materialization_mode,
        ])

    return {
        "mode": mode,
        "cwd": str(root_dir),
        "cmd": cmd,
        "out_root": str(out_root),
        "resolved": {
            "python_bin": _as_rel(root_dir, python_bin),
            "closed_loop": _as_rel(root_dir, closed_loop),
            "fuzzer_manifest": _as_rel(root_dir, fuzzer_manifest),
            "firmware_config": _as_rel(root_dir, firmware_config),
            "ghidra_src": _as_rel(root_dir, ghidra_src),
            "import_dir": _as_rel(root_dir, import_dir) if import_dir else None,
            "contract_bundle": _as_rel(root_dir, contract_bundle) if contract_bundle else None,
            "pdf": _as_rel(root_dir, pdf) if pdf else None,
            "svd": _as_rel(root_dir, svd) if svd else None,
            "binary": _as_rel(root_dir, binary) if binary else None,
            "out_root": _as_rel(root_dir, out_root),
        },
    }


def _run_one(rec: BenchRecord, repo_root: Path, manifest_path: Path, args: argparse.Namespace) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "bench_id": rec.bench_id,
        "enabled": bool(rec.data.get("enabled", True)),
        "mapping_confidence": str(rec.data.get("mapping_confidence", "exact")),
        "timestamp": _now_z(),
    }

    if not _eligible(rec, args):
        item.update({"status": "skipped", "reason": "filtered_by_flags"})
        return item

    try:
        built = _build_cmd(repo_root, manifest_path, rec)
        item.update({
            "status": "ready",
            "mode": built["mode"],
            "cwd": built["cwd"],
            "cmd": built["cmd"],
            "resolved": built["resolved"],
            "out_root": built["out_root"],
        })
    except Exception as e:
        item.update({"status": "error", "reason": str(e)})
        return item

    prep = _prepare_outdir(Path(built["out_root"]), args)
    item["out_root_prepare"] = prep

    if args.validate_only or args.dry_run:
        return item

    log_path = Path(built["out_root"]) / "batch_runner.log"
    with log_path.open("w", encoding="utf-8") as logf:
        logf.write(f"cwd = {built['cwd']}\n")
        logf.write("cmd = " + " ".join(built["cmd"]) + "\n")
        logf.flush()
        proc = subprocess.run(
            built["cmd"],
            cwd=built["cwd"],
            stdout=logf,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    item["returncode"] = proc.returncode
    item["runner_log"] = str(log_path)
    item["status"] = "ok" if proc.returncode == 0 else "error"
    if proc.returncode != 0:
        item["reason"] = f"command failed with return code {proc.returncode}"
    return item


def main() -> None:
    ap = argparse.ArgumentParser(description="Batch orchestrator for MultiFuzz adaptive-mmio-loop runs")
    ap.add_argument("--manifest", required=True, help="Path to bench manifest YAML")
    ap.add_argument("--dry-run", action="store_true", help="Print resolved commands without executing them")
    ap.add_argument("--validate-only", action="store_true", help="Validate and summarize without executing")
    ap.add_argument("--include-provisional", action="store_true", help="Include provisional mappings")
    ap.add_argument("--include-unsupported", action="store_true", help="Include unsupported mappings")
    ap.add_argument("--include-disabled", action="store_true", help="Include disabled entries")
    ap.add_argument("--clean-run", action="store_true", help="Delete only the target out_root before running")
    ap.add_argument("--archive-existing", action="store_true", help="Archive existing out_root before running")
    args = ap.parse_args()

    if args.clean_run and args.archive_existing:
        raise SystemExit("Use only one of --clean-run or --archive-existing")

    manifest_path = Path(args.manifest).resolve()
    manifest = _load_manifest(manifest_path)
    repo_root = _resolve_path(manifest_path.parent, manifest.get("repo_root") or ".") or manifest_path.parent
    benches = _read_benches(manifest)

    summary: Dict[str, Any] = {
        "timestamp": _now_z(),
        "manifest": str(manifest_path),
        "repo_root": str(repo_root),
        "items": [],
    }

    for rec in benches:
        item = _run_one(rec, repo_root, manifest_path, args)
        summary["items"].append(item)
        if args.dry_run and item.get("status") == "ready":
            print(f"cwd = {item['cwd']}")
            print("cmd = " + " ".join(item["cmd"]))
            print()

    out_root = (repo_root / DEFAULT_BATCH_SUBDIR).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    summary_path = out_root / "batch_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"summary written to {summary_path}")


if __name__ == "__main__":
    main()
