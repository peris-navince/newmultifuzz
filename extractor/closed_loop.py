from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from debug_trace import info, load_json, save_json, save_text, warn
from evidence_builder import build_evidence_pack
from guidance_compiler import compile_plan
from strategy_planner import build_llm_prompt_bundle, heuristic_plan, normalize_llm_plan
from task_context import build_task_context, summarize_run_log


def _abs(path: str) -> str:
    return str(Path(path).expanduser().resolve())


def _ensure_dir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def _parse_env_overrides(items: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"invalid --setenv entry (expected KEY=VALUE): {item}")
        k, v = item.split("=", 1)
        k = k.strip()
        if not k:
            raise ValueError(f"invalid --setenv key: {item}")
        out[k] = v
    return out


def _run_logged(cmd: List[str], *, cwd: Optional[str], env: Dict[str, str], log_path: str):
    _ensure_dir(str(Path(log_path).parent))
    info(f"exec cwd={cwd or os.getcwd()} :: {' '.join(shlex.quote(x) for x in cmd)}")
    with open(log_path, "w", encoding="utf-8") as logf:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            stdout=logf,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}), see log: {log_path}")


_FUZZER_BIN_CACHE: Dict[str, str] = {}


def _cargo_metadata(manifest_path: str) -> Dict[str, Any]:
    manifest = _abs(manifest_path)
    out = subprocess.check_output(
        ["cargo", "metadata", "--manifest-path", manifest, "--format-version", "1", "--no-deps"],
        text=True,
        cwd=str(Path(manifest).resolve().parent),
    )
    return json.loads(out)


def _resolve_fuzzer_binary(manifest_path: str) -> str:
    manifest = _abs(manifest_path)
    cached = _FUZZER_BIN_CACHE.get(manifest)
    if cached:
        return cached

    meta = _cargo_metadata(manifest)
    target_dir = Path(meta["target_directory"])

    pkg = None
    for p in meta.get("packages", []):
        if _abs(p.get("manifest_path", "")) == manifest:
            pkg = p
            break
    if pkg is None:
        pkg = (meta.get("packages") or [None])[0]
    if pkg is None:
        raise RuntimeError(f"unable to resolve package for manifest: {manifest}")

    bin_name = None
    for t in pkg.get("targets", []):
        if "bin" in (t.get("kind") or []):
            bin_name = t.get("name")
            break
    if not bin_name:
        bin_name = pkg.get("name")
    if not bin_name:
        raise RuntimeError(f"unable to resolve binary name for manifest: {manifest}")

    suffix = ".exe" if os.name == "nt" else ""
    bin_path = str((target_dir / "debug" / f"{bin_name}{suffix}").resolve())
    _FUZZER_BIN_CACHE[manifest] = bin_path
    return bin_path


def ensure_fuzzer_binary(manifest_path: str, *, force_build: bool = False) -> str:
    manifest = _abs(manifest_path)
    bin_path = _resolve_fuzzer_binary(manifest)
    if force_build or not os.path.exists(bin_path):
        info(f"building fuzzer binary via cargo build: {manifest}")
        subprocess.run(
            ["cargo", "build", "--manifest-path", manifest],
            cwd=str(Path(manifest).resolve().parent),
            check=True,
            text=True,
        )
    return bin_path


def _extract_import_summary(run_log: str) -> Dict[str, Any]:
    imported_seed_count: Optional[int] = None
    import_dir_lines: List[str] = []
    try:
        with open(run_log, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "[import]" in line:
                    import_dir_lines.append(line.strip())
                    m = re.search(r"imported\s+(\d+)\s+seed", line)
                    if m:
                        imported_seed_count = int(m.group(1))
    except FileNotFoundError:
        pass
    return {
        "imported_seed_count": imported_seed_count,
        "import_log_lines": import_dir_lines[-20:],
    }


def run_hail_fuzz(
    *,
    manifest_path: str,
    firmware_config: str,
    ghidra_src: str,
    workdir: str,
    run_log: str,
    run_for: str = "300s",
    observer_dir: Optional[str] = None,
    guidance_file: Optional[str] = None,
    guidance_summary_out: Optional[str] = None,
    import_dir: Optional[str] = None,
    fuzzer_bin: Optional[str] = None,
    setenv: Optional[List[str]] = None,
) -> Dict[str, Any]:
    env = os.environ.copy()
    env["GHIDRA_SRC"] = _abs(ghidra_src)
    env["WORKDIR"] = _abs(workdir)
    env["RUN_FOR"] = run_for

    if observer_dir:
        env["MF_STREAM_OBSERVER_OUT"] = _abs(observer_dir)
    else:
        env.pop("MF_STREAM_OBSERVER_OUT", None)

    if guidance_file:
        env["MF_MMIO_GUIDANCE_FILE"] = _abs(guidance_file)
    else:
        env.pop("MF_MMIO_GUIDANCE_FILE", None)

    if guidance_summary_out:
        env["MF_MMIO_GUIDANCE_SUMMARY_OUT"] = _abs(guidance_summary_out)
    else:
        env.pop("MF_MMIO_GUIDANCE_SUMMARY_OUT", None)

    if import_dir:
        env["MF_IMPORT_DIR"] = _abs(import_dir)
    else:
        env.pop("MF_IMPORT_DIR", None)

    for k, v in _parse_env_overrides(setenv).items():
        env[k] = v

    resolved_bin = _abs(fuzzer_bin) if fuzzer_bin else ensure_fuzzer_binary(manifest_path)
    cmd = [resolved_bin, firmware_config]
    _run_logged(cmd, cwd=str(Path(manifest_path).resolve().parent), env=env, log_path=run_log)

    return {
        "run_log": _abs(run_log),
        "workdir": _abs(workdir),
        "observer_dir": _abs(observer_dir) if observer_dir else None,
        "guidance_file": _abs(guidance_file) if guidance_file else None,
        "guidance_summary_out": _abs(guidance_summary_out) if guidance_summary_out else None,
        "import_dir": _abs(import_dir) if import_dir else None,
        "fuzzer_bin": resolved_bin,
        "run_summary": summarize_run_log(run_log),
        **_extract_import_summary(run_log),
    }


def _maybe_json(path: str) -> Optional[Any]:
    if path and os.path.exists(path):
        return load_json(path)
    return None


def _observer_addrs(data: Optional[List[Dict[str, Any]]]) -> set[str]:
    out: set[str] = set()
    for item in data or []:
        addr = str(item.get("addr") or "").upper()
        if addr:
            out.add(addr)
    return out


def _sum_action_fires(summary: Optional[Dict[str, Any]]) -> int:
    total = 0
    for item in (summary or {}).get("actions", []) or []:
        total += int(item.get("fire_count") or 0)
    return total


def _queue_dir(workdir: str) -> str:
    return str(Path(workdir).resolve() / "queue")


def _checkpoint_from_run(checkpoint_id: str, run_root: str, *, parent_checkpoint_id: Optional[str] = None, score: Optional[float] = None) -> Dict[str, Any]:
    run_root_abs = _abs(run_root)
    obs = os.path.join(run_root_abs, "observer")
    return {
        "checkpoint_id": checkpoint_id,
        "parent_checkpoint_id": parent_checkpoint_id,
        "run_root": run_root_abs,
        "workdir": os.path.join(run_root_abs, "workdir"),
        "queue_dir": os.path.join(run_root_abs, "workdir", "queue"),
        "run_log": os.path.join(run_root_abs, "run.log"),
        "observer_dir": obs,
        "run_summary": summarize_run_log(os.path.join(run_root_abs, "run.log")),
        "latest_window_summary": _maybe_json(os.path.join(obs, "latest_window_summary.json")),
        "latest_window_discovered_streams": _maybe_json(os.path.join(obs, "latest_window_discovered_streams.json")),
        "latest_window_interesting_streams": _maybe_json(os.path.join(obs, "latest_window_interesting_streams.json")),
        "guidance_runtime_summary": _maybe_json(os.path.join(run_root_abs, "guidance_runtime_summary.json")),
        "score": score,
    }


def _score_candidate(parent_checkpoint: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
    parent_addrs = _observer_addrs(parent_checkpoint.get("latest_window_discovered_streams"))
    child_addrs = _observer_addrs(report.get("latest_window_discovered_streams"))
    new_hotspots = len(child_addrs - parent_addrs)

    grs = report.get("guidance_runtime_summary") or {}
    fire_count = _sum_action_fires(grs)
    active_stage_count = len(grs.get("active_stages") or [])

    parent_rs = parent_checkpoint.get("run_summary") or {}
    rs = report.get("run_summary") or {}
    parent_cov = int(parent_rs.get("last_cov") or 0)
    child_cov = int(rs.get("last_cov") or 0)
    delta_cov = max(0, child_cov - parent_cov)
    child_inputs = int(rs.get("last_in") or 0)
    child_hangs = int(rs.get("last_hang") or 0)
    imported_seed_count = int(report.get("imported_seed_count") or 0)

    score = (
        500.0 * new_hotspots
        + 250.0 * fire_count
        + 50.0 * active_stage_count
        + 10.0 * delta_cov
        + 0.05 * child_inputs
        + 0.02 * imported_seed_count
        - 0.2 * child_hangs
    )

    return {
        "score": score,
        "new_hotspots": new_hotspots,
        "fire_count": fire_count,
        "active_stage_count": active_stage_count,
        "parent_cov": parent_cov,
        "child_cov": child_cov,
        "delta_cov": delta_cov,
        "child_inputs": child_inputs,
        "child_hangs": child_hangs,
        "imported_seed_count": imported_seed_count,
    }


def _candidate_report(candidate_id: str, run_root: str, *, parent_checkpoint: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    run_log = os.path.join(run_root, "run.log")
    obs = os.path.join(run_root, "observer")
    report = {
        "candidate_id": candidate_id,
        "run_root": _abs(run_root),
        "run_summary": summarize_run_log(run_log),
        "guidance_runtime_summary": _maybe_json(os.path.join(run_root, "guidance_runtime_summary.json")),
        "latest_window_summary": _maybe_json(os.path.join(obs, "latest_window_summary.json")),
        "latest_window_discovered_streams": _maybe_json(os.path.join(obs, "latest_window_discovered_streams.json")),
        "latest_window_interesting_streams": _maybe_json(os.path.join(obs, "latest_window_interesting_streams.json")),
        **_extract_import_summary(run_log),
    }
    if parent_checkpoint is not None:
        report["score_breakdown"] = _score_candidate(parent_checkpoint, report)
        report["score"] = report["score_breakdown"]["score"]
    return report


def _build_plan(
    task_context_path: str,
    mode: str,
    out_path: str,
    *,
    max_candidates: int,
    default_after_reads: int,
    llm_json: Optional[str],
) -> Dict[str, Any]:
    task_context = load_json(task_context_path)
    if mode == "heuristic":
        plan = heuristic_plan(
            task_context,
            max_candidates=max_candidates,
            default_after_reads=default_after_reads,
        )
    elif mode == "normalize_llm":
        if not llm_json:
            raise ValueError("--llm-json is required when --plan-mode normalize_llm")
        plan = normalize_llm_plan(task_context, llm_json)
    else:
        raise ValueError(f"unknown plan mode: {mode}")
    save_json(out_path, plan)
    return plan


def _build_round_artifacts(
    *,
    parent_checkpoint: Dict[str, Any],
    round_root: Path,
    shared_cache_root: Path,
    pdf: str,
    svd: str,
    board: str,
    mcu: str,
    benchmark_name: str,
    extract_strategy: str,
    top_k: int,
    force_pdf: bool,
    plan_mode: str,
    llm_json: Optional[str],
    best_guidance: Optional[str],
    max_candidates: int,
    default_after_reads: int,
) -> Dict[str, Any]:
    evidence_root = round_root / "evidence"
    context_root = round_root / "context"
    prompt_root = round_root / "prompt"
    plan_root = round_root / "plan"
    guidance_root = round_root / "guidance"
    cache_root = shared_cache_root
    for d in [evidence_root, context_root, prompt_root, plan_root, guidance_root, cache_root]:
        _ensure_dir(str(d))

    build_evidence_pack(
        pdf_path=pdf,
        svd_path=svd,
        observer_dir=parent_checkpoint["observer_dir"],
        cache_root=str(cache_root),
        out_path=str(evidence_root / "evidence_pack.json"),
        extract_strategy=extract_strategy,
        top_k=top_k,
        force_pdf=force_pdf,
    )

    task_context = build_task_context(
        evidence_pack_path=str(evidence_root / "evidence_pack.json"),
        run_log=parent_checkpoint["run_log"],
        out_path=str(context_root / "task_context.json"),
        board=board,
        mcu=mcu,
        benchmark=benchmark_name,
        best_guidance=best_guidance,
    )

    prompt_bundle = build_llm_prompt_bundle(task_context)
    save_json(str(prompt_root / "prompt_bundle.json"), prompt_bundle)
    save_text(str(prompt_root / "prompt_bundle.txt"), json.dumps(prompt_bundle, indent=2, ensure_ascii=False))

    _build_plan(
        str(context_root / "task_context.json"),
        plan_mode,
        str(plan_root / "plan.json"),
        max_candidates=max_candidates,
        default_after_reads=default_after_reads,
        llm_json=llm_json,
    )

    guidance_index = compile_plan(str(plan_root / "plan.json"), str(guidance_root))

    return {
        "evidence_pack_path": str(evidence_root / "evidence_pack.json"),
        "task_context_path": str(context_root / "task_context.json"),
        "prompt_bundle_path": str(prompt_root / "prompt_bundle.json"),
        "plan_path": str(plan_root / "plan.json"),
        "guidance_index_path": str(guidance_root / "guidance_index.json"),
        "guidance_index": guidance_index,
    }


def auto_loop(args):
    out_root = Path(args.out_root).expanduser().resolve()
    fuzzer_bin = _abs(args.fuzzer_bin) if getattr(args, "fuzzer_bin", None) else ensure_fuzzer_binary(args.fuzzer_manifest)

    baseline_root = out_root / "baseline"
    evidence_root = out_root / "evidence"
    context_root = out_root / "context"
    prompt_root = out_root / "prompt"
    plan_root = out_root / "plan"
    guidance_root = out_root / "guidance"
    guided_root = out_root / "guided"
    report_root = out_root / "report"
    cache_root = out_root / "cache"

    for d in [baseline_root, evidence_root, context_root, prompt_root, plan_root, guidance_root, guided_root, report_root, cache_root]:
        _ensure_dir(str(d))

    baseline = run_hail_fuzz(
        manifest_path=args.fuzzer_manifest,
        firmware_config=args.firmware_config,
        ghidra_src=args.ghidra_src,
        workdir=str(baseline_root / "workdir"),
        run_log=str(baseline_root / "run.log"),
        run_for=args.run_for,
        observer_dir=str(baseline_root / "observer"),
        guidance_file=None,
        guidance_summary_out=None,
        import_dir=None,
        fuzzer_bin=fuzzer_bin,
        setenv=args.setenv,
    )

    build_evidence_pack(
        pdf_path=args.pdf,
        svd_path=args.svd,
        observer_dir=str(baseline_root / "observer"),
        cache_root=str(cache_root),
        out_path=str(evidence_root / "evidence_pack.json"),
        extract_strategy=args.extract_strategy,
        top_k=args.top_k,
        force_pdf=args.force_pdf,
    )

    task_context = build_task_context(
        evidence_pack_path=str(evidence_root / "evidence_pack.json"),
        run_log=str(baseline_root / "run.log"),
        out_path=str(context_root / "task_context.json"),
        board=args.board,
        mcu=args.mcu,
        benchmark=args.benchmark_name,
        best_guidance=args.best_guidance,
    )

    prompt_bundle = build_llm_prompt_bundle(task_context)
    save_json(str(prompt_root / "prompt_bundle.json"), prompt_bundle)
    save_text(str(prompt_root / "prompt_bundle.txt"), json.dumps(prompt_bundle, indent=2, ensure_ascii=False))

    _build_plan(
        str(context_root / "task_context.json"),
        args.plan_mode,
        str(plan_root / "plan.json"),
        max_candidates=args.max_candidates,
        default_after_reads=args.default_after_reads,
        llm_json=args.llm_json,
    )

    guidance_index = compile_plan(str(plan_root / "plan.json"), str(guidance_root))

    candidate_reports = []
    for item in guidance_index.get("compiled", []):
        candidate_id = str(item["candidate_id"])
        guidance_path = str(item["guidance_path"])
        run_root = guided_root / candidate_id
        _ensure_dir(str(run_root))

        run_hail_fuzz(
            manifest_path=args.fuzzer_manifest,
            firmware_config=args.firmware_config,
            ghidra_src=args.ghidra_src,
            workdir=str(run_root / "workdir"),
            run_log=str(run_root / "run.log"),
            run_for=args.run_for,
            observer_dir=str(run_root / "observer"),
            guidance_file=guidance_path,
            guidance_summary_out=str(run_root / "guidance_runtime_summary.json"),
            import_dir=None,
            fuzzer_bin=fuzzer_bin,
            setenv=args.setenv,
        )

        candidate_reports.append(_candidate_report(candidate_id, str(run_root)))

    final_report = {
        "fuzzer_bin": fuzzer_bin,
        "baseline": {
            **baseline,
            "latest_window_summary": _maybe_json(str(baseline_root / "observer" / "latest_window_summary.json")),
            "latest_window_discovered_streams": _maybe_json(str(baseline_root / "observer" / "latest_window_discovered_streams.json")),
            "latest_window_interesting_streams": _maybe_json(str(baseline_root / "observer" / "latest_window_interesting_streams.json")),
        },
        "evidence_pack_path": str(evidence_root / "evidence_pack.json"),
        "task_context_path": str(context_root / "task_context.json"),
        "prompt_bundle_path": str(prompt_root / "prompt_bundle.json"),
        "plan_path": str(plan_root / "plan.json"),
        "guidance_index_path": str(guidance_root / "guidance_index.json"),
        "candidate_reports": candidate_reports,
    }
    save_json(str(report_root / "auto_loop_summary.json"), final_report)
    info(f"auto loop summary written: {report_root / 'auto_loop_summary.json'}")


def staged_loop(args):
    out_root = Path(args.out_root).expanduser().resolve()
    _ensure_dir(str(out_root))
    fuzzer_bin = _abs(args.fuzzer_bin) if getattr(args, "fuzzer_bin", None) else ensure_fuzzer_binary(args.fuzzer_manifest)
    report_root = out_root / "report"
    shared_cache_root = out_root / "shared_cache"
    _ensure_dir(str(report_root))
    _ensure_dir(str(shared_cache_root))

    initial_root = out_root / "round_0_seed"
    _ensure_dir(str(initial_root))
    run_hail_fuzz(
        manifest_path=args.fuzzer_manifest,
        firmware_config=args.firmware_config,
        ghidra_src=args.ghidra_src,
        workdir=str(initial_root / "workdir"),
        run_log=str(initial_root / "run.log"),
        run_for=args.initial_run_for,
        observer_dir=str(initial_root / "observer"),
        guidance_file=None,
        guidance_summary_out=None,
        import_dir=None,
        fuzzer_bin=fuzzer_bin,
        setenv=args.setenv,
    )

    beam: List[Dict[str, Any]] = [_checkpoint_from_run("seed", str(initial_root), parent_checkpoint_id=None, score=None)]
    rounds: List[Dict[str, Any]] = []

    for round_idx in range(1, args.rounds + 1):
        round_root = out_root / f"round_{round_idx}"
        _ensure_dir(str(round_root))
        next_beam: List[Dict[str, Any]] = []
        round_report: Dict[str, Any] = {
            "round_index": round_idx,
            "parents": [],
            "beam_input": [cp["checkpoint_id"] for cp in beam],
        }

        for parent_idx, parent_cp in enumerate(beam):
            parent_root = round_root / f"parent_{parent_idx}_{parent_cp['checkpoint_id']}"
            _ensure_dir(str(parent_root))
            artifacts = _build_round_artifacts(
                parent_checkpoint=parent_cp,
                round_root=parent_root,
                shared_cache_root=shared_cache_root,
                pdf=args.pdf,
                svd=args.svd,
                board=args.board,
                mcu=args.mcu,
                benchmark_name=args.benchmark_name,
                extract_strategy=args.extract_strategy,
                top_k=args.top_k,
                force_pdf=args.force_pdf,
                plan_mode=args.plan_mode,
                llm_json=args.llm_json,
                best_guidance=args.best_guidance,
                max_candidates=args.max_candidates,
                default_after_reads=args.default_after_reads,
            )

            parent_entry = {
                "checkpoint_id": parent_cp["checkpoint_id"],
                "parent_run_root": parent_cp["run_root"],
                "artifacts": {k: v for k, v in artifacts.items() if k.endswith("_path")},
                "candidate_reports": [],
            }

            for item in artifacts["guidance_index"].get("compiled", []):
                candidate_id = str(item["candidate_id"])
                guidance_path = str(item["guidance_path"])
                candidate_run_root = parent_root / "candidates" / candidate_id
                _ensure_dir(str(candidate_run_root))

                run_hail_fuzz(
                    manifest_path=args.fuzzer_manifest,
                    firmware_config=args.firmware_config,
                    ghidra_src=args.ghidra_src,
                    workdir=str(candidate_run_root / "workdir"),
                    run_log=str(candidate_run_root / "run.log"),
                    run_for=args.candidate_run_for,
                    observer_dir=str(candidate_run_root / "observer"),
                    guidance_file=guidance_path,
                    guidance_summary_out=str(candidate_run_root / "guidance_runtime_summary.json"),
                    import_dir=parent_cp["queue_dir"],
                    fuzzer_bin=fuzzer_bin,
                    setenv=args.setenv,
                )

                report = _candidate_report(candidate_id, str(candidate_run_root), parent_checkpoint=parent_cp)
                parent_entry["candidate_reports"].append(report)
                next_beam.append(
                    _checkpoint_from_run(
                        checkpoint_id=f"r{round_idx}_{candidate_id}",
                        run_root=str(candidate_run_root),
                        parent_checkpoint_id=parent_cp["checkpoint_id"],
                        score=float(report.get("score") or 0.0),
                    )
                )

            parent_entry["candidate_reports"].sort(key=lambda x: float(x.get("score") or 0.0), reverse=True)
            round_report["parents"].append(parent_entry)

        next_beam.sort(key=lambda x: float(x.get("score") or 0.0), reverse=True)
        beam = next_beam[: args.beam_width]
        round_report["beam_after_round"] = [cp["checkpoint_id"] for cp in beam]
        round_report["beam_scores"] = {cp["checkpoint_id"]: cp.get("score") for cp in beam}
        rounds.append(round_report)
        save_json(str(report_root / f"round_{round_idx}_summary.json"), round_report)
        info(f"staged round {round_idx} summary written: {report_root / f'round_{round_idx}_summary.json'}")

        if not beam:
            warn(f"staged loop terminated early at round {round_idx}: no surviving candidates")
            break

    final_report = {
        "schema": "mf_staged_loop_report_v1",
        "shared_cache_root": str(shared_cache_root),
        "initial_seed": _checkpoint_from_run("seed", str(initial_root), parent_checkpoint_id=None, score=None),
        "rounds": rounds,
        "final_beam": beam,
    }
    save_json(str(report_root / "staged_loop_summary.json"), final_report)
    info(f"staged loop summary written: {report_root / 'staged_loop_summary.json'}")


def main():
    ap = argparse.ArgumentParser(description="Evidence-driven closed-loop fuzz planning CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("build-evidence")
    s1.add_argument("--pdf", required=True)
    s1.add_argument("--svd", required=True)
    s1.add_argument("--observer-dir", required=True)
    s1.add_argument("--cache-root", required=True)
    s1.add_argument("--out", required=True)
    s1.add_argument("--extract-strategy", default="layout")
    s1.add_argument("--top-k", type=int, default=8)
    s1.add_argument("--force-pdf", action="store_true")

    s2 = sub.add_parser("build-context")
    s2.add_argument("--evidence-pack", required=True)
    s2.add_argument("--run-log")
    s2.add_argument("--best-guidance")
    s2.add_argument("--board", required=True)
    s2.add_argument("--mcu", required=True)
    s2.add_argument("--benchmark", required=True)
    s2.add_argument("--out", required=True)

    s3 = sub.add_parser("prompt")
    s3.add_argument("--task-context", required=True)
    s3.add_argument("--out", required=True)
    s3.add_argument("--out-text")

    s4 = sub.add_parser("plan")
    s4.add_argument("--task-context", required=True)
    s4.add_argument("--mode", choices=["heuristic", "normalize_llm"], required=True)
    s4.add_argument("--out", required=True)
    s4.add_argument("--max-candidates", type=int, default=4)
    s4.add_argument("--default-after-reads", type=int, default=192)
    s4.add_argument("--llm-json")

    s5 = sub.add_parser("compile")
    s5.add_argument("--plan", required=True)
    s5.add_argument("--out-dir", required=True)

    s6 = sub.add_parser("run-fuzz")
    s6.add_argument("--fuzzer-manifest", required=True)
    s6.add_argument("--fuzzer-bin")
    s6.add_argument("--firmware-config", required=True)
    s6.add_argument("--ghidra-src", required=True)
    s6.add_argument("--workdir", required=True)
    s6.add_argument("--run-log", required=True)
    s6.add_argument("--run-for", default="300s")
    s6.add_argument("--observer-dir")
    s6.add_argument("--guidance-file")
    s6.add_argument("--guidance-summary-out")
    s6.add_argument("--import-dir")
    s6.add_argument("--setenv", action="append")

    s7 = sub.add_parser("auto-loop")
    s7.add_argument("--fuzzer-manifest", required=True)
    s7.add_argument("--fuzzer-bin")
    s7.add_argument("--firmware-config", required=True)
    s7.add_argument("--ghidra-src", required=True)
    s7.add_argument("--pdf", required=True)
    s7.add_argument("--svd", required=True)
    s7.add_argument("--board", required=True)
    s7.add_argument("--mcu", required=True)
    s7.add_argument("--benchmark-name", required=True)
    s7.add_argument("--out-root", required=True)
    s7.add_argument("--run-for", default="300s")
    s7.add_argument("--extract-strategy", default="layout")
    s7.add_argument("--top-k", type=int, default=8)
    s7.add_argument("--force-pdf", action="store_true")
    s7.add_argument("--plan-mode", choices=["heuristic", "normalize_llm"], default="heuristic")
    s7.add_argument("--llm-json")
    s7.add_argument("--best-guidance")
    s7.add_argument("--max-candidates", type=int, default=4)
    s7.add_argument("--default-after-reads", type=int, default=192)
    s7.add_argument("--setenv", action="append")

    s8 = sub.add_parser("staged-loop")
    s8.add_argument("--fuzzer-manifest", required=True)
    s8.add_argument("--fuzzer-bin")
    s8.add_argument("--firmware-config", required=True)
    s8.add_argument("--ghidra-src", required=True)
    s8.add_argument("--pdf", required=True)
    s8.add_argument("--svd", required=True)
    s8.add_argument("--board", required=True)
    s8.add_argument("--mcu", required=True)
    s8.add_argument("--benchmark-name", required=True)
    s8.add_argument("--out-root", required=True)
    s8.add_argument("--initial-run-for", default="300s")
    s8.add_argument("--candidate-run-for", default="60s")
    s8.add_argument("--rounds", type=int, default=2)
    s8.add_argument("--beam-width", type=int, default=2)
    s8.add_argument("--extract-strategy", default="layout")
    s8.add_argument("--top-k", type=int, default=8)
    s8.add_argument("--force-pdf", action="store_true")
    s8.add_argument("--plan-mode", choices=["heuristic", "normalize_llm"], default="heuristic")
    s8.add_argument("--llm-json")
    s8.add_argument("--best-guidance")
    s8.add_argument("--max-candidates", type=int, default=4)
    s8.add_argument("--default-after-reads", type=int, default=192)
    s8.add_argument("--setenv", action="append")

    args = ap.parse_args()

    if args.cmd == "build-evidence":
        build_evidence_pack(
            pdf_path=args.pdf,
            svd_path=args.svd,
            observer_dir=args.observer_dir,
            cache_root=args.cache_root,
            out_path=args.out,
            extract_strategy=args.extract_strategy,
            top_k=args.top_k,
            force_pdf=args.force_pdf,
        )
    elif args.cmd == "build-context":
        build_task_context(
            evidence_pack_path=args.evidence_pack,
            run_log=args.run_log,
            out_path=args.out,
            board=args.board,
            mcu=args.mcu,
            benchmark=args.benchmark,
            best_guidance=args.best_guidance,
        )
    elif args.cmd == "prompt":
        task_context = load_json(args.task_context)
        bundle = build_llm_prompt_bundle(task_context)
        save_json(args.out, bundle)
        if args.out_text:
            save_text(args.out_text, json.dumps(bundle, indent=2, ensure_ascii=False))
        info(f"prompt bundle saved: {args.out}")
    elif args.cmd == "plan":
        plan = _build_plan(
            args.task_context,
            args.mode,
            args.out,
            max_candidates=args.max_candidates,
            default_after_reads=args.default_after_reads,
            llm_json=args.llm_json,
        )
        info(f"plan saved: {args.out}; candidates={len(plan.get('candidates', []))}")
    elif args.cmd == "compile":
        compile_plan(args.plan, args.out_dir)
    elif args.cmd == "run-fuzz":
        out = run_hail_fuzz(
            manifest_path=args.fuzzer_manifest,
            firmware_config=args.firmware_config,
            ghidra_src=args.ghidra_src,
            workdir=args.workdir,
            run_log=args.run_log,
            run_for=args.run_for,
            observer_dir=args.observer_dir,
            guidance_file=args.guidance_file,
            guidance_summary_out=args.guidance_summary_out,
            import_dir=args.import_dir,
            fuzzer_bin=args.fuzzer_bin,
            setenv=args.setenv,
        )
        save_json(
            os.path.join(str(Path(args.workdir).resolve().parent), "run_fuzz_summary.json"),
            out,
        )
        info("run-fuzz completed")
    elif args.cmd == "auto-loop":
        auto_loop(args)
    elif args.cmd == "staged-loop":
        staged_loop(args)


if __name__ == "__main__":
    main()
