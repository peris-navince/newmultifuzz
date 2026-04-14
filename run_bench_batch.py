#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError as e:
    raise SystemExit("PyYAML is required: pip install pyyaml") from e


def _as_path(v: Any) -> Optional[Path]:
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.lower() == 'null':
        return None
    return Path(s).expanduser()


def load_manifest(path: Path) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or 'benchmarks' not in data:
        raise ValueError(f'invalid manifest: {path}')
    return data


def repo_root_from_manifest(manifest_path: Path, manifest: Dict[str, Any]) -> Path:
    raw = manifest.get('repo_root')
    if raw is None:
        return manifest_path.parent.resolve()
    p = _as_path(raw)
    if p is None:
        return manifest_path.parent.resolve()
    if not p.is_absolute():
        p = manifest_path.parent / p
    return p.resolve()


def resolve_repo_path(value: Any, *, repo_root: Path) -> Optional[str]:
    p = _as_path(value)
    if p is None:
        return None
    if not p.is_absolute():
        p = repo_root / p
    return str(p.resolve())


def merged_cfg(defaults: Dict[str, Any], bench: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(defaults or {})
    out.update(bench or {})
    return out


def should_run(bench: Dict[str, Any], args) -> Tuple[bool, str]:
    if args.only and bench.get('bench_id') not in set(args.only):
        return False, 'not_selected'
    if bench.get('enabled') is not True and not args.include_disabled:
        return False, 'disabled'
    conf = str(bench.get('mapping_confidence') or 'unsupported')
    if conf == 'unsupported' and not args.include_unsupported:
        return False, 'unsupported'
    if conf == 'provisional' and not args.include_provisional:
        return False, 'provisional_not_included'
    return True, 'selected'



def _infer_binary_from_config(resolved_cfg_path: str) -> Optional[str]:
    cfg = Path(resolved_cfg_path).resolve()
    parent = cfg.parent
    if not parent.exists():
        return None
    elfs = sorted(parent.glob('*.elf'))
    if len(elfs) == 1:
        return str(elfs[0].resolve())
    parent_name = parent.name.lower()
    stem = cfg.stem.lower()
    for cand in elfs:
        n = cand.stem.lower()
        if n == parent_name or n == stem:
            return str(cand.resolve())
    return str(elfs[0].resolve()) if elfs else None


def resolved_binary_path(cfg: Dict[str, Any], *, repo_root: Path) -> Optional[str]:
    for key in ['binary', 'elf']:
        resolved = resolve_repo_path(cfg.get(key), repo_root=repo_root)
        if resolved and Path(resolved).exists():
            return resolved
    fw = resolve_repo_path(cfg.get('firmware_config'), repo_root=repo_root)
    if fw and Path(fw).exists():
        return _infer_binary_from_config(fw)
    return None

def contract_bundle_path(cfg: Dict[str, Any], repo_root: Path) -> Optional[str]:
    explicit = cfg.get('contract_bundle') or cfg.get('default_contract_bundle')
    if explicit:
        return resolve_repo_path(explicit, repo_root=repo_root)
    return None


def validate_cfg(cfg: Dict[str, Any], *, repo_root: Path, args) -> Tuple[List[str], List[str], Optional[str], bool]:
    errors: List[str] = []
    warnings: List[str] = []
    for key in ['closed_loop_script', 'fuzzer_manifest', 'firmware_config', 'ghidra_src']:
        resolved = resolve_repo_path(cfg.get(key), repo_root=repo_root)
        if not resolved or not Path(resolved).exists():
            errors.append(f'missing {key}: {cfg.get(key)} -> {resolved}')

    bundle = contract_bundle_path(cfg, repo_root)
    bundle_exists = bool(bundle and Path(bundle).exists())
    using_materialization = False

    for key in ['elf']:
        resolved = resolve_repo_path(cfg.get(key), repo_root=repo_root)
        if resolved and not Path(resolved).exists():
            warnings.append(f'missing {key}: {cfg.get(key)} -> {resolved}')

    pdf_resolved = resolve_repo_path(cfg.get('pdf'), repo_root=repo_root)
    svd_resolved = resolve_repo_path(cfg.get('svd'), repo_root=repo_root)
    binary_resolved = resolved_binary_path(cfg, repo_root=repo_root)
    for key, resolved in [('pdf', pdf_resolved), ('svd', svd_resolved)]:
        if resolved and not Path(resolved).exists():
            warnings.append(f'missing {key}: {cfg.get(key)} -> {resolved}')

    if bundle_exists:
        return errors, warnings, bundle, using_materialization

    materialization_fields = [cfg.get('pdf'), cfg.get('svd'), cfg.get('board'), cfg.get('mcu'), cfg.get('benchmark_name')]
    materialization_ready = all(materialization_fields) and bool(pdf_resolved and Path(pdf_resolved).exists()) and bool(svd_resolved and Path(svd_resolved).exists())
    if materialization_ready and not binary_resolved:
        warnings.append('no ELF/binary resolved; materialization will continue without automatic Ghidra export')
    if materialization_ready:
        using_materialization = True
        if bundle and not Path(bundle).exists():
            warnings.append(f'contract bundle does not exist; using materialization route instead: {bundle}')
        elif not bundle:
            warnings.append('contract bundle missing; using materialization route instead')
    else:
        if bundle and not Path(bundle).exists():
            if not args.allow_missing_contract:
                errors.append(f'contract bundle does not exist: {bundle}')
            else:
                warnings.append(f'contract bundle does not exist: {bundle}')
        elif not bundle and not args.allow_missing_contract:
            errors.append('missing contract bundle and insufficient materialization inputs')
        else:
            warnings.append('missing contract bundle and insufficient materialization inputs')
    return errors, warnings, bundle, using_materialization


def build_command(cfg: Dict[str, Any], *, repo_root: Path, out_root: str, bundle: Optional[str], using_materialization: bool) -> List[str]:
    cmd = [
        sys.executable,
        resolve_repo_path(cfg['closed_loop_script'], repo_root=repo_root),
        str(cfg.get('default_mode') or 'adaptive-mmio-loop'),
        '--fuzzer-manifest', resolve_repo_path(cfg['fuzzer_manifest'], repo_root=repo_root),
        '--firmware-config', resolve_repo_path(cfg['firmware_config'], repo_root=repo_root),
        '--ghidra-src', resolve_repo_path(cfg['ghidra_src'], repo_root=repo_root),
        '--out-root', out_root,
        '--warmup-run-for', str(cfg['warmup_run_for']),
        '--warmup-restarts', str(cfg['warmup_restarts']),
        '--main-window-count', str(cfg['main_window_count']),
        '--main-window-run-for', str(cfg['main_window_run_for']),
        '--adaptive-period-windows', str(cfg['adaptive_period_windows']),
        '--adaptive-plateau-windows', str(cfg['adaptive_plateau_windows']),
        '--probe-run-for', str(cfg['probe_run_for']),
        '--followup-run-for', str(cfg['followup_run_for']),
        '--portfolio-run-for', str(cfg['portfolio_run_for']),
        '--strategy-control-every-windows', str(cfg['strategy_control_every_windows']),
        '--strategy-pool-max-size', str(cfg['strategy_pool_max_size']),
        '--strategy-trial-windows', str(cfg['strategy_trial_windows']),
        '--portfolio-intervention-coverage-slack', str(cfg['portfolio_intervention_coverage_slack']),
        '--use-recent-exec', str(cfg['use_recent_exec']),
        '--max-llm-cycles', str(cfg['max_llm_cycles']),
        '--llm-max-output-tokens', str(cfg['llm_max_output_tokens']),
        '--llm-max-attempts', str(cfg['llm_max_attempts']),
    ]
    if bundle and not using_materialization:
        cmd.extend(['--contract-bundle', bundle])
    if using_materialization:
        cmd.extend([
            '--pdf', resolve_repo_path(cfg['pdf'], repo_root=repo_root),
            '--svd', resolve_repo_path(cfg['svd'], repo_root=repo_root),
            '--board', str(cfg['board']),
            '--mcu', str(cfg['mcu']),
            '--benchmark-name', str(cfg['benchmark_name']),
            '--materialization-mode', str(cfg.get('materialization_mode') or 'staged-loop'),
            '--extract-strategy', str(cfg.get('extract_strategy') or 'layout'),
            '--top-k', str(cfg.get('top_k', 8)),
            '--plan-mode', str(cfg.get('plan_mode') or 'heuristic'),
            '--max-candidates', str(cfg.get('max_candidates', 4)),
            '--default-after-reads', str(cfg.get('default_after_reads', 192)),
        ])
        if cfg.get('shared_cache_root'):
            cmd.extend(['--shared-cache-root', resolve_repo_path(cfg['shared_cache_root'], repo_root=repo_root)])
        if cfg.get('shared_query_cache_root'):
            cmd.extend(['--shared-query-cache-root', resolve_repo_path(cfg['shared_query_cache_root'], repo_root=repo_root)])
        if cfg.get('candidate_run_for'):
            cmd.extend(['--candidate-run-for', str(cfg['candidate_run_for'])])
        if cfg.get('rounds') is not None:
            cmd.extend(['--rounds', str(cfg['rounds'])])
        if cfg.get('beam_width') is not None:
            cmd.extend(['--beam-width', str(cfg['beam_width'])])
        if cfg.get('allow_aggressive'):
            cmd.append('--allow-aggressive')
        if cfg.get('force_pdf'):
            cmd.append('--force-pdf')
        if cfg.get('llm_json'):
            cmd.extend(['--llm-json', resolve_repo_path(cfg['llm_json'], repo_root=repo_root)])
        if cfg.get('best_guidance'):
            cmd.extend(['--best-guidance', resolve_repo_path(cfg['best_guidance'], repo_root=repo_root)])
        binary_resolved = resolved_binary_path(cfg, repo_root=repo_root)
        if binary_resolved:
            cmd.extend(['--binary', binary_resolved])
        if cfg.get('ghidra_outdir'):
            cmd.extend(['--ghidra-outdir', resolve_repo_path(cfg['ghidra_outdir'], repo_root=repo_root)])
        if cfg.get('ghidra_summary_json'):
            cmd.extend(['--ghidra-summary-json', resolve_repo_path(cfg['ghidra_summary_json'], repo_root=repo_root)])
        if cfg.get('ghidra_export_json'):
            cmd.extend(['--ghidra-export-json', resolve_repo_path(cfg['ghidra_export_json'], repo_root=repo_root)])
    if cfg.get('import_dir'):
        cmd.extend(['--import-dir', resolve_repo_path(cfg['import_dir'], repo_root=repo_root)])
    return cmd


def run_one(cmd: List[str], *, cwd: Path, log_path: Path, dry_run: bool) -> int:
    print('cwd =', cwd)
    print('cmd =', ' '.join(shlex.quote(x) for x in cmd))
    if dry_run:
        return 0
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, 'w', encoding='utf-8') as logf:
        proc = subprocess.run(cmd, cwd=str(cwd), stdout=logf, stderr=subprocess.STDOUT, text=True, check=False)
    return proc.returncode


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--validate-only', action='store_true')
    ap.add_argument('--allow-missing-contract', action='store_true')
    ap.add_argument('--include-provisional', action='store_true')
    ap.add_argument('--include-unsupported', action='store_true')
    ap.add_argument('--include-disabled', action='store_true')
    ap.add_argument('--only', nargs='*')
    ap.add_argument('--repo-root', default=None, help='optional override; otherwise use manifest repo_root or manifest directory')
    args = ap.parse_args()

    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest = load_manifest(manifest_path)
    repo_root = Path(args.repo_root).expanduser().resolve() if args.repo_root else repo_root_from_manifest(manifest_path, manifest)

    defaults = manifest.get('defaults') or {}
    output_root = resolve_repo_path(defaults.get('output_root', 'workdir/batch_runs'), repo_root=repo_root)
    output_root_p = Path(output_root)
    output_root_p.mkdir(parents=True, exist_ok=True)

    summary = {
        'manifest': str(manifest_path),
        'repo_root': str(repo_root),
        'timestamp': datetime.now(UTC).isoformat().replace('+00:00', 'Z'),
        'results': [],
    }

    for bench in manifest.get('benchmarks', []):
        run_ok, reason = should_run(bench, args)
        cfg = merged_cfg(defaults, bench)
        errors, warnings, bundle, using_materialization = validate_cfg(cfg, repo_root=repo_root, args=args)
        rec = {
            'bench_id': bench.get('bench_id'),
            'selected': run_ok,
            'selection_reason': reason,
            'errors': errors,
            'warnings': warnings,
            'mapping_confidence': bench.get('mapping_confidence'),
            'family': bench.get('family'),
            'contract_bundle': bundle,
            'using_materialization': using_materialization,
            'binary': resolved_binary_path(cfg, repo_root=repo_root),
        }
        if not run_ok or errors or args.validate_only:
            summary['results'].append(rec)
            continue

        out_root = str((output_root_p / str(bench['bench_id'])).resolve())
        cmd = build_command(cfg, repo_root=repo_root, out_root=out_root, bundle=bundle, using_materialization=using_materialization)
        log_path = output_root_p / str(bench['bench_id']) / 'batch_run.log'
        rc = run_one(cmd, cwd=repo_root, log_path=log_path, dry_run=args.dry_run)
        rec.update({
            'out_root': out_root,
            'cwd': str(repo_root),
            'log_path': str(log_path),
            'returncode': rc,
        })
        summary['results'].append(rec)

    summary_path = output_root_p / 'batch_summary.json'
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f'\nsummary written to {summary_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
