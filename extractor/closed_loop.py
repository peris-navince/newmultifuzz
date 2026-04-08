from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from debug_trace import info, load_json, save_json, save_text, warn
from evidence_builder import build_evidence_pack
from guidance_compiler import compile_plan
from fixedpoint_manifest_builder import build_fixedpoint_manifest
from fixedpoint_selector import save_fixedpoint_prompt_bundle, save_fixedpoint_selector_plan
from strategy_planner import build_llm_prompt_bundle, heuristic_plan, normalize_llm_plan
from task_context import build_task_context, summarize_run_log


def _abs(path: str) -> str:
    return str(Path(path).expanduser().resolve())


def _ensure_dir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def _default_extractor_dir() -> Path:
    return Path(__file__).resolve().parent


def _default_shared_cache_root() -> Path:
    return _default_extractor_dir() / ".shared_pdf_svd_cache"


def _default_shared_query_cache_root() -> Path:
    return _default_extractor_dir() / ".shared_query_cache"


def _default_repo_root() -> Path:
    return _default_extractor_dir().parent


def _default_ghidra_src() -> str:
    candidates = [
        _default_repo_root() / "tools" / "ghidra",
        _default_repo_root() / "ghidra",
    ]
    for path in candidates:
        if path.exists():
            return str(path.resolve())
    return str(candidates[0].resolve())


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


def _run_root_from_workdir(workdir: str) -> Path:
    return Path(_abs(workdir)).parent


def _default_trace_paths(workdir: str, basename: str = "replay_trace") -> Dict[str, str]:
    run_root = _run_root_from_workdir(workdir)
    return {
        "trace_out": str((run_root / f"{basename}.json").resolve()),
        "trace_text_out": str((run_root / f"{basename}.log").resolve()),
        "trace_meta_out": str((run_root / f"{basename}.meta.json").resolve()),
    }


def _resolve_trace_paths(
    *,
    workdir: str,
    dump_trace: bool,
    trace_out: Optional[str],
    trace_text_out: Optional[str],
    trace_meta_out: Optional[str],
    trace_basename: str = "replay_trace",
) -> Dict[str, Optional[str]]:
    defaults = _default_trace_paths(workdir, basename=trace_basename)
    enabled = bool(dump_trace or trace_out or trace_text_out or trace_meta_out)
    if not enabled:
        return {
            "enabled": False,
            "trace_out": None,
            "trace_text_out": None,
            "trace_meta_out": None,
        }

    resolved_trace_out = _abs(trace_out) if trace_out else defaults["trace_out"]
    resolved_trace_text_out = _abs(trace_text_out) if trace_text_out else defaults["trace_text_out"]
    resolved_trace_meta_out = _abs(trace_meta_out) if trace_meta_out else defaults["trace_meta_out"]

    return {
        "enabled": True,
        "trace_out": resolved_trace_out,
        "trace_text_out": resolved_trace_text_out,
        "trace_meta_out": resolved_trace_meta_out,
    }


def _trace_file_info(run_root: str, basename: str = "replay_trace") -> Dict[str, Any]:
    run_root_abs = _abs(run_root)
    trace_json = os.path.join(run_root_abs, f"{basename}.json")
    trace_text = os.path.join(run_root_abs, f"{basename}.log")
    trace_meta = os.path.join(run_root_abs, f"{basename}.meta.json")
    return {
        "trace_json": trace_json if os.path.exists(trace_json) else None,
        "trace_text": trace_text if os.path.exists(trace_text) else None,
        "trace_meta_path": trace_meta if os.path.exists(trace_meta) else None,
        "trace_meta": _maybe_json(trace_meta),
    }


def _default_analysis_dir() -> Path:
    return _default_repo_root() / "analysis"


def _default_stuck_dir() -> Path:
    return _default_analysis_dir() / "stuck_attribution"


def _run_python_tool(script_path: str, args: List[str], *, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, _abs(script_path), *args]
    info(f"python tool :: {' '.join(shlex.quote(x) for x in cmd)}")
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        env=env or os.environ.copy(),
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"python tool failed ({proc.returncode}): {script_path}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def _run_llm_fallback_pipeline(args):
    out_root = Path(args.out_root).expanduser().resolve()
    _ensure_dir(str(out_root))

    fuzzer_bin = _abs(args.fuzzer_bin) if getattr(args, 'fuzzer_bin', None) else ensure_fuzzer_binary(args.fuzzer_manifest)
    run_root = out_root / 'run'
    _ensure_dir(str(run_root))

    run_log = run_root / 'run.log'
    workdir = run_root / 'workdir'
    observer_dir = run_root / 'observer'
    guidance_summary_out = run_root / 'guidance_runtime_summary.json'
    trace_base = str(getattr(args, 'trace_basename', 'replay_trace'))
    trace_json = run_root / f'{trace_base}.json'
    trace_text = run_root / f'{trace_base}.log'
    trace_meta = run_root / f'{trace_base}.meta.json'

    run_result = run_hail_fuzz(
        manifest_path=args.fuzzer_manifest,
        firmware_config=args.firmware_config,
        ghidra_src=args.ghidra_src,
        workdir=str(workdir),
        run_log=str(run_log),
        run_for=args.run_for,
        observer_dir=str(observer_dir),
        guidance_file=args.guidance_file,
        guidance_summary_out=str(guidance_summary_out),
        import_dir=args.import_dir,
        fuzzer_bin=fuzzer_bin,
        setenv=args.setenv,
        dump_trace=True,
        trace_out=str(trace_json),
        trace_text_out=str(trace_text),
        trace_meta_out=str(trace_meta),
        trace_basename=trace_base,
    )

    if not trace_json.exists():
        raise RuntimeError(f"trace export missing after run-fuzz: {trace_json}")

    stuck_dir = _default_stuck_dir()
    find_script = str(stuck_dir / 'find_stuck_functions.py')
    package_script = str(stuck_dir / 'package_llm_fallback.py')
    llm_script = str(stuck_dir / 'run_llm_fallback.py')

    stuck_report = out_root / 'stuck_report.json'
    llm_bundle_json = out_root / 'llm_fallback_bundle.json'
    llm_bundle_text = out_root / 'llm_fallback_prompt.txt'
    llm_answer_json = out_root / 'llm_answer.json'
    llm_answer_text = out_root / 'llm_answer.txt'
    llm_answer_raw = out_root / 'llm_answer.raw.json'

    find_args = [
        '--contract-bundle', _abs(args.contract_bundle),
        '--trace-json', str(trace_json),
        '--use-recent-exec', str(args.use_recent_exec),
        '--seed-path', _abs(args.guidance_file),
        '--out', str(stuck_report),
    ]
    if args.baseline_trace_json:
        find_args.extend(['--baseline-trace-json', _abs(args.baseline_trace_json)])
    if args.baseline_use_recent_exec:
        find_args.extend(['--baseline-use-recent-exec', str(args.baseline_use_recent_exec)])
    _run_python_tool(find_script, find_args)
    stuck_data = load_json(str(stuck_report))

    package_args = [
        '--contract-bundle', _abs(args.contract_bundle),
        '--stuck-report', str(stuck_report),
        '--manual-trace-json', str(trace_json),
        '--manual-seed', _abs(args.guidance_file),
        '--out', str(llm_bundle_json),
        '--out-text', str(llm_bundle_text),
    ]
    if args.baseline_trace_json:
        package_args.extend(['--baseline-trace-json', _abs(args.baseline_trace_json)])
    if args.baseline_seed:
        package_args.extend(['--baseline-seed', str(args.baseline_seed)])
    _run_python_tool(package_script, package_args)

    llm_invoked = False
    llm_result: Optional[Dict[str, Any]] = None
    if (not getattr(args, 'skip_llm', False)) and (bool(getattr(args, 'force_llm', False)) or bool(stuck_data.get('still_ambiguous'))):
        llm_args = [
            '--prompt-text', str(llm_bundle_text),
            '--bundle-json', str(llm_bundle_json),
            '--out-json', str(llm_answer_json),
            '--out-text', str(llm_answer_text),
            '--out-raw-response', str(llm_answer_raw),
            '--max-output-tokens', str(int(args.llm_max_output_tokens)),
            '--max-attempts', str(int(args.llm_max_attempts)),
            '--reasoning-effort', str(args.llm_reasoning_effort),
        ]
        if getattr(args, 'llm_model', None):
            llm_args.extend(['--model', str(args.llm_model)])
        _run_python_tool(llm_script, llm_args)
        llm_invoked = True
        llm_result = _maybe_json(str(llm_answer_json))

    summary = {
        'schema': 'mf_llm_fallback_pipeline_v1',
        'out_root': str(out_root),
        'run': run_result,
        'contract_bundle': _abs(args.contract_bundle),
        'guidance_file': _abs(args.guidance_file),
        'trace_json': str(trace_json),
        'trace_text': str(trace_text),
        'trace_meta': _maybe_json(str(trace_meta)),
        'stuck_report_path': str(stuck_report),
        'stuck_report': stuck_data,
        'llm_bundle_json': str(llm_bundle_json),
        'llm_bundle_text': str(llm_bundle_text),
        'llm_invoked': llm_invoked,
        'llm_answer_json': str(llm_answer_json) if llm_invoked else None,
        'llm_answer_text': str(llm_answer_text) if llm_invoked else None,
        'llm_answer_raw': str(llm_answer_raw) if llm_invoked else None,
        'llm_result': llm_result,
    }
    save_json(str(out_root / 'llm_fallback_pipeline_summary.json'), summary)
    info(f"llm-fallback-pipeline summary written: {out_root / 'llm_fallback_pipeline_summary.json'}")



def _safe_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", str(s or "")).strip("_") or "item"


def _normalize_hex(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        if s.lower().startswith('0x'):
            return f"0x{int(s,16):08X}"
        return f"0x{int(s,10):08X}"
    except Exception:
        return None


def _u32_hex(v: int) -> str:
    return f"0x{int(v) & 0xFFFFFFFF:08X}"


def _int_from_any(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        s = str(v).strip()
        if s.lower().startswith('0x'):
            return int(s, 16)
        return int(s, 10)
    except Exception:
        return None


def _load_contract_bundle(path: str) -> Dict[str, Any]:
    data = load_json(_abs(path))
    if 'program_context' not in data or 'document_context' not in data:
        raise ValueError(f"{path} does not look like a contract bundle")
    return data


def _bundle_target_hints(bundle: Dict[str, Any], extra: Optional[List[str]] = None) -> List[str]:
    hints: List[str] = []
    for spec in bundle.get('hot_peripheral_specs', []) or []:
        p = str(spec.get('peripheral') or '').strip().lower()
        if p and p not in hints:
            hints.append(p)
    for reg in bundle.get('document_context', {}).get('matched_peripheral_registers', []) or []:
        periph = str(reg.get('peripheral') or '').strip().lower()
        rname = str((reg.get('register') or {}).get('name') or '').strip().lower()
        for x in [periph, rname]:
            if x and x not in hints:
                hints.append(x)
    for x in extra or []:
        y = str(x).strip().lower()
        if y and y not in hints:
            hints.append(y)
    return hints


def _bundle_register_catalog(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for item in bundle.get('document_context', {}).get('matched_peripheral_registers', []) or []:
        reg = item.get('register') or {}
        periph = str(item.get('peripheral') or '').strip()
        rname = str(reg.get('name') or '').strip()
        addr = _normalize_hex(reg.get('absoluteAddress_hex') or reg.get('absoluteAddress'))
        off = _normalize_hex(reg.get('addressOffset_hex') or reg.get('addressOffset'))
        if not periph or not rname or not addr:
            continue
        key = (periph.upper(), rname.upper(), addr)
        if key in seen:
            continue
        seen.add(key)
        width = reg.get('size_bytes') or max(1, int((reg.get('size_bits') or 32) // 8))
        out.append({
            'peripheral': periph,
            'register': rname,
            'full_name': f"{periph}.{rname}",
            'absolute_addr_hex': addr,
            'offset_hex': off,
            'width': int(width),
            'svd_description': reg.get('svd_description'),
            'pdf_description': reg.get('pdf_description'),
            'fields': reg.get('fields') or [],
        })
    return out


def _catalog_lookup(catalog: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for reg in catalog:
        for key in [
            reg['register'].upper(),
            reg['full_name'].upper(),
            f"{reg['peripheral'].upper()}.{reg['register'].upper()}",
        ]:
            out.setdefault(key, reg)
    return out


def _read_seq_action(*, action_id: str, addr_hex: str, width: int, values: List[int], trigger: Dict[str, Any], activate_stage: Optional[str] = None, notes: str = "") -> Dict[str, Any]:
    action = {
        'type': 'mmio_read_sequence',
        'id': action_id,
        'addr': addr_hex,
        'width': int(width),
        'values': [_u32_hex(v) for v in values],
        'trigger': trigger,
        'notes': notes,
    }
    if activate_stage:
        action['activate_stage'] = activate_stage
    return action


def _write_observe_action(*, action_id: str, addr_hex: str, notes: str = "") -> Dict[str, Any]:
    return {
        'type': 'mmio_write_observe',
        'id': action_id,
        'addr': addr_hex,
        'trigger': {'kind': 'after_write', 'addr': addr_hex},
        'notes': notes,
    }


def _bit_update_action(*, action_id: str, addr_hex: str, width: int, set_bits: List[int], clear_bits: List[int], trigger: Dict[str, Any], activate_stage: Optional[str] = None, notes: str = "") -> Dict[str, Any]:
    action = {
        'type': 'mmio_bit_update',
        'id': action_id,
        'addr': addr_hex,
        'width': int(width),
        'set_bits': list(set_bits),
        'clear_bits': list(clear_bits),
        'trigger': trigger,
        'notes': notes,
    }
    if activate_stage:
        action['activate_stage'] = activate_stage
    return action


def _write_then_read_gate_action(*, action_id: str, write_addr_hex: str, read_addr_hex: str, width: int, read_value: int, mask: int = 1, value: int = 1, activate_stage: Optional[str] = None, notes: str = "") -> Dict[str, Any]:
    action = {
        'type': 'mmio_write_then_read_gate',
        'id': action_id,
        'write_addr': write_addr_hex,
        'write_mask': _u32_hex(mask),
        'write_value': _u32_hex(value),
        'read_addr': read_addr_hex,
        'width': int(width),
        'read_value': _u32_hex(read_value),
        'trigger': {
            'kind': 'after_write_value',
            'addr': write_addr_hex,
            'mask': _u32_hex(mask),
            'value': _u32_hex(value),
        },
        'notes': notes,
    }
    if activate_stage:
        action['activate_stage'] = activate_stage
    return action


def _pick_reg(catalog_lookup: Dict[str, Dict[str, Any]], *names: str) -> Optional[Dict[str, Any]]:
    for name in names:
        if not name:
            continue
        reg = catalog_lookup.get(str(name).upper())
        if reg:
            return reg
    return None


def _synthesize_generic_probe_guidance(*, contract_bundle_path: str, out_path: str, plan_name: str, peripheral_hints: Optional[List[str]] = None) -> Dict[str, Any]:
    bundle = _load_contract_bundle(contract_bundle_path)
    hints = _bundle_target_hints(bundle, peripheral_hints)
    catalog = _bundle_register_catalog(bundle)
    lookup = _catalog_lookup(catalog)
    actions: List[Dict[str, Any]] = []
    rationale_bits: List[str] = []

    tsr = _pick_reg(lookup, 'TSR')
    tar = _pick_reg(lookup, 'TAR')
    sr = _pick_reg(lookup, 'SR')
    ier = _pick_reg(lookup, 'IER')

    if tsr and tar:
        actions.append(_read_seq_action(
            action_id='probe_tsr_progression',
            addr_hex=tsr['absolute_addr_hex'],
            width=tsr['width'],
            values=[1, 1, 2, 2],
            trigger={'kind': 'on_first_touch', 'addr': tsr['absolute_addr_hex'], 'access': 'read'},
            activate_stage='tsr_seen',
            notes='Auto probe: drive TSR progression from contract-bundle register evidence.',
        ))
        actions.append(_read_seq_action(
            action_id='probe_tar_progression',
            addr_hex=tar['absolute_addr_hex'],
            width=tar['width'],
            values=[1, 2, 2, 3],
            trigger={'kind': 'when_stage_active', 'stage': 'tsr_seen'},
            activate_stage='tar_seen',
            notes='Auto probe: drive TAR progression to expose TAR/TSR relation.',
        ))
        rationale_bits.append('TSR/TAR progression seeded from contract-bundle register matches')
        if sr:
            actions.append(_bit_update_action(
                action_id='probe_sr_ready',
                addr_hex=sr['absolute_addr_hex'],
                width=sr['width'],
                set_bits=[4],
                clear_bits=[0],
                trigger={'kind': 'on_first_touch', 'addr': sr['absolute_addr_hex'], 'access': 'read'},
                activate_stage='sr_seen',
                notes='Auto probe: set a ready/alarm-style status bit on SR first touch.',
            ))
            rationale_bits.append('SR first-touch bit update added')
        if ier and sr:
            actions.append(_write_observe_action(
                action_id='probe_ier_write_observe',
                addr_hex=ier['absolute_addr_hex'],
                notes='Auto probe: observe IER writes to correlate interrupt-enable paths.',
            ))
            actions.append(_write_then_read_gate_action(
                action_id='probe_ier_then_sr_gate',
                write_addr_hex=ier['absolute_addr_hex'],
                read_addr_hex=sr['absolute_addr_hex'],
                width=sr['width'],
                read_value=0x10,
                activate_stage='irq_enable_seen',
                notes='Auto probe: if firmware enables IER low bit, force a ready-like SR value on the next read.',
            ))
            rationale_bits.append('IER->SR gate added')
    if not actions:
        for idx, reg in enumerate(catalog[:4]):
            rname = reg['register'].upper()
            aid = _safe_id(f"probe_{reg['full_name']}")
            if rname.endswith('SR') or 'STATUS' in rname:
                actions.append(_bit_update_action(
                    action_id=aid,
                    addr_hex=reg['absolute_addr_hex'],
                    width=reg['width'],
                    set_bits=[4],
                    clear_bits=[0],
                    trigger={'kind': 'on_first_touch', 'addr': reg['absolute_addr_hex'], 'access': 'read'},
                    activate_stage=f'seen_{idx}',
                    notes=f'Auto probe for {reg["full_name"]}: status-style first-touch bit update.',
                ))
            elif rname.endswith('CR') or rname.endswith('IER') or 'CTRL' in rname or 'CFG' in rname:
                actions.append(_write_observe_action(
                    action_id=aid,
                    addr_hex=reg['absolute_addr_hex'],
                    notes=f'Auto probe for {reg["full_name"]}: observe writes.',
                ))
            else:
                actions.append(_read_seq_action(
                    action_id=aid,
                    addr_hex=reg['absolute_addr_hex'],
                    width=reg['width'],
                    values=[1, 1, 2, 2],
                    trigger={'kind': 'on_first_touch', 'addr': reg['absolute_addr_hex'], 'access': 'read'},
                    activate_stage=f'seen_{idx}',
                    notes=f'Auto probe for {reg["full_name"]}: generic progression sequence.',
                ))
        rationale_bits.append('generic register probe synthesized from contract-bundle register catalog')

    guidance = {
        'schema': 'mf_runtime_strategy_v1',
        'plan_name': plan_name,
        'rationale': '; '.join(rationale_bits) or 'Auto-synthesized probe guidance from contract bundle.',
        'target_hints': hints,
        'actions': actions,
    }
    save_json(out_path, guidance)
    return guidance


_ASSIGNMENT_RE = re.compile(r'(?:\b([A-Za-z0-9_]+)\.)?([A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)')


def _parse_llm_assignments(parsed_json: Dict[str, Any]) -> Dict[str, List[int]]:
    text_parts = []
    for key in ['seed_hypothesis', 'likely_constraint', 'likely_blocking_condition']:
        v = parsed_json.get(key)
        if isinstance(v, str) and v.strip():
            text_parts.append(v)
    text = '\n'.join(text_parts)
    out: Dict[str, List[int]] = {}
    for m in _ASSIGNMENT_RE.finditer(text):
        periph, reg, val_s = m.groups()
        reg_key = f"{periph}.{reg}" if periph else reg
        val = _int_from_any(val_s)
        if val is None:
            continue
        out.setdefault(reg_key.upper(), [])
        if val not in out[reg_key.upper()]:
            out[reg_key.upper()].append(val)
    return out


def _pick_regs_from_offsets(catalog: List[Dict[str, Any]], offsets: List[str]) -> List[Dict[str, Any]]:
    norm_offsets = {_normalize_hex(x) for x in offsets if _normalize_hex(x)}
    out: List[Dict[str, Any]] = []
    for reg in catalog:
        if reg.get('offset_hex') in norm_offsets:
            out.append(reg)
    return out


def _synthesize_guidance_from_llm_answer(*, llm_answer_json_path: str, fallback_bundle_json_path: str, contract_bundle_path: str, out_path: str, plan_name: str) -> Dict[str, Any]:
    llm_answer = load_json(_abs(llm_answer_json_path))
    parsed = llm_answer.get('parsed_json') or {}
    fallback_bundle = load_json(_abs(fallback_bundle_json_path))
    contract_bundle = _load_contract_bundle(contract_bundle_path)
    catalog = _bundle_register_catalog(contract_bundle)
    lookup = _catalog_lookup(catalog)
    assignments = _parse_llm_assignments(parsed)

    actions: List[Dict[str, Any]] = []
    rationale_bits: List[str] = []

    matched_regs: List[Dict[str, Any]] = []
    for reg_key, vals in assignments.items():
        reg = lookup.get(reg_key.upper()) or lookup.get(reg_key.split('.')[-1].upper())
        if not reg:
            continue
        matched_regs.append(reg)
        seq = list(vals)[:4]
        while len(seq) < 4:
            seq.append(seq[-1])
        actions.append(_read_seq_action(
            action_id=_safe_id(f'llm_{reg["full_name"]}'),
            addr_hex=reg['absolute_addr_hex'],
            width=reg['width'],
            values=seq,
            trigger={'kind': 'on_first_touch', 'addr': reg['absolute_addr_hex'], 'access': 'read'},
            activate_stage=_safe_id(f'seen_{reg["register"]}'),
            notes=f'LLM-synthesized from seed_hypothesis for {reg["full_name"]}.',
        ))
        rationale_bits.append(f"LLM assignment {reg_key}={seq}")

    if not actions:
        likely_offsets = fallback_bundle.get('likely_blocking_offsets') or []
        offset_regs = _pick_regs_from_offsets(catalog, likely_offsets)
        for reg in offset_regs[:3]:
            actions.append(_read_seq_action(
                action_id=_safe_id(f'llm_offset_{reg["full_name"]}'),
                addr_hex=reg['absolute_addr_hex'],
                width=reg['width'],
                values=[1, 1, 2, 2],
                trigger={'kind': 'on_first_touch', 'addr': reg['absolute_addr_hex'], 'access': 'read'},
                activate_stage=_safe_id(f'seen_{reg["register"]}'),
                notes=f'LLM fallback synthesized from likely_blocking_offsets for {reg["full_name"]}.',
            ))
        if offset_regs:
            rationale_bits.append(f"offset-derived probe for {','.join(r['register'] for r in offset_regs[:3])}")

    # RTC-specific but evidence-driven: if both TSR and TAR appear, add a TAR/TSR relation probe.
    tsr = _pick_reg(lookup, 'TSR')
    tar = _pick_reg(lookup, 'TAR')
    sr = _pick_reg(lookup, 'SR')
    ier = _pick_reg(lookup, 'IER')
    parsed_text = ' '.join(str(parsed.get(k) or '') for k in ['likely_blocking_condition', 'likely_constraint', 'seed_hypothesis']).upper()
    if tsr and tar and ('TAR' in parsed_text and 'TSR' in parsed_text):
        have_tsr = any(a.get('addr') == tsr['absolute_addr_hex'] for a in actions)
        have_tar = any(a.get('addr') == tar['absolute_addr_hex'] for a in actions)
        if not have_tsr:
            actions.append(_read_seq_action(
                action_id='llm_tsr_progression',
                addr_hex=tsr['absolute_addr_hex'],
                width=tsr['width'],
                values=[1, 1, 2, 2],
                trigger={'kind': 'on_first_touch', 'addr': tsr['absolute_addr_hex'], 'access': 'read'},
                activate_stage='tsr_seen',
                notes='LLM relation probe for TSR.',
            ))
        if not have_tar:
            actions.append(_read_seq_action(
                action_id='llm_tar_progression',
                addr_hex=tar['absolute_addr_hex'],
                width=tar['width'],
                values=[1, 2, 2, 3],
                trigger={'kind': 'on_first_touch', 'addr': tar['absolute_addr_hex'], 'access': 'read'},
                activate_stage='tar_seen',
                notes='LLM relation probe for TAR.',
            ))
        if sr and not any(a.get('addr') == sr['absolute_addr_hex'] and a.get('type') == 'mmio_bit_update' for a in actions):
            actions.append(_bit_update_action(
                action_id='llm_sr_taf_ready',
                addr_hex=sr['absolute_addr_hex'],
                width=sr['width'],
                set_bits=[4],
                clear_bits=[0],
                trigger={'kind': 'on_first_touch', 'addr': sr['absolute_addr_hex'], 'access': 'read'},
                activate_stage='sr_seen',
                notes='LLM relation probe: set a ready/alarm-style SR bit.',
            ))
        if ier and sr and ('ALARM' in parsed_text or 'TAF' in parsed_text or 'TAIE' in parsed_text):
            actions.append(_write_observe_action(
                action_id='llm_ier_write_observe',
                addr_hex=ier['absolute_addr_hex'],
                notes='LLM relation probe: observe IER writes.',
            ))
            actions.append(_write_then_read_gate_action(
                action_id='llm_ier_then_sr_gate',
                write_addr_hex=ier['absolute_addr_hex'],
                read_addr_hex=sr['absolute_addr_hex'],
                width=sr['width'],
                read_value=0x10,
                activate_stage='irq_enable_seen',
                notes='LLM relation probe: on IER enable, force a ready-like SR read.',
            ))
        rationale_bits.append('TSR/TAR/SR/IER relation probe synthesized from LLM answer')

    if not actions:
        raise RuntimeError('failed to synthesize any runtime actions from the LLM answer')

    guidance = {
        'schema': 'mf_runtime_strategy_v1',
        'plan_name': plan_name,
        'rationale': '; '.join(rationale_bits) or 'LLM-synthesized runtime strategy.',
        'llm_source': {
            'response_id': llm_answer.get('response_id'),
            'model': llm_answer.get('model'),
            'parsed_json': parsed,
        },
        'actions': actions,
    }
    save_json(out_path, guidance)
    return guidance


def _coverage_from_run_summary(run_summary: Optional[Dict[str, Any]]) -> int:
    return int((run_summary or {}).get('last_cov') or 0)


def _run_adaptive_mmio_loop(args):
    out_root = Path(args.out_root).expanduser().resolve()
    _ensure_dir(str(out_root))
    fuzzer_bin = _abs(args.fuzzer_bin) if getattr(args, 'fuzzer_bin', None) else ensure_fuzzer_binary(args.fuzzer_manifest)

    # 1) establish a plateau frontier queue to import from
    if getattr(args, 'import_dir', None):
        current_import_dir = _abs(args.import_dir)
        baseline_summary = {'import_dir': current_import_dir, 'reused_existing_import_dir': True}
    else:
        seed_root = out_root / 'round_0_seed'
        _ensure_dir(str(seed_root))
        baseline_run = run_hail_fuzz(
            manifest_path=args.fuzzer_manifest,
            firmware_config=args.firmware_config,
            ghidra_src=args.ghidra_src,
            workdir=str(seed_root / 'workdir'),
            run_log=str(seed_root / 'run.log'),
            run_for=args.initial_run_for,
            observer_dir=str(seed_root / 'observer'),
            guidance_file=None,
            guidance_summary_out=None,
            import_dir=None,
            fuzzer_bin=fuzzer_bin,
            setenv=args.setenv,
            dump_trace=bool(getattr(args, 'dump_trace', False)),
            trace_basename=str(getattr(args, 'trace_basename', 'replay_trace')),
        )
        current_import_dir = str(seed_root / 'workdir' / 'queue')
        baseline_summary = baseline_run

    # 2) get an initial probe guidance, either provided or synthesized from the contract bundle
    if getattr(args, 'guidance_file', None):
        current_guidance_file = _abs(args.guidance_file)
        initial_guidance_kind = 'provided'
    else:
        current_guidance_file = str(out_root / 'auto_probe.guidance.json')
        _synthesize_generic_probe_guidance(
            contract_bundle_path=args.contract_bundle,
            out_path=current_guidance_file,
            plan_name=str(getattr(args, 'probe_plan_name', 'auto_mmio_probe')),
            peripheral_hints=getattr(args, 'peripheral_hint', None),
        )
        initial_guidance_kind = 'synthesized_from_contract_bundle'

    cycle_reports: List[Dict[str, Any]] = []
    final_queue_dir = current_import_dir
    final_guidance_file = current_guidance_file

    for cycle_idx in range(1, int(getattr(args, 'max_llm_cycles', 1)) + 1):
        cycle_root = out_root / f'cycle_{cycle_idx}'
        _ensure_dir(str(cycle_root))
        trace_base = str(getattr(args, 'trace_basename', 'replay_trace'))

        probe_root = cycle_root / 'probe'
        probe_run = run_hail_fuzz(
            manifest_path=args.fuzzer_manifest,
            firmware_config=args.firmware_config,
            ghidra_src=args.ghidra_src,
            workdir=str(probe_root / 'workdir'),
            run_log=str(probe_root / 'run.log'),
            run_for=args.probe_run_for,
            observer_dir=str(probe_root / 'observer'),
            guidance_file=current_guidance_file,
            guidance_summary_out=str(probe_root / 'guidance_runtime_summary.json'),
            import_dir=current_import_dir,
            fuzzer_bin=fuzzer_bin,
            setenv=args.setenv,
            dump_trace=True,
            trace_out=str(probe_root / f'{trace_base}.json'),
            trace_text_out=str(probe_root / f'{trace_base}.log'),
            trace_meta_out=str(probe_root / f'{trace_base}.meta.json'),
            trace_basename=trace_base,
        )
        probe_trace_json = str(probe_root / f'{trace_base}.json')

        stuck_dir = _default_stuck_dir()
        find_script = str(stuck_dir / 'find_stuck_functions.py')
        package_script = str(stuck_dir / 'package_llm_fallback.py')
        llm_script = str(stuck_dir / 'run_llm_fallback.py')

        stuck_report = cycle_root / 'stuck_report.json'
        llm_bundle_json = cycle_root / 'llm_fallback_bundle.json'
        llm_bundle_text = cycle_root / 'llm_fallback_prompt.txt'
        llm_answer_json = cycle_root / 'llm_answer.json'
        llm_answer_text = cycle_root / 'llm_answer.txt'
        llm_answer_raw = cycle_root / 'llm_answer.raw.json'
        llm_seed_guidance = cycle_root / 'llm_seed.guidance.json'

        _run_python_tool(find_script, [
            '--contract-bundle', _abs(args.contract_bundle),
            '--trace-json', probe_trace_json,
            '--use-recent-exec', str(args.use_recent_exec),
            '--seed-path', current_guidance_file,
            '--out', str(stuck_report),
        ])
        stuck_data = load_json(str(stuck_report))

        _run_python_tool(package_script, [
            '--contract-bundle', _abs(args.contract_bundle),
            '--stuck-report', str(stuck_report),
            '--manual-trace-json', probe_trace_json,
            '--manual-seed', current_guidance_file,
            '--out', str(llm_bundle_json),
            '--out-text', str(llm_bundle_text),
        ])

        llm_invoked = False
        llm_result = None
        synthesized_guidance = None
        next_guidance_file = None

        should_call_llm = (not bool(getattr(args, 'skip_llm', False))) and (bool(getattr(args, 'force_llm', False)) or bool(stuck_data.get('still_ambiguous', True)))
        if should_call_llm:
            llm_args = [
                '--prompt-text', str(llm_bundle_text),
                '--bundle-json', str(llm_bundle_json),
                '--out-json', str(llm_answer_json),
                '--out-text', str(llm_answer_text),
                '--out-raw-response', str(llm_answer_raw),
                '--max-output-tokens', str(int(args.llm_max_output_tokens)),
                '--max-attempts', str(int(args.llm_max_attempts)),
                '--reasoning-effort', str(args.llm_reasoning_effort),
            ]
            if getattr(args, 'llm_model', None):
                llm_args.extend(['--model', str(args.llm_model)])
            _run_python_tool(llm_script, llm_args)
            llm_invoked = True
            llm_result = _maybe_json(str(llm_answer_json))
            if llm_result and llm_result.get('parsed_json'):
                synthesized_guidance = _synthesize_guidance_from_llm_answer(
                    llm_answer_json_path=str(llm_answer_json),
                    fallback_bundle_json_path=str(llm_bundle_json),
                    contract_bundle_path=args.contract_bundle,
                    out_path=str(llm_seed_guidance),
                    plan_name=f"{getattr(args, 'llm_seed_plan_name', 'llm_seed')}_cycle_{cycle_idx}",
                )
                next_guidance_file = str(llm_seed_guidance)

        if not next_guidance_file:
            next_guidance_file = current_guidance_file

        followup_root = cycle_root / 'followup'
        followup_run = run_hail_fuzz(
            manifest_path=args.fuzzer_manifest,
            firmware_config=args.firmware_config,
            ghidra_src=args.ghidra_src,
            workdir=str(followup_root / 'workdir'),
            run_log=str(followup_root / 'run.log'),
            run_for=args.followup_run_for,
            observer_dir=str(followup_root / 'observer'),
            guidance_file=next_guidance_file,
            guidance_summary_out=str(followup_root / 'guidance_runtime_summary.json'),
            import_dir=str(probe_root / 'workdir' / 'queue'),
            fuzzer_bin=fuzzer_bin,
            setenv=args.setenv,
            dump_trace=bool(getattr(args, 'dump_followup_trace', False)),
            trace_basename=trace_base,
        )

        cycle_report = {
            'cycle_index': cycle_idx,
            'input_import_dir': current_import_dir,
            'input_guidance_file': current_guidance_file,
            'probe_run': probe_run,
            'stuck_report_path': str(stuck_report),
            'stuck_report': stuck_data,
            'llm_bundle_json': str(llm_bundle_json),
            'llm_bundle_text': str(llm_bundle_text),
            'llm_invoked': llm_invoked,
            'llm_answer_json': str(llm_answer_json) if llm_invoked else None,
            'llm_answer_text': str(llm_answer_text) if llm_invoked else None,
            'llm_answer_raw': str(llm_answer_raw) if llm_invoked else None,
            'llm_result': llm_result,
            'generated_guidance_file': str(llm_seed_guidance) if synthesized_guidance else None,
            'generated_guidance': synthesized_guidance,
            'followup_run': followup_run,
            'coverage_delta_probe_vs_input': _coverage_from_run_summary(probe_run.get('run_summary')) - int((baseline_summary.get('run_summary') or {}).get('last_cov') or 0) if cycle_idx == 1 else _coverage_from_run_summary(probe_run.get('run_summary')) - _coverage_from_run_summary(cycle_reports[-1]['followup_run'].get('run_summary')),
            'coverage_delta_followup_vs_probe': _coverage_from_run_summary(followup_run.get('run_summary')) - _coverage_from_run_summary(probe_run.get('run_summary')),
        }
        cycle_reports.append(cycle_report)

        current_import_dir = str(followup_root / 'workdir' / 'queue')
        final_queue_dir = current_import_dir
        current_guidance_file = next_guidance_file
        final_guidance_file = current_guidance_file

        if (not llm_invoked) and (not bool(getattr(args, 'force_llm', False))):
            break

    summary = {
        'schema': 'mf_adaptive_mmio_loop_v1',
        'contract_bundle': _abs(args.contract_bundle),
        'initial_guidance_kind': initial_guidance_kind,
        'initial_guidance_file': current_guidance_file if initial_guidance_kind == 'provided' else str(out_root / 'auto_probe.guidance.json'),
        'baseline_summary': baseline_summary,
        'cycles': cycle_reports,
        'final_queue_dir': final_queue_dir,
        'final_guidance_file': final_guidance_file,
    }
    save_json(str(out_root / 'adaptive_mmio_loop_summary.json'), summary)
    info(f"adaptive-mmio-loop summary written: {out_root / 'adaptive_mmio_loop_summary.json'}")


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
    dump_trace: bool = False,
    trace_out: Optional[str] = None,
    trace_text_out: Optional[str] = None,
    trace_meta_out: Optional[str] = None,
    trace_basename: str = "replay_trace",
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

    trace_paths = _resolve_trace_paths(
        workdir=workdir,
        dump_trace=dump_trace,
        trace_out=trace_out,
        trace_text_out=trace_text_out,
        trace_meta_out=trace_meta_out,
        trace_basename=trace_basename,
    )
    trace_env_keys = {
        "MF_EXEC_TRACE_OUT": trace_paths["trace_out"],
        "MF_EXEC_TRACE_TEXT_OUT": trace_paths["trace_text_out"],
        "MF_EXEC_TRACE_META_OUT": trace_paths["trace_meta_out"],
        # Generic aliases so downstream executor/fuzzer code can adopt either naming style.
        "MF_TRACE_OUT": trace_paths["trace_out"],
        "MF_TRACE_TEXT_OUT": trace_paths["trace_text_out"],
        "MF_TRACE_META_OUT": trace_paths["trace_meta_out"],
        "MF_RUNTIME_TRACE_OUT": trace_paths["trace_out"],
        "MF_RUNTIME_TRACE_TEXT_OUT": trace_paths["trace_text_out"],
        "MF_RUNTIME_TRACE_META_OUT": trace_paths["trace_meta_out"],
    }
    for k, v in trace_env_keys.items():
        if v:
            env[k] = v
        else:
            env.pop(k, None)

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
        "trace_enabled": bool(trace_paths["enabled"]),
        "trace_out": trace_paths["trace_out"],
        "trace_text_out": trace_paths["trace_text_out"],
        "trace_meta_out": trace_paths["trace_meta_out"],
        "trace_json_exists": bool(trace_paths["trace_out"] and os.path.exists(trace_paths["trace_out"])),
        "trace_text_exists": bool(trace_paths["trace_text_out"] and os.path.exists(trace_paths["trace_text_out"])),
        "trace_meta_exists": bool(trace_paths["trace_meta_out"] and os.path.exists(trace_paths["trace_meta_out"])),
        "trace_meta": _maybe_json(trace_paths["trace_meta_out"]) if trace_paths["trace_meta_out"] else None,
        **_extract_import_summary(run_log),
    }


def run_fixedpoint_sweep(
    *,
    manifest_path: str,
    fuzzer_manifest: str,
    firmware_config: str,
    ghidra_src: str,
    workdir: str,
    run_log: str,
    fuzzer_bin: Optional[str] = None,
    setenv: Optional[List[str]] = None,
) -> Dict[str, Any]:
    env = os.environ.copy()
    env["GHIDRA_SRC"] = _abs(ghidra_src)
    env["WORKDIR"] = _abs(workdir)
    env["MF_FIXED_SWEEP_MANIFEST"] = _abs(manifest_path)
    env.pop("MF_MMIO_GUIDANCE_FILE", None)
    env.pop("MF_MMIO_GUIDANCE_SUMMARY_OUT", None)
    env.pop("MF_IMPORT_DIR", None)

    for k, v in _parse_env_overrides(setenv).items():
        env[k] = v

    resolved_bin = _abs(fuzzer_bin) if fuzzer_bin else ensure_fuzzer_binary(fuzzer_manifest)
    cmd = [resolved_bin, firmware_config]
    _run_logged(cmd, cwd=str(Path(fuzzer_manifest).resolve().parent), env=env, log_path=run_log)

    manifest = load_json(manifest_path)
    summary_out = str(manifest.get("summary_out") or "")
    return {
        "manifest_path": _abs(manifest_path),
        "run_log": _abs(run_log),
        "workdir": _abs(workdir),
        "fuzzer_bin": resolved_bin,
        "summary_out": _abs(summary_out) if summary_out else None,
        "summary": _maybe_json(summary_out) if summary_out else None,
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
    trace_info = _trace_file_info(run_root_abs)
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
        **trace_info,
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
    trace_info = _trace_file_info(run_root)
    report = {
        "candidate_id": candidate_id,
        "run_root": _abs(run_root),
        "run_summary": summarize_run_log(run_log),
        "guidance_runtime_summary": _maybe_json(os.path.join(run_root, "guidance_runtime_summary.json")),
        "latest_window_summary": _maybe_json(os.path.join(obs, "latest_window_summary.json")),
        "latest_window_discovered_streams": _maybe_json(os.path.join(obs, "latest_window_discovered_streams.json")),
        "latest_window_interesting_streams": _maybe_json(os.path.join(obs, "latest_window_interesting_streams.json")),
        **_extract_import_summary(run_log),
        **trace_info,
    }
    if parent_checkpoint is not None:
        report["score_breakdown"] = _score_candidate(parent_checkpoint, report)
        report["score"] = report["score_breakdown"]["score"]
    return report


AGGRESSIVE_TEMPLATE_PREFIXES = (
    "status_then_",
    "handshake",
    "uart_handshake",
)
AGGRESSIVE_ACTION_TYPES = {
    "uart_handshake_once",
}


def _candidate_plan_map(plan_path: str) -> Dict[str, Dict[str, Any]]:
    plan = load_json(plan_path)
    out: Dict[str, Dict[str, Any]] = {}
    for cand in plan.get("candidates", []) or []:
        cid = str(cand.get("id") or "")
        if cid:
            out[cid] = cand
    return out


def _template_is_aggressive(template_id: str) -> bool:
    tid = str(template_id or "")
    return any(tid.startswith(prefix) for prefix in AGGRESSIVE_TEMPLATE_PREFIXES)



def _action_types_for_candidate(plan_candidate: Dict[str, Any]) -> List[str]:
    return [str(a.get("type") or "") for a in (plan_candidate.get("actions") or [])]



def _plan_candidate_meta(candidate_id: str, plan_candidate: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cand = plan_candidate or {}
    action_types = _action_types_for_candidate(cand)
    template_id = str(cand.get("template_id") or "")
    aggressive = _template_is_aggressive(template_id) or any(a in AGGRESSIVE_ACTION_TYPES for a in action_types)
    return {
        "candidate_id": candidate_id,
        "group_id": str(cand.get("group_id") or ""),
        "template_id": template_id,
        "action_types": action_types,
        "aggressive": aggressive,
    }



def _filter_tournament_candidates(
    *,
    guidance_index: Dict[str, Any],
    plan_path: str,
    allow_aggressive: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    plan_map = _candidate_plan_map(plan_path)
    selected: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for item in guidance_index.get("compiled", []) or []:
        candidate_id = str(item.get("candidate_id") or "")
        meta = _plan_candidate_meta(candidate_id, plan_map.get(candidate_id))
        wrapped = {"compiled": item, "meta": meta}
        if meta["aggressive"] and not allow_aggressive:
            skipped.append({**meta, "reason": "filtered_aggressive"})
            continue
        selected.append(wrapped)

    return selected, skipped



def _control_meta() -> Dict[str, Any]:
    return {
        "candidate_id": "control",
        "group_id": "",
        "template_id": "control",
        "action_types": [],
        "aggressive": False,
    }



def _report_compare_to_control(report: Dict[str, Any], control_report: Dict[str, Any]) -> Dict[str, Any]:
    sb = report.get("score_breakdown") or {}
    ctrl_sb = control_report.get("score_breakdown") or {}
    return {
        "delta_cov_vs_control": int(sb.get("delta_cov") or 0) - int(ctrl_sb.get("delta_cov") or 0),
        "new_hotspots_vs_control": int(sb.get("new_hotspots") or 0) - int(ctrl_sb.get("new_hotspots") or 0),
        "fire_count_vs_control": int(sb.get("fire_count") or 0) - int(ctrl_sb.get("fire_count") or 0),
        "active_stage_count_vs_control": int(sb.get("active_stage_count") or 0) - int(ctrl_sb.get("active_stage_count") or 0),
        "child_cov_vs_control": int(sb.get("child_cov") or 0) - int(ctrl_sb.get("child_cov") or 0),
        "child_hangs_vs_control": int(sb.get("child_hangs") or 0) - int(ctrl_sb.get("child_hangs") or 0),
        "score_vs_control": float(report.get("score") or 0.0) - float(control_report.get("score") or 0.0),
    }



def _classify_guided_report(report: Dict[str, Any], control_report: Optional[Dict[str, Any]]) -> str:
    candidate_id = str(report.get("candidate_id") or "")
    if candidate_id == "control":
        return "control"

    sb = report.get("score_breakdown") or {}
    delta_cov = int(sb.get("delta_cov") or 0)
    new_hotspots = int(sb.get("new_hotspots") or 0)
    fire_count = int(sb.get("fire_count") or 0)
    active_stage_count = int(sb.get("active_stage_count") or 0)
    child_hangs = int(sb.get("child_hangs") or 0)
    child_cov = int(sb.get("child_cov") or 0)

    if control_report is None:
        if delta_cov > 0 or new_hotspots > 0:
            return "effective"
        if fire_count > 0 or active_stage_count > 0:
            return "weak_effect"
        return "no_effect"

    ctrl_sb = control_report.get("score_breakdown") or {}
    ctrl_delta_cov = int(ctrl_sb.get("delta_cov") or 0)
    ctrl_new_hotspots = int(ctrl_sb.get("new_hotspots") or 0)
    ctrl_child_hangs = int(ctrl_sb.get("child_hangs") or 0)
    ctrl_child_cov = int(ctrl_sb.get("child_cov") or 0)

    if delta_cov > ctrl_delta_cov or new_hotspots > ctrl_new_hotspots or child_cov > ctrl_child_cov:
        return "effective"
    if child_hangs > ctrl_child_hangs and child_cov < ctrl_child_cov:
        return "regressive"
    if fire_count > 0 or active_stage_count > 0:
        return "weak_effect"
    return "no_effect"



def _attach_candidate_eval(report: Dict[str, Any], *, meta: Dict[str, Any], control_report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    report["candidate_meta"] = meta
    report["compare_to_control"] = _report_compare_to_control(report, control_report) if control_report is not None else None
    report["verdict"] = _classify_guided_report(report, control_report)
    return report



def _verdict_rank(verdict: Optional[str]) -> int:
    order = {
        "control": 0,
        "effective": 1,
        "weak_effect": 2,
        "no_effect": 3,
        "regressive": 4,
    }
    return order.get(str(verdict or ""), 99)



def _report_sort_key(report: Dict[str, Any]) -> Tuple[int, float, int, int]:
    sb = report.get("score_breakdown") or {}
    return (
        _verdict_rank(report.get("verdict")),
        -float(report.get("score") or 0.0),
        -int(sb.get("delta_cov") or 0),
        -int(sb.get("new_hotspots") or 0),
    )



def _promote_parent_survivors(
    *,
    control_checkpoint: Dict[str, Any],
    guided_checkpoints: List[Dict[str, Any]],
    max_weak_per_parent: int,
) -> List[Dict[str, Any]]:
    effective = [cp for cp in guided_checkpoints if cp.get("verdict") == "effective"]
    weak = [cp for cp in guided_checkpoints if cp.get("verdict") == "weak_effect"]

    effective.sort(key=lambda cp: _report_sort_key(cp), reverse=False)
    weak.sort(key=lambda cp: _report_sort_key(cp), reverse=False)

    survivors: List[Dict[str, Any]] = [control_checkpoint]
    survivors.extend(effective)
    survivors.extend(weak[: max(0, int(max_weak_per_parent))])
    return survivors



def _select_next_beam(candidates: List[Dict[str, Any]], beam_width: int) -> List[Dict[str, Any]]:
    ordered = sorted(candidates, key=lambda cp: _report_sort_key(cp))
    return ordered[: max(0, int(beam_width))]


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



def _copy_tree(src: Path, dst: Path):
    if not src.exists():
        return
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def _valid_json_file(path: Path) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            json.load(f)
        return True
    except Exception:
        return False


def _canonical_hotspot_addrs(parent_checkpoint: Dict[str, Any], top_k: int) -> List[str]:
    """
    Stable hotspot signature used for query-cache matching.

    We intentionally ignore read-count jitter and keep only the first top_k
    unique hotspot addresses in observed priority order, then sort the selected
    subset so minor ordering changes do not break cache hits.
    """
    sources = [
        parent_checkpoint.get("latest_window_discovered_streams") or [],
        parent_checkpoint.get("latest_window_interesting_streams") or [],
    ]
    ordered: List[str] = []
    seen = set()
    for src in sources:
        for item in src:
            addr = str(item.get("addr") or "").strip().upper()
            if not addr or addr in seen:
                continue
            seen.add(addr)
            ordered.append(addr)
            if len(ordered) >= top_k:
                break
        if ordered:
            break
    return sorted(ordered[:top_k])


def _query_cache_sig(
    *,
    hotspot_addrs: List[str],
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
    return {
        "hotspot_addrs": list(hotspot_addrs),
        "pdf": _abs(pdf),
        "svd": _abs(svd),
        "board": board,
        "mcu": mcu,
        "benchmark_name": benchmark_name,
        "extract_strategy": extract_strategy,
        "top_k": top_k,
        "force_pdf": bool(force_pdf),
        "plan_mode": plan_mode,
        "llm_json": llm_json or "",
        "best_guidance": best_guidance or "",
        "max_candidates": max_candidates,
        "default_after_reads": default_after_reads,
    }


def _query_cache_key_from_sig(sig: Dict[str, Any]) -> str:
    blob = json.dumps(sig, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _query_cache_variants(
    *,
    parent_checkpoint: Dict[str, Any],
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
) -> List[Dict[str, Any]]:
    addrs = _canonical_hotspot_addrs(parent_checkpoint, top_k)
    if not addrs:
        return []

    base_kwargs = dict(
        pdf=pdf,
        svd=svd,
        board=board,
        mcu=mcu,
        benchmark_name=benchmark_name,
        extract_strategy=extract_strategy,
        top_k=top_k,
        force_pdf=force_pdf,
        plan_mode=plan_mode,
        llm_json=llm_json,
        best_guidance=best_guidance,
        max_candidates=max_candidates,
        default_after_reads=default_after_reads,
    )

    variants: List[Dict[str, Any]] = []
    seen = set()

    def _add(label: str, subset: List[str]):
        sig = _query_cache_sig(hotspot_addrs=subset, **base_kwargs)
        key = _query_cache_key_from_sig(sig)
        if key in seen:
            return
        seen.add(key)
        variants.append({"label": label, "sig": sig, "key": key, "hotspot_addrs": subset})

    _add("strict", addrs)
    if len(addrs) >= 6:
        _add("prefix6", addrs[:6])
    if len(addrs) >= 4:
        _add("prefix4", addrs[:4])

    return variants


def _cache_bundle_ok(cache_root: Path) -> bool:
    needed = [
        cache_root / "evidence" / "evidence_pack.json",
        cache_root / "context" / "task_context.json",
        cache_root / "plan" / "plan.json",
        cache_root / "guidance" / "guidance_index.json",
    ]
    return all(_valid_json_file(p) for p in needed)


def _materialize_cached_bundle(cache_root: Path, round_root: Path, *, hit_label: str, hit_hotspot_addrs: List[str]) -> Dict[str, Any]:
    for sub in ["evidence", "context", "prompt", "plan", "guidance"]:
        src = cache_root / sub
        dst = round_root / sub
        if src.exists():
            _copy_tree(src, dst)
    guidance_index = load_json(str(round_root / "guidance" / "guidance_index.json"))
    return {
        "cache_hit": True,
        "query_cache_key": cache_root.name,
        "query_cache_hit_label": hit_label,
        "query_cache_hotspot_addrs": hit_hotspot_addrs,
        "evidence_pack_path": str(round_root / "evidence" / "evidence_pack.json"),
        "task_context_path": str(round_root / "context" / "task_context.json"),
        "prompt_bundle_path": str(round_root / "prompt" / "prompt_bundle.json"),
        "plan_path": str(round_root / "plan" / "plan.json"),
        "guidance_index_path": str(round_root / "guidance" / "guidance_index.json"),
        "guidance_index": guidance_index,
    }


def _populate_query_cache(round_root: Path, cache_root: Path, *, cache_meta: Optional[Dict[str, Any]] = None):
    for sub in ["evidence", "context", "prompt", "plan", "guidance"]:
        src = round_root / sub
        dst = cache_root / sub
        if src.exists():
            _copy_tree(src, dst)
    if cache_meta is not None:
        save_json(str(cache_root / "query_cache_meta.json"), cache_meta)


def _find_query_cache_bundle(
    *,
    parent_checkpoint: Dict[str, Any],
    shared_query_cache_root: Path,
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
    variants = _query_cache_variants(
        parent_checkpoint=parent_checkpoint,
        pdf=pdf,
        svd=svd,
        board=board,
        mcu=mcu,
        benchmark_name=benchmark_name,
        extract_strategy=extract_strategy,
        top_k=top_k,
        force_pdf=force_pdf,
        plan_mode=plan_mode,
        llm_json=llm_json,
        best_guidance=best_guidance,
        max_candidates=max_candidates,
        default_after_reads=default_after_reads,
    )
    if not variants:
        warn("query bundle cache miss: no hotspot addresses available for signature")
        return {"hit": False, "reason": "no_hotspot_addresses"}

    tried = []
    for v in variants:
        cache_dir = shared_query_cache_root / v["key"]
        ok = _cache_bundle_ok(cache_dir)
        if ok:
            info(f"reusing cached query bundle: {cache_dir} (label={v['label']} addrs={v['hotspot_addrs']})")
            return {
                "hit": True,
                "cache_dir": cache_dir,
                "key": v["key"],
                "label": v["label"],
                "hotspot_addrs": v["hotspot_addrs"],
                "reason": "bundle_ok",
            }
        tried.append({
            "label": v["label"],
            "key": v["key"],
            "hotspot_addrs": v["hotspot_addrs"],
            "exists": cache_dir.exists(),
            "bundle_ok": ok,
        })

    info("query bundle cache miss: no valid cached bundle for variants=" + json.dumps(tried, ensure_ascii=False))
    return {
        "hit": False,
        "reason": "no_valid_bundle",
        "tried": tried,
        "strict_key": variants[0]["key"],
        "strict_hotspot_addrs": variants[0]["hotspot_addrs"],
        "strict_sig": variants[0]["sig"],
    }



def _build_round_artifacts(
    *,
    parent_checkpoint: Dict[str, Any],
    round_root: Path,
    shared_cache_root: Path,
    shared_query_cache_root: Path,
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
    for d in [evidence_root, context_root, prompt_root, plan_root, guidance_root, cache_root, shared_query_cache_root]:
        _ensure_dir(str(d))

    cache_lookup = _find_query_cache_bundle(
        parent_checkpoint=parent_checkpoint,
        shared_query_cache_root=shared_query_cache_root,
        pdf=pdf,
        svd=svd,
        board=board,
        mcu=mcu,
        benchmark_name=benchmark_name,
        extract_strategy=extract_strategy,
        top_k=top_k,
        force_pdf=force_pdf,
        plan_mode=plan_mode,
        llm_json=llm_json,
        best_guidance=best_guidance,
        max_candidates=max_candidates,
        default_after_reads=default_after_reads,
    )
    if cache_lookup.get("hit"):
        return _materialize_cached_bundle(
            cache_lookup["cache_dir"],
            round_root,
            hit_label=str(cache_lookup["label"]),
            hit_hotspot_addrs=list(cache_lookup.get("hotspot_addrs") or []),
        )

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

    if cache_lookup.get("strict_key"):
        qdir = shared_query_cache_root / str(cache_lookup["strict_key"])
        _populate_query_cache(
            round_root,
            qdir,
            cache_meta={
                "query_cache_key": cache_lookup["strict_key"],
                "hotspot_addrs": cache_lookup.get("strict_hotspot_addrs") or [],
                "signature": cache_lookup.get("strict_sig") or {},
                "source_parent_checkpoint": parent_checkpoint.get("checkpoint_id"),
            },
        )
        info(f"stored query bundle cache: {qdir}")

    return {
        "cache_hit": False,
        "query_cache_key": cache_lookup.get("strict_key"),
        "query_cache_hotspot_addrs": cache_lookup.get("strict_hotspot_addrs") or [],
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
    cache_root = Path(args.shared_cache_root).expanduser().resolve() if getattr(args, "shared_cache_root", None) else _default_shared_cache_root()

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
        dump_trace=bool(getattr(args, "dump_trace", False)),
        trace_out=str((baseline_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".json")),
        trace_text_out=str((baseline_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".log")),
        trace_meta_out=str((baseline_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".meta.json")),
        trace_basename=str(getattr(args, "trace_basename", "replay_trace")),
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
            dump_trace=bool(getattr(args, "dump_trace", False)),
            trace_out=str((run_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".json")),
            trace_text_out=str((run_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".log")),
            trace_meta_out=str((run_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".meta.json")),
            trace_basename=str(getattr(args, "trace_basename", "replay_trace")),
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
    shared_cache_root = Path(args.shared_cache_root).expanduser().resolve() if getattr(args, "shared_cache_root", None) else _default_shared_cache_root()
    shared_query_cache_root = Path(args.shared_query_cache_root).expanduser().resolve() if getattr(args, "shared_query_cache_root", None) else _default_shared_query_cache_root()
    _ensure_dir(str(report_root))
    _ensure_dir(str(shared_cache_root))
    _ensure_dir(str(shared_query_cache_root))

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
        dump_trace=bool(getattr(args, "dump_trace", False)),
        trace_out=str((initial_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".json")),
        trace_text_out=str((initial_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".log")),
        trace_meta_out=str((initial_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".meta.json")),
        trace_basename=str(getattr(args, "trace_basename", "replay_trace")),
    )

    beam: List[Dict[str, Any]] = [_checkpoint_from_run("seed", str(initial_root), parent_checkpoint_id=None, score=None)]
    rounds: List[Dict[str, Any]] = []

    for round_idx in range(1, args.rounds + 1):
        round_root = out_root / f"round_{round_idx}"
        _ensure_dir(str(round_root))
        next_beam_candidates: List[Dict[str, Any]] = []
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
                shared_query_cache_root=shared_query_cache_root,
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

            selected_items, skipped_items = _filter_tournament_candidates(
                guidance_index=artifacts["guidance_index"],
                plan_path=artifacts["plan_path"],
                allow_aggressive=bool(getattr(args, "allow_aggressive", False)),
            )

            parent_entry = {
                "checkpoint_id": parent_cp["checkpoint_id"],
                "parent_run_root": parent_cp["run_root"],
                "artifacts": {k: v for k, v in artifacts.items() if k.endswith("_path") or k.startswith("query_cache_") or k == "cache_hit"},
                "candidate_selection": {
                    "allow_aggressive": bool(getattr(args, "allow_aggressive", False)),
                    "compiled_total": len(artifacts["guidance_index"].get("compiled", []) or []),
                    "selected_candidate_ids": [str(x["compiled"].get("candidate_id") or "") for x in selected_items],
                    "skipped_candidates": skipped_items,
                },
                "candidate_reports": [],
                "promoted_checkpoints": [],
            }

            control_run_root = parent_root / "control"
            _ensure_dir(str(control_run_root))
            run_hail_fuzz(
                manifest_path=args.fuzzer_manifest,
                firmware_config=args.firmware_config,
                ghidra_src=args.ghidra_src,
                workdir=str(control_run_root / "workdir"),
                run_log=str(control_run_root / "run.log"),
                run_for=args.candidate_run_for,
                observer_dir=str(control_run_root / "observer"),
                guidance_file=None,
                guidance_summary_out=None,
                import_dir=parent_cp["queue_dir"],
                fuzzer_bin=fuzzer_bin,
                setenv=args.setenv,
                dump_trace=bool(getattr(args, "dump_trace", False)),
                trace_out=str((control_run_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".json")),
                trace_text_out=str((control_run_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".log")),
                trace_meta_out=str((control_run_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".meta.json")),
                trace_basename=str(getattr(args, "trace_basename", "replay_trace")),
            )
            control_report = _candidate_report("control", str(control_run_root), parent_checkpoint=parent_cp)
            _attach_candidate_eval(control_report, meta=_control_meta(), control_report=None)
            parent_entry["candidate_reports"].append(control_report)

            control_checkpoint = _checkpoint_from_run(
                checkpoint_id=f"r{round_idx}_p{parent_idx}_control",
                run_root=str(control_run_root),
                parent_checkpoint_id=parent_cp["checkpoint_id"],
                score=float(control_report.get("score") or 0.0),
            )
            control_checkpoint.update(
                {
                    "candidate_id": "control",
                    "candidate_meta": _control_meta(),
                    "verdict": control_report.get("verdict"),
                    "score_breakdown": control_report.get("score_breakdown"),
                }
            )

            guided_checkpoints: List[Dict[str, Any]] = []
            for wrapped in selected_items:
                item = wrapped["compiled"]
                meta = wrapped["meta"]
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
                    dump_trace=bool(getattr(args, "dump_trace", False)),
                    trace_out=str((candidate_run_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".json")),
                    trace_text_out=str((candidate_run_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".log")),
                    trace_meta_out=str((candidate_run_root / str(getattr(args, "trace_basename", "replay_trace"))).with_suffix(".meta.json")),
                    trace_basename=str(getattr(args, "trace_basename", "replay_trace")),
                )

                report = _candidate_report(candidate_id, str(candidate_run_root), parent_checkpoint=parent_cp)
                _attach_candidate_eval(report, meta=meta, control_report=control_report)
                parent_entry["candidate_reports"].append(report)

                cp = _checkpoint_from_run(
                    checkpoint_id=f"r{round_idx}_p{parent_idx}_{candidate_id}",
                    run_root=str(candidate_run_root),
                    parent_checkpoint_id=parent_cp["checkpoint_id"],
                    score=float(report.get("score") or 0.0),
                )
                cp.update(
                    {
                        "candidate_id": candidate_id,
                        "candidate_meta": meta,
                        "verdict": report.get("verdict"),
                        "score_breakdown": report.get("score_breakdown"),
                        "compare_to_control": report.get("compare_to_control"),
                    }
                )
                guided_checkpoints.append(cp)

            survivors = _promote_parent_survivors(
                control_checkpoint=control_checkpoint,
                guided_checkpoints=guided_checkpoints,
                max_weak_per_parent=args.max_weak_per_parent,
            )
            next_beam_candidates.extend(survivors)
            parent_entry["promoted_checkpoints"] = [cp["checkpoint_id"] for cp in survivors]
            parent_entry["candidate_reports"].sort(key=_report_sort_key)
            round_report["parents"].append(parent_entry)

        beam = _select_next_beam(next_beam_candidates, args.beam_width)
        round_report["beam_after_round"] = [cp["checkpoint_id"] for cp in beam]
        round_report["beam_scores"] = {cp["checkpoint_id"]: cp.get("score") for cp in beam}
        round_report["beam_verdicts"] = {cp["checkpoint_id"]: cp.get("verdict") for cp in beam}
        rounds.append(round_report)
        save_json(str(report_root / f"round_{round_idx}_summary.json"), round_report)
        info(f"staged round {round_idx} summary written: {report_root / f'round_{round_idx}_summary.json'}")

        if not beam:
            warn(f"staged loop terminated early at round {round_idx}: no surviving candidates")
            break

    final_report = {
        "schema": "mf_staged_loop_report_v2",
        "shared_cache_root": str(shared_cache_root),
        "shared_query_cache_root": str(shared_query_cache_root),
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
    s6.add_argument("--ghidra-src", default=_default_ghidra_src(), help="Path to Ghidra install (default: repository tools/ghidra)")
    s6.add_argument("--workdir", required=True)
    s6.add_argument("--run-log", required=True)
    s6.add_argument("--run-for", default="300s")
    s6.add_argument("--observer-dir")
    s6.add_argument("--guidance-file")
    s6.add_argument("--guidance-summary-out")
    s6.add_argument("--import-dir")
    s6.add_argument("--dump-trace", action="store_true", help="Request executor/fuzzer trace export and auto-place files next to the run root")
    s6.add_argument("--trace-out", help="Explicit JSON trace output path; defaults to <run_root>/replay_trace.json when --dump-trace is set")
    s6.add_argument("--trace-text-out", help="Optional plain-text trace output path; defaults to <run_root>/replay_trace.log when tracing is enabled")
    s6.add_argument("--trace-meta-out", help="Optional JSON metadata output path; defaults to <run_root>/replay_trace.meta.json when tracing is enabled")
    s6.add_argument("--trace-basename", default="replay_trace", help="Basename for auto-generated trace files when tracing is enabled")
    s6.add_argument("--setenv", action="append")

    s7 = sub.add_parser("auto-loop")
    s7.add_argument("--fuzzer-manifest", required=True)
    s7.add_argument("--fuzzer-bin")
    s7.add_argument("--firmware-config", required=True)
    s7.add_argument("--ghidra-src", default=_default_ghidra_src(), help="Path to Ghidra install (default: repository tools/ghidra)")
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
    s7.add_argument("--dump-trace", action="store_true", help="Emit per-run replay traces under each auto-loop run root")
    s7.add_argument("--trace-basename", default="replay_trace")
    s7.add_argument("--shared-cache-root")

    s8 = sub.add_parser("staged-loop")
    s8.add_argument("--fuzzer-manifest", required=True)
    s8.add_argument("--fuzzer-bin")
    s8.add_argument("--firmware-config", required=True)
    s8.add_argument("--ghidra-src", default=_default_ghidra_src(), help="Path to Ghidra install (default: repository tools/ghidra)")
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
    s8.add_argument("--allow-aggressive", action="store_true")
    s8.add_argument("--max-weak-per-parent", type=int, default=1)
    s8.add_argument("--setenv", action="append")
    s8.add_argument("--dump-trace", action="store_true", help="Emit per-run replay traces under each staged-loop run root")
    s8.add_argument("--trace-basename", default="replay_trace")
    s8.add_argument("--shared-cache-root")
    s8.add_argument("--shared-query-cache-root")

    s14 = sub.add_parser("adaptive-mmio-loop")
    s14.add_argument("--fuzzer-manifest", required=True)
    s14.add_argument("--fuzzer-bin")
    s14.add_argument("--firmware-config", required=True)
    s14.add_argument("--ghidra-src", default=_default_ghidra_src(), help="Path to Ghidra install (default: repository tools/ghidra)")
    s14.add_argument("--contract-bundle", required=True)
    s14.add_argument("--out-root", required=True)
    s14.add_argument("--import-dir")
    s14.add_argument("--guidance-file")
    s14.add_argument("--peripheral-hint", action="append")
    s14.add_argument("--initial-run-for", default="30s")
    s14.add_argument("--probe-run-for", default="30s")
    s14.add_argument("--followup-run-for", default="60s")
    s14.add_argument("--use-recent-exec", default="latest")
    s14.add_argument("--max-llm-cycles", type=int, default=1)
    s14.add_argument("--setenv", action="append")
    s14.add_argument("--trace-basename", default="replay_trace")
    s14.add_argument("--dump-trace", action="store_true", help="Emit traces for the baseline seed run if one is created")
    s14.add_argument("--dump-followup-trace", action="store_true", help="Emit traces for followup runs after LLM seed reinjection")
    s14.add_argument("--skip-llm", action="store_true")
    s14.add_argument("--force-llm", action="store_true")
    s14.add_argument("--llm-model")
    s14.add_argument("--llm-max-output-tokens", type=int, default=6000)
    s14.add_argument("--llm-max-attempts", type=int, default=2)
    s14.add_argument("--llm-reasoning-effort", default=os.environ.get("OPENAI_REASONING_EFFORT", "none"))
    s14.add_argument("--probe-plan-name", default="auto_mmio_probe")
    s14.add_argument("--llm-seed-plan-name", default="llm_seed")

    s13 = sub.add_parser("llm-fallback-pipeline")
    s13.add_argument("--fuzzer-manifest", required=True)
    s13.add_argument("--fuzzer-bin")
    s13.add_argument("--firmware-config", required=True)
    s13.add_argument("--ghidra-src", default=_default_ghidra_src(), help="Path to Ghidra install (default: repository tools/ghidra)")
    s13.add_argument("--contract-bundle", required=True)
    s13.add_argument("--guidance-file", required=True)
    s13.add_argument("--import-dir", required=True)
    s13.add_argument("--out-root", required=True)
    s13.add_argument("--run-for", default="30s")
    s13.add_argument("--use-recent-exec", default="latest")
    s13.add_argument("--baseline-trace-json")
    s13.add_argument("--baseline-use-recent-exec")
    s13.add_argument("--baseline-seed")
    s13.add_argument("--setenv", action="append")
    s13.add_argument("--trace-basename", default="replay_trace")
    s13.add_argument("--skip-llm", action="store_true")
    s13.add_argument("--force-llm", action="store_true")
    s13.add_argument("--llm-model")
    s13.add_argument("--llm-max-output-tokens", type=int, default=6000)
    s13.add_argument("--llm-max-attempts", type=int, default=2)
    s13.add_argument("--llm-reasoning-effort", default=os.environ.get("OPENAI_REASONING_EFFORT", "none"))

    s9 = sub.add_parser("fixedpoint-prompt")
    s9.add_argument("--task-context", required=True)
    s9.add_argument("--out", required=True)
    s9.add_argument("--out-text")

    s10 = sub.add_parser("fixedpoint-select")
    s10.add_argument("--task-context", required=True)
    s10.add_argument("--out", required=True)
    s10.add_argument("--llm-json")
    s10.add_argument("--include-full-sweep-fallback", action="store_true")
    s10.add_argument("--max-multi-region-candidates", type=int, default=6)

    s11 = sub.add_parser("build-fixedpoint-manifest")
    s11.add_argument("--selector-plan", required=True)
    s11.add_argument("--input-path", required=True)
    s11.add_argument("--out-dir", required=True)
    s11.add_argument("--manifest-out", required=True)
    s11.add_argument("--summary-out", required=True)
    s11.add_argument("--continue-icount-delta", type=int, default=200000)
    s11.add_argument("--no-control", action="store_true")

    s12 = sub.add_parser("run-fixedpoint-sweep")
    s12.add_argument("--manifest", required=True)
    s12.add_argument("--fuzzer-manifest", required=True)
    s12.add_argument("--fuzzer-bin")
    s12.add_argument("--firmware-config", required=True)
    s12.add_argument("--ghidra-src", default=_default_ghidra_src(), help="Path to Ghidra install (default: repository tools/ghidra)")
    s12.add_argument("--workdir", required=True)
    s12.add_argument("--run-log", required=True)
    s12.add_argument("--setenv", action="append")

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
    elif args.cmd == "fixedpoint-prompt":
        save_fixedpoint_prompt_bundle(args.task_context, args.out, out_text=args.out_text)
    elif args.cmd == "fixedpoint-select":
        save_fixedpoint_selector_plan(
            args.task_context,
            args.out,
            llm_json_path=args.llm_json,
            include_full_sweep_fallback=bool(args.include_full_sweep_fallback),
            max_multi_region_candidates=args.max_multi_region_candidates,
        )
    elif args.cmd == "build-fixedpoint-manifest":
        build_fixedpoint_manifest(
            selector_plan_path=args.selector_plan,
            input_path=args.input_path,
            out_dir=args.out_dir,
            manifest_out=args.manifest_out,
            summary_out=args.summary_out,
            continue_icount_delta=args.continue_icount_delta,
            include_control=not bool(args.no_control),
        )
    elif args.cmd == "run-fixedpoint-sweep":
        out = run_fixedpoint_sweep(
            manifest_path=args.manifest,
            fuzzer_manifest=args.fuzzer_manifest,
            firmware_config=args.firmware_config,
            ghidra_src=args.ghidra_src,
            workdir=args.workdir,
            run_log=args.run_log,
            fuzzer_bin=args.fuzzer_bin,
            setenv=args.setenv,
        )
        save_json(os.path.join(str(Path(args.workdir).resolve().parent), "run_fixedpoint_sweep_summary.json"), out)
        info("run-fixedpoint-sweep completed")
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
            dump_trace=bool(args.dump_trace),
            trace_out=args.trace_out,
            trace_text_out=args.trace_text_out,
            trace_meta_out=args.trace_meta_out,
            trace_basename=args.trace_basename,
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
    elif args.cmd == "llm-fallback-pipeline":
        _run_llm_fallback_pipeline(args)
    elif args.cmd == "adaptive-mmio-loop":
        _run_adaptive_mmio_loop(args)


if __name__ == "__main__":
    main()
