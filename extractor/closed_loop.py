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




def _touch_entries_to_map(summary: Optional[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for key in ['read_touches', 'write_touches']:
        for item in (summary or {}).get(key, []) or []:
            if isinstance(item, list) and len(item) >= 2:
                addr = _normalize_hex(item[0])
                if addr:
                    out[addr] = out.get(addr, 0) + int(item[1] or 0)
            elif isinstance(item, dict):
                addr = _normalize_hex(item.get('address_hex') or item.get('addr'))
                if addr:
                    out[addr] = out.get(addr, 0) + int(item.get('count') or 0)
    return out


def _touch_profile_entries(bundle_or_profile: Optional[Any]) -> List[Dict[str, Any]]:
    if isinstance(bundle_or_profile, dict):
        profile = bundle_or_profile.get('trace_touch_profile') or bundle_or_profile.get('probe_trace_touch_profile') or []
    elif isinstance(bundle_or_profile, list):
        profile = bundle_or_profile
    else:
        profile = []
    out: List[Dict[str, Any]] = []
    for item in profile or []:
        if not isinstance(item, dict):
            continue
        addr = _normalize_hex(item.get('address_hex') or item.get('addr'))
        if not addr:
            continue
        widths = []
        for w in item.get('observed_widths') or []:
            try:
                widths.append(int(w))
            except Exception:
                pass
        dominant = item.get('dominant_width')
        try:
            dominant_i = int(dominant) if dominant is not None else None
        except Exception:
            dominant_i = None
        out.append({
            'address_hex': addr,
            'count': int(item.get('count') or 0),
            'dominant_width': dominant_i,
            'observed_widths': sorted(set(widths)),
            'width_counts': {str(k): int(v) for k, v in (item.get('width_counts') or {}).items()},
        })
    return out


def _touch_profile_to_count_map(bundle_or_profile: Optional[Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in _touch_profile_entries(bundle_or_profile):
        addr = item['address_hex']
        out[addr] = out.get(addr, 0) + int(item.get('count') or 0)
    return out


def _touch_profile_to_width_map(bundle_or_profile: Optional[Any]) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    for item in _touch_profile_entries(bundle_or_profile):
        widths = list(item.get('observed_widths') or [])
        dominant = item.get('dominant_width')
        if dominant and dominant not in widths:
            widths.append(int(dominant))
        if widths:
            out[item['address_hex']] = sorted(set(int(x) for x in widths))
    return out


def _dominant_width_for_addr(bundle_or_profile: Optional[Any], addr: Optional[str], default: int = 4) -> int:
    norm = _normalize_hex(addr)
    if not norm:
        return int(default)
    for item in _touch_profile_entries(bundle_or_profile):
        if item['address_hex'] == norm and item.get('dominant_width'):
            return int(item['dominant_width'])
    widths = _touch_profile_to_width_map(bundle_or_profile).get(norm) or []
    if widths:
        return int(widths[0])
    return int(default)


def _merge_touch_maps(*maps: Dict[str, int]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for mp in maps:
        for k, v in (mp or {}).items():
            out[k] = out.get(k, 0) + int(v or 0)
    return out


def _guidance_action_trigger_addr(action: Dict[str, Any]) -> Optional[str]:
    trigger = action.get('trigger') or {}
    kind = str(trigger.get('kind') or '').strip()
    if kind in {'on_first_touch', 'on_nth_touch', 'after_write', 'after_write_value'}:
        return _normalize_hex(trigger.get('addr'))
    return None


def _guidance_action_width_addrs(action: Dict[str, Any]) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    width = action.get('width')
    try:
        width_i = int(width) if width is not None else None
    except Exception:
        width_i = None
    if width_i:
        for key in ['addr', 'read_addr']:
            addr = _normalize_hex(action.get(key))
            if addr:
                out.append((addr, width_i))
    return out


def _mask_values_for_width(values: List[int], width: int) -> List[int]:
    try:
        w = max(1, int(width))
    except Exception:
        w = 4
    mask = (1 << (8 * w)) - 1
    return [int(v) & mask for v in values]


def _guidance_action_identity(action: Dict[str, Any]) -> Tuple[Any, ...]:
    trigger = json.dumps(action.get('trigger') or {}, sort_keys=True)
    return (
        action.get('type'),
        action.get('addr'),
        action.get('write_addr'),
        action.get('read_addr'),
        trigger,
    )


def _dedupe_guidance_actions(actions: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    seen_keys = set()
    seen_ids = set()
    deduped: List[Dict[str, Any]] = []
    dropped: List[Dict[str, Any]] = []
    for action in actions:
        act = dict(action)
        act_id = str(act.get('id') or _safe_id(str(_guidance_action_identity(act))))
        act['id'] = act_id
        ident = _guidance_action_identity(act)
        if act_id in seen_ids or ident in seen_keys:
            dropped.append({'id': act_id, 'reason': 'duplicate_action'})
            continue
        seen_ids.add(act_id)
        seen_keys.add(ident)
        deduped.append(act)
    return deduped, {
        'input_action_count': len(actions),
        'output_action_count': len(deduped),
        'dropped': dropped,
    }


def _preflight_guidance(guidance: Dict[str, Any], touched_addrs: Dict[str, int], observed_widths: Optional[Dict[str, List[int]]] = None) -> Dict[str, Any]:
    actions = list(guidance.get('actions') or [])
    trigger_addrs: List[str] = []
    width_mismatches: List[Dict[str, Any]] = []
    observed_widths = observed_widths or {}
    for action in actions:
        addr = _guidance_action_trigger_addr(action)
        if addr:
            trigger_addrs.append(addr)
        for width_addr, width in _guidance_action_width_addrs(action):
            obs = sorted(set(int(x) for x in (observed_widths.get(width_addr) or []) if x))
            if obs and int(width) not in obs:
                width_mismatches.append({
                    'action_id': action.get('id'),
                    'address_hex': width_addr,
                    'action_width': int(width),
                    'observed_widths': obs,
                })
    touched_trigger_addrs = [addr for addr in trigger_addrs if addr in touched_addrs]
    action_count = len(actions)
    verdict = 'preflight_ok'
    if action_count == 0:
        verdict = 'empty_guidance'
    elif trigger_addrs and not touched_trigger_addrs:
        verdict = 'untouched_trigger'
    elif width_mismatches:
        verdict = 'width_mismatch'
    return {
        'plan_name': guidance.get('plan_name'),
        'action_count': action_count,
        'trigger_addrs': trigger_addrs,
        'touched_trigger_addrs': touched_trigger_addrs,
        'touched_trigger_ratio': (len(set(touched_trigger_addrs)) / max(1, len(set(trigger_addrs)))) if trigger_addrs else 0.0,
        'observed_widths_checked': bool(observed_widths),
        'width_mismatches': width_mismatches,
        'verdict': verdict,
    }


def _addr_int(addr: Any) -> Optional[int]:
    norm = _normalize_hex(addr)
    if not norm:
        return None
    try:
        return int(norm, 16)
    except Exception:
        return None


def _addr_page(addr: Any, page_size: int = 0x1000) -> Optional[int]:
    value = _addr_int(addr)
    if value is None:
        return None
    return value // max(1, int(page_size))


def _status_like_register_name(name: Optional[str]) -> bool:
    s = str(name or '').strip().upper()
    if not s:
        return False
    return (
        s.endswith('SR')
        or s.endswith('STAT')
        or 'STATUS' in s
        or 'FLAG' in s
        or s.endswith('IF')
    )


def _state_like_register_name(name: Optional[str]) -> bool:
    s = str(name or '').strip().upper()
    if not s:
        return False
    return (
        _status_like_register_name(s)
        or s in {'TSR', 'TAR'}
        or 'TIME' in s
        or 'COUNT' in s
        or s.endswith('CNT')
    )


def _control_like_register_name(name: Optional[str]) -> bool:
    s = str(name or '').strip().upper()
    if not s:
        return False
    return (
        s.endswith('CR')
        or s.endswith('CCR')
        or s.endswith('TCR')
        or s.endswith('IER')
        or s.endswith('IMR')
        or 'CTRL' in s
        or 'CFG' in s
        or 'ENABLE' in s
    )


def _nearby_touched_addr(addr: Any, touched_addrs: Dict[str, int], max_distance: int = 0x20) -> Optional[str]:
    target = _addr_int(addr)
    if target is None:
        return None
    best: Optional[Tuple[int, int, str]] = None
    for cand, count in (touched_addrs or {}).items():
        cand_int = _addr_int(cand)
        if cand_int is None:
            continue
        dist = abs(cand_int - target)
        if dist > max(0, int(max_distance)):
            continue
        key = (dist, -int(count or 0), cand)
        if best is None or key < best:
            best = key
    return best[2] if best else None


def _semantic_register_candidates(fallback_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()

    def _add(item: Dict[str, Any], source_kind: str):
        if not isinstance(item, dict):
            return
        reg_obj = item.get('register')
        if isinstance(reg_obj, dict):
            reg_name = str(reg_obj.get('name') or '').strip()
            addr = _normalize_hex(reg_obj.get('absoluteAddress_hex') or reg_obj.get('absoluteAddress'))
            off = _normalize_hex(reg_obj.get('addressOffset_hex') or reg_obj.get('addressOffset'))
        else:
            reg_name = str(reg_obj or item.get('register') or '').strip()
            addr = _normalize_hex(item.get('absoluteAddress_hex') or item.get('absoluteAddress'))
            off = _normalize_hex(item.get('addressOffset_hex') or item.get('addressOffset'))
        if not addr:
            return
        key = (addr, reg_name.upper(), str(item.get('peripheral') or '').upper())
        if key in seen:
            return
        seen.add(key)
        out.append({
            'peripheral': str(item.get('peripheral') or '').strip(),
            'register': reg_name,
            'absolute_addr_hex': addr,
            'offset_hex': off,
            'touch_count': int(item.get('touch_count') or 0),
            'source_kind': source_kind,
        })

    for item in fallback_bundle.get('target_touched_registers') or []:
        _add(item, 'target_touched_register')
    for item in fallback_bundle.get('likely_blocking_registers') or []:
        _add(item, 'likely_blocking_register')
    for item in fallback_bundle.get('matched_register_docs') or []:
        _add(item, 'matched_register_doc')
    return out


def _dynamic_role_selection(*, fallback_bundle: Dict[str, Any], touched_addrs: Dict[str, int]) -> Dict[str, Any]:
    dynamic_cluster = fallback_bundle.get('dynamic_primary_cluster') or {}
    semantic_regs = _semantic_register_candidates(fallback_bundle)
    scores: Dict[str, float] = {}
    meta: Dict[str, Dict[str, Any]] = {}

    def _touch_count(addr: Optional[str]) -> int:
        return int((touched_addrs or {}).get(addr or '', 0) or 0)

    def _observe(addr: Optional[str], base_score: float, reason: str, extra: Optional[Dict[str, Any]] = None):
        norm = _normalize_hex(addr)
        if not norm:
            return
        scores[norm] = float(scores.get(norm, 0.0)) + float(base_score)
        info = meta.setdefault(norm, {
            'address_hex': norm,
            'touch_count': _touch_count(norm),
            'reasons': [],
            'semantic_registers': [],
        })
        info['touch_count'] = max(int(info.get('touch_count') or 0), _touch_count(norm))
        info['reasons'].append(reason)
        if extra:
            if extra.get('semantic_register'):
                info['semantic_registers'].append(dict(extra['semantic_register']))
            info.update({k: v for k, v in extra.items() if k != 'semantic_register'})

    anchor_hint = _normalize_hex(dynamic_cluster.get('anchor_address'))
    anchor_page = _addr_page(anchor_hint)

    for item in dynamic_cluster.get('addresses') or []:
        addr = _normalize_hex(item.get('address_hex'))
        if not addr:
            continue
        count = int(item.get('count') or 0)
        score = 60.0 + min(count, 512)
        if bool(item.get('same_page_as_anchor')):
            score += 18.0
        if addr == anchor_hint:
            score += 50.0
        _observe(addr, score, 'dynamic_cluster', {'same_page_as_anchor': bool(item.get('same_page_as_anchor'))})

    for item in _touch_profile_entries(fallback_bundle):
        addr = _normalize_hex(item.get('address_hex'))
        if not addr:
            continue
        count = int(item.get('count') or 0)
        _observe(addr, 8.0 + min(count, 128) * 0.5, 'touch_profile')

    for item in (fallback_bundle.get('probe_guidance_summary') or {}).get('read_touches', []) or []:
        addr = _normalize_hex(item.get('address_hex'))
        if not addr:
            continue
        count = int(item.get('count') or 0)
        _observe(addr, 4.0 + min(count, 128) * 0.35, 'probe_read_touch')

    for item in (fallback_bundle.get('probe_guidance_summary') or {}).get('write_touches', []) or []:
        addr = _normalize_hex(item.get('address_hex'))
        if not addr:
            continue
        count = int(item.get('count') or 0)
        _observe(addr, 14.0 + min(count, 128) * 0.5, 'probe_write_touch', {'has_write_touch': True})

    for reg in semantic_regs:
        reg_name = reg.get('register')
        reg_addr = reg.get('absolute_addr_hex')
        if reg_addr in touched_addrs:
            bonus = 20.0 + min(int(reg.get('touch_count') or 0), 64) * 0.5
            if _state_like_register_name(reg_name):
                bonus += 8.0
            if _control_like_register_name(reg_name):
                bonus += 5.0
            _observe(reg_addr, bonus, f"semantic:{reg.get('source_kind')}", {'semantic_register': reg})
        else:
            nearby = _nearby_touched_addr(reg_addr, touched_addrs, max_distance=0x40)
            if nearby:
                bonus = 10.0 if _state_like_register_name(reg_name) else 6.0
                _observe(nearby, bonus, f"semantic_near:{reg_name}", {'semantic_register': reg, 'semantic_nearby': reg_addr})

    ranked = sorted(scores.items(), key=lambda kv: (kv[1], int(meta.get(kv[0], {}).get('touch_count') or 0)), reverse=True)
    ordered = [addr for addr, _ in ranked]

    anchor = None
    if anchor_hint and anchor_hint in scores:
        anchor = anchor_hint
    elif ordered:
        anchor = ordered[0]

    companion = None
    for addr in ordered:
        if addr == anchor:
            continue
        companion = addr
        break

    semantic_choice: Optional[Dict[str, Any]] = None
    semantic_addr = None
    for reg in semantic_regs:
        reg_addr = reg.get('absolute_addr_hex')
        resolved_addr = reg_addr if reg_addr in touched_addrs else _nearby_touched_addr(reg_addr, touched_addrs, max_distance=0x40)
        if not resolved_addr:
            continue
        if resolved_addr in {anchor, companion}:
            continue
        semantic_choice = dict(reg)
        semantic_addr = resolved_addr
        break

    if not semantic_choice:
        anchor_page = _addr_page(anchor)
        for addr in ordered:
            if addr in {anchor, companion}:
                continue
            if anchor_page is not None and _addr_page(addr) == anchor_page:
                semantic_addr = addr
                break
        if semantic_addr:
            semantic_choice = {
                'peripheral': '',
                'register': 'HOTSPOT_COMPANION',
                'absolute_addr_hex': semantic_addr,
                'offset_hex': None,
                'touch_count': _touch_count(semantic_addr),
                'source_kind': 'dynamic_companion',
            }

    role_info = {
        'anchor': anchor,
        'companion': companion,
        'semantic_companion': semantic_addr,
        'semantic_register': semantic_choice,
        'ranked': [
            {
                'address_hex': addr,
                'score': float(score),
                'touch_count': int(meta.get(addr, {}).get('touch_count') or 0),
                'reasons': list(meta.get(addr, {}).get('reasons') or []),
                'semantic_registers': list(meta.get(addr, {}).get('semantic_registers') or []),
            }
            for addr, score in ranked
        ],
    }
    ordered_unique: List[str] = []
    for addr in [anchor, companion, semantic_addr, *ordered]:
        norm = _normalize_hex(addr)
        if norm and norm not in ordered_unique:
            ordered_unique.append(norm)
    role_info['ordered_addrs'] = ordered_unique[:3]
    return role_info


def _pick_dynamic_trigger_addrs(*, fallback_bundle: Dict[str, Any], touched_addrs: Dict[str, int], limit: int = 3) -> List[str]:
    roles = _dynamic_role_selection(fallback_bundle=fallback_bundle, touched_addrs=touched_addrs)
    ordered = list(roles.get('ordered_addrs') or [])
    return ordered[:max(1, int(limit))]


def _synthesize_dynamic_hotspot_guidance(*, fallback_bundle_json_path: str, out_path: str, plan_name: str) -> Dict[str, Any]:
    fallback_bundle = load_json(_abs(fallback_bundle_json_path))
    touched_addrs = _merge_touch_maps(_touch_entries_to_map(fallback_bundle.get('probe_guidance_summary')), _touch_profile_to_count_map(fallback_bundle))
    role_info = _dynamic_role_selection(fallback_bundle=fallback_bundle, touched_addrs=touched_addrs)
    primary_addrs = list(role_info.get('ordered_addrs') or [])
    if not primary_addrs:
        likely_regs = fallback_bundle.get('likely_blocking_registers') or []
        for reg in likely_regs[:3]:
            addr = _normalize_hex(reg.get('absoluteAddress_hex'))
            if addr:
                primary_addrs.append(addr)

    anchor_addr = _normalize_hex(role_info.get('anchor')) or (primary_addrs[0] if primary_addrs else None)
    companion_addr = _normalize_hex(role_info.get('companion'))
    semantic_addr = _normalize_hex(role_info.get('semantic_companion'))
    semantic_reg = role_info.get('semantic_register') or {}

    actions: List[Dict[str, Any]] = []
    rationale_bits: List[str] = []
    stages: Dict[str, str] = {}

    def _touch_count(addr: Optional[str]) -> int:
        return max(0, int((touched_addrs or {}).get(addr or '', 0) or 0))

    def _read_trigger(addr: str) -> Dict[str, Any]:
        touched = max(1, _touch_count(addr))
        if touched > 1:
            return {'kind': 'on_nth_touch', 'addr': addr, 'n': min(3, touched), 'access': 'read'}
        return {'kind': 'on_first_touch', 'addr': addr, 'access': 'read'}

    if anchor_addr:
        actions.append(_read_seq_action(
            action_id='dynamic_anchor',
            addr_hex=anchor_addr,
            width=_dominant_width_for_addr(fallback_bundle, anchor_addr, default=4),
            values=_mask_values_for_width([1, 1, 2, 2], _dominant_width_for_addr(fallback_bundle, anchor_addr, default=4)),
            trigger=_read_trigger(anchor_addr),
            activate_stage='anchor_seen',
            notes='Dynamic anchor: hottest runtime loop address selected from clustered probe touches.',
        ))
        stages['anchor'] = 'anchor_seen'
        rationale_bits.append(f'anchor={anchor_addr} touches={_touch_count(anchor_addr)}')

    if companion_addr and companion_addr != anchor_addr:
        companion_trigger: Dict[str, Any]
        if _touch_count(companion_addr) >= max(2, _touch_count(anchor_addr) // 8 if anchor_addr else 2):
            companion_trigger = _read_trigger(companion_addr)
        else:
            companion_trigger = {'kind': 'when_stage_active', 'stage': stages.get('anchor', 'anchor_seen')}
        actions.append(_read_seq_action(
            action_id='dynamic_companion',
            addr_hex=companion_addr,
            width=_dominant_width_for_addr(fallback_bundle, companion_addr, default=4),
            values=_mask_values_for_width([1, 2, 2, 3], _dominant_width_for_addr(fallback_bundle, companion_addr, default=4)),
            trigger=companion_trigger,
            activate_stage='companion_seen',
            notes='Dynamic companion: second runtime hotspot gated by anchor progress or its own hot-touch cadence.',
        ))
        stages['companion'] = 'companion_seen'
        rationale_bits.append(f'companion={companion_addr} touches={_touch_count(companion_addr)}')

    if semantic_addr and semantic_addr not in {anchor_addr, companion_addr}:
        semantic_name = str(semantic_reg.get('register') or '').strip()
        semantic_stage = stages.get('companion') or stages.get('anchor')
        semantic_trigger: Dict[str, Any]
        if semantic_addr in touched_addrs and _touch_count(semantic_addr) > 0:
            semantic_trigger = _read_trigger(semantic_addr)
        elif semantic_stage:
            semantic_trigger = {'kind': 'when_stage_active', 'stage': semantic_stage}
        else:
            semantic_trigger = {'kind': 'on_first_touch', 'addr': anchor_addr or semantic_addr, 'access': 'read'}

        if _status_like_register_name(semantic_name):
            actions.append(_bit_update_action(
                action_id='dynamic_semantic_status',
                addr_hex=semantic_addr,
                width=_dominant_width_for_addr(fallback_bundle, semantic_addr, default=4),
                set_bits=[4],
                clear_bits=[0],
                trigger=semantic_trigger,
                activate_stage='semantic_seen',
                notes=f'Dynamic semantic companion: status-style register {semantic_name or semantic_addr} is nudged once anchor/companion activity is observed.',
            ))
        else:
            actions.append(_read_seq_action(
                action_id='dynamic_semantic_companion',
                addr_hex=semantic_addr,
                width=_dominant_width_for_addr(fallback_bundle, semantic_addr, default=4),
                values=_mask_values_for_width([0, 1, 1, 2], _dominant_width_for_addr(fallback_bundle, semantic_addr, default=4)),
                trigger=semantic_trigger,
                activate_stage='semantic_seen',
                notes=f'Dynamic semantic companion synthesized from semantic/runtime overlap for {semantic_name or semantic_addr}.',
            ))
        rationale_bits.append(f'semantic_companion={semantic_addr} register={semantic_name or "<unknown>"}')

    if len(actions) < 2:
        for idx, addr in enumerate(primary_addrs[:3]):
            if addr in {anchor_addr, companion_addr, semantic_addr}:
                continue
            actions.append(_read_seq_action(
                action_id=f'dynamic_fallback_{idx}',
                addr_hex=addr,
                width=_dominant_width_for_addr(fallback_bundle, addr, default=4),
                values=_mask_values_for_width([1, 1, 2, 2], _dominant_width_for_addr(fallback_bundle, addr, default=4)),
                trigger={'kind': 'when_stage_active', 'stage': stages.get('anchor', 'anchor_seen')} if stages else _read_trigger(addr),
                activate_stage=f'fallback_seen_{idx}',
                notes='Dynamic fallback: additional hotspot retained to preserve diversity when semantic companion is unavailable.',
            ))
            rationale_bits.append(f'fallback_hotspot={addr}')
            if len(actions) >= 2:
                break

    actions, dedupe_meta = _dedupe_guidance_actions(actions)
    if not actions:
        raise RuntimeError('failed to synthesize any dynamic-hotspot actions')
    guidance = {
        'schema': 'mf_runtime_strategy_v1',
        'plan_name': plan_name,
        'rationale': '; '.join(rationale_bits) or 'Dynamic-hotspot fallback guidance.',
        'source_kind': 'dynamic_hotspot_fallback',
        'source_bundle': _abs(fallback_bundle_json_path),
        'role_selection': role_info,
        'preflight_dedupe': dedupe_meta,
        'actions': actions,
    }
    save_json(out_path, guidance)
    return guidance


def _synthesize_guidance_from_llm_answer(*, llm_answer_json_path: str, fallback_bundle_json_path: str, contract_bundle_path: str, out_path: str, plan_name: str) -> Dict[str, Any]:
    llm_answer = load_json(_abs(llm_answer_json_path))
    parsed = llm_answer.get('parsed_json') or {}
    fallback_bundle = load_json(_abs(fallback_bundle_json_path))
    contract_bundle = _load_contract_bundle(contract_bundle_path)
    catalog = _bundle_register_catalog(contract_bundle)
    lookup = _catalog_lookup(catalog)
    assignments = _parse_llm_assignments(parsed)
    touched_addrs = _merge_touch_maps(_touch_entries_to_map(fallback_bundle.get('probe_guidance_summary')), _touch_profile_to_count_map(fallback_bundle))

    actions: List[Dict[str, Any]] = []
    rationale_bits: List[str] = []
    used_addrs: set[str] = set()

    def _add_read_seq_for_reg(reg: Dict[str, Any], seq: List[int], *, trigger_addr: Optional[str] = None, note_prefix: str = 'LLM'):
        addr = reg['absolute_addr_hex']
        if addr in used_addrs:
            return
        trigger_addr = trigger_addr or addr
        trigger_kind = 'on_nth_touch' if int(touched_addrs.get(trigger_addr) or 0) > 1 else 'on_first_touch'
        trigger: Dict[str, Any] = {'kind': trigger_kind, 'addr': trigger_addr, 'access': 'read'}
        if trigger_kind == 'on_nth_touch':
            trigger['n'] = min(3, max(1, int(touched_addrs.get(trigger_addr) or 1)))
        width = _dominant_width_for_addr(fallback_bundle, addr, default=int(reg['width']))
        actions.append(_read_seq_action(
            action_id=_safe_id(f'llm_{reg["full_name"]}'),
            addr_hex=addr,
            width=width,
            values=_mask_values_for_width(seq, width),
            trigger=trigger,
            activate_stage=_safe_id(f'seen_{reg["register"]}'),
            notes=f'{note_prefix} synthesized from bounded answer evidence for {reg["full_name"]}.',
        ))
        used_addrs.add(addr)

    focus_regs = parsed.get('primary_focus_registers') or []
    if isinstance(focus_regs, list):
        for reg_key in focus_regs:
            reg = lookup.get(str(reg_key).upper()) or lookup.get(str(reg_key).split('.')[-1].upper())
            if reg:
                _add_read_seq_for_reg(reg, [1, 1, 2, 2], note_prefix='LLM focus-register')
                rationale_bits.append(f'LLM focus register {reg_key}')

    touched_trigger_addrs = [
        _normalize_hex(x) for x in (parsed.get('touched_trigger_addrs') or []) if _normalize_hex(x)
    ]

    for reg_key, vals in assignments.items():
        reg = lookup.get(reg_key.upper()) or lookup.get(reg_key.split('.')[-1].upper())
        if not reg:
            continue
        seq = list(vals)[:4]
        while len(seq) < 4:
            seq.append(seq[-1])
        trigger_addr = reg['absolute_addr_hex'] if reg['absolute_addr_hex'] in touched_addrs else None
        if not trigger_addr:
            for cand in touched_trigger_addrs:
                if cand == reg['absolute_addr_hex']:
                    trigger_addr = cand
                    break
        _add_read_seq_for_reg(reg, seq, trigger_addr=trigger_addr, note_prefix='LLM assignment')
        rationale_bits.append(f"LLM assignment {reg_key}={seq}")

    if not actions:
        likely_offsets = fallback_bundle.get('likely_blocking_offsets') or []
        offset_regs = _pick_regs_from_offsets(catalog, likely_offsets)
        for reg in offset_regs[:3]:
            if reg['absolute_addr_hex'] in touched_addrs:
                _add_read_seq_for_reg(reg, [1, 1, 2, 2], note_prefix='offset-derived')
        if offset_regs:
            rationale_bits.append(f"offset-derived probe for {','.join(r['register'] for r in offset_regs[:3])}")

    if not actions:
        dynamic_addrs = _pick_dynamic_trigger_addrs(fallback_bundle=fallback_bundle, touched_addrs=touched_addrs, limit=2)
        for idx, addr in enumerate(dynamic_addrs):
            actions.append(_read_seq_action(
                action_id=f'llm_dynamic_hot_{idx}',
                addr_hex=addr,
                width=_dominant_width_for_addr(fallback_bundle, addr, default=4),
                values=_mask_values_for_width([1, 1, 2, 2], _dominant_width_for_addr(fallback_bundle, addr, default=4)),
                trigger={'kind': 'on_nth_touch', 'addr': addr, 'n': min(3, max(1, int(touched_addrs.get(addr) or 1))), 'access': 'read'},
                activate_stage=f'dynamic_hot_{idx}',
                notes='LLM fallback retargeted to dynamically touched hotspot address.',
            ))
        if dynamic_addrs:
            rationale_bits.append('retargeted to dynamic-hotspot touched addresses')

    actions, dedupe_meta = _dedupe_guidance_actions(actions)
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
        'preflight_dedupe': dedupe_meta,
        'actions': actions,
    }
    save_json(out_path, guidance)
    return guidance

def _coverage_from_run_summary(run_summary: Optional[Dict[str, Any]]) -> int:
    return int((run_summary or {}).get('last_cov') or 0)


def _parse_duration_seconds(text: str) -> int:
    s = str(text).strip().lower()
    m = re.fullmatch(r"(\d+)([smhd]?)", s)
    if not m:
        raise ValueError(f"unsupported duration: {text}")
    value = int(m.group(1))
    unit = m.group(2) or 's'
    mult = {'s':1,'m':60,'h':3600,'d':86400}[unit]
    return value * mult


def _format_duration_seconds(seconds: int) -> str:
    return f"{max(1, int(seconds))}s"


def _run_warmup_frontier(*, manifest_path: str, firmware_config: str, ghidra_src: str, out_root: str,
                        warmup_run_for: str, warmup_restarts: int, initial_import_dir: Optional[str],
                        fuzzer_bin: str, setenv: Optional[List[str]], trace_basename: str = 'replay_trace',
                        dump_trace: bool = False) -> Dict[str, Any]:
    root = Path(out_root).expanduser().resolve() / 'baseline_warmup'
    _ensure_dir(str(root))

    current_import_dir = _abs(initial_import_dir) if initial_import_dir else None
    runs: List[Dict[str, Any]] = []
    best_idx = 0
    best_cov = -1
    best_queue_dir = current_import_dir
    best_run = None

    restarts = max(1, int(warmup_restarts))
    for idx in range(1, restarts + 1):
        run_root = root / f'run_{idx}'
        _ensure_dir(str(run_root))
        run = run_hail_fuzz(
            manifest_path=manifest_path,
            firmware_config=firmware_config,
            ghidra_src=ghidra_src,
            workdir=str(run_root / 'workdir'),
            run_log=str(run_root / 'run.log'),
            run_for=warmup_run_for,
            observer_dir=str(run_root / 'observer'),
            guidance_file=None,
            guidance_summary_out=None,
            import_dir=current_import_dir,
            fuzzer_bin=fuzzer_bin,
            setenv=setenv,
            dump_trace=dump_trace and (idx == restarts),
            trace_basename=trace_basename,
        )
        save_json(str(run_root / 'run_fuzz_summary.json'), run)
        cov = _coverage_from_run_summary(run.get('run_summary'))
        queue_dir = _queue_dir(str(run_root / 'workdir'))
        rec = {
            'warmup_index': idx,
            'run_for': warmup_run_for,
            'import_dir': current_import_dir,
            'queue_dir': queue_dir,
            'run_summary': run,
            'last_cov': cov,
        }
        runs.append(rec)
        if cov > best_cov:
            best_cov = cov
            best_idx = idx
            best_queue_dir = queue_dir
            best_run = run
        current_import_dir = queue_dir

    return {
        'mode': 'fixed_warmup_frontier',
        'initial_import_dir': _abs(initial_import_dir) if initial_import_dir else None,
        'warmup_run_for': warmup_run_for,
        'warmup_restarts': restarts,
        'best_warmup_index': best_idx,
        'frontier_import_dir': best_queue_dir,
        'frontier_last_cov': best_cov,
        'frontier_run': best_run,
        'reused_existing_import_dir': bool(initial_import_dir),
        'warmup_runs': runs,
    }




def _guidance_verdict_from_preflight_and_run(preflight: Dict[str, Any], run: Optional[Dict[str, Any]]) -> str:
    verdict = str(preflight.get('verdict') or 'preflight_ok')
    if verdict != 'preflight_ok':
        return verdict
    grs = _maybe_json(run.get('guidance_summary_out')) if run else None
    fires = _sum_action_fires(grs)
    tail_fires = _run_tail_fire_signals(run)
    seq_progress = _sum_sequence_progress(grs)
    active_stage_count = _count_active_stages(grs)
    cov = _coverage_from_run_summary((run or {}).get('run_summary')) if run else 0
    if fires == 0 and tail_fires == 0 and seq_progress == 0 and active_stage_count == 0:
        return 'nonfiring_guidance'
    if cov <= 0:
        return 'no_effect'
    return 'effective'


def _evaluate_followup_candidates(*, args, cycle_root: Path, probe_queue_dir: str, fuzzer_bin: str, ghidra_src: str, candidates: List[Dict[str, Any]], trace_base: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    candidate_reports: List[Dict[str, Any]] = []
    for idx, cand in enumerate(candidates, start=1):
        cand_root = cycle_root / 'candidate_portfolio' / f'{idx:02d}_{_safe_id(cand.get("name") or cand.get("source") or "candidate")}'
        _ensure_dir(str(cand_root))
        run = run_hail_fuzz(
            manifest_path=args.fuzzer_manifest,
            firmware_config=args.firmware_config,
            ghidra_src=ghidra_src,
            workdir=str(cand_root / 'workdir'),
            run_log=str(cand_root / 'run.log'),
            run_for=str(getattr(args, 'portfolio_run_for', '20s')),
            observer_dir=str(cand_root / 'observer'),
            guidance_file=cand.get('guidance_file'),
            guidance_summary_out=str(cand_root / 'guidance_runtime_summary.json'),
            import_dir=probe_queue_dir,
            fuzzer_bin=fuzzer_bin,
            setenv=args.setenv,
            dump_trace=False,
            trace_basename=trace_base,
        )
        save_json(str(cand_root / 'run_fuzz_summary.json'), run)
        grs = _maybe_json(str(cand_root / 'guidance_runtime_summary.json')) or {}
        istats = _intervention_stats(grs, run)
        coverage = _coverage_from_run_summary(run.get('run_summary'))
        preflight = cand.get('preflight') or {}
        verdict = _guidance_verdict_from_preflight_and_run(preflight, run)
        rec = {
            'name': cand.get('name'),
            'source': cand.get('source'),
            'guidance_file': cand.get('guidance_file'),
            'preflight': preflight,
            'run': run,
            'guidance_runtime_summary': grs,
            'summary_action_fires': int(istats['summary_action_fires']),
            'effective_action_fires': int(istats['effective_action_fires']),
            'action_fires': int(istats['effective_action_fires']),
            'tail_fire_signals': int(istats['tail_fire_signals']),
            'sequence_progress': int(istats['sequence_progress']),
            'active_stage_count': int(istats['active_stage_count']),
            'touched_trigger_ratio': float(preflight.get('touched_trigger_ratio') or 0.0),
            'coverage': coverage,
            'hangs': _run_last_hang(run),
            'crashes': _run_last_crash(run),
            'verdict': verdict,
        }
        rec['intervention_signal'] = _candidate_has_intervention_signal(rec)
        rec['selection_score'] = _candidate_selection_scalar(rec, args=args)
        rec['selection_score_breakdown'] = {
            'coverage': coverage,
            'summary_action_fires': rec['summary_action_fires'],
            'effective_action_fires': rec['effective_action_fires'],
            'tail_fire_signals': rec['tail_fire_signals'],
            'sequence_progress': rec['sequence_progress'],
            'active_stage_count': rec['active_stage_count'],
            'touched_trigger_ratio': rec['touched_trigger_ratio'],
            'hangs': rec['hangs'],
            'crashes': rec['crashes'],
            'source': rec.get('source'),
            'selection_score': rec['selection_score'],
        }
        rec['queue_dir'] = _queue_dir(run.get('workdir'))
        if rec.get('source') == 'control' and rec.get('guidance_file'):
            rec['control_guidance_mismatch'] = not str(rec.get('guidance_file')).endswith('auto_probe.guidance.json') and 'auto_probe' not in str(rec.get('guidance_file'))
        candidate_reports.append(rec)

    if not candidate_reports:
        raise RuntimeError('candidate portfolio produced no runnable branches')

    control_coverage = max((int(r.get('coverage') or 0) for r in candidate_reports if r.get('source') == 'control'), default=0)
    coverage_slack = int(getattr(args, 'portfolio_intervention_coverage_slack', 160))

    intervention_ready = [
        r for r in candidate_reports
        if r.get('source') != 'control'
        and r.get('verdict') == 'effective'
        and r.get('intervention_signal')
    ]
    intervention_within_slack = [
        r for r in intervention_ready
        if int(r.get('coverage') or 0) >= max(0, control_coverage - coverage_slack)
    ]

    if intervention_within_slack:
        pool = intervention_within_slack
        selection_policy = 'prefer_intervention_within_coverage_slack'
    elif intervention_ready:
        pool = intervention_ready
        selection_policy = 'prefer_any_effective_intervention'
    else:
        pool = candidate_reports
        selection_policy = 'max_selection_score'

    def _rank_tuple(r: Dict[str, Any]) -> Tuple[Any, ...]:
        return (
            float(r.get('selection_score') or 0.0),
            int(bool(r.get('intervention_signal'))),
            int(r.get('tail_fire_signals') or 0),
            int(r.get('action_fires') or 0),
            int(r.get('sequence_progress') or 0),
            int(r.get('active_stage_count') or 0),
            float(r.get('touched_trigger_ratio') or 0.0),
            int(r.get('coverage') or 0),
            0 if r.get('source') == 'control' else 1,
        )

    best = max(pool, key=_rank_tuple)
    best = dict(best)
    best['selection_policy'] = selection_policy
    best['control_coverage'] = control_coverage
    best['coverage_slack'] = coverage_slack
    return candidate_reports, best


def _build_initial_adaptive_context(args, out_root: Path, fuzzer_bin: str) -> Dict[str, Any]:
    warmup_run_for = str(getattr(args, 'warmup_run_for', None) or '600s')
    warmup_restarts = int(getattr(args, 'warmup_restarts', 1) or 1)
    baseline_summary = _run_warmup_frontier(
        manifest_path=args.fuzzer_manifest,
        firmware_config=args.firmware_config,
        ghidra_src=args.ghidra_src,
        out_root=str(out_root),
        warmup_run_for=warmup_run_for,
        warmup_restarts=warmup_restarts,
        initial_import_dir=getattr(args, 'import_dir', None),
        fuzzer_bin=fuzzer_bin,
        setenv=args.setenv,
        trace_basename=str(getattr(args, 'trace_basename', 'replay_trace')),
        dump_trace=bool(getattr(args, 'dump_trace', False)),
    )
    current_import_dir = baseline_summary.get('frontier_import_dir')
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
    return {
        'baseline_summary': baseline_summary,
        'current_import_dir': current_import_dir,
        'current_guidance_file': current_guidance_file,
        'initial_guidance_kind': initial_guidance_kind,
        'baseline_frontier_cov': int(baseline_summary.get('frontier_last_cov') or 0),
    }


def _run_adaptive_event_once(*, args, event_root: Path, event_index: int, current_import_dir: str,
                             current_guidance_file: str, control_guidance_file: str, previous_cov: int, fuzzer_bin: str) -> Tuple[Dict[str, Any], str, str]:
    _ensure_dir(str(event_root))
    trace_base = str(getattr(args, 'trace_basename', 'replay_trace'))

    probe_root = event_root / 'probe'
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
    save_json(str(probe_root / 'run_fuzz_summary.json'), probe_run)
    probe_trace_json = str(probe_root / f'{trace_base}.json')

    stuck_dir = _default_stuck_dir()
    find_script = str(stuck_dir / 'find_stuck_functions.py')
    package_script = str(stuck_dir / 'package_llm_fallback.py')
    llm_script = str(stuck_dir / 'run_llm_fallback.py')

    stuck_report = event_root / 'stuck_report.json'
    llm_bundle_json = event_root / 'llm_fallback_bundle.json'
    llm_bundle_text = event_root / 'llm_fallback_prompt.txt'
    llm_answer_json = event_root / 'llm_answer.json'
    llm_answer_text = event_root / 'llm_answer.txt'
    llm_answer_raw = event_root / 'llm_answer.raw.json'
    llm_seed_guidance = event_root / 'llm_seed.guidance.json'

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
        '--probe-guidance-summary', str(probe_root / 'guidance_runtime_summary.json'),
        '--out', str(llm_bundle_json),
        '--out-text', str(llm_bundle_text),
    ])

    llm_invoked = False
    llm_result = None
    synthesized_guidance = None
    dynamic_guidance = None
    next_guidance_file = None
    candidate_reports: List[Dict[str, Any]] = []
    selected_candidate: Optional[Dict[str, Any]] = None

    should_call_llm = (not bool(getattr(args, 'skip_llm', False))) and (
        bool(getattr(args, 'force_llm', False)) or bool(stuck_data.get('still_ambiguous', True))
    )
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
                plan_name=f"{getattr(args, 'llm_seed_plan_name', 'llm_seed')}_cycle_{event_index}",
            )

    dynamic_guidance_path = event_root / 'dynamic_hotspot.guidance.json'
    try:
        dynamic_guidance = _synthesize_dynamic_hotspot_guidance(
            fallback_bundle_json_path=str(llm_bundle_json),
            out_path=str(dynamic_guidance_path),
            plan_name=f"dynamic_hotspot_cycle_{event_index}",
        )
    except Exception as e:
        warn(f'dynamic-hotspot guidance synthesis failed: {e}')
        dynamic_guidance = None

    probe_guidance_summary = _maybe_json(str(probe_root / 'guidance_runtime_summary.json')) or {}
    llm_bundle_data = _maybe_json(str(llm_bundle_json)) or {}
    touched_addrs = _merge_touch_maps(_touch_entries_to_map(probe_guidance_summary), _touch_profile_to_count_map(llm_bundle_data))
    observed_widths = _touch_profile_to_width_map(llm_bundle_data)
    portfolio_candidates: List[Dict[str, Any]] = []
    canonical_control_guidance_file = _abs(control_guidance_file) if control_guidance_file else current_guidance_file
    control_guidance = _maybe_json(canonical_control_guidance_file) if canonical_control_guidance_file and os.path.exists(canonical_control_guidance_file) else {'plan_name': 'control', 'actions': []}
    portfolio_candidates.append({
        'name': 'control',
        'source': 'control',
        'guidance_file': canonical_control_guidance_file,
        'preflight': _preflight_guidance(control_guidance, touched_addrs, observed_widths),
    })
    if dynamic_guidance:
        portfolio_candidates.append({
            'name': 'dynamic_hotspot',
            'source': 'dynamic_hotspot',
            'guidance_file': str(dynamic_guidance_path),
            'preflight': _preflight_guidance(dynamic_guidance, touched_addrs, observed_widths),
        })
    if synthesized_guidance:
        portfolio_candidates.append({
            'name': 'llm_seed',
            'source': 'llm_seed',
            'guidance_file': str(llm_seed_guidance),
            'preflight': _preflight_guidance(synthesized_guidance, touched_addrs, observed_widths),
        })

    if bool(getattr(args, 'disable_candidate_portfolio', False)):
        selected_candidate = portfolio_candidates[-1] if len(portfolio_candidates) > 1 else portfolio_candidates[0]
        next_guidance_file = selected_candidate.get('guidance_file') or current_guidance_file
        candidate_reports = [{
            'name': selected_candidate.get('name'),
            'source': selected_candidate.get('source'),
            'preflight': selected_candidate.get('preflight'),
            'run': None,
            'guidance_runtime_summary': None,
            'action_fires': 0,
            'coverage': 0,
            'verdict': str((selected_candidate.get('preflight') or {}).get('verdict') or 'preflight_ok')
        }]
        selected_candidate = candidate_reports[0]
        followup_import_dir = str(probe_root / 'workdir' / 'queue')
    else:
        candidate_reports, selected_candidate = _evaluate_followup_candidates(
            args=args,
            cycle_root=event_root,
            probe_queue_dir=str(probe_root / 'workdir' / 'queue'),
            fuzzer_bin=fuzzer_bin,
            ghidra_src=args.ghidra_src,
            candidates=portfolio_candidates[:max(1, int(getattr(args, 'portfolio_max_candidates', 3)))],
            trace_base=trace_base,
        )
        next_guidance_file = selected_candidate.get('guidance_file') or current_guidance_file
        followup_import_dir = selected_candidate.get('run', {}).get('workdir')
        followup_import_dir = _queue_dir(followup_import_dir) if followup_import_dir else str(probe_root / 'workdir' / 'queue')

    followup_root = event_root / 'followup'
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
        import_dir=followup_import_dir,
        fuzzer_bin=fuzzer_bin,
        setenv=args.setenv,
        dump_trace=bool(getattr(args, 'dump_followup_trace', False)),
        trace_basename=trace_base,
    )
    save_json(str(followup_root / 'run_fuzz_summary.json'), followup_run)

    event_report = {
        'cycle_index': event_index,
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
        'dynamic_guidance_file': str(dynamic_guidance_path) if dynamic_guidance else None,
        'dynamic_guidance': dynamic_guidance,
        'candidate_portfolio': candidate_reports,
        'selected_candidate': selected_candidate,
        'followup_run': followup_run,
        'coverage_delta_probe_vs_input': _coverage_from_run_summary(probe_run.get('run_summary')) - int(previous_cov or 0),
        'coverage_delta_followup_vs_probe': _coverage_from_run_summary(followup_run.get('run_summary')) - _coverage_from_run_summary(probe_run.get('run_summary')),
    }
    next_import_dir = str(followup_root / 'workdir' / 'queue')
    return event_report, next_import_dir, str(next_guidance_file or current_guidance_file)


def _new_strategy_entry(*, name: str, source: str, guidance_file: str, origin: str, event_index: Optional[int] = None) -> Dict[str, Any]:
    sid_src = f"{source}|{_abs(guidance_file) if guidance_file else ''}|{event_index or 0}|{origin}"
    sid = f"{_safe_id(name)}_{hashlib.sha1(sid_src.encode('utf-8')).hexdigest()[:8]}"
    return {
        'strategy_id': sid,
        'name': name,
        'source': source,
        'guidance_file': _abs(guidance_file) if guidance_file else None,
        'origin': origin,
        'origin_event_index': event_index,
        'status': 'active',
        'windows_run': 0,
        'windows_selected': 0,
        'cumulative_cov_delta': 0,
        'cumulative_hang_delta': 0,
        'cumulative_hangs': 0,
        'cumulative_intervention_signals': 0,
        'cumulative_action_fires': 0,
        'cumulative_tail_fire_signals': 0,
        'cumulative_sequence_progress': 0,
        'sustained_positive_windows': 0,
        'last_window_index': None,
        'last_cov_delta': None,
        'last_hang_delta': None,
        'last_cov': None,
        'last_hangs': None,
        'last_verdict': None,
        'last_intervention_signal': False,
        'last_summary_action_fires': 0,
        'last_effective_action_fires': 0,
        'last_tail_fire_signals': 0,
        'last_sequence_progress': 0,
        'last_active_stage_count': 0,
        'last_effective_intervention_stats': None,
        'rolling_cov_deltas': [],
        'rolling_hang_deltas': [],
        'recent_avg_cov_delta': 0.0,
        'recent_avg_hang_delta': 0.0,
        'recent_positive_windows': 0,
        'trial_windows_remaining': 0,
        'credit': 0.0,
    }


def _find_strategy_entry(strategy_pool: List[Dict[str, Any]], guidance_file: Optional[str], source: Optional[str]) -> Optional[Dict[str, Any]]:
    gf = _abs(guidance_file) if guidance_file else None
    for entry in strategy_pool:
        if gf and entry.get('guidance_file') == gf:
            return entry
    for entry in strategy_pool:
        if source and entry.get('source') == source and source == 'control':
            return entry
    return None


def _strategy_score_components(entry: Dict[str, Any], current_window: Optional[int] = None) -> Dict[str, float]:
    recent_avg_cov = float(entry.get('recent_avg_cov_delta') or 0.0)
    last_cov = float(entry.get('last_cov_delta') or 0.0)
    recent_avg_hang = float(entry.get('recent_avg_hang_delta') or 0.0)
    last_hang = float(entry.get('last_hang_delta') or 0.0)
    recent_positive = float(entry.get('recent_positive_windows') or 0)
    effective_action_fires = float(min(int(entry.get('last_effective_action_fires') or 0), 3))
    sequence_progress = float(min(int(entry.get('last_sequence_progress') or 0), 2))
    tail_fire_signals = float(min(int(entry.get('last_tail_fire_signals') or 0), 3))
    intervention_signal = 1.0 if bool(entry.get('last_intervention_signal')) else 0.0
    trial_windows_remaining = float(max(0, int(entry.get('trial_windows_remaining') or 0)))
    freshness_bonus = 0.0
    promoted_after = entry.get('last_promoted_after_window')
    if current_window is not None and promoted_after is not None:
        try:
            delta = int(current_window) - int(promoted_after)
            if 1 <= delta <= 3:
                freshness_bonus = 12.0
        except Exception:
            freshness_bonus = 0.0
    source_bias = 0.0
    score = (
        4.0 * recent_avg_cov
        + 2.0 * last_cov
        - 5.0 * max(recent_avg_hang, 0.0)
        - 3.0 * max(last_hang, 0.0)
        + 4.0 * recent_positive
        + 1.5 * effective_action_fires
        + 1.0 * sequence_progress
        + 0.5 * tail_fire_signals
        + 0.25 * intervention_signal
        + freshness_bonus
        + 8.0 * min(trial_windows_remaining, 1.0)
        + source_bias
    )
    return {
        'score': float(score),
        'recent_avg_cov_delta': recent_avg_cov,
        'last_cov_delta': last_cov,
        'recent_avg_hang_delta': recent_avg_hang,
        'last_hang_delta': last_hang,
        'recent_positive_windows': recent_positive,
        'sustained_positive_windows': float(entry.get('sustained_positive_windows') or 0),
        'effective_action_fires': effective_action_fires,
        'sequence_progress': sequence_progress,
        'tail_fire_signals': tail_fire_signals,
        'intervention_signal': intervention_signal,
        'trial_windows_remaining': trial_windows_remaining,
        'freshness_bonus': freshness_bonus,
        'source_bias': source_bias,
    }


def _strategy_window_score(entry: Dict[str, Any], current_window: Optional[int] = None) -> Tuple[Any, ...]:
    c = _strategy_score_components(entry, current_window=current_window)
    return (
        float(c['score']),
        float(c['recent_avg_cov_delta']),
        -float(max(c['recent_avg_hang_delta'], 0.0)),
        float(c['effective_action_fires']),
        float(c['sequence_progress']),
        float(c['tail_fire_signals']),
        float(c['sustained_positive_windows']),
        float(c['last_cov_delta']),
        -int(entry.get('windows_run') or 0),
    )


def _choose_strategy_for_window(strategy_pool: List[Dict[str, Any]], window_index: int, args) -> Tuple[Dict[str, Any], str]:
    active = [s for s in strategy_pool if str(s.get('status') or 'active') == 'active']
    controls = [s for s in active if s.get('source') == 'control']
    interventions = [s for s in active if s.get('source') != 'control']
    control_every = max(1, int(getattr(args, 'strategy_control_every_windows', 2) or 2))
    if not interventions:
        chosen = controls[0] if controls else max(active, key=lambda s: _strategy_window_score(s, current_window=window_index))
        return chosen, 'no_intervention_available'
    if controls and ((window_index - 1) % control_every == 0):
        return controls[0], 'periodic_control_refresh'

    trial_ready = [s for s in interventions if int(s.get('trial_windows_remaining') or 0) > 0]
    if trial_ready:
        def _trial_rank(entry: Dict[str, Any]) -> Tuple[Any, ...]:
            comps = _strategy_score_components(entry, current_window=window_index)
            return (
                int(entry.get('trial_windows_remaining') or 0),
                float(comps.get('freshness_bonus') or 0.0),
                -int(entry.get('windows_run') or 0),
                -int(entry.get('windows_selected') or 0),
                int(entry.get('last_promoted_after_window') or -1),
            )
        return max(trial_ready, key=_trial_rank), 'trial_new_strategy'

    chosen = max(active, key=lambda s: _strategy_window_score(s, current_window=window_index))
    return chosen, 'best_active_strategy'


def _strategy_pool_snapshot(strategy_pool: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    snap: List[Dict[str, Any]] = []
    for entry in strategy_pool:
        snap.append({
            'strategy_id': entry.get('strategy_id'),
            'name': entry.get('name'),
            'source': entry.get('source'),
            'status': entry.get('status'),
            'credit': float(entry.get('credit') or 0.0),
            'recent_avg_cov_delta': float(entry.get('recent_avg_cov_delta') or 0.0),
            'recent_avg_hang_delta': float(entry.get('recent_avg_hang_delta') or 0.0),
            'windows_run': int(entry.get('windows_run') or 0),
            'windows_selected': int(entry.get('windows_selected') or 0),
            'last_window_index': entry.get('last_window_index'),
            'last_cov_delta': entry.get('last_cov_delta'),
            'last_hang_delta': entry.get('last_hang_delta'),
            'last_intervention_signal': bool(entry.get('last_intervention_signal')),
            'last_effective_action_fires': int(entry.get('last_effective_action_fires') or 0),
            'last_sequence_progress': int(entry.get('last_sequence_progress') or 0),
        })
    snap.sort(key=lambda x: (x['credit'], x['recent_avg_cov_delta'], -max(x['recent_avg_hang_delta'], 0.0)), reverse=True)
    return snap


def _strategy_candidate_scores(strategy_pool: List[Dict[str, Any]], current_window: Optional[int] = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for entry in strategy_pool:
        comps = _strategy_score_components(entry, current_window=current_window)
        rows.append({
            'strategy_id': entry.get('strategy_id'),
            'name': entry.get('name'),
            'source': entry.get('source'),
            'status': entry.get('status'),
            'score': float(comps['score']),
            'components': comps,
        })
    rows.sort(key=lambda x: (x['score'], x['components']['recent_avg_cov_delta'], -max(x['components']['recent_avg_hang_delta'], 0.0)), reverse=True)
    return rows


def _update_strategy_after_window(entry: Dict[str, Any], *, window_index: int, run: Dict[str, Any], guidance_summary: Optional[Dict[str, Any]], cov_delta: int, hang_delta: int):
    grs = guidance_summary or {}
    istats = _intervention_stats(grs, run)
    summary_action_fires = int(istats['summary_action_fires'])
    effective_action_fires = int(istats['effective_action_fires'])
    tail_fires = int(istats['tail_fire_signals'])
    sequence_progress = int(istats['sequence_progress'])
    active_stage_count = int(istats['active_stage_count'])
    intervention_signal = bool(istats['intervention_signal'])
    current_hangs = _run_last_hang(run)
    entry['windows_run'] = int(entry.get('windows_run') or 0) + 1
    entry['cumulative_cov_delta'] = int(entry.get('cumulative_cov_delta') or 0) + int(cov_delta)
    entry['cumulative_hang_delta'] = int(entry.get('cumulative_hang_delta') or 0) + int(hang_delta)
    entry['cumulative_hangs'] = int(entry.get('cumulative_hangs') or 0) + int(current_hangs)
    entry['cumulative_intervention_signals'] = int(entry.get('cumulative_intervention_signals') or 0) + int(intervention_signal)
    entry['cumulative_action_fires'] = int(entry.get('cumulative_action_fires') or 0) + int(effective_action_fires)
    entry['cumulative_tail_fire_signals'] = int(entry.get('cumulative_tail_fire_signals') or 0) + int(tail_fires)
    entry['cumulative_sequence_progress'] = int(entry.get('cumulative_sequence_progress') or 0) + int(sequence_progress)
    entry['sustained_positive_windows'] = int(entry.get('sustained_positive_windows') or 0) + int((cov_delta > 0) and (hang_delta <= 0))
    entry['last_window_index'] = window_index
    entry['last_cov_delta'] = int(cov_delta)
    entry['last_hang_delta'] = int(hang_delta)
    entry['last_cov'] = _coverage_from_run_summary(run.get('run_summary'))
    entry['last_hangs'] = int(current_hangs)
    entry['last_verdict'] = _guidance_verdict_from_preflight_and_run({'verdict': 'preflight_ok'}, run)
    entry['last_intervention_signal'] = bool(intervention_signal)
    entry['last_summary_action_fires'] = int(summary_action_fires)
    entry['last_effective_action_fires'] = int(effective_action_fires)
    entry['last_tail_fire_signals'] = int(tail_fires)
    entry['last_sequence_progress'] = int(sequence_progress)
    entry['last_active_stage_count'] = int(active_stage_count)
    entry['last_effective_intervention_stats'] = dict(istats)
    rolling_cov = list(entry.get('rolling_cov_deltas') or [])[-4:] + [int(cov_delta)]
    rolling_hang = list(entry.get('rolling_hang_deltas') or [])[-4:] + [int(hang_delta)]
    entry['rolling_cov_deltas'] = rolling_cov
    entry['rolling_hang_deltas'] = rolling_hang
    entry['recent_avg_cov_delta'] = (sum(rolling_cov) / len(rolling_cov)) if rolling_cov else 0.0
    entry['recent_avg_hang_delta'] = (sum(rolling_hang) / len(rolling_hang)) if rolling_hang else 0.0
    entry['recent_positive_windows'] = sum(1 for c, h in zip(rolling_cov, rolling_hang) if int(c) > 0 and int(h) <= 0)
    if int(entry.get('trial_windows_remaining') or 0) > 0:
        entry['trial_windows_remaining'] = max(0, int(entry.get('trial_windows_remaining') or 0) - 1)

    old_credit = float(entry.get('credit') or 0.0)
    recent_avg_cov = float(entry.get('recent_avg_cov_delta') or 0.0)
    recent_avg_hang = float(entry.get('recent_avg_hang_delta') or 0.0)
    recent_positive = float(entry.get('recent_positive_windows') or 0)
    window_score = (
        4.0 * recent_avg_cov
        + 2.0 * float(cov_delta)
        - 5.0 * max(recent_avg_hang, 0.0)
        - 3.0 * max(float(hang_delta), 0.0)
        + 4.0 * recent_positive
        + 1.5 * float(min(effective_action_fires, 3))
        + 1.0 * float(min(sequence_progress, 2))
        + 0.5 * float(min(tail_fires, 3))
        + (0.25 if intervention_signal else 0.0)
    )
    if int(cov_delta) <= 0 and int(hang_delta) >= 0:
        window_score -= 20.0
    entry['credit'] = 0.6 * old_credit + window_score


def _maybe_cool_strategy(entry: Dict[str, Any], args):
    if entry.get('source') == 'control':
        return
    min_windows = max(1, int(getattr(args, 'strategy_cooldown_min_windows', 2) or 2))
    negative_guard = int(getattr(args, 'strategy_cooldown_negative_delta', 200) or 200)
    hang_guard = int(getattr(args, 'strategy_cooldown_hang_delta', 10) or 10)
    if int(entry.get('windows_run') or 0) < min_windows:
        return
    if int(entry.get('cumulative_cov_delta') or 0) <= -negative_guard and not bool(entry.get('last_intervention_signal')):
        entry['status'] = 'cooling'
        return
    if float(entry.get('recent_avg_cov_delta') or 0.0) < 0 and float(entry.get('recent_avg_hang_delta') or 0.0) >= hang_guard:
        entry['status'] = 'cooling'


def _register_promoted_strategy(strategy_pool: List[Dict[str, Any]], candidate: Optional[Dict[str, Any]], event_index: int, args) -> Optional[Dict[str, Any]]:
    if not candidate:
        return None
    source = str(candidate.get('source') or '')
    guidance_file = candidate.get('guidance_file')
    if source == 'control' or not guidance_file:
        return _find_strategy_entry(strategy_pool, guidance_file, source)

    trial_windows = max(1, int(getattr(args, 'strategy_trial_windows', 1) or 1))
    existing = _find_strategy_entry(strategy_pool, guidance_file, source)
    if existing:
        existing['status'] = 'active'
        existing['last_selected_event_index'] = event_index
        existing['trial_windows_remaining'] = max(int(existing.get('trial_windows_remaining') or 0), trial_windows)
        return existing

    entry = _new_strategy_entry(
        name=str(candidate.get('name') or source),
        source=source,
        guidance_file=str(guidance_file),
        origin='adaptive_event',
        event_index=event_index,
    )
    entry['selection_policy'] = candidate.get('selection_policy')
    entry['trial_windows_remaining'] = trial_windows
    strategy_pool.append(entry)
    max_size = max(2, int(getattr(args, 'strategy_pool_max_size', 4) or 4))
    controls = [s for s in strategy_pool if s.get('source') == 'control']
    others = [s for s in strategy_pool if s.get('source') != 'control']
    others.sort(key=_strategy_window_score, reverse=True)
    strategy_pool[:] = controls[:1] + others[:max_size - 1]
    return entry


def _should_trigger_adaptive_window(*, window_index: int, recent_cov_deltas: List[int], args) -> List[str]:
    reasons: List[str] = []
    period = int(getattr(args, 'adaptive_period_windows', 0) or 0)
    if period > 0 and window_index % period == 0:
        reasons.append('periodic_window')
    plateau_windows = int(getattr(args, 'adaptive_plateau_windows', 0) or 0)
    plateau_threshold = int(getattr(args, 'adaptive_plateau_delta_threshold', 0) or 0)
    if plateau_windows > 0 and len(recent_cov_deltas) >= plateau_windows:
        tail = recent_cov_deltas[-plateau_windows:]
        if all(int(x) <= plateau_threshold for x in tail):
            reasons.append('plateau_window')
    return reasons


def _run_adaptive_mmio_loop_single_cycle(args, out_root: Path, fuzzer_bin: str) -> Dict[str, Any]:
    ctx = _build_initial_adaptive_context(args, out_root, fuzzer_bin)
    baseline_summary = ctx['baseline_summary']
    current_import_dir = ctx['current_import_dir']
    current_guidance_file = ctx['current_guidance_file']
    control_guidance_file = ctx['current_guidance_file']
    initial_guidance_kind = ctx['initial_guidance_kind']
    baseline_frontier_cov = ctx['baseline_frontier_cov']

    cycle_reports: List[Dict[str, Any]] = []
    final_queue_dir = current_import_dir
    final_guidance_file = current_guidance_file
    prev_cov = baseline_frontier_cov

    for cycle_idx in range(1, int(getattr(args, 'max_llm_cycles', 1)) + 1):
        cycle_root = out_root / f'cycle_{cycle_idx}'
        cycle_report, current_import_dir, current_guidance_file = _run_adaptive_event_once(
            args=args,
            event_root=cycle_root,
            event_index=cycle_idx,
            current_import_dir=current_import_dir,
            current_guidance_file=current_guidance_file,
            control_guidance_file=current_guidance_file,
            previous_cov=prev_cov,
            fuzzer_bin=fuzzer_bin,
        )
        cycle_reports.append(cycle_report)
        final_queue_dir = current_import_dir
        final_guidance_file = current_guidance_file
        prev_cov = _coverage_from_run_summary(cycle_report.get('followup_run', {}).get('run_summary'))
        if (not cycle_report.get('llm_invoked')) and (not bool(getattr(args, 'force_llm', False))):
            break

    return {
        'schema': 'mf_adaptive_mmio_loop_v4',
        'mode': 'single_cycle_adaptive',
        'contract_bundle': _abs(args.contract_bundle),
        'initial_guidance_kind': initial_guidance_kind,
        'initial_guidance_file': _abs(args.guidance_file) if initial_guidance_kind == 'provided' else str(out_root / 'auto_probe.guidance.json'),
        'baseline_summary': baseline_summary,
        'cycles': cycle_reports,
        'final_queue_dir': final_queue_dir,
        'final_guidance_file': final_guidance_file,
    }


def _run_long_horizon_main_loop(args, out_root: Path, fuzzer_bin: str) -> Dict[str, Any]:
    ctx = _build_initial_adaptive_context(args, out_root, fuzzer_bin)
    baseline_summary = ctx['baseline_summary']
    current_import_dir = ctx['current_import_dir']
    control_guidance_file = ctx['current_guidance_file']
    initial_guidance_kind = ctx['initial_guidance_kind']
    baseline_frontier_cov = ctx['baseline_frontier_cov']

    strategy_pool: List[Dict[str, Any]] = [
        _new_strategy_entry(name='control', source='control', guidance_file=control_guidance_file, origin='baseline_control')
    ]
    window_reports: List[Dict[str, Any]] = []
    adaptive_events: List[Dict[str, Any]] = []
    recent_cov_deltas: List[int] = []
    prev_cov = baseline_frontier_cov
    prev_hang = int((baseline_summary.get('frontier_run') or {}).get('run_summary', {}).get('last_hang') or 0)
    event_index = 0
    last_guidance_file = control_guidance_file

    total_windows = max(1, int(getattr(args, 'main_window_count', 0) or 0))
    main_window_run_for = str(getattr(args, 'main_window_run_for', None) or args.followup_run_for or '300s')
    trace_base = str(getattr(args, 'trace_basename', 'replay_trace'))

    for window_index in range(1, total_windows + 1):
        pre_schedule_snapshot = _strategy_pool_snapshot(strategy_pool)
        candidate_scores = _strategy_candidate_scores(strategy_pool, current_window=window_index)
        chosen, schedule_policy = _choose_strategy_for_window(strategy_pool, window_index, args)
        chosen['windows_selected'] = int(chosen.get('windows_selected') or 0) + 1
        window_root = out_root / 'main_windows' / f'window_{window_index:03d}_{_safe_id(chosen.get("name") or chosen.get("source") or "strategy")}'
        _ensure_dir(str(window_root))
        run = run_hail_fuzz(
            manifest_path=args.fuzzer_manifest,
            firmware_config=args.firmware_config,
            ghidra_src=args.ghidra_src,
            workdir=str(window_root / 'workdir'),
            run_log=str(window_root / 'run.log'),
            run_for=main_window_run_for,
            observer_dir=str(window_root / 'observer'),
            guidance_file=chosen.get('guidance_file'),
            guidance_summary_out=str(window_root / 'guidance_runtime_summary.json'),
            import_dir=current_import_dir,
            fuzzer_bin=fuzzer_bin,
            setenv=args.setenv,
            dump_trace=False,
            trace_basename=trace_base,
        )
        save_json(str(window_root / 'run_fuzz_summary.json'), run)
        grs = _maybe_json(str(window_root / 'guidance_runtime_summary.json')) or {}
        cov = _coverage_from_run_summary(run.get('run_summary'))
        cov_delta = cov - prev_cov
        current_hang = _run_last_hang(run)
        hang_delta = int(current_hang) - int(prev_hang)
        prev_cov = cov
        prev_hang = current_hang
        current_import_dir = _queue_dir(run.get('workdir'))
        last_guidance_file = chosen.get('guidance_file') or last_guidance_file
        _update_strategy_after_window(chosen, window_index=window_index, run=run, guidance_summary=grs, cov_delta=cov_delta, hang_delta=hang_delta)
        _maybe_cool_strategy(chosen, args)
        istats = _intervention_stats(grs, run)
        window_report = {
            'window_index': window_index,
            'schedule_policy': schedule_policy,
            'selected_strategy_id': chosen.get('strategy_id'),
            'selected_strategy_name': chosen.get('name'),
            'selected_strategy_source': chosen.get('source'),
            'selected_strategy_reason': schedule_policy,
            'candidate_scores': candidate_scores,
            'strategy_pool_snapshot': pre_schedule_snapshot,
            'guidance_file': chosen.get('guidance_file'),
            'selected_guidance_file': chosen.get('guidance_file'),
            'run': run,
            'guidance_runtime_summary': grs,
            'coverage_delta_vs_prev_window': cov_delta,
            'hang_delta_vs_prev_window': hang_delta,
            'effective_intervention_stats': istats,
            'strategy_snapshot': dict(chosen),
        }
        window_reports.append(window_report)
        recent_cov_deltas.append(cov_delta)
        max_recent = max(2, int(getattr(args, 'adaptive_plateau_windows', 0) or 0), int(getattr(args, 'adaptive_period_windows', 0) or 0), 8)
        recent_cov_deltas = recent_cov_deltas[-max_recent:]

        trigger_reasons = _should_trigger_adaptive_window(window_index=window_index, recent_cov_deltas=recent_cov_deltas, args=args)
        if trigger_reasons:
            event_index += 1
            event_root = out_root / 'adaptive_events' / f'event_{event_index:03d}'
            event_report, current_import_dir, promoted_guidance_file = _run_adaptive_event_once(
                args=args,
                event_root=event_root,
                event_index=event_index,
                current_import_dir=current_import_dir,
                current_guidance_file=chosen.get('guidance_file') or control_guidance_file,
                control_guidance_file=control_guidance_file,
                previous_cov=prev_cov,
                fuzzer_bin=fuzzer_bin,
            )
            event_report['triggered_after_window'] = window_index
            event_report['trigger_reasons'] = trigger_reasons
            adaptive_events.append(event_report)
            promoted = _register_promoted_strategy(strategy_pool, event_report.get('selected_candidate'), event_index, args)
            if promoted:
                promoted['last_promoted_after_window'] = window_index
            last_guidance_file = promoted_guidance_file or last_guidance_file
            prev_cov = _coverage_from_run_summary(event_report.get('followup_run', {}).get('run_summary'))

    return {
        'schema': 'mf_adaptive_mmio_loop_v4',
        'mode': 'continuous_long_horizon',
        'contract_bundle': _abs(args.contract_bundle),
        'initial_guidance_kind': initial_guidance_kind,
        'initial_guidance_file': _abs(args.guidance_file) if initial_guidance_kind == 'provided' else str(out_root / 'auto_probe.guidance.json'),
        'baseline_summary': baseline_summary,
        'main_window_run_for': main_window_run_for,
        'main_window_count': total_windows,
        'adaptive_period_windows': int(getattr(args, 'adaptive_period_windows', 0) or 0),
        'adaptive_plateau_windows': int(getattr(args, 'adaptive_plateau_windows', 0) or 0),
        'windows': window_reports,
        'adaptive_events': adaptive_events,
        'strategy_pool': strategy_pool,
        'final_queue_dir': current_import_dir,
        'final_guidance_file': last_guidance_file,
    }


def _run_adaptive_mmio_loop(args):
    out_root = Path(args.out_root).expanduser().resolve()
    _ensure_dir(str(out_root))
    fuzzer_bin = _abs(args.fuzzer_bin) if getattr(args, 'fuzzer_bin', None) else ensure_fuzzer_binary(args.fuzzer_manifest)
    if int(getattr(args, 'main_window_count', 0) or 0) > 0:
        summary = _run_long_horizon_main_loop(args, out_root, fuzzer_bin)
    else:
        summary = _run_adaptive_mmio_loop_single_cycle(args, out_root, fuzzer_bin)
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


def _sum_sequence_progress(summary: Optional[Dict[str, Any]]) -> int:
    total = 0
    for item in (summary or {}).get("actions", []) or []:
        total += int(item.get("sequence_pos") or 0)
    return total


def _count_active_stages(summary: Optional[Dict[str, Any]]) -> int:
    return len((summary or {}).get("active_stages") or [])


def _run_tail_fire_signals(run: Optional[Dict[str, Any]]) -> int:
    total = 0
    for line in ((run or {}).get("run_summary") or {}).get("tail", []) or []:
        if "[strategy-runtime] fire" in str(line):
            total += 1
    return total


def _run_last_hang(run: Optional[Dict[str, Any]]) -> int:
    return int(((run or {}).get("run_summary") or {}).get("last_hang") or 0)


def _run_last_crash(run: Optional[Dict[str, Any]]) -> int:
    return int(((run or {}).get("run_summary") or {}).get("last_crash") or 0)


def _intervention_stats(summary: Optional[Dict[str, Any]], run: Optional[Dict[str, Any]]) -> Dict[str, int | bool]:
    summary_action_fires = _sum_action_fires(summary)
    tail_fire_signals = _run_tail_fire_signals(run)
    effective_action_fires = max(int(summary_action_fires), int(tail_fire_signals))
    sequence_progress = _sum_sequence_progress(summary)
    active_stage_count = _count_active_stages(summary)
    intervention_signal = bool(
        effective_action_fires > 0
        or sequence_progress > 0
        or active_stage_count > 0
    )
    return {
        'summary_action_fires': int(summary_action_fires),
        'tail_fire_signals': int(tail_fire_signals),
        'effective_action_fires': int(effective_action_fires),
        'sequence_progress': int(sequence_progress),
        'active_stage_count': int(active_stage_count),
        'intervention_signal': bool(intervention_signal),
    }


def _candidate_has_intervention_signal(rec: Dict[str, Any]) -> bool:
    return bool(
        int(rec.get('effective_action_fires') or rec.get('action_fires') or 0) > 0
        or int(rec.get('sequence_progress') or 0) > 0
        or int(rec.get('active_stage_count') or 0) > 0
        or int(rec.get('tail_fire_signals') or 0) > 0
    )


def _candidate_selection_scalar(rec: Dict[str, Any], *, args) -> float:
    coverage = float(rec.get('coverage') or 0)
    touched_ratio = float(rec.get('touched_trigger_ratio') or 0.0)
    effective_fires = int(rec.get('effective_action_fires') or rec.get('action_fires') or 0)
    tail_fires = int(rec.get('tail_fire_signals') or 0)
    seq = int(rec.get('sequence_progress') or 0)
    active = int(rec.get('active_stage_count') or 0)
    non_control = 0 if rec.get('source') == 'control' else 1
    hangs = int(rec.get('hangs') or 0)
    crashes = int(rec.get('crashes') or 0)

    fire_bonus = float(getattr(args, 'portfolio_fire_bonus', 120.0))
    tail_fire_bonus = float(getattr(args, 'portfolio_tail_fire_bonus', 25.0))
    sequence_bonus = float(getattr(args, 'portfolio_sequence_bonus', 90.0))
    active_stage_bonus = float(getattr(args, 'portfolio_active_stage_bonus', 40.0))
    touched_ratio_bonus = float(getattr(args, 'portfolio_touched_ratio_bonus', 25.0))
    non_control_bonus = float(getattr(args, 'portfolio_non_control_bonus', 10.0))
    hang_penalty = float(getattr(args, 'portfolio_hang_penalty', 15.0))
    crash_penalty = float(getattr(args, 'portfolio_crash_penalty', 50.0))

    score = coverage
    score += effective_fires * fire_bonus
    score += tail_fires * tail_fire_bonus
    score += seq * sequence_bonus
    score += active * active_stage_bonus
    score += touched_ratio * touched_ratio_bonus
    score += non_control * non_control_bonus
    score -= hangs * hang_penalty
    score -= crashes * crash_penalty
    return score


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
    s14.add_argument("--warmup-run-for", default="600s")
    s14.add_argument("--warmup-restarts", type=int, default=1)
    s14.add_argument("--probe-run-for", default="30s")
    s14.add_argument("--followup-run-for", default="60s")
    s14.add_argument("--portfolio-run-for", default="20s")
    s14.add_argument("--portfolio-max-candidates", type=int, default=3)
    s14.add_argument("--disable-candidate-portfolio", action="store_true")
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
    s14.add_argument("--main-window-count", type=int, default=0, help="If >0, run long-horizon mode with this many main windows after warmup")
    s14.add_argument("--main-window-run-for", default="300s")
    s14.add_argument("--adaptive-period-windows", type=int, default=3)
    s14.add_argument("--adaptive-plateau-windows", type=int, default=2)
    s14.add_argument("--adaptive-plateau-delta-threshold", type=int, default=0)
    s14.add_argument("--strategy-control-every-windows", type=int, default=2)
    s14.add_argument("--strategy-pool-max-size", type=int, default=4)
    s14.add_argument("--strategy-trial-windows", type=int, default=1)
    s14.add_argument("--strategy-cooldown-min-windows", type=int, default=2)
    s14.add_argument("--strategy-cooldown-negative-delta", type=int, default=200)
    s14.add_argument("--portfolio-intervention-coverage-slack", type=int, default=64)

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
