from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from debug_trace import debug, info, load_json, save_json, warn
from pdf_evidence_locator import locate_register_pdf_evidence
from svd_parser import parse_svd
from svd_resolver import resolve_address


def _int_auto(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except Exception:
        return None



_WINDOW_FILE_RE = re.compile(r"window_(\d+)_([a-z_]+)\.json$")


def _load_json_if_exists(path: str) -> Optional[Any]:
    if path and os.path.exists(path):
        return load_json(path)
    return None


def _window_index_from_name(path: Path) -> int:
    m = _WINDOW_FILE_RE.search(path.name)
    return int(m.group(1)) if m else -1


def _merge_width_counts(dst: Dict[str, int], src: Dict[str, Any]) -> Dict[str, int]:
    out = dict(dst)
    for k, v in (src or {}).items():
        try:
            out[str(k)] = int(out.get(str(k), 0)) + int(v or 0)
        except Exception:
            continue
    return out


def _aggregate_discovered_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for row in rows or []:
        addr = str(row.get('addr') or '').upper().strip()
        if not addr:
            continue
        cur = merged.setdefault(addr, {'addr': addr, 'width_counts': {}})
        for key in ['read_count', 'total_bytes_requested', 'executions_seen', 'interesting_executions_seen']:
            try:
                cur[key] = int(cur.get(key, 0)) + int(row.get(key) or 0)
            except Exception:
                pass
        for key, chooser in [('first_seen_order', min), ('last_seen_order', max)]:
            try:
                rv = int(row.get(key))
            except Exception:
                continue
            if key not in cur:
                cur[key] = rv
            else:
                cur[key] = chooser(int(cur[key]), rv)
        cur['width_counts'] = _merge_width_counts(cur.get('width_counts') or {}, row.get('width_counts') or {})
    ordered = sorted(merged.values(), key=lambda x: (int(x.get('read_count', 0)), int(x.get('executions_seen', 0)), x.get('addr', '')), reverse=True)
    return ordered


def _aggregate_interesting_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for row in rows or []:
        addr = str(row.get('addr') or '').upper().strip()
        if not addr:
            continue
        cur = merged.setdefault(addr, {'addr': addr})
        for key in ['interesting_hit_count', 'recent_window_hit_count']:
            try:
                cur[key] = int(cur.get(key, 0)) + int(row.get(key) or 0)
            except Exception:
                pass
    ordered = sorted(merged.values(), key=lambda x: (int(x.get('interesting_hit_count', 0)), int(x.get('recent_window_hit_count', 0)), x.get('addr', '')), reverse=True)
    return ordered


def _observer_windows_dir(observer_dir: str) -> Path:
    return Path(observer_dir).resolve() / 'windows'


def _observer_window_files(observer_dir: str, suffix: str) -> List[Path]:
    windows_dir = _observer_windows_dir(observer_dir)
    if not windows_dir.exists():
        return []
    pats = list(windows_dir.rglob(f'window_*_{suffix}.json'))
    pats.sort(key=lambda p: (_window_index_from_name(p), p.stat().st_mtime if p.exists() else 0.0))
    return pats


def _derive_observer_views(observer_dir: str) -> Dict[str, Any]:
    obs = str(Path(observer_dir).resolve())
    latest_summary = _load_json_if_exists(os.path.join(obs, 'latest_window_summary.json'))
    latest_discovered = _load_json_if_exists(os.path.join(obs, 'latest_window_discovered_streams.json'))
    latest_interesting = _load_json_if_exists(os.path.join(obs, 'latest_window_interesting_streams.json'))
    discovered = _load_json_if_exists(os.path.join(obs, 'discovered_streams.json'))
    interesting = _load_json_if_exists(os.path.join(obs, 'interesting_streams.json'))

    if latest_summary is None:
        files = _observer_window_files(obs, 'summary')
        if files:
            latest_summary = load_json(str(files[-1]))
    if latest_discovered is None:
        files = _observer_window_files(obs, 'discovered_streams')
        if files:
            latest_discovered = load_json(str(files[-1]))
    if latest_interesting is None:
        files = _observer_window_files(obs, 'interesting_streams')
        if files:
            latest_interesting = load_json(str(files[-1]))
    if discovered is None:
        rows: List[Dict[str, Any]] = []
        for fp in _observer_window_files(obs, 'discovered_streams'):
            data = load_json(str(fp))
            if isinstance(data, list):
                rows.extend(data)
        discovered = _aggregate_discovered_rows(rows)
    if interesting is None:
        rows2: List[Dict[str, Any]] = []
        for fp in _observer_window_files(obs, 'interesting_streams'):
            data = load_json(str(fp))
            if isinstance(data, list):
                rows2.extend(data)
        interesting = _aggregate_interesting_rows(rows2)

    return {
        'latest_window_summary': latest_summary or {},
        'latest_window_discovered_streams': latest_discovered or [],
        'latest_window_interesting_streams': latest_interesting or [],
        'discovered_streams': discovered or [],
        'interesting_streams': interesting or [],
    }

def _pick_hotspots(rows: List[Dict[str, Any]], top_k: int) -> List[Dict[str, Any]]:
    ordered = sorted(
        rows,
        key=lambda x: (
            int(x.get("read_count", 0)),
            int(x.get("executions_seen", 0)),
            str(x.get("addr", "")),
        ),
        reverse=True,
    )
    return ordered[:top_k]


def build_evidence_pack(
    pdf_path: str,
    svd_path: str,
    observer_dir: str,
    cache_root: str,
    out_path: str,
    extract_strategy: str = "layout",
    top_k: int = 8,
    force_pdf: bool = False,
) -> Dict[str, Any]:
    info(f"build_evidence_pack observer_dir={observer_dir}")
    observer_views = _derive_observer_views(observer_dir)
    latest = observer_views.get('latest_window_discovered_streams') or []
    discovered = observer_views.get('discovered_streams') or []

    latest_hotspots = _pick_hotspots(latest, top_k=top_k)
    if not latest_hotspots:
        latest_hotspots = _pick_hotspots(discovered, top_k=top_k)
    all_rows_by_addr = {str(x.get("addr")): x for x in discovered}
    svd_data = parse_svd(svd_path)

    evidence_rows = []
    for row in latest_hotspots:
        addr_s = str(row.get("addr") or "")
        addr_i = _int_auto(addr_s)
        if addr_i is None:
            warn(f"skip hotspot with unparsable addr: {addr_s}")
            continue
        info(f"resolving hotspot addr={addr_s} read_count={row.get('read_count')} exec_seen={row.get('executions_seen')}")
        resolved = resolve_address(svd_data, addr_i)
        runtime_evidence = {
            "latest_window": row,
            "global_discovered": all_rows_by_addr.get(addr_s),
        }
        if resolved is None:
            evidence_rows.append(
                {
                    "addr": addr_s,
                    "status": "unresolved_in_svd",
                    "runtime_evidence": runtime_evidence,
                    "svd_resolution": None,
                    "pdf_evidence": None,
                }
            )
            continue

        try:
            pdf_evidence = locate_register_pdf_evidence(
                pdf_path=pdf_path,
                svd_path=svd_path,
                cache_root=cache_root,
                resolved=resolved,
                extract_strategy=extract_strategy,
                force=force_pdf,
            )
            status = "ok"
        except Exception as e:
            warn(f"pdf locate failed for {addr_s}: {e}")
            pdf_evidence = {
                "status": "error",
                "error": str(e),
            }
            status = "pdf_locate_error"

        evidence_rows.append(
            {
                "addr": addr_s,
                "status": status,
                "runtime_evidence": runtime_evidence,
                "svd_resolution": resolved,
                "pdf_evidence": pdf_evidence,
            }
        )

    out = {
        "pdf": os.path.abspath(pdf_path),
        "svd": os.path.abspath(svd_path),
        "observer_dir": os.path.abspath(observer_dir),
        "cache_root": os.path.abspath(cache_root),
        "top_k": top_k,
        "observer_views": {
            "latest_window_summary": observer_views.get("latest_window_summary") or {},
            "latest_window_discovered_count": len(latest),
            "discovered_count": len(discovered),
            "interesting_count": len(observer_views.get("interesting_streams") or []),
        },
        "evidence": evidence_rows,
    }
    save_json(out_path, out)
    return out


def main():
    ap = argparse.ArgumentParser(description="Build source-backed evidence pack from runtime hotspots")
    ap.add_argument("--pdf", required=True)
    ap.add_argument("--svd", required=True)
    ap.add_argument("--observer-dir", required=True)
    ap.add_argument("--cache-root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--extract-strategy", default="layout")
    ap.add_argument("--top-k", type=int, default=8)
    ap.add_argument("--force-pdf", action="store_true")
    args = ap.parse_args()

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


if __name__ == "__main__":
    main()
