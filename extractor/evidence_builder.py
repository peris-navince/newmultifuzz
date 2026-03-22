from __future__ import annotations

import argparse
import os
from typing import Any, Dict, List, Optional

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
    latest_path = os.path.join(observer_dir, "latest_window_discovered_streams.json")
    discovered_path = os.path.join(observer_dir, "discovered_streams.json")
    info(f"build_evidence_pack observer_dir={observer_dir}")
    latest = load_json(latest_path)
    discovered = load_json(discovered_path) if os.path.exists(discovered_path) else []

    latest_hotspots = _pick_hotspots(latest, top_k=top_k)
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
