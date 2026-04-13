#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Package bounded evidence for LLM fallback.

This script should only be used after:
1) static contract bundling, and
2) dynamic stuck attribution.

It does not attempt to identify the stuck function again.
Instead it packages the already bounded evidence so the LLM only needs to infer:
- likely blocking condition
- likely MMIO / input constraints
- next seed hypothesis
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Iterable


def safe_read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_text(path: Path) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _normalize_hex(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, int):
        return f"0X{v:X}"
    s = str(v).strip()
    if not s:
        return None
    try:
        if s.lower().startswith("0x"):
            return f"0X{int(s, 16):X}"
        return f"0X{int(s, 10):X}"
    except Exception:
        return s.upper()


def load_guidance_summary(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise ValueError(f"guidance summary file does not exist: {path}")
    data = safe_read_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not look like a guidance runtime summary")
    return data


def _touch_list(summary: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    out = []
    for item in summary.get(key, []) or []:
        if isinstance(item, list) and len(item) >= 2:
            out.append({"address_hex": str(item[0]).upper(), "count": int(item[1])})
        elif isinstance(item, dict):
            addr = str(item.get("address_hex") or item.get("addr") or "").upper().strip()
            if addr:
                out.append({"address_hex": addr, "count": int(item.get("count") or 0)})
    return out


def load_bundle(path: Path) -> Dict[str, Any]:
    data = safe_read_json(path)
    if "program_context" not in data:
        raise ValueError(f"{path} does not look like a contract bundle")
    return data


def load_stuck(path: Path) -> Dict[str, Any]:
    data = safe_read_json(path)
    if "candidate_stuck_functions" not in data:
        raise ValueError(f"{path} does not look like a stuck report")
    return data


def build_function_map(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out = {}
    for f in bundle.get("program_context", {}).get("functions", []) or []:
        name = str(f.get("name") or "")
        if name:
            out[name] = f
    return out


TRACE_LIST_KEYS = ["trace", "events", "bb_trace", "blocks", "pcs", "items", "history"]


def load_trace_json(path: Optional[Path]) -> Any:
    if path is None:
        return None
    if not path.exists():
        raise ValueError(f"trace file does not exist: {path}")
    try:
        return safe_read_json(path)
    except json.JSONDecodeError:
        rows = []
        for line in read_text(path).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                return {"text_excerpt": read_text(path)[:4000], "trace_format": "text"}
        return {"events": rows, "trace_format": "jsonl"}


def _iter_trace_events(raw: Any) -> Iterable[Dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, dict):
        latest = raw.get("latest_exec")
        if isinstance(latest, dict) and isinstance(latest.get("events"), list):
            return [x for x in latest.get("events") or [] if isinstance(x, dict)]
        for k in TRACE_LIST_KEYS:
            if isinstance(raw.get(k), list):
                return [x for x in raw.get(k) or [] if isinstance(x, dict)]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    return []


def _build_trace_touch_profile(raw: Any, limit: int = 32) -> List[Dict[str, Any]]:
    stats: Dict[str, Dict[str, Any]] = {}
    for ev in _iter_trace_events(raw):
        candidates = []
        mmio_addr = _normalize_hex(ev.get("mmio_addr") or ev.get("mmio_address"))
        last_read = _normalize_hex(ev.get("last_read"))
        if mmio_addr:
            candidates.append(mmio_addr)
        if last_read and last_read not in candidates:
            candidates.append(last_read)
        if not candidates:
            continue
        width = ev.get("mmio_size") or ev.get("size") or ev.get("width")
        try:
            width_i = int(width) if width is not None else None
        except Exception:
            width_i = None
        for addr in candidates:
            ent = stats.setdefault(addr, {"address_hex": addr, "count": 0, "width_counts": {}})
            ent["count"] += 1
            if width_i:
                wc = ent["width_counts"]
                wc[str(width_i)] = int(wc.get(str(width_i), 0)) + 1
    ranked = sorted(stats.values(), key=lambda x: (-int(x.get("count") or 0), x.get("address_hex") or ""))
    out: List[Dict[str, Any]] = []
    for ent in ranked[:limit]:
        width_counts = {str(k): int(v) for k, v in (ent.get("width_counts") or {}).items()}
        dominant_width = None
        if width_counts:
            dominant_width = int(sorted(width_counts.items(), key=lambda kv: (-int(kv[1]), int(kv[0])))[0][0])
        out.append({
            "address_hex": ent["address_hex"],
            "count": int(ent.get("count") or 0),
            "dominant_width": dominant_width,
            "observed_widths": sorted(int(k) for k in width_counts.keys()),
            "width_counts": width_counts,
        })
    return out


def extract_trace_points(raw: Any, limit: int = 32) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    items = []
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        for k in TRACE_LIST_KEYS:
            if isinstance(raw.get(k), list):
                items = raw.get(k)
                break
    out = []
    for item in items[:limit]:
        if isinstance(item, dict):
            out.append(
                {
                    "pc": item.get("pc") or item.get("addr") or item.get("address") or item.get("bb_pc"),
                    "function": item.get("function") or item.get("func") or item.get("function_name"),
                    "block": item.get("block") or item.get("bb"),
                    "mmio_addr": item.get("mmio_addr") or item.get("mmio_address"),
                    "mmio_offset": item.get("mmio_offset") or item.get("offset"),
                }
            )
        else:
            out.append({"pc": item, "function": None, "block": None, "mmio_addr": None, "mmio_offset": None})
    return out


def filter_relevant_register_docs(
    bundle: Dict[str, Any],
    top_functions: List[Dict[str, Any]],
    likely_offsets: List[str],
) -> List[Dict[str, Any]]:
    regs = bundle.get("document_context", {}).get("matched_peripheral_registers", []) or []
    hot_abs = set()
    hot_rel = set(likely_offsets or [])
    for cand in top_functions:
        fn = cand.get("function")
        for f in bundle.get("program_context", {}).get("functions", []) or []:
            if f.get("name") == fn:
                hot_abs.update(f.get("hot_abs_addresses") or [])
                hot_rel.update(f.get("hot_rel_offsets") or [])
    out = []
    seen = set()
    for doc in regs:
        reg = doc.get("register") or {}
        key = (doc.get("peripheral"), reg.get("name"), reg.get("absoluteAddress_hex"))
        if key in seen:
            continue
        abs_hex = reg.get("absoluteAddress_hex")
        off_hex = reg.get("addressOffset_hex")
        if hot_abs and abs_hex in hot_abs:
            out.append(doc)
            seen.add(key)
        elif hot_rel and off_hex in hot_rel:
            out.append(doc)
            seen.add(key)
    if out:
        return out[:12]
    # fallback: top matched docs if no precise filter matched
    return regs[:12]


def build_llm_fallback_bundle(
    contract_bundle: Dict[str, Any],
    stuck_report: Dict[str, Any],
    baseline_trace: Any,
    manual_trace: Any,
    baseline_seed: Optional[str],
    manual_seed: Optional[str],
    probe_guidance_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    static_candidates = contract_bundle.get("program_context", {}).get("anchor_candidates", []) or []
    anchor_only_static = [c for c in static_candidates if c.get("is_anchor")]
    top_static = (anchor_only_static or static_candidates)[:10]
    top_dynamic = (stuck_report.get("candidate_stuck_functions", []) or [])[:8]
    likely_offsets = list(stuck_report.get("likely_blocking_offsets") or [])
    docs = filter_relevant_register_docs(contract_bundle, top_dynamic, likely_offsets)

    baseline_points = extract_trace_points(baseline_trace)
    manual_points = extract_trace_points(manual_trace)

    probe_guidance_summary = probe_guidance_summary or {}
    read_touches = _touch_list(probe_guidance_summary, "read_touches")
    write_touches = _touch_list(probe_guidance_summary, "write_touches")
    trace_touch_profile = _build_trace_touch_profile(manual_trace, limit=48)
    profile_seen = {str(x.get("address_hex") or "").upper() for x in trace_touch_profile}
    for item in (read_touches + write_touches):
        addr = str(item.get("address_hex") or "").upper()
        if addr and addr not in profile_seen:
            trace_touch_profile.append({
                "address_hex": addr,
                "count": int(item.get("count") or 0),
                "dominant_width": None,
                "observed_widths": [],
                "width_counts": {},
            })
            profile_seen.add(addr)
    touched_addrs = [x["address_hex"] for x in trace_touch_profile[:24]]
    dynamic_primary_cluster = stuck_report.get("dynamic_primary_cluster") or {}
    target_touched_registers = stuck_report.get("target_touched_registers") or []

    return {
        "schema": "llm_fallback_bundle_v2",
        "target_seed": manual_seed,
        "baseline_seed": baseline_seed,
        "stop_reason": stuck_report.get("stop_reason"),
        "last_pc": stuck_report.get("last_pc"),
        "last_pc_function": stuck_report.get("last_pc_function"),
        "still_ambiguous": stuck_report.get("still_ambiguous"),
        "top_static_candidates": top_static,
        "top_dynamic_candidates": top_dynamic,
        "dominant_loop_functions": stuck_report.get("dominant_loop_functions", []),
        "dominant_loop_blocks": stuck_report.get("dominant_loop_blocks", []),
        "tail_mmio": stuck_report.get("tail_mmio", {}),
        "likely_blocking_offsets": likely_offsets,
        "likely_blocking_registers": stuck_report.get("likely_blocking_registers", []),
        "matched_register_docs": docs,
        "dynamic_primary_cluster": dynamic_primary_cluster,
        "trace_touched_addrs": touched_addrs[:24],
        "trace_touch_profile": trace_touch_profile[:24],
        "probe_guidance_summary": {
            "plan_name": probe_guidance_summary.get("plan_name"),
            "global_reads": probe_guidance_summary.get("global_reads"),
            "global_writes": probe_guidance_summary.get("global_writes"),
            "read_touches": read_touches[:24],
            "write_touches": write_touches[:24],
        },
        "target_touched_registers": target_touched_registers[:12],
        "hypothesis_portfolio": {
            "dynamic_primary": dynamic_primary_cluster,
            "target_peripheral": {
                "target_rel_offsets": stuck_report.get("target_rel_offsets"),
                "target_touched_registers": target_touched_registers[:12],
            },
            "control_policy": "keep a control or minimal-perturbation candidate alongside any LLM-ranked branch",
        },
        "baseline_vs_manual_diff": {
            "trace_divergence": stuck_report.get("trace_divergence"),
            "baseline_trace_points": baseline_points,
            "manual_trace_points": manual_points,
        },
        "question": {
            "infer_blocking_condition": True,
            "infer_mmio_or_input_constraint": True,
            "propose_seed_hypothesis": True,
        },
        "packaging_notes": {
            "top_static_source": "anchor_only" if anchor_only_static else "all_candidates",
            "trace_inputs": {
                "baseline_available": baseline_trace is not None,
                "manual_available": manual_trace is not None,
            },
        },
    }


def build_prompt_text(bundle: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("You are given bounded evidence for a stuck firmware replay.")
    lines.append("Do not re-identify the hotspot globally. Work only inside the evidence below.")
    lines.append("")
    lines.append("Tasks:")
    lines.append("1. Treat dynamic evidence as primary and static peripheral anchors as secondary.")
    lines.append("2. Infer up to three bounded hypotheses, then choose one primary hypothesis.")
    lines.append("3. Infer the MMIO / input constraint that would satisfy the chosen hypothesis.")
    lines.append("4. Propose a next seed hypothesis in a concrete, testable form.")
    lines.append("5. Only use primary trigger addresses that were actually touched in the probe trace when possible.")
    lines.append("")
    lines.append(f"stop_reason: {bundle.get('stop_reason')}")
    lines.append(f"last_pc: {bundle.get('last_pc')}")
    lines.append(f"last_pc_function: {bundle.get('last_pc_function')}")
    lines.append(f"still_ambiguous: {bundle.get('still_ambiguous')}")
    lines.append("")
    lines.append("Dynamic primary cluster:")
    lines.append(f"- {bundle.get('dynamic_primary_cluster')}")
    lines.append("")
    lines.append("Probe-touched addresses:")
    profile = bundle.get("trace_touch_profile") or []
    if profile:
        for item in profile[:16]:
            addr = item.get("address_hex")
            count = item.get("count")
            dom = item.get("dominant_width")
            if dom:
                lines.append(f"- {addr} count={count} dominant_width={dom}")
            else:
                lines.append(f"- {addr} count={count}")
    else:
        for addr in bundle.get("trace_touched_addrs", [])[:16]:
            lines.append(f"- {addr}")
    lines.append("")
    lines.append("Top dynamic candidates:")
    for cand in bundle.get("top_dynamic_candidates", [])[:5]:
        lines.append(
            f"- {cand.get('function')}: combined={cand.get('combined_score')} dynamic={cand.get('dynamic_score')} static={cand.get('static_anchor_score')} evidence={cand.get('evidence')}"
        )
    lines.append("")
    lines.append(f"likely_blocking_offsets: {bundle.get('likely_blocking_offsets')}")
    lines.append("likely_blocking_registers:")
    for reg in bundle.get("likely_blocking_registers", [])[:8]:
        lines.append(
            f"- {reg.get('peripheral')}.{reg.get('register')} abs={reg.get('absoluteAddress_hex')} off={reg.get('addressOffset_hex')}"
        )
    lines.append("")
    lines.append("Relevant register docs:")
    for doc in bundle.get("matched_register_docs", [])[:6]:
        reg = doc.get("register") or {}
        lines.append(
            f"- {doc.get('peripheral')}.{reg.get('name')} abs={reg.get('absoluteAddress_hex')} off={reg.get('addressOffset_hex')}"
        )
        desc = str(reg.get("pdf_description") or reg.get("svd_description") or "").strip()
        if desc:
            lines.append(f"  desc: {desc[:400]}")
    lines.append("")
    lines.append("Return JSON with keys:")
    lines.append("- primary_hypothesis")
    lines.append("- alternative_hypotheses")
    lines.append("- selected_family")
    lines.append("- primary_focus_registers")
    lines.append("- touched_trigger_addrs")
    lines.append("- likely_blocking_condition")
    lines.append("- likely_constraint")
    lines.append("- seed_hypothesis")
    lines.append("- confidence")
    lines.append("- reasoning_evidence_refs")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract-bundle", required=True, type=Path)
    ap.add_argument("--stuck-report", required=True, type=Path)
    ap.add_argument("--baseline-trace-json", type=Path, default=None)
    ap.add_argument("--manual-trace-json", type=Path, default=None)
    ap.add_argument("--baseline-seed", default=None)
    ap.add_argument("--manual-seed", default=None)
    ap.add_argument("--probe-guidance-summary", type=Path, default=None)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--out-text", type=Path, default=None)
    args = ap.parse_args()

    contract_bundle = load_bundle(args.contract_bundle)
    stuck_report = load_stuck(args.stuck_report)
    try:
        baseline_trace = load_trace_json(args.baseline_trace_json)
        manual_trace = load_trace_json(args.manual_trace_json)
        probe_guidance_summary = load_guidance_summary(args.probe_guidance_summary)
    except ValueError as e:
        raise SystemExit(str(e))

    out_bundle = build_llm_fallback_bundle(
        contract_bundle=contract_bundle,
        stuck_report=stuck_report,
        baseline_trace=baseline_trace,
        manual_trace=manual_trace,
        baseline_seed=args.baseline_seed,
        manual_seed=args.manual_seed,
        probe_guidance_summary=probe_guidance_summary,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_bundle, f, indent=2, ensure_ascii=False)

    if args.out_text is not None:
        args.out_text.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_text, "w", encoding="utf-8") as f:
            f.write(build_prompt_text(out_bundle))

    print(
        json.dumps(
            {
                "out": str(args.out),
                "out_text": str(args.out_text) if args.out_text is not None else None,
                "top_dynamic_candidates": out_bundle.get("top_dynamic_candidates", [])[:5],
                "likely_blocking_offsets": out_bundle.get("likely_blocking_offsets", []),
                "matched_register_doc_count": len(out_bundle.get("matched_register_docs", [])),
                "still_ambiguous": out_bundle.get("still_ambiguous"),
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
