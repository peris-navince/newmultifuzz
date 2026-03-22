from __future__ import annotations

import argparse
import os
import re
from typing import Any, Dict, List, Optional

from debug_trace import info, load_json, save_json
from strategy_catalog import llm_visible_schema


_COV_RE = re.compile(r"\bcov=\s*(\d+)")
_HANG_RE = re.compile(r"\bhang=\s*(\d+)")
_CRASH_RE = re.compile(r"\bcrash=\s*(\d+)")
_IN_RE = re.compile(r"\bin=\s*(\d+)")

STATUS_NAME_RE = re.compile(r"^(S|S\d+|SR|STAT|STATUS|ISR|RIS|MIS)$")
DATA_NAME_RE = re.compile(r"^(D|DR|RDR|TDR|RXD|TXD|DATA)$")
FIFO_NAME_RE = re.compile(r".*FIFO.*")
CONTROL_NAME_RE = re.compile(r"^(C\d+|CR\d*|CCR\d*|CTRL\d*|CFG\d*|CONFIG\d*|MODE\d*)$")
GPIO_BANK_NAME_RE = re.compile(r"^(PDIR|PDDR|PDOR|PSOR|PCOR|PTOR|PCR\d*)$")
READY_FIELD_RE = re.compile(r"(RDRF|TDRE|TXEMPTY|RXNE|READY|RDY|VALID|DONE|TC)")
BUSY_FIELD_RE = re.compile(r"(BUSY|BSY|PENDING|WAIT|SYNC|LOCK)")
ENABLE_FIELD_RE = re.compile(r"(EN|ENABLE)")


def summarize_run_log(path: Optional[str]) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {"run_log": path, "status": "missing"}

    lines = open(path, "r", encoding="utf-8", errors="ignore").read().splitlines()
    summary = {"run_log": os.path.abspath(path), "status": "ok", "last_cov": None, "last_hang": None, "last_crash": None, "last_in": None}
    for ln in lines:
        m = _COV_RE.search(ln)
        if m:
            summary["last_cov"] = int(m.group(1))
        m = _HANG_RE.search(ln)
        if m:
            summary["last_hang"] = int(m.group(1))
        m = _CRASH_RE.search(ln)
        if m:
            summary["last_crash"] = int(m.group(1))
        m = _IN_RE.search(ln)
        if m:
            summary["last_in"] = int(m.group(1))
    if lines:
        summary["tail"] = lines[-5:]
    return summary


def _register_role(register: str) -> str:
    reg = str(register or "").strip().upper()
    if not reg:
        return "unknown"
    if STATUS_NAME_RE.fullmatch(reg):
        return "status"
    if DATA_NAME_RE.fullmatch(reg):
        return "data"
    if FIFO_NAME_RE.fullmatch(reg):
        return "fifo_config"
    if CONTROL_NAME_RE.fullmatch(reg):
        return "control"
    if GPIO_BANK_NAME_RE.fullmatch(reg):
        return "config"
    return "unknown"


def _field_candidates(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    resolved = item.get("svd_resolution") or {}
    out: List[Dict[str, Any]] = []
    for fld in resolved.get("fields", []) or []:
        name = str(fld.get("name") or "").strip().upper()
        bo = fld.get("bitOffset")
        bw = fld.get("bitWidth")
        if not isinstance(bo, int) or not isinstance(bw, int) or bw <= 0:
            continue
        bits = list(range(int(bo), int(bo) + int(bw)))
        score = 0.1
        tags: List[str] = []
        if READY_FIELD_RE.search(name):
            score += 0.6
            tags.append("ready_like")
        if BUSY_FIELD_RE.search(name):
            score += 0.5
            tags.append("busy_like")
        if ENABLE_FIELD_RE.search(name):
            score += 0.2
            tags.append("enable_like")
        if STATUS_NAME_RE.fullmatch(str(resolved.get("register") or "").upper()):
            score += 0.1
            tags.append("status_register")
        out.append(
            {
                "field": name,
                "bits": bits,
                "score": round(score, 3),
                "tags": tags,
            }
        )
    out.sort(key=lambda x: (x["score"], len(x["bits"])), reverse=True)
    return out


def _group_kind(anchor_role: str, has_data: bool, has_control: bool, anchor_reads: int) -> str:
    polling_like = anchor_role == "status" and anchor_reads >= 1000
    if polling_like and has_data:
        return "status_data_group"
    if polling_like and has_control:
        return "status_config_group"
    if polling_like:
        return "polling_group"
    return "config_group"


def _build_hotspot_groups(evidence_pack: Dict[str, Any]) -> List[Dict[str, Any]]:
    evidence = evidence_pack.get("evidence", []) or []
    by_instance: Dict[str, List[Dict[str, Any]]] = {}
    for item in evidence:
        resolved = item.get("svd_resolution") or {}
        instance = str(resolved.get("instance") or "").strip().upper()
        register = str(resolved.get("register") or "").strip().upper()
        if not instance or not register:
            continue
        latest = ((item.get("runtime_evidence") or {}).get("latest_window") or {})
        by_instance.setdefault(instance, []).append(
            {
                "addr": str(item.get("addr") or resolved.get("register_address_hex") or "").upper(),
                "register": register,
                "instance": instance,
                "status": item.get("status"),
                "read_count": int(latest.get("read_count") or 0),
                "executions_seen": int(latest.get("executions_seen") or 0),
                "interesting_executions_seen": int(latest.get("interesting_executions_seen") or 0),
                "width_bytes": int(resolved.get("width_bytes") or 4),
                "role": _register_role(register),
                "field_candidates": _field_candidates(item),
                "svd_resolution": resolved,
                "pdf_evidence": item.get("pdf_evidence") or {},
            }
        )

    groups: List[Dict[str, Any]] = []
    for instance, members in by_instance.items():
        members.sort(key=lambda x: (x["read_count"], x["executions_seen"]), reverse=True)
        anchor = None
        for m in members:
            if m["role"] == "status":
                anchor = m
                break
        if anchor is None:
            anchor = members[0]

        companions = [m for m in members if m is not anchor]
        has_data = any(m["role"] == "data" for m in companions)
        has_control = any(m["role"] in {"control", "fifo_config"} for m in companions)
        kind = _group_kind(anchor["role"], has_data, has_control, anchor["read_count"])

        groups.append(
            {
                "group_id": f"{instance.lower()}_{kind}",
                "instance": instance,
                "kind": kind,
                "anchor": {
                    "instance": instance,
                    "register": anchor["register"],
                    "addr": anchor["addr"],
                    "role": anchor["role"],
                    "width_bytes": anchor["width_bytes"],
                    "read_count": anchor["read_count"],
                    "executions_seen": anchor["executions_seen"],
                },
                "members": [
                    {
                        "instance": m["instance"],
                        "register": m["register"],
                        "addr": m["addr"],
                        "role": m["role"],
                        "width_bytes": m["width_bytes"],
                        "read_count": m["read_count"],
                        "executions_seen": m["executions_seen"],
                    }
                    for m in members
                ],
                "companions": [
                    {
                        "instance": m["instance"],
                        "register": m["register"],
                        "addr": m["addr"],
                        "role": m["role"],
                        "width_bytes": m["width_bytes"],
                        "read_count": m["read_count"],
                        "executions_seen": m["executions_seen"],
                    }
                    for m in companions
                ],
                "signals": {
                    "polling_like": anchor["role"] == "status" and anchor["read_count"] >= 1000,
                    "has_data_companion": has_data,
                    "has_control_companion": has_control,
                    "anchor_read_count": anchor["read_count"],
                },
                "field_candidates": anchor["field_candidates"][:8],
            }
        )

    groups.sort(key=lambda g: int((g.get("signals") or {}).get("anchor_read_count") or 0), reverse=True)
    return groups


def build_task_context(
    evidence_pack_path: str,
    run_log: Optional[str],
    out_path: str,
    board: str,
    mcu: str,
    benchmark: str,
    best_guidance: Optional[str] = None,
) -> Dict[str, Any]:
    evidence_pack = load_json(evidence_pack_path)
    best = load_json(best_guidance) if best_guidance and os.path.exists(best_guidance) else None
    run_summary = summarize_run_log(run_log)

    hotspots_summary = []
    for item in evidence_pack.get("evidence", []) or []:
        latest = ((item.get("runtime_evidence") or {}).get("latest_window") or {})
        hotspots_summary.append(
            {
                "addr": item.get("addr"),
                "status": item.get("status"),
                "read_count": latest.get("read_count"),
                "executions_seen": latest.get("executions_seen"),
                "interesting_executions_seen": latest.get("interesting_executions_seen"),
                "resolved_register": ((item.get("svd_resolution") or {}).get("register")),
                "resolved_instance": ((item.get("svd_resolution") or {}).get("instance")),
            }
        )

    hotspot_groups = _build_hotspot_groups(evidence_pack)

    out = {
        "target": {
            "board": board,
            "mcu": mcu,
            "benchmark": benchmark,
        },
        "runtime_problem": {
            "run_summary": run_summary,
            "hotspots_summary": hotspots_summary,
            "hotspot_groups": hotspot_groups,
        },
        "best_known_strategy": best,
        "evidence_pack": evidence_pack,
        "llm_visible_strategy_schema": llm_visible_schema(),
        "planner_contract": {
            "objective": "Choose a small number of feasible staged fuzz actions using hotspot-group templates rather than isolated register edits.",
            "hard_rules": [
                "Use only action types from llm_visible_strategy_schema.action_catalog.",
                "Use only trigger kinds from llm_visible_strategy_schema.trigger_catalog.",
                "Prefer hotspot_groups over isolated hotspots when proposing candidates.",
                "Use only templates allowed for the hotspot group kind.",
                "All addresses must come from evidence_pack.evidence[*].addr or hotspot_groups[*].members[*].addr.",
                "All bit-level edits must use SVD-defined fields/bits only.",
                "Planner must always emit at least one fallback candidate when any hotspot group exists.",
                "Output JSON only.",
            ],
        },
    }
    save_json(out_path, out)
    info(f"task context written: {out_path}")
    return out


def main():
    ap = argparse.ArgumentParser(description="Build task context for the LLM planner")
    ap.add_argument("--evidence-pack", required=True)
    ap.add_argument("--run-log")
    ap.add_argument("--out", required=True)
    ap.add_argument("--board", required=True)
    ap.add_argument("--mcu", required=True)
    ap.add_argument("--benchmark", required=True)
    ap.add_argument("--best-guidance")
    args = ap.parse_args()
    build_task_context(
        evidence_pack_path=args.evidence_pack,
        run_log=args.run_log,
        out_path=args.out,
        board=args.board,
        mcu=args.mcu,
        benchmark=args.benchmark,
        best_guidance=args.best_guidance,
    )


if __name__ == "__main__":
    main()
