#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


HEX_RE = re.compile(r"0x[0-9a-fA-F]+")


def load_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def save_json(path: Path, obj: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def read_tail(path: Path, max_lines: int) -> Dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "exists": False, "tail": []}
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return {
        "path": str(path),
        "exists": True,
        "line_count": len(lines),
        "tail": lines[-max_lines:],
    }


def parse_int_auto(x: Any) -> Optional[int]:
    if x is None:
        return None
    s = str(x).strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except Exception:
        pass
    try:
        return int(s, 16)
    except Exception:
        return None


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def child_text(el: ET.Element, name: str) -> Optional[str]:
    for c in list(el):
        if local_name(c.tag) == name:
            return (c.text or "").strip()
    return None


def iter_desc(el: ET.Element, name: str):
    for x in el.iter():
        if local_name(x.tag) == name:
            yield x


def parse_top_addrs_from_signature(sig: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = (
        sig.get("signature_key", {}).get("latest_mmio_top_addrs")
        or sig.get("latest_history_row", {}).get("mmio_top_addrs")
        or ""
    )
    out = []
    for part in str(raw).split("|"):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            addr, count = part.split(":", 1)
            out.append({
                "addr": addr.strip(),
                "count": parse_int_auto(count.strip()),
                "raw": part,
            })
        else:
            m = HEX_RE.search(part)
            if m:
                out.append({"addr": m.group(0), "count": None, "raw": part})
    return out


def load_history(random_detector_root: Path) -> List[Dict[str, str]]:
    candidates = [
        random_detector_root / "random_bottleneck_history.csv",
    ] + list(random_detector_root.glob("*/random_bottleneck_history.csv"))

    for p in candidates:
        if p.exists():
            with p.open(newline="", encoding="utf-8", errors="ignore") as f:
                rows = list(csv.DictReader(f))
            return rows
    return []


def summarize_history(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    status = Counter(r.get("status", "") for r in rows)
    by_rep = defaultdict(list)
    for r in rows:
        by_rep[str(r.get("rep", ""))].append(r)

    last_by_rep = {}
    confirmed_like = {}
    for rep, xs in by_rep.items():
        if not xs:
            continue
        last_by_rep[rep] = xs[-1]
        confirmed_like[rep] = {
            "last_status": xs[-1].get("status"),
            "last_reasons": xs[-1].get("reasons"),
            "last_score": xs[-1].get("score"),
            "history_len": len(xs),
        }

    return {
        "row_count": len(rows),
        "status_counts": dict(status),
        "rep_count": len(by_rep),
        "last_by_rep": last_by_rep,
        "rep_summaries": confirmed_like,
    }


def find_manifest_row(manifest: Path, case_id: str) -> Dict[str, Any]:
    if not manifest.exists():
        return {}
    for line in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        cid = str(obj.get("case_id") or obj.get("target_id") or obj.get("name") or "")
        if cid == case_id:
            return obj
    return {}


def score_manual_candidate(path: Path, tokens: List[str]) -> int:
    name = path.name.lower()
    return sum(1 for t in tokens if t and t in name)


def collect_manual_candidates(repo: Path, case_id: str, manifest_row: Dict[str, Any], roots: List[Path], limit: int = 20) -> List[Dict[str, Any]]:
    raw = [case_id]
    for v in manifest_row.values():
        if isinstance(v, str):
            raw.append(v)
    tokens = []
    for s in raw:
        for t in re.split(r"[^a-zA-Z0-9]+", s.lower()):
            if len(t) >= 3 and t not in {"config", "json", "yaml", "yml", "bin", "elf", "p2im", "uemu"}:
                tokens.append(t)
    tokens = sorted(set(tokens))

    files = []
    allowed_suffixes = {".pdf", ".txt", ".md"}
    for root in roots:
        r = root if root.is_absolute() else repo / root
        if not r.exists():
            continue
        if r.is_file():
            if r.suffix.lower() in allowed_suffixes:
                files.append(r)
            continue
        for ext in ("*.pdf", "*.txt", "*.md"):
            files.extend(r.rglob(ext))

    scored = []
    for p in files:
        score = score_manual_candidate(p, tokens)
        if score > 0:
            scored.append((score, p))
    scored.sort(key=lambda x: (-x[0], str(x[1])))

    return [
        {"path": str(p), "score": score, "name": p.name}
        for score, p in scored[:limit]
    ]


def parse_svd_file(path: Path, addrs: List[int]) -> Dict[str, Any]:
    result = {
        "path": str(path),
        "device_name": None,
        "matches": [],
        "errors": [],
    }
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        result["errors"].append(f"parse_error: {e}")
        return result

    result["device_name"] = child_text(root, "name")

    for periph in iter_desc(root, "peripheral"):
        pname = child_text(periph, "name")
        base = parse_int_auto(child_text(periph, "baseAddress"))
        if base is None:
            continue

        # Collect register matches.
        for reg in iter_desc(periph, "register"):
            rname = child_text(reg, "name")
            off = parse_int_auto(child_text(reg, "addressOffset"))
            if off is None:
                continue
            abs_addr = base + off
            if abs_addr not in addrs:
                continue

            fields = []
            for fld in iter_desc(reg, "field"):
                fname = child_text(fld, "name")
                bit_offset = parse_int_auto(child_text(fld, "bitOffset"))
                bit_width = parse_int_auto(child_text(fld, "bitWidth"))
                lsb = parse_int_auto(child_text(fld, "lsb"))
                msb = parse_int_auto(child_text(fld, "msb"))
                if bit_offset is None and lsb is not None:
                    bit_offset = lsb
                if bit_width is None and lsb is not None and msb is not None:
                    bit_width = msb - lsb + 1
                fields.append({
                    "name": fname,
                    "bitOffset": bit_offset,
                    "bitWidth": bit_width,
                    "description": child_text(fld, "description"),
                })

            result["matches"].append({
                "addr": f"0x{abs_addr:X}",
                "peripheral": pname,
                "baseAddress": f"0x{base:X}",
                "register": rname,
                "addressOffset": f"0x{off:X}",
                "description": child_text(reg, "description"),
                "fields": fields[:64],
            })

        # If no exact register match, still record peripheral range candidates.
        for a in addrs:
            if base <= a < base + 0x4000:
                # Avoid huge duplicates: only if no exact match for this peripheral/address.
                exists = any(m.get("addr") == f"0x{a:X}" and m.get("peripheral") == pname for m in result["matches"])
                if not exists:
                    result["matches"].append({
                        "addr": f"0x{a:X}",
                        "peripheral": pname,
                        "baseAddress": f"0x{base:X}",
                        "register": None,
                        "addressOffset": f"0x{a - base:X}",
                        "description": "Peripheral-range candidate; no exact register match found in this SVD file.",
                        "fields": [],
                    })

    return result


def collect_svd_context(repo: Path, hotspot_addrs: List[Dict[str, Any]], roots: List[Path], max_files: int) -> Dict[str, Any]:
    addrs = []
    for h in hotspot_addrs:
        v = parse_int_auto(h.get("addr"))
        if v is not None:
            addrs.append(v)
    addrs = sorted(set(addrs))

    svd_files = []
    for root in roots:
        r = root if root.is_absolute() else repo / root
        if not r.exists():
            continue
        if r.is_file() and r.suffix.lower() in {".svd", ".xml"}:
            svd_files.append(r)
        elif r.is_dir():
            svd_files.extend(list(r.rglob("*.svd")))
            svd_files.extend(list(r.rglob("*.xml")))

    svd_files = sorted(set(svd_files), key=lambda p: str(p))[:max_files]

    all_matches = []
    parsed_files = 0
    files_with_matches = 0
    for p in svd_files:
        parsed_files += 1
        res = parse_svd_file(p, addrs)
        if res.get("matches"):
            files_with_matches += 1
            all_matches.append(res)

    exact = []
    range_only = []
    for f in all_matches:
        for m in f.get("matches", []):
            item = dict(m)
            item["svd_file"] = f["path"]
            item["device_name"] = f.get("device_name")
            if m.get("register"):
                exact.append(item)
            else:
                range_only.append(item)

    return {
        "hotspot_addrs": [h.get("addr") for h in hotspot_addrs],
        "searched_roots": [str(r) for r in roots],
        "searched_file_count": len(svd_files),
        "parsed_file_count": parsed_files,
        "files_with_matches": files_with_matches,
        "exact_register_matches": exact[:50],
        "peripheral_range_candidates": range_only[:50],
    }


def infer_evidence_level(svd_context: Dict[str, Any], manual_candidates: List[Dict[str, Any]], run_artifacts: Dict[str, Any]) -> str:
    if svd_context.get("exact_register_matches"):
        return "svd_register_mapped"
    if svd_context.get("peripheral_range_candidates"):
        return "svd_peripheral_range_mapped"
    if manual_candidates:
        return "manual_candidate_only"
    if run_artifacts.get("observer_latest", {}).get("exists"):
        return "trace_observer_hotspot_only"
    return "hotspot_only"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--manifest", default="workdir/newmulti_ab/targets_manifest.jsonl")
    ap.add_argument("--event-dir", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--svd-root", action="append", default=[
        "extractor/svd",
        "svd",
        "SVD",
    ])
    ap.add_argument("--manual-root", action="append", default=[
        "extractor/text",
        "text",
        "manuals",
    ])
    ap.add_argument("--max-log-lines", type=int, default=80)
    ap.add_argument("--max-trace-lines", type=int, default=80)
    ap.add_argument("--max-svd-files", type=int, default=300)
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = repo / manifest

    event_dir = Path(args.event_dir)
    if not event_dir.is_absolute():
        event_dir = repo / event_dir

    sig_path = event_dir / "signature.json"
    if not sig_path.exists():
        raise SystemExit(f"missing signature.json: {sig_path}")

    sig = load_json(sig_path, {})
    case_id = sig.get("case_id")
    if not case_id:
        raise SystemExit("signature.json has no case_id")

    case_root = event_dir.parent.parent
    random_detector_root = case_root / "random_detector"

    history_rows = load_history(random_detector_root)
    hist_summary = summarize_history(history_rows)
    hotspots = parse_top_addrs_from_signature(sig)

    latest = sig.get("latest_history_row") or {}
    run_root = Path(latest.get("run_root", "")) if latest.get("run_root") else None

    run_artifacts = {
        "run_root": str(run_root) if run_root else None,
        "run_log": read_tail(run_root / "run.log", args.max_log_lines) if run_root else {"exists": False},
        "replay_trace": read_tail(run_root / "replay_trace.log", args.max_trace_lines) if run_root else {"exists": False},
        "observer_latest": load_json(run_root / "observer" / "latest_window_summary.json", {}) if run_root else {},
        "observer_latest_path": str(run_root / "observer" / "latest_window_summary.json") if run_root else None,
    }

    if isinstance(run_artifacts["observer_latest"], dict):
        run_artifacts["observer_latest"]["exists"] = bool(run_artifacts["observer_latest"])

    manifest_row = find_manifest_row(manifest, case_id)

    manifest_svd_path = manifest_row.get("svd")
    svd_roots_for_case = []
    if manifest_svd_path:
        svd_roots_for_case = [Path(manifest_svd_path)]
    else:
        svd_roots_for_case = [Path(x) for x in args.svd_root]

    svd_context = collect_svd_context(
        repo=repo,
        hotspot_addrs=hotspots,
        roots=svd_roots_for_case,
        max_files=args.max_svd_files,
    )

    manifest_pdf_path = manifest_row.get("pdf")
    manual_roots_for_case = []
    if manifest_pdf_path:
        manual_roots_for_case = [Path(manifest_pdf_path)]
    else:
        manual_roots_for_case = [Path(x) for x in args.manual_root]

    manual_candidates = collect_manual_candidates(
        repo=repo,
        case_id=case_id,
        manifest_row=manifest_row,
        roots=manual_roots_for_case,
    )

    # ------------------------------------------------------------------
    # Rank evidence for the planner.
    #
    # The full SVD/manual search is useful as fallback evidence, but the
    # planner should primarily see evidence tied to the target manifest.
    # Otherwise unrelated SVD files with overlapping address ranges can
    # pollute the context.
    # ------------------------------------------------------------------
    manifest_svd = manifest_row.get("svd")
    manifest_pdf = manifest_row.get("pdf")
    manifest_mcu = str(manifest_row.get("mcu") or "").lower()
    manifest_board = str(manifest_row.get("board") or "").lower()

    def norm_path(x):
        if not x:
            return ""
        try:
            return str(Path(x).resolve())
        except Exception:
            return str(x)

    manifest_svd_norm = norm_path(manifest_svd)
    manifest_pdf_norm = norm_path(manifest_pdf)

    hotspot_rank = {}
    for i, h in enumerate(hotspots):
        addr = str(h.get("addr") or "").upper()
        if addr:
            hotspot_rank[addr] = i

    def rank_svd_match(m):
        score = 0
        svd_file = norm_path(m.get("svd_file"))
        svd_file_l = svd_file.lower()
        addr = str(m.get("addr") or "").upper()

        if manifest_svd_norm and svd_file == manifest_svd_norm:
            score += 10000
        if manifest_mcu and manifest_mcu in svd_file_l:
            score += 1000
        if manifest_board and manifest_board in svd_file_l:
            score += 500
        if m.get("register"):
            score += 200
        if addr in hotspot_rank:
            score += max(0, 100 - hotspot_rank[addr])
        if m.get("fields"):
            score += 50
        return score

    def rank_manual_candidate(m):
        score = int(m.get("score") or 0)
        path = norm_path(m.get("path"))
        path_l = path.lower()

        if manifest_pdf_norm and path == manifest_pdf_norm:
            score += 10000
        if manifest_mcu and manifest_mcu in path_l:
            score += 1000
        if manifest_board and manifest_board in path_l:
            score += 500
        return score

    exact_matches = list(svd_context.get("exact_register_matches", []))
    range_matches = list(svd_context.get("peripheral_range_candidates", []))

    ranked_exact = sorted(exact_matches, key=lambda m: (-rank_svd_match(m), str(m.get("svd_file")), str(m.get("addr"))))
    ranked_range = sorted(range_matches, key=lambda m: (-rank_svd_match(m), str(m.get("svd_file")), str(m.get("addr"))))
    ranked_manuals = sorted(manual_candidates, key=lambda m: (-rank_manual_candidate(m), str(m.get("path"))))

    planner_evidence = {
        "manifest_svd": manifest_svd,
        "manifest_pdf": manifest_pdf,
        "manifest_mcu": manifest_row.get("mcu"),
        "manifest_board": manifest_row.get("board"),
        "primary_svd_exact_matches": [
            m for m in ranked_exact
            if manifest_svd_norm and norm_path(m.get("svd_file")) == manifest_svd_norm
        ][:32],
        "primary_svd_range_candidates": [
            m for m in ranked_range
            if manifest_svd_norm and norm_path(m.get("svd_file")) == manifest_svd_norm
        ][:16],
        "ranked_exact_register_matches": ranked_exact[:32],
        "ranked_range_candidates": ranked_range[:16],
        "primary_manual": ranked_manuals[0] if ranked_manuals else None,
        "ranked_manual_candidates": ranked_manuals[:10],
        "evidence_policy": {
            "planner_should_prefer_manifest_svd": True,
            "planner_should_prefer_exact_register_matches": True,
            "range_candidates_are_fallback_only": True,
            "manual_candidates_are_ranked_by_manifest_and_name": True,
        },
    }

    # Keep raw search results for debugging, but also expose ranked evidence.
    svd_context["ranked_exact_register_matches"] = ranked_exact[:50]
    svd_context["ranked_range_candidates"] = ranked_range[:50]
    manual_candidates = ranked_manuals

    knowledge_path = event_dir / "knowledge_extraction.json"
    knowledge = load_json(knowledge_path, {}) if knowledge_path.exists() else {}

    context = {
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "schema": "multifuzz_bottleneck_context_v1",
        "case_id": case_id,
        "event_dir": str(event_dir),
        "source_files": {
            "signature": str(sig_path),
            "knowledge_extraction": str(knowledge_path) if knowledge_path.exists() else None,
            "manifest": str(manifest),
            "random_detector_root": str(random_detector_root),
        },
        "evidence_level": infer_evidence_level(svd_context, manual_candidates, run_artifacts),
        "bottleneck_signature": sig,
        "hotspots": hotspots,
        "history_summary": hist_summary,
        "run_artifacts": run_artifacts,
        "manifest_metadata": manifest_row,
        "svd_context": svd_context,
        "manual_candidates": manual_candidates,
        "planner_evidence": planner_evidence,
        "prior_knowledge_extraction": knowledge.get("extraction", knowledge),
        "planner_requirements": {
            "must_not_assume_register_semantics_without_evidence": True,
            "must_produce_generic_plan_not_target_specific_patch": True,
            "allowed_plan_families": [
                "mmio_status_progression",
                "field_aware_status_update",
                "after_write_delayed_ready",
                "periodic_event_status_flip",
                "interrupt_like_event",
                "crash_hang_escape",
                "uncertain_needs_more_evidence",
            ],
            "next_output_expected": "guidance_plan.json",
        },
    }

    out = Path(args.out) if args.out else event_dir / "llm_context.json"
    if not out.is_absolute():
        out = repo / out
    save_json(out, context)

    print("wrote", out)
    print("case_id:", case_id)
    print("evidence_level:", context["evidence_level"])
    print("hotspots:", ", ".join(h["addr"] for h in hotspots[:8]))
    print("svd_exact_matches:", len(svd_context.get("exact_register_matches", [])))
    print("svd_range_candidates:", len(svd_context.get("peripheral_range_candidates", [])))
    print("manual_candidates:", len(manual_candidates))


if __name__ == "__main__":
    main()
