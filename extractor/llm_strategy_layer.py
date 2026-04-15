from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from debug_trace import info, load_json, save_json, save_text, warn
from strategy_planner import normalize_llm_plan


def _ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def _read_json(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = load_json(str(p))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _walk(obj: Any):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for it in obj:
            yield from _walk(it)


def _normalize_hex(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        if s.lower().startswith("0x"):
            return f"0x{int(s, 16):08X}"
        return f"0x{int(s, 10):08X}"
    except Exception:
        return None


def _extract_primary_hotspot(task_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    runtime = task_context.get("runtime_problem") or {}
    for key in ["hotspots_summary", "hotspot_groups"]:
        items = runtime.get(key) or []
        if isinstance(items, list) and items:
            first = items[0]
            if isinstance(first, dict):
                return first
    return None


def _extract_hotspot_register_cluster(task_context: Dict[str, Any], evidence_pack: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    primary = _extract_primary_hotspot(task_context) or {}
    primary_addr = _normalize_hex(primary.get("addr") or primary.get("address_hex") or primary.get("anchor_addr"))
    primary_instance = str(primary.get("instance") or primary.get("peripheral") or "").strip()
    primary_register = str(primary.get("register") or primary.get("anchor_register") or "").strip()

    candidates: List[Dict[str, Any]] = []

    for node in _walk(task_context):
        addr = _normalize_hex(node.get("addr") or node.get("address_hex") or node.get("absolute_addr_hex") or node.get("absoluteAddress_hex"))
        reg = str(node.get("register") or node.get("register_name") or node.get("name") or "").strip()
        inst = str(node.get("instance") or node.get("peripheral") or node.get("family") or "").strip()
        if not addr or not reg:
            continue
        if primary_addr and addr == primary_addr:
            pass
        elif primary_instance and inst and inst.upper() == primary_instance.upper():
            pass
        else:
            continue
        candidates.append({
            "addr": addr,
            "register": reg,
            "instance": inst,
            "width": int(node.get("width_bytes") or node.get("width") or 1),
            "kind": node.get("kind"),
            "field_candidates": node.get("field_candidates") or [],
        })

    if evidence_pack:
        for ev in evidence_pack.get("evidence") or []:
            if not isinstance(ev, dict):
                continue
            resolved = ev.get("resolved") or {}
            addr = _normalize_hex(resolved.get("addr") or resolved.get("absolute_addr_hex") or resolved.get("absoluteAddress_hex"))
            reg = str(resolved.get("register") or resolved.get("register_name") or "").strip()
            inst = str(resolved.get("instance") or resolved.get("peripheral") or "").strip()
            if not addr or not reg:
                continue
            if primary_addr and addr == primary_addr:
                pass
            elif primary_instance and inst and inst.upper() == primary_instance.upper():
                pass
            else:
                continue
            candidates.append({
                "addr": addr,
                "register": reg,
                "instance": inst,
                "width": int(resolved.get("width_bytes") or resolved.get("width") or 1),
                "kind": "evidence_register",
                "field_candidates": [],
            })

    dedup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in candidates:
        key = (item["addr"], item["register"].upper())
        dedup.setdefault(key, item)

    ordered = sorted(dedup.values(), key=lambda x: (0 if x["addr"] == primary_addr else 1, x["register"]))
    return {
        "primary_addr": primary_addr,
        "primary_instance": primary_instance,
        "primary_register": primary_register,
        "registers": ordered[:12],
    }


def _build_prompt_payload(task_context: Dict[str, Any], evidence_pack: Optional[Dict[str, Any]], max_candidates: int) -> Dict[str, Any]:
    primary = _extract_primary_hotspot(task_context) or {}
    cluster = _extract_hotspot_register_cluster(task_context, evidence_pack)
    runtime = task_context.get("runtime_problem") or {}
    schema = {
        "top_level_key": "candidates",
        "candidate_fields": ["id", "group_id", "template_id", "rationale", "actions"],
        "supported_action_types": [
            "mmio_read_override_once",
            "mmio_read_override_repeat",
            "mmio_read_sequence",
            "mmio_bit_update",
            "mmio_write_observe",
            "mmio_write_then_read_gate",
            "uart_handshake_once",
        ],
        "supported_trigger_kinds": [
            "after_global_reads",
            "on_first_touch",
            "on_nth_touch",
            "after_write",
            "after_write_value",
            "when_stage_active",
        ],
        "requirements": [
            "Use only addresses from allowed_register_cluster.",
            "Prefer state-advancing strategies over pure read shaping.",
            "Return 1 to max_candidates candidates.",
            "Keep candidate IDs stable and descriptive.",
            "Do not return prose outside JSON.",
        ],
    }
    return {
        "task": "Generate generic MMIO runtime strategy candidates that can advance execution beyond the current primary hotspot.",
        "max_candidates": int(max_candidates),
        "primary_hotspot": {
            "addr": _normalize_hex(primary.get("addr") or primary.get("address_hex") or primary.get("anchor_addr")),
            "instance": primary.get("instance") or primary.get("peripheral"),
            "register": primary.get("register") or primary.get("anchor_register"),
            "kind": primary.get("kind"),
            "read_count": primary.get("read_count"),
            "width": primary.get("width") or primary.get("width_bytes"),
        },
        "allowed_register_cluster": cluster,
        "runtime_problem": {
            "hotspots_summary": runtime.get("hotspots_summary") or [],
            "hotspot_groups": runtime.get("hotspot_groups") or [],
            "best_known_strategy": task_context.get("best_known_strategy") or {},
        },
        "evidence": {
            "top_items": (evidence_pack or {}).get("evidence", [])[:6],
        },
        "output_schema": schema,
    }


def build_llm_strategy_prompt(*, task_context_path: str, evidence_pack_path: Optional[str], out_dir: str, max_candidates: int = 4) -> Dict[str, Any]:
    task_context = load_json(task_context_path)
    evidence_pack = _read_json(evidence_pack_path)
    payload = _build_prompt_payload(task_context, evidence_pack, max_candidates=max_candidates)
    _ensure_dir(out_dir)

    prompt_text = (
        "You are generating executable MMIO fuzzing strategies in strict JSON.\n"
        "Focus on the current primary hotspot and nearby same-peripheral registers.\n"
        "Prefer strategies that can advance state, such as status/data pairing, enable-then-ready gating, or write-followed-by-read effects.\n"
        "Only use allowed addresses and supported action/trigger kinds.\n"
        "Return JSON only, with top-level key 'candidates'.\n\n"
        + json.dumps(payload, indent=2, ensure_ascii=False)
    )

    save_json(str(Path(out_dir) / "llm_strategy_prompt.json"), payload)
    save_text(str(Path(out_dir) / "llm_strategy_prompt.txt"), prompt_text)
    return {"payload": payload, "prompt_text": prompt_text}


def _extract_text_from_response(obj: Dict[str, Any]) -> str:
    if isinstance(obj.get("output_text"), str) and obj.get("output_text").strip():
        return obj["output_text"]
    texts: List[str] = []
    for item in obj.get("output") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "message":
            for c in item.get("content") or []:
                if isinstance(c, dict):
                    if c.get("type") in {"output_text", "text"} and c.get("text"):
                        texts.append(str(c["text"]))
                    elif c.get("type") == "input_text" and c.get("text"):
                        texts.append(str(c["text"]))
    return "\n".join(t for t in texts if t)


def _extract_json_candidate(text: str) -> Dict[str, Any]:
    s = text.strip()
    if not s:
        raise ValueError("empty LLM response text")
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", s, flags=re.S)
    if fence:
        return json.loads(fence.group(1))
    try:
        return json.loads(s)
    except Exception:
        pass
    start = s.find("{")
    end = s.rfind("}")
    if start >= 0 and end > start:
        return json.loads(s[start:end+1])
    raise ValueError("could not locate JSON object in LLM response")


def _call_openai_responses_api(*, prompt_text: str, model: Optional[str], max_output_tokens: int, reasoning_effort: str) -> Dict[str, Any]:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    body: Dict[str, Any] = {
        "model": model or os.environ.get("OPENAI_MODEL") or "gpt-5.4",
        "input": prompt_text,
        "max_output_tokens": int(max_output_tokens),
    }
    eff = str(reasoning_effort or "none").strip().lower()
    if eff and eff != "none":
        body["reasoning"] = {"effort": eff}
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _merge_candidates(base_plan: Dict[str, Any], extra_plan: Dict[str, Any]) -> Dict[str, Any]:
    merged = list(base_plan.get("candidates") or [])
    seen = {str(c.get("id") or "") for c in merged if str(c.get("id") or "")}
    added = []
    for cand in extra_plan.get("candidates") or []:
        cid = str(cand.get("id") or "").strip()
        if not cid:
            continue
        if cid in seen:
            cand = dict(cand)
            cand["id"] = f"llm_{cid}"
            cid = cand["id"]
        seen.add(cid)
        merged.append(cand)
        added.append(cid)
    return {"schema": base_plan.get("schema") or "llm_strategy_choice_v1", "candidates": merged, "_llm_added_ids": added}


def augment_plan_with_llm_strategies(
    *,
    plan_path: str,
    task_context_path: str,
    evidence_pack_path: Optional[str],
    out_dir: str,
    mode: str = "prompt-only",
    model: Optional[str] = None,
    llm_json_path: Optional[str] = None,
    max_candidates: int = 4,
    max_output_tokens: int = 4000,
    max_attempts: int = 2,
    reasoning_effort: str = "none",
    strategy_version: str = "v1",
) -> Dict[str, Any]:
    _ensure_dir(out_dir)
    plan = load_json(plan_path)
    prompt_info = build_llm_strategy_prompt(
        task_context_path=task_context_path,
        evidence_pack_path=evidence_pack_path,
        out_dir=out_dir,
        max_candidates=max_candidates,
    )
    prompt_text = prompt_info["prompt_text"]

    report: Dict[str, Any] = {
        "schema": "mf_llm_strategy_layer_v1",
        "mode": mode,
        "strategy_version": strategy_version,
        "prompt_json": str(Path(out_dir) / "llm_strategy_prompt.json"),
        "prompt_text": str(Path(out_dir) / "llm_strategy_prompt.txt"),
        "raw_response_json": None,
        "raw_response_text": None,
        "normalized_json": None,
        "merge_report_json": str(Path(out_dir) / "llm_strategy_merge_report.json"),
        "added_candidate_ids": [],
        "error": None,
    }

    if mode == "prompt-only":
        save_json(str(Path(out_dir) / "llm_strategy_merge_report.json"), report)
        return report

    raw_obj: Optional[Dict[str, Any]] = None
    raw_text: str = ""

    try:
        if mode == "json-file":
            if not llm_json_path:
                raise ValueError("llm_strategy_mode=json-file requires llm_json_path")
            raw_obj = load_json(llm_json_path)
            raw_text = json.dumps(raw_obj, indent=2, ensure_ascii=False)
        elif mode == "api":
            last_err = None
            for attempt in range(1, max(1, int(max_attempts)) + 1):
                try:
                    raw_resp = _call_openai_responses_api(
                        prompt_text=prompt_text,
                        model=model,
                        max_output_tokens=max_output_tokens,
                        reasoning_effort=reasoning_effort,
                    )
                    raw_obj = raw_resp
                    raw_text = _extract_text_from_response(raw_resp)
                    break
                except Exception as e:
                    last_err = e
                    warn(f"LLM strategy attempt {attempt} failed: {e}")
            if raw_obj is None:
                raise RuntimeError(f"LLM strategy API failed after {max_attempts} attempts: {last_err}")
        else:
            raise ValueError(f"unsupported llm strategy mode: {mode}")

        save_json(str(Path(out_dir) / "llm_strategy_raw.json"), raw_obj)
        save_text(str(Path(out_dir) / "llm_strategy_raw.txt"), raw_text or json.dumps(raw_obj, indent=2, ensure_ascii=False))
        report["raw_response_json"] = str(Path(out_dir) / "llm_strategy_raw.json")
        report["raw_response_text"] = str(Path(out_dir) / "llm_strategy_raw.txt")

        parsed = raw_obj if (isinstance(raw_obj, dict) and "candidates" in raw_obj) else _extract_json_candidate(raw_text)
        save_json(str(Path(out_dir) / "llm_strategy_extracted.json"), parsed)

        normalized = normalize_llm_plan(load_json(task_context_path), str(Path(out_dir) / "llm_strategy_extracted.json"))
        save_json(str(Path(out_dir) / "llm_strategy_normalized.json"), normalized)
        report["normalized_json"] = str(Path(out_dir) / "llm_strategy_normalized.json")

        merged = _merge_candidates(plan, normalized)
        added_ids = list(merged.pop("_llm_added_ids", []))
        save_json(plan_path, merged)
        report["added_candidate_ids"] = added_ids
        report["added_candidate_count"] = len(added_ids)
        save_json(str(Path(out_dir) / "llm_strategy_merge_report.json"), report)
        info(f"LLM strategy layer added {len(added_ids)} candidates into {plan_path}")
        return report
    except Exception as e:
        report["error"] = str(e)
        save_json(str(Path(out_dir) / "llm_strategy_merge_report.json"), report)
        warn(f"LLM strategy layer failed; keeping original heuristic plan: {e}")
        return report
