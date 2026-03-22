from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .kg_schema import (
    GraphBuilder,
    function_node_id,
    mmio_node_id,
    peripheral_node_id,
    register_node_id,
    risk_node_id,
)
from .manual_map import ManualMMIOIndex


class LLMAnalysisError(RuntimeError):
    pass


def _json_request(url: str, payload: Dict[str, Any], api_key: str, timeout: int = 120) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise LLMAnalysisError(f"HTTP {e.code}: {body}")
    except Exception as e:
        raise LLMAnalysisError(str(e))


def _extract_text_from_chat_response(resp: Dict[str, Any]) -> str:
    if isinstance(resp.get("choices"), list) and resp["choices"]:
        msg = resp["choices"][0].get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            chunks = []
            for x in content:
                if isinstance(x, dict) and x.get("type") == "text":
                    chunks.append(str(x.get("text") or ""))
            return "\n".join(chunks).strip()
    raise LLMAnalysisError(f"unexpected chat response: {resp}")


def _find_json_blob(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        raise LLMAnalysisError(f"LLM did not return JSON: {text[:500]}")
    return json.loads(m.group(0))


def _looks_suspicious(func: Dict[str, Any]) -> bool:
    name = str(func.get("name") or "").lower()
    decomp = str(func.get("decompile") or "").lower()
    disasm = "\n".join(func.get("disassembly") or []).lower()
    text = f"{name}\n{decomp}\n{disasm}"
    cues = [
        "memcpy", "memmove", "strcpy", "strncpy", "dma", "irq", "isr", "handler",
        "timeout", "while", "for", "rx", "tx", "length", "index", "overflow", "underflow",
        "watchdog", "reset", "enable", "disable", "status", "flag", "error",
    ]
    return any(c in text for c in cues)


def pick_candidate_functions(export_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for func in export_data.get("functions") or []:
        mmio = func.get("mmio_accesses") or []
        if mmio or func.get("is_isr") or _looks_suspicious(func):
            out.append(func)
    return out


def _resolved_mmio_lines(func: Dict[str, Any], manual_index: Optional[ManualMMIOIndex]) -> List[str]:
    lines: List[str] = []
    for item in func.get("mmio_accesses") or []:
        addr_hex = str(item.get("address_hex") or "")
        kind = str(item.get("kind") or "unknown")
        resolved = ""
        if manual_index and item.get("address") is not None:
            match = manual_index.resolve(int(item["address"]))
            if match:
                resolved = f" -> {match.peripheral}.{match.register}"
        lines.append(f"- {kind} {addr_hex}{resolved} :: {item.get('instruction_text') or ''}")
    return lines


def _build_prompt(func: Dict[str, Any], manual_index: Optional[ManualMMIOIndex]) -> str:
    mmio_lines = _resolved_mmio_lines(func, manual_index)
    mmio_text = "\n".join(mmio_lines) if mmio_lines else "- none"
    decompile = str(func.get("decompile") or "")[:7000]
    disasm_excerpt = "\n".join(func.get("disassembly") or [])[:3500]
    called = ", ".join(func.get("calls") or [])
    return f"""
You are analyzing ONE embedded firmware function.
Return STRICT JSON only.

Goal:
1. Identify concrete MMIO/field/register/peripheral relations used by this function.
2. Identify potential vulnerability-oriented behavior worth guiding fuzzing toward.
3. Do not invent entities that are not grounded in the provided text.
4. Prefer explicit edges over vague commentary.

Return JSON with this schema:
{{
  "edges": [
    {{
      "relation": "checks|reads_from|writes_to|controls|enables|disables|clears|sets|triggers|calls|depends_on",
      "target_type": "mmio|register|field|peripheral|function",
      "target": "...",
      "evidence": "short quote or paraphrase"
    }}
  ],
  "findings": [
    {{
      "kind": "polling_loop|interrupt_logic|dma_setup|buffer_length|state_machine|unchecked_error|other",
      "summary": "...",
      "reason": "..."
    }}
  ]
}}

Function name: {func.get('name')}
Entry: {func.get('entry')}
Is ISR: {bool(func.get('is_isr'))}
Calls: {called}

MMIO observations:
{mmio_text}

Decompile:
{decompile}

Disassembly excerpt:
{disasm_excerpt}
""".strip()


def _chat_once(prompt: str, model: str, api_key: str, base_url: str) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": "Return strict JSON only. No markdown."},
            {"role": "user", "content": prompt},
        ],
    }
    return _json_request(url, payload, api_key=api_key)


def analyze_functions_with_llm(
    export_data: Dict[str, Any],
    graph: GraphBuilder,
    outdir: str,
    manual_index: Optional[ManualMMIOIndex],
    model: str = "gpt-5.4",
    relation_mode: str = "llm",
    max_candidates: int = 0,
) -> Dict[str, Any]:
    root = Path(outdir)
    raw_dir = root / "llm_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    if relation_mode == "llm" and not api_key:
        raise LLMAnalysisError("OPENAI_API_KEY is required for relation-mode=llm")

    candidates = pick_candidate_functions(export_data)
    if max_candidates and max_candidates > 0:
        candidates = candidates[:max_candidates]

    candidate_rows = []
    total_edges = 0
    total_findings = 0

    for idx, func in enumerate(candidates):
        func_name = str(func.get("name") or f"sub_{idx}")
        entry = str(func.get("entry") or "0x0")
        func_id = function_node_id(func_name, entry)
        candidate_rows.append({
            "name": func_name,
            "entry": entry,
            "is_isr": bool(func.get("is_isr")),
            "mmio_access_count": len(func.get("mmio_accesses") or []),
        })

        prompt = _build_prompt(func, manual_index)
        response = _chat_once(prompt, model=model, api_key=api_key, base_url=base_url)
        text = _extract_text_from_chat_response(response)
        parsed = _find_json_blob(text)

        (raw_dir / f"{idx:04d}_{func_name}.json").write_text(
            json.dumps(
                {
                    "function": {"name": func_name, "entry": entry},
                    "prompt": prompt,
                    "response": response,
                    "parsed": parsed,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        for edge in parsed.get("edges") or []:
            relation = str(edge.get("relation") or "related_to").strip()
            target_type = str(edge.get("target_type") or "").strip()
            target = str(edge.get("target") or "").strip()
            evidence = str(edge.get("evidence") or "").strip()
            if not relation or not target_type or not target:
                continue

            if target_type == "mmio":
                target_id = graph.add_node(mmio_node_id(target), "mmio", address_hex=target)
            elif target_type == "function":
                target_id = graph.add_node(f"func:{target}", "function", name=target)
            elif target_type == "peripheral":
                target_id = graph.add_node(peripheral_node_id(target), "peripheral", name=target)
            elif target_type == "register":
                # keep register target unscoped if LLM only returns raw register token
                target_id = graph.add_node(f"reg:{target.upper()}", "register", name=target)
            elif target_type == "field":
                target_id = graph.add_node(f"field:{target.upper()}", "field", name=target)
            else:
                target_id = graph.add_node(f"entity:{target_type}:{target}", target_type, name=target)

            graph.add_edge(func_id, relation, target_id, evidence=evidence, source="llm")
            total_edges += 1

        for j, finding in enumerate(parsed.get("findings") or []):
            kind = str(finding.get("kind") or "other")
            summary = str(finding.get("summary") or "").strip()
            reason = str(finding.get("reason") or "").strip()
            if not summary:
                continue
            risk_id = graph.add_node(
                risk_node_id(kind, func_name, entry, j),
                "risk",
                kind=kind,
                summary=summary,
                reason=reason,
                function=func_name,
                entry=entry,
            )
            graph.add_edge(func_id, "has_risk", risk_id, source="llm")
            graph.add_finding(
                {
                    "function": func_name,
                    "entry": entry,
                    "kind": kind,
                    "summary": summary,
                    "reason": reason,
                    "source": "llm",
                }
            )
            total_findings += 1

    with (root / "candidate_functions.jsonl").open("w", encoding="utf-8") as f:
        for row in candidate_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    return {
        "candidate_function_count": len(candidates),
        "llm_edge_count": total_edges,
        "llm_finding_count": total_findings,
        "llm_model": model,
    }
