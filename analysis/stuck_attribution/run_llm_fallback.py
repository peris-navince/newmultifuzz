#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run the packaged LLM fallback prompt against the OpenAI Responses API.

Model name may be fixed in code by default, but can also be overridden via:
    export OPENAI_MODEL=...

API key must be provided via environment variable:
    export OPENAI_API_KEY=...

Optional:
    export OPENAI_BASE_URL=https://api.openai.com/v1
    export OPENAI_REASONING_EFFORT=none
"""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.4")
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MAX_OUTPUT_TOKENS = 6000
DEFAULT_REASONING_EFFORT = os.environ.get("OPENAI_REASONING_EFFORT", "none")
DEFAULT_MAX_ATTEMPTS = 2
MAX_RETRY_OUTPUT_TOKENS = 24000


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if path is None:
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_user_text(prompt_text: str, bundle: Optional[Dict[str, Any]]) -> str:
    parts: List[str] = []
    parts.append(prompt_text.strip())
    if bundle is not None:
        parts.append("\n\nBounded evidence bundle (JSON):\n")
        parts.append(json.dumps(bundle, ensure_ascii=False, indent=2))
    return "".join(parts).strip() + "\n"


def build_request_payload(
    *,
    model: str,
    user_text: str,
    max_output_tokens: int,
    reasoning_effort: Optional[str],
) -> Dict[str, Any]:
    developer_text = (
        "You are analyzing bounded firmware evidence. "
        "Return only valid JSON and nothing else. "
        "Do not wrap it in markdown fences. "
        "Be concise. Keep each string value short and specific. "
        "Use exactly these top-level keys: "
        "likely_blocking_condition, likely_constraint, seed_hypothesis, confidence, reasoning_evidence_refs. "
        "reasoning_evidence_refs must be a JSON array of short strings."
    )

    payload: Dict[str, Any] = {
        "model": model,
        "input": [
            {
                "role": "developer",
                "content": [{"type": "input_text", "text": developer_text}],
            },
            {
                "role": "user",
                "content": [{"type": "input_text", "text": user_text}],
            },
        ],
        "max_output_tokens": max_output_tokens,
        "temperature": 0,
        "text": {"format": {"type": "text"}},
    }
    if reasoning_effort:
        payload["reasoning"] = {"effort": reasoning_effort}
    return payload


def extract_output_text(resp: Dict[str, Any]) -> str:
    output_text = resp.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    chunks: List[str] = []
    for item in resp.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []) or []:
            if not isinstance(content, dict):
                continue
            text = content.get("text")
            ctype = content.get("type")
            if isinstance(text, str) and (ctype in ("output_text", "text") or ctype is None):
                chunks.append(text)
    return "\n".join(chunks).strip()


def _extract_json_candidate(text: str) -> Optional[str]:
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()

    # first try direct parse
    try:
        json.loads(stripped)
        return stripped
    except Exception:
        pass

    # then try first balanced {...} region
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = stripped[start:end + 1]
        try:
            json.loads(candidate)
            return candidate
        except Exception:
            return None
    return None


def try_parse_json(text: str) -> Optional[Any]:
    candidate = _extract_json_candidate(text)
    if not candidate:
        return None
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def call_responses_api(payload: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set. Export it before running this script.")

    base_url = os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    url = f"{base_url}/responses"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API request failed: HTTP {e.code}\n{detail}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"API request failed: {e}") from e


def should_retry(resp: Dict[str, Any], output_text: str, parsed: Optional[Any]) -> bool:
    if parsed is not None:
        return False
    status = str(resp.get("status") or "")
    incomplete = resp.get("incomplete_details") or {}
    reason = str(incomplete.get("reason") or "")
    if status == "incomplete" and reason == "max_output_tokens":
        return True
    if not output_text.strip():
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Run packaged LLM fallback against the OpenAI Responses API.")
    ap.add_argument("--prompt-text", required=True, type=Path)
    ap.add_argument("--bundle-json", type=Path, default=None)
    ap.add_argument("--out-json", required=True, type=Path)
    ap.add_argument("--out-text", required=True, type=Path)
    ap.add_argument("--out-raw-response", type=Path, default=None)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    ap.add_argument("--reasoning-effort", default=DEFAULT_REASONING_EFFORT)
    ap.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    args = ap.parse_args()

    prompt_text = read_text(args.prompt_text)
    bundle = read_json(args.bundle_json)
    user_text = build_user_text(prompt_text, bundle)

    attempts: List[Dict[str, Any]] = []
    current_tokens = max(1, int(args.max_output_tokens))
    raw_response: Dict[str, Any] = {}
    output_text = ""
    parsed = None

    for attempt in range(1, max(1, int(args.max_attempts)) + 1):
        payload = build_request_payload(
            model=args.model,
            user_text=user_text,
            max_output_tokens=current_tokens,
            reasoning_effort=args.reasoning_effort,
        )
        raw_response = call_responses_api(payload)
        output_text = extract_output_text(raw_response)
        parsed = try_parse_json(output_text)
        attempts.append({
            "attempt": attempt,
            "request_max_output_tokens": current_tokens,
            "response_id": raw_response.get("id"),
            "status": raw_response.get("status"),
            "incomplete_details": raw_response.get("incomplete_details"),
            "output_text_len": len(output_text),
            "parsed_json_ok": parsed is not None,
        })

        if not should_retry(raw_response, output_text, parsed):
            break
        if attempt >= int(args.max_attempts):
            break
        current_tokens = min(MAX_RETRY_OUTPUT_TOKENS, max(current_tokens * 2, current_tokens + 2000))

    args.out_text.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_text.write_text(output_text + (("\n" if output_text and not output_text.endswith("\n") else "")), encoding="utf-8")

    result = {
        "model": args.model,
        "request_reasoning_effort": args.reasoning_effort,
        "request_max_output_tokens": args.max_output_tokens,
        "final_request_max_output_tokens": current_tokens,
        "attempts": attempts,
        "response_id": raw_response.get("id"),
        "status": raw_response.get("status"),
        "incomplete_details": raw_response.get("incomplete_details"),
        "parsed_json": parsed,
        "raw_output_text": output_text,
    }
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    if args.out_raw_response is not None:
        args.out_raw_response.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_raw_response, "w", encoding="utf-8") as f:
            json.dump(raw_response, f, ensure_ascii=False, indent=2)

    print(json.dumps({
        "model": args.model,
        "response_id": raw_response.get("id"),
        "status": raw_response.get("status"),
        "incomplete_details": raw_response.get("incomplete_details"),
        "out_json": str(args.out_json),
        "out_text": str(args.out_text),
        "parsed_json_ok": parsed is not None,
        "attempts": attempts,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
