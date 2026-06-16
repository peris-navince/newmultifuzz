#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def extract_output_text(resp: Dict[str, Any]) -> str:
    texts = []
    for item in resp.get("output", []):
        for c in item.get("content", []):
            if c.get("type") == "output_text":
                texts.append(c.get("text", ""))
    return "\n".join(texts).strip()


def call_responses_api(payload: Dict[str, Any], api_key: str, timeout_s: int):
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            body = r.read().decode("utf-8")
            return r.status, json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw_error_body": body}


def compact_fields(fields: List[Dict[str, Any]], limit: int = 16) -> List[Dict[str, Any]]:
    out = []
    for f in fields[:limit]:
        out.append({
            "name": f.get("name"),
            "bitOffset": f.get("bitOffset"),
            "bitWidth": f.get("bitWidth"),
        })
    return out


def compact_match(m: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "addr": m.get("addr"),
        "peripheral": m.get("peripheral"),
        "register": m.get("register"),
        "addressOffset": m.get("addressOffset"),
        "fields": compact_fields(m.get("fields") or []),
        "svd_file": m.get("svd_file"),
    }


def compact_context(ctx: Dict[str, Any]) -> Dict[str, Any]:
    pe = ctx.get("planner_evidence", {})
    sig = ctx.get("bottleneck_signature", {})
    hist = ctx.get("history_summary", {})
    prior = ctx.get("prior_knowledge_extraction", {}) or {}

    primary = pe.get("primary_svd_exact_matches", [])[:10]
    ranked = pe.get("ranked_exact_register_matches", [])[:10]

    compact_prior = {}
    if isinstance(prior, dict):
        compact_prior = {
            "bottleneck_type": prior.get("bottleneck_type"),
            "confidence": prior.get("confidence"),
            "likely_blocking_conditions": (prior.get("likely_blocking_conditions") or [])[:3],
            "guidance_hypotheses": [
                {
                    "name": h.get("name"),
                    "candidate_action": h.get("candidate_action"),
                    "rationale": h.get("rationale"),
                }
                for h in (prior.get("guidance_hypotheses") or [])[:3]
                if isinstance(h, dict)
            ],
        }

    return {
        "case_id": ctx.get("case_id"),
        "evidence_level": ctx.get("evidence_level"),
        "hotspots": ctx.get("hotspots", [])[:8],
        "history": {
            "status_counts": hist.get("status_counts"),
            "rep_summaries": hist.get("rep_summaries"),
        },
        "manifest": {
            "mcu": pe.get("manifest_mcu"),
            "board": pe.get("manifest_board"),
            "svd": pe.get("manifest_svd"),
            "pdf": pe.get("manifest_pdf"),
        },
        "primary_svd_exact_matches": [compact_match(m) for m in primary],
        "ranked_exact_register_matches": [compact_match(m) for m in ranked],
        "latest_history_row": {
            "status": sig.get("latest_history_row", {}).get("status"),
            "reasons": sig.get("latest_history_row", {}).get("reasons"),
            "recent_cov_delta": sig.get("latest_history_row", {}).get("recent_cov_delta"),
            "recent_in_delta": sig.get("latest_history_row", {}).get("recent_in_delta"),
            "mmio_top_addrs": sig.get("latest_history_row", {}).get("mmio_top_addrs"),
            "mmio_total_accesses": sig.get("latest_history_row", {}).get("mmio_total_accesses"),
            "mmio_top_share": sig.get("latest_history_row", {}).get("mmio_top_share"),
            "mmio_hhi": sig.get("latest_history_row", {}).get("mmio_hhi"),
        },
        "prior_knowledge_summary": compact_prior,
        "planner_rules": {
            "produce_at_most_plans": 3,
            "prefer_manifest_svd": True,
            "prefer_exact_register_matches": True,
            "do_not_use_fallback_svd_as_primary": True,
            "guidance_is_temporary": True,
            "return_to_random_after_success": True,
            "coverage_is_primary_objective": True,
            "avoid_all_ones_when_possible": True,
            "prefer_narrow_masks_and_delayed_triggers": True,
            "prefer_status_ready_done_flag_interrupt_error_fields": True,
        },
    }


def build_prompt_base(ctx: Dict[str, Any]) -> str:
    compact = compact_context(ctx)
    return f"""
You are a planner in a firmware fuzzing closed loop.

Task:
Given a confirmed bottleneck and compact evidence, produce up to 3 generic guidance plans.
Do not write code patches. Do not assume register semantics beyond evidence. Use only the manifest-selected MCU/SVD/manual. Never import register/peripheral names from other MCU families; unmatched addresses must remain UNKNOWN_MMIO.
Prefer manifest SVD/PDF and exact SVD register matches.
If a register has fields, prefer field-aware status update plans.
If the exact field is uncertain, propose a conservative portfolio plan.
Guidance is temporary: if it resolves the bottleneck, return to random exploration.

Coverage-aware requirements:
- The primary objective is to increase or preserve coverage while reducing the measured MMIO bottleneck.
- Prefer plans that plausibly open a downstream branch, not just plans that repeatedly fire on a spin-loop register.
- Prefer runtime-observed MMIO read addresses, exact SVD register matches, and fields named/described as status, ready, done, flag, interrupt, error, completion, or transfer-complete.
- Prefer narrow single-bit or field-width masks. Preserve unrelated bits.
- Prefer on_nth_touch or after_write_then_n_reads triggers over on_first_touch when previous feedback indicates no-fire, regression, or instability.
- Avoid all-ones, permanent full-register overrides, and broad all-bit masks unless the manual/SVD evidence strongly justifies them.
- If previous feedback reports coverage/input regression, generate a less aggressive variant and explicitly explain how it avoids the regression.
- If previous feedback reports repeat-gate instability, stabilize the same evidence-supported family with lower frequency, narrower masks, and bounded one-shot behavior rather than immediately changing to an unrelated register.
- If previous feedback reports repeated no-fire, retarget to a different runtime-observed MMIO address/field/timing family; do not repeat the same zero-fire family.

Keep every string concise. The output must be valid JSON matching the schema.

Compact context:
{json.dumps(compact, indent=2, ensure_ascii=False)}
""".strip()



def chain_feedback_prompt_block(ctx: Dict[str, Any]) -> str:
    parts = []

    override = ctx.get("planner_task_override")
    if override:
        parts.append(
            "CHAIN PLANNER TASK OVERRIDE:\n"
            + json.dumps(override, indent=2, ensure_ascii=False)
        )

    feedback = ctx.get("chain_validation_feedback")
    if feedback:
        parts.append(
            "CHAIN VALIDATION FEEDBACK FROM PREVIOUS RUNS:\n"
            + json.dumps(feedback, indent=2, ensure_ascii=False)
        )

    if parts:
        parts.append(
            "MANDATORY COMBINED-REPLAN REQUIREMENT:\n"
            "- If planner_task_override.mode == combined_replan, do NOT return only the current hotspot.\n"
            "- Generate at least one plan that explicitly covers BOTH addresses/registers:\n"
            "  1) manifest-selected SVD only; unknown address -> UNKNOWN_MMIO\n"
            "  2) manifest-selected SVD only; unknown address -> UNKNOWN_MMIO\n"
            "- The plan must avoid oscillation/back-edge to the previous hotspot.\n"
            "- A successful next plan must preserve or increase input while keeping both MMIO hotspots from rebounding.\n"
            "- Prefer runtime-supported read_override_repeat or read_sequence with observed-width matching.\n"
        )

    return "\n\n".join(parts)


def build_prompt(ctx: Dict[str, Any]) -> str:
    base_prompt = build_prompt_base(ctx)
    feedback_block = chain_feedback_prompt_block(ctx)

    if feedback_block:
        return base_prompt + "\n\n" + feedback_block

    return base_prompt

def load_feedback_md_text(path: str) -> str:
    if not path:
        return ""
    try:
        p = Path(path)
        if not p.exists():
            return ""
        text = p.read_text(errors="replace").strip()
        if not text:
            return ""
        return (
            "\n\n"
            "================ CLOSED-LOOP REPAIR FEEDBACK ================\n"
            + text
            + "\n================ END CLOSED-LOOP REPAIR FEEDBACK ================\n"
        )
    except Exception as e:
        return f"\n\n[WARN] failed to load feedback-md: {e}\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--event-dir", required=True)
    ap.add_argument("--feedback-md", default="", help="optional closed-loop repair feedback markdown appended to the LLM prompt")
    ap.add_argument("--model", default="gpt-5.4")
    ap.add_argument("--timeout-s", type=int, default=240)
    ap.add_argument("--max-output-tokens", type=int, default=5000)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    feedback_md_text = load_feedback_md_text(getattr(args, "feedback_md", ""))

    event_dir = Path(args.event_dir)
    ctx_path = event_dir / "llm_context.json"
    if not ctx_path.exists():
        raise SystemExit(f"missing llm_context.json: {ctx_path}")

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is not set")

    ctx = load_json(ctx_path)

    plan_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "case_id",
            "planner_version",
            "evidence_level",
            "overall_strategy",
            "plans",
            "return_to_random_policy",
            "notes"
        ],
        "properties": {
            "case_id": {"type": "string"},
            "planner_version": {"type": "string"},
            "evidence_level": {"type": "string"},
            "overall_strategy": {"type": "string"},
            "plans": {
                "type": "array",
                "minItems": 1,
                "maxItems": 3,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "plan_id",
                        "family",
                        "priority",
                        "target_addr",
                        "target_peripheral",
                        "target_register",
                        "target_field",
                        "trigger_kind",
                        "trigger_addr",
                        "trigger_access",
                        "trigger_nth_touch",
                        "action_kind",
                        "action_operation",
                        "set_bits",
                        "clear_bits",
                        "value",
                        "mask",
                        "portfolio_enabled",
                        "portfolio_policy",
                        "short_validation",
                        "long_validation",
                        "risk",
                        "materialization_status",
                        "evidence_basis"
                    ],
                    "properties": {
                        "plan_id": {"type": "string"},
                        "family": {
                            "type": "string",
                            "enum": [
                                "field_aware_status_update",
                                "mmio_status_progression",
                                "after_write_delayed_ready",
                                "periodic_event_status_flip",
                                "interrupt_like_event",
                                "uncertain_needs_more_evidence"
                            ]
                        },
                        "priority": {"type": "integer"},
                        "target_addr": {"type": "string"},
                        "target_peripheral": {"type": ["string", "null"]},
                        "target_register": {"type": ["string", "null"]},
                        "target_field": {"type": ["string", "null"]},
                        "trigger_kind": {
                            "type": "string",
                            "enum": ["on_first_touch", "on_nth_touch", "after_write_then_n_reads", "periodic", "manual_validation_only"]
                        },
                        "trigger_addr": {"type": ["string", "null"]},
                        "trigger_access": {
                            "type": ["string", "null"],
                            "enum": ["read", "write", "readwrite", None]
                        },
                        "trigger_nth_touch": {"type": ["integer", "null"]},
                        "action_kind": {
                            "type": "string",
                            "enum": ["mmio_bit_update", "mmio_value_update", "mmio_sequence_update", "no_action_needs_more_evidence"]
                        },
                        "action_operation": {
                            "type": ["string", "null"],
                            "enum": ["set_bits", "clear_bits", "assign_masked_value", "toggle_bits", "sequence", None]
                        },
                        "set_bits": {"type": "array", "items": {"type": "integer"}},
                        "clear_bits": {"type": "array", "items": {"type": "integer"}},
                        "value": {"type": ["string", "null"]},
                        "mask": {"type": ["string", "null"]},
                        "portfolio_enabled": {"type": "boolean"},
                        "portfolio_policy": {"type": "string"},
                        "short_validation": {"type": "string"},
                        "long_validation": {"type": "string"},
                        "risk": {"type": "string"},
                        "materialization_status": {
                            "type": "string",
                            "enum": ["ready_for_materialization", "needs_field_selection", "needs_more_evidence", "manual_review_recommended"]
                        },
                        "evidence_basis": {"type": "array", "items": {"type": "string"}}
                    }
                }
            },
            "return_to_random_policy": {"type": "string"},
            "notes": {"type": "array", "items": {"type": "string"}}
        }
    }

    payload = {
        "model": args.model,
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": build_prompt(ctx) + feedback_md_text}
                ]
            }
        ],
        "max_output_tokens": args.max_output_tokens,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "multifuzz_compact_guidance_plan",
                "strict": True,
                "schema": plan_schema
            }
        }
    }

    save_json(event_dir / "guidance_plan_request.json", {
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "model": args.model,
        "context_file": str(ctx_path),
        "payload": payload,
    })

    status, resp = call_responses_api(payload, api_key, args.timeout_s)
    save_json(event_dir / "guidance_plan_response.json", {
        "http_status": status,
        "response": resp,
    })

    if status != 200 or resp.get("error"):
        print("LLM planner request failed")
        print(json.dumps(resp.get("error", resp), indent=2, ensure_ascii=False))
        raise SystemExit(1)

    if resp.get("status") == "incomplete":
        print("LLM planner response incomplete")
        print("incomplete_details:", resp.get("incomplete_details"))
        print("usage:", json.dumps(resp.get("usage", {}), indent=2, ensure_ascii=False))
        raise SystemExit(2)

    text = extract_output_text(resp)
    if not text:
        print("No output_text found")
        print(json.dumps(resp, indent=2, ensure_ascii=False)[:4000])
        raise SystemExit(1)

    try:
        plan = json.loads(text)
    except Exception:
        save_json(event_dir / "guidance_plan_unparsed.json", {"text": text})
        print("Saved unparsed model output to guidance_plan_unparsed.json")
        raise

    out = Path(args.out) if args.out else event_dir / "guidance_plan.json"
    save_json(out, {
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "model": resp.get("model"),
        "response_id": resp.get("id"),
        "usage": resp.get("usage", {}),
        "context_file": str(ctx_path),
        "plan": plan,
    })

    print("wrote", out)
    print("model:", resp.get("model"))
    print("usage:", json.dumps(resp.get("usage", {}), ensure_ascii=False))
    print("plan_count:", len(plan.get("plans", [])))
    for p in plan.get("plans", []):
        print(
            p.get("plan_id"),
            p.get("family"),
            "priority=", p.get("priority"),
            "target=", p.get("target_addr"),
            p.get("target_peripheral"),
            p.get("target_register"),
            p.get("target_field"),
            "status=", p.get("materialization_status"),
        )


if __name__ == "__main__":
    main()
