#!/usr/bin/env python3
"""
Apply a narrow repair to extractor/closed_loop.py:
- keep runtime width matching strict;
- repair impossible on_first_touch(read) triggers when the action width appears only on a later read touch;
- add repair before guidance is saved in dynamic-hotspot and LLM guidance synthesis paths.

Usage:
  python3 apply_touchwidth_repair.py /home/wgh/Multifuzz
"""
from __future__ import annotations

import argparse
import datetime as _dt
from pathlib import Path

HELPER = r'''def _iter_trace_events_from_bundle(bundle_or_profile: Optional[Any]) -> List[Dict[str, Any]]:
    """Best-effort ordered MMIO event extraction from a fallback/evidence bundle."""
    if not isinstance(bundle_or_profile, dict):
        return []

    candidates: List[Any] = []

    def walk(obj: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(obj, dict):
            for key in ("events", "trace", "mmio_events", "records", "entries"):
                val = obj.get(key)
                if isinstance(val, list):
                    candidates.append(val)
            for key in ("source_trace", "trace_json", "replay_trace", "replay_trace_json"):
                val = obj.get(key)
                if isinstance(val, str) and val.endswith(".json"):
                    try:
                        ref = load_json(_abs(val))
                        walk(ref, depth + 1)
                    except Exception:
                        pass
            for val in obj.values():
                walk(val, depth + 1)
        elif isinstance(obj, list):
            if obj and all(isinstance(x, dict) for x in obj[: min(5, len(obj))]):
                candidates.append(obj)
            for val in obj[:64]:
                walk(val, depth + 1)

    walk(bundle_or_profile)

    out: List[Dict[str, Any]] = []
    seen = set()
    for cand in candidates:
        if not isinstance(cand, list):
            continue
        for e in cand:
            if not isinstance(e, dict):
                continue
            addr = _normalize_hex(e.get("mmio_addr") or e.get("addr") or e.get("address"))
            if not addr:
                continue
            event_type = str(e.get("event_type") or e.get("access") or e.get("kind") or e.get("op") or "").lower()
            size = e.get("mmio_size", e.get("size", e.get("width")))
            try:
                size_i = int(size) if size is not None else None
            except Exception:
                size_i = None
            item = {
                "addr": addr,
                "event_type": event_type,
                "size": size_i,
                "step": e.get("step"),
            }
            ident = (item["addr"], item["event_type"], item["size"], item["step"])
            if ident in seen:
                continue
            seen.add(ident)
            out.append(item)

    def sort_key(e: Dict[str, Any]) -> int:
        try:
            return int(e.get("step"))
        except Exception:
            return 10**12

    out.sort(key=sort_key)
    return out


def _read_touch_index_for_width(bundle_or_profile: Optional[Any], addr: Optional[str], width: int) -> Optional[int]:
    """Return 1-based read touch index for the first read of addr whose size equals width."""
    norm = _normalize_hex(addr)
    if not norm:
        return None
    try:
        width_i = int(width)
    except Exception:
        return None

    touch_index = 0
    for e in _iter_trace_events_from_bundle(bundle_or_profile):
        if e.get("addr") != norm:
            continue
        event_type = str(e.get("event_type") or "").lower()
        if "read" not in event_type:
            continue
        touch_index += 1
        if e.get("size") == width_i:
            return touch_index
    return None


def _read_trigger_for_action_width(bundle_or_profile: Optional[Any], addr: str, width: int) -> Dict[str, Any]:
    """Use on_nth_touch when the first read has a different width from the action width."""
    n = _read_touch_index_for_width(bundle_or_profile, addr, width)
    if n and n > 1:
        return {"kind": "on_nth_touch", "addr": addr, "n": int(n), "access": "read"}
    return {"kind": "on_first_touch", "addr": addr, "access": "read"}


def _repair_first_touch_width_triggers(guidance: Dict[str, Any], bundle_or_profile: Optional[Any]) -> Dict[str, Any]:
    """Repair impossible on_first_touch(read) triggers when action width appears only on a later touch."""
    if not isinstance(guidance, dict):
        return guidance
    repaired = dict(guidance)
    actions = []
    repairs = []
    for action in list(guidance.get("actions") or []):
        act = dict(action)
        trigger = dict(act.get("trigger") or {})
        kind = str(trigger.get("kind") or "")
        access = str(trigger.get("access") or "read").lower()
        if kind == "on_first_touch" and access == "read":
            addr = _normalize_hex(trigger.get("addr") or act.get("addr"))
            width = act.get("width")
            try:
                width_i = int(width)
            except Exception:
                width_i = None
            if addr and width_i:
                fixed = _read_trigger_for_action_width(bundle_or_profile, addr, width_i)
                if fixed.get("kind") == "on_nth_touch":
                    old = dict(trigger)
                    trigger.update(fixed)
                    act["trigger"] = trigger
                    repairs.append({
                        "action_id": act.get("id"),
                        "addr": addr,
                        "width": width_i,
                        "old_trigger": old,
                        "new_trigger": dict(trigger),
                    })
        actions.append(act)
    repaired["actions"] = actions
    if repairs:
        repaired["first_touch_width_repairs"] = repairs
    return repaired


'''

ANCHOR = '''def _merge_touch_maps(*maps: Dict[str, int]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for mp in maps:
        for k, v in (mp or {}).items():
            out[k] = out.get(k, 0) + int(v or 0)
    return out


'''

PATCHES = [
    (
        "dynamic-hotspot guidance repair",
        '''    guidance = {
        'schema': 'mf_runtime_strategy_v1',
        'plan_name': plan_name,
        'rationale': '; '.join(rationale_bits) or 'Dynamic-hotspot fallback guidance.',
        'source_kind': 'dynamic_hotspot_fallback',
        'source_bundle': _abs(fallback_bundle_json_path),
        'preflight_dedupe': dedupe_meta,
        'actions': actions,
    }
    save_json(out_path, guidance)
    return guidance
''',
        '''    guidance = {
        'schema': 'mf_runtime_strategy_v1',
        'plan_name': plan_name,
        'rationale': '; '.join(rationale_bits) or 'Dynamic-hotspot fallback guidance.',
        'source_kind': 'dynamic_hotspot_fallback',
        'source_bundle': _abs(fallback_bundle_json_path),
        'preflight_dedupe': dedupe_meta,
        'actions': actions,
    }
    guidance = _repair_first_touch_width_triggers(guidance, fallback_bundle)
    save_json(out_path, guidance)
    return guidance
''',
    ),
    (
        "LLM guidance repair",
        '''    guidance = {
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
''',
        '''    guidance = {
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
    guidance = _repair_first_touch_width_triggers(guidance, fallback_bundle)
    save_json(out_path, guidance)
    return guidance
''',
    ),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", nargs="?", default=".", help="Path to Multifuzz repo root")
    ap.add_argument("--no-backup", action="store_true")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    target = repo / "extractor" / "closed_loop.py"
    if not target.exists():
        raise SystemExit(f"missing target file: {target}")

    s = target.read_text()
    original = s
    changes = []

    if "def _repair_first_touch_width_triggers(" in s:
        changes.append("helper already present")
    else:
        if ANCHOR not in s:
            raise SystemExit("anchor for helper insertion not found: def _merge_touch_maps")
        s = s.replace(ANCHOR, HELPER + ANCHOR, 1)
        changes.append("inserted helper functions")

    for name, old, new in PATCHES:
        if new in s:
            changes.append(f"{name}: already patched")
        elif old in s:
            s = s.replace(old, new, 1)
            changes.append(f"{name}: patched")
        else:
            changes.append(f"{name}: pattern not found; inspect manually")

    if s != original:
        if not args.no_backup:
            ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = target.with_suffix(target.suffix + f".bak_touchwidth_{ts}")
            backup.write_text(original)
            print(f"backup: {backup}")
        target.write_text(s)
        print(f"updated: {target}")
    else:
        print("no file changes needed")

    for c in changes:
        print("-", c)

    # Lightweight post-patch sanity warnings.
    current = target.read_text()
    if "save_json(out_path, guidance)" in current:
        count = current.count("save_json(out_path, guidance)")
        print(f"note: save_json(out_path, guidance) occurrences = {count}")
        if current.count("_repair_first_touch_width_triggers(guidance, fallback_bundle)") < 2:
            print("warning: fewer than two guidance repair call sites found")


if __name__ == "__main__":
    main()
