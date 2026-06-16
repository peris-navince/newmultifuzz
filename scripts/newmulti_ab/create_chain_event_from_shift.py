#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path


def load_json(p):
    return json.loads(Path(p).read_text(encoding="utf-8", errors="ignore"))


def save_json(p, obj):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def norm_addr(x):
    if not x:
        return ""
    try:
        return f"0x{int(str(x), 0):X}"
    except Exception:
        return str(x)


def pick_next(rows, prefer="shift_or_reduced"):
    """
    Pick the next MMIO node from shift analysis.

    Generic policy:
    - Prefer candidates that actually consumed guidance.
    - Prefer current-target reduction.
    - Prefer an emergent next MMIO hotspot.
    - Strongly penalize coverage/input regression.
    - Avoid selecting a visually clear shift if it came from a degraded path.
    """
    candidates = []

    control = None
    for r in rows:
        if r.get("candidate_id") == "control":
            control = r
            break

    control_cov = int((control or {}).get("last_cov") or 0)
    control_in = int((control or {}).get("last_in") or 0)

    for r in rows:
        cid = r.get("candidate_id", "")
        if cid == "control":
            continue

        cls = r.get("shift_classification", "")
        next_addr = norm_addr(r.get("next_non_target_addr", ""))
        if not next_addr:
            continue

        fire = int(r.get("fire_lines") or 0)

        # A candidate that never fired is not valid evidence for selecting
        # the next chain node. Hotspot deltas from zero-fire runs are likely
        # random replay variation and must not become a Depth2 prefix.
        if fire <= 0 or cls == "no_guidance_consumption":
            continue

        target_delta = int(r.get("target_delta_vs_control") or 0)
        next_count = int(r.get("next_non_target_count") or 0)
        cov = int(r.get("last_cov") or 0)
        inp = int(r.get("last_in") or 0)

        cov_delta = cov - control_cov
        in_delta = inp - control_in

        score = 0

        # Must have runtime consumption to be a serious next-node source.
        if fire > 0:
            score += 200
        else:
            score -= 500

        # Classification evidence.
        if cls == "shifted_to_new_mmio_bottleneck":
            score += 700
        elif cls == "target_reduced_no_clear_next_bottleneck":
            score += 500
        elif cls == "guidance_consumed_no_clear_shift":
            score += 250
        elif cls == "same_bottleneck_still_dominant":
            score -= 200

        # Current target reduction.
        if target_delta < 0:
            score += min(400, -target_delta)
        else:
            score -= min(400, target_delta)

        # Next hotspot strength.
        score += min(250, next_count // 4)

        # Path-quality terms. This is the important fix:
        # a "shift" that reduces coverage/input should not dominate selection.
        if cov_delta > 0:
            score += 1000 * cov_delta
        elif cov_delta < 0:
            score -= 1200 * abs(cov_delta)

        if in_delta > 0:
            score += 150 * in_delta
        elif in_delta < 0:
            score -= 250 * abs(in_delta)

        # Strong penalty for severe input collapse.
        if inp <= max(0, control_in - 2):
            score -= 500

        candidates.append({
            "score": score,
            "candidate_id": cid,
            "shift_classification": cls,
            "next_addr": next_addr,
            "next_count": next_count,
            "target_delta": target_delta,
            "fire_lines": fire,
            "last_cov": cov,
            "last_in": inp,
            "control_cov": control_cov,
            "control_in": control_in,
            "cov_delta": cov_delta,
            "in_delta": in_delta,
            "row": r,
        })

    candidates.sort(key=lambda x: (-x["score"], -x["last_cov"], -x["last_in"], -x["next_count"], x["next_addr"]))
    return candidates[0] if candidates else None, candidates


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-event-dir", required=True)
    ap.add_argument("--shift-csv", required=True)
    ap.add_argument("--out-event-dir", required=True)
    ap.add_argument("--chain-depth", type=int, default=2)
    ap.add_argument("--force-next-addr", default=None)
    args = ap.parse_args()

    source_event = Path(args.source_event_dir)
    shift_csv = Path(args.shift_csv)
    out_event = Path(args.out_event_dir)

    source_sig = load_json(source_event / "signature.json")
    rows = list(csv.DictReader(shift_csv.open()))

    picked, ranked = pick_next(rows)
    if args.force_next_addr:
        next_addr = norm_addr(args.force_next_addr)
        picked = {
            "score": 999999,
            "candidate_id": "forced",
            "shift_classification": "forced_next_addr",
            "next_addr": next_addr,
            "next_count": 0,
            "target_delta": 0,
            "fire_lines": 0,
            "last_cov": 0,
            "last_in": 0,
        }
    elif picked:
        next_addr = picked["next_addr"]
    else:
        raise SystemExit("no next addr candidate found")

    sig = dict(source_sig)
    sig["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    sig["source"] = "chain_event_from_shift"
    sig["chain_depth"] = args.chain_depth
    sig["parent_event_dir"] = str(source_event)
    sig["chain_focus_addr"] = next_addr
    sig["chain_selection"] = picked
    sig["ranked_next_candidates"] = ranked[:20]

    latest = dict(sig.get("latest_history_row") or {})
    latest["mmio_top_addrs"] = f"{next_addr}:{picked.get('next_count', 0)}"
    latest["status"] = "mmio_chain_bottleneck"
    latest["decision"] = "chain_continue_next_mmio"
    latest["reasons"] = (
        "previous_hotspot_reduced_or_shifted+next_mmio_hotspot_candidate"
    )
    sig["latest_history_row"] = latest

    sk = dict(sig.get("signature_key") or {})
    sk["latest_mmio_top_addrs"] = f"{next_addr}:{picked.get('next_count', 0)}"
    sig["signature_key"] = sk

    out_event.mkdir(parents=True, exist_ok=True)
    save_json(out_event / "signature.json", sig)
    save_json(out_event / "chain_selection.json", {
        "selected": picked,
        "ranked_next_candidates": ranked[:20],
        "source_event_dir": str(source_event),
        "shift_csv": str(shift_csv),
    })

    print("wrote", out_event / "signature.json")
    print("selected_next_addr:", next_addr)
    print("selected_from:", picked)


if __name__ == "__main__":
    main()
