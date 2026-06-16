#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path


def load_json(p):
    return json.loads(Path(p).read_text(encoding="utf-8", errors="ignore"))


def save_json(p, obj):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def safe_name(s):
    return re.sub(r"[^A-Za-z0-9_.=-]+", "_", str(s)).strip("_") or "stack"


def make_stack(prefix_paths, candidate_path, out_dir):
    docs = [load_json(p) for p in prefix_paths] + [load_json(candidate_path)]

    actions = []
    sources = []

    for doc in docs:
        plan_name = doc.get("plan_name", Path(str(doc)).stem)
        sources.append({
            "plan_name": doc.get("plan_name"),
            "rationale": doc.get("rationale"),
            "metadata": doc.get("metadata", {}),
        })

        for a in doc.get("actions", []):
            b = dict(a)
            old_id = b.get("id") or "action"
            b["id"] = safe_name(f"{plan_name}__{old_id}")
            b["activate_stage"] = safe_name(f"{plan_name}__{b.get('activate_stage', old_id)}")
            actions.append(b)

    cid_parts = [Path(p).stem.replace(".guidance", "") for p in prefix_paths]
    cid_parts.append(Path(candidate_path).stem.replace(".guidance", ""))
    candidate_id = safe_name("__STACK__".join(cid_parts))

    stacked = {
        "schema": "mf_runtime_strategy_v1",
        "plan_name": candidate_id,
        "rationale": "Stacked chain guidance: keep earlier solved MMIO guidance active while validating the current chain node.",
        "actions": actions,
        "metadata": {
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "build_guidance_stack.py",
            "stack_depth": len(docs),
            "source_guidance_files": [str(Path(p).resolve()) for p in prefix_paths] + [str(Path(candidate_path).resolve())],
            "source_docs": sources,
            "return_to_random_after_success": True,
        },
    }

    out_path = out_dir / f"{candidate_id}.guidance.json"
    save_json(out_path, stacked)
    return candidate_id, out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--prefix-guidance", action="append", default=[])
    ap.add_argument("--candidate-guidance", action="append", default=[])
    ap.add_argument("--candidate-index", default=None)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    candidate_guidance = list(args.candidate_guidance or [])
    if args.candidate_index:
        idx = load_json(args.candidate_index)
        for item in idx.get("compiled", []):
            gp = item.get("guidance_path")
            if gp:
                candidate_guidance.append(gp)

    if not candidate_guidance:
        raise SystemExit("no candidate guidance provided; use --candidate-guidance or --candidate-index")

    compiled = []
    for cand in candidate_guidance:
        cid, path = make_stack(args.prefix_guidance, cand, out_dir)
        compiled.append({
            "candidate_id": cid,
            "guidance_path": str(path.resolve()),
        })

    save_json(out_dir / "guidance_index.json", {
        "schema": "mf_runtime_guidance_index_v1",
        "compiled": compiled,
    })

    save_json(out_dir / "stack_manifest.json", {
        "schema": "multifuzz_guidance_stack_manifest_v1",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "out_dir": str(out_dir.resolve()),
        "prefix_guidance": [str(Path(p).resolve()) for p in args.prefix_guidance],
        "candidate_guidance": [str(Path(p).resolve()) for p in candidate_guidance],
        "compiled": compiled,
    })

    print("out_dir:", out_dir)
    print("candidate_count:", len(compiled))
    for x in compiled:
        print(x["candidate_id"], x["guidance_path"])


if __name__ == "__main__":
    main()
