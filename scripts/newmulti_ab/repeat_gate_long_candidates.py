#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
from pathlib import Path
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--repo", default=".")
ap.add_argument("--case-root", required=True)
ap.add_argument("--stack-index", required=True)
ap.add_argument("--score-csv", required=True)
ap.add_argument("--import-dir", required=True)
ap.add_argument("--firmware-config", required=True)
ap.add_argument("--out-root", required=True)
ap.add_argument("--run-for", default="30s")
ap.add_argument("--top-k", type=int, default=4)
ap.add_argument("--repeats", type=int, default=2)
args = ap.parse_args()

repo = Path(args.repo).resolve()
case_root = Path(args.case_root)
out_root = Path(args.out_root)
out_root.mkdir(parents=True, exist_ok=True)

def load_json(p):
    try:
        return json.loads(Path(p).read_text())
    except Exception:
        return {}

def to_i(v, default=0):
    try:
        return int(v)
    except Exception:
        return default

def count_fire(log):
    p = Path(log)
    if not p.exists():
        return 0
    return p.read_text(errors="ignore").count("[strategy-runtime] fire")

def load_run_summary(p):
    d = load_json(p)
    return d.get("run_summary", d)

idx = load_json(args.stack_index)
by_id = {x.get("candidate_id"): x.get("guidance_path") for x in idx.get("compiled", [])}

rows = list(csv.DictReader(open(args.score_csv, encoding="utf-8", errors="ignore")))

PROMOTABLE_DECISIONS = {
    # New coverage-aware decisions.
    "coverage_positive_hotspot_safe",
    "coverage_positive_candidate",
    "coverage_neutral_hotspot_candidate",
    "active_nonregressing_but_unfocused",
    # Backward-compatible decisions from earlier scorers.
    "return_to_random_candidate",
    "promising_stack_repeat",
    "partial_stack_repeat",
    "old_solved_current_not_solved",
}

decision_rank = {
    "coverage_positive_hotspot_safe": 0,
    "coverage_positive_candidate": 1,
    "return_to_random_candidate": 2,
    "coverage_neutral_hotspot_candidate": 3,
    "promising_stack_repeat": 4,
    "partial_stack_repeat": 5,
    "old_solved_current_not_solved": 6,
    "active_nonregressing_but_unfocused": 7,
}

def row_score(r):
    # Prefer coverage-positive, non-regressing, lower-risk candidates.
    # risk_score is produced by score_guidance_stack.py; older CSVs default to 0.
    return (
        decision_rank.get(r.get("decision"), 99),
        -to_i(r.get("cov_delta")),
        -to_i(r.get("input_delta")),
        to_i(r.get("risk_score")),
        -to_i(r.get("fire_lines") or r.get("fire")),
        -to_i(r.get("score")),
        r.get("candidate_id", ""),
    )

cands = []
for r in sorted(rows, key=row_score):
    cid = r.get("candidate_id")
    decision = r.get("decision", "")

    # Hard filter: only candidates with evidence-based promotable decisions
    # may enter repeat gate. Zero-fire/no-consumption/not-promising rows are
    # intentionally excluded even if their numeric score is high.
    if decision not in PROMOTABLE_DECISIONS:
        continue

    if cid and cid != "control" and cid in by_id:
        cands.append(cid)
    if len(cands) >= args.top_k:
        break

print("selected candidates:")
for c in cands:
    print(" ", c)

gate_rows = []

for cid in cands:
    guidance = by_id[cid]
    for rep in range(1, args.repeats + 1):
        out = out_root / cid / f"rep_{rep}"
        out.mkdir(parents=True, exist_ok=True)

        cmd = [
            "python3", "extractor/closed_loop.py", "run-fuzz",
            "--fuzzer-manifest", "Cargo.toml",
            "--fuzzer-bin", "target/debug/hail-fuzz",
            "--firmware-config", args.firmware_config,
            "--ghidra-src", "tools/ghidra",
            "--workdir", str(out / "workdir"),
            "--run-log", str(out / "run.log"),
            "--run-for", args.run_for,
            "--observer-dir", str(out / "observer"),
            "--guidance-file", guidance,
            "--guidance-summary-out", str(out / "guidance_runtime_summary.json"),
            "--import-dir", args.import_dir,
            "--dump-trace",
            "--trace-basename", "replay_trace",
        ]

        with (out / "cmd.txt").open("w") as f:
            f.write(" ".join(cmd) + "\n")

        with (out / "stdout.log").open("w") as f:
            rc = subprocess.run(cmd, cwd=repo, stdout=f, stderr=subprocess.STDOUT).returncode

        rs = load_run_summary(out / "run_fuzz_summary.json")
        fire = count_fire(out / "run.log")

        gate_rows.append({
            "candidate_id": cid,
            "rep": rep,
            "rc": rc,
            "fire": fire,
            "cov": to_i(rs.get("last_cov")),
            "input": to_i(rs.get("last_in")),
            "hang": to_i(rs.get("last_hang")),
            "crash": to_i(rs.get("last_crash")),
            "guidance_path": guidance,
            "run_root": str(out),
        })

out_csv = out_root / "repeat_gate_summary.csv"
with out_csv.open("w", newline="", encoding="utf-8") as f:
    fields = ["candidate_id", "rep", "rc", "fire", "cov", "input", "hang", "crash", "guidance_path", "run_root"]
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(gate_rows)

agg = []
by = defaultdict(list)
for r in gate_rows:
    by[r["candidate_id"]].append(r)

promoted = []
for cid, xs in by.items():
    fire_reps = sum(1 for r in xs if to_i(r["fire"]) > 0)
    hang_reps = sum(1 for r in xs if to_i(r["hang"]) > 0)
    crash_reps = sum(1 for r in xs if to_i(r["crash"]) > 0)
    unstable_reps = hang_reps + crash_reps
    fire_total = sum(to_i(r["fire"]) for r in xs)
    pass_gate = fire_reps >= 1 and unstable_reps == 0
    src_row = next((r for r in rows if r.get("candidate_id") == cid), {})
    decision = src_row.get("decision", "")
    item = {
        "candidate_id": cid,
        "repeats": len(xs),
        "fire_reps": fire_reps,
        "unstable_reps": unstable_reps,
        "hang_reps": hang_reps,
        "crash_reps": crash_reps,
        "fire_total": fire_total,
        "min_cov": min(to_i(r["cov"]) for r in xs),
        "max_cov": max(to_i(r["cov"]) for r in xs),
        "min_input": min(to_i(r["input"]) for r in xs),
        "max_input": max(to_i(r["input"]) for r in xs),
        "pass_gate": pass_gate,
        "guidance_path": xs[0]["guidance_path"],
        "decision": decision,
        "score": src_row.get("score", ""),
        "cov_delta": src_row.get("cov_delta", ""),
        "input_delta": src_row.get("input_delta", ""),
        "risk_score": src_row.get("risk_score", ""),
    }
    agg.append(item)
    if pass_gate:
        promoted.append({
            "candidate_id": cid,
            "guidance_path": xs[0]["guidance_path"],
            "decision": decision,
            "score": src_row.get("score", ""),
            "cov_delta": src_row.get("cov_delta", ""),
            "input_delta": src_row.get("input_delta", ""),
            "risk_score": src_row.get("risk_score", ""),
            "fire_reps": fire_reps,
            "unstable_reps": unstable_reps,
            "hang_reps": hang_reps,
            "crash_reps": crash_reps,
            "fire_total": fire_total,
            "source": "repeat_gate_stack_depth2",
            "pass_gate": True,
        })

agg_csv = out_root / "repeat_gate_aggregate.csv"
with agg_csv.open("w", newline="", encoding="utf-8") as f:
    fields = ["candidate_id", "repeats", "fire_reps", "unstable_reps", "hang_reps", "crash_reps", "fire_total", "min_cov", "max_cov", "min_input", "max_input", "pass_gate", "guidance_path", "decision", "score", "cov_delta", "input_delta", "risk_score"]
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(agg)

promoted_json = out_root / "promoted_candidates.json"
promoted_json.write_text(json.dumps({
    "schema": "repeat_gate_promoted_candidates_v1",
    "promoted_count": len(promoted),
    "promoted": promoted,
}, indent=2, sort_keys=True))

stats = {
    "candidate_count": len(agg),
    "pass_gate_count": len(promoted),
    "fire_positive_count": sum(1 for r in agg if to_i(r.get("fire_total")) > 0),
    "fire_zero_count": sum(1 for r in agg if to_i(r.get("fire_total")) <= 0),
    "unstable_count": sum(1 for r in agg if to_i(r.get("unstable_reps")) > 0),
}
stats_json = out_root / "repeat_gate_stats.json"
stats_json.write_text(json.dumps(stats, indent=2, sort_keys=True))

print("wrote", out_csv)
print("wrote", agg_csv)
print("wrote", promoted_json)
print("wrote", stats_json)
print("promoted_count=", len(promoted))
print()
for r in agg:
    print(
        r["candidate_id"],
        "pass_gate=", r["pass_gate"],
        "fire_reps=", r["fire_reps"],
        "unstable_reps=", r["unstable_reps"],
        "fire_total=", r["fire_total"],
        "input=", r["min_input"], "-", r["max_input"],
    )
