#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-$PWD}"
cd "$REPO"

source extractor/.venv/bin/activate || true

python3 -m py_compile extractor/closed_loop.py
cargo build -p hail-fuzz

python3 - <<'PY'
import json
from pathlib import Path
src = Path("workdir/newmulti_ab/targets_manifest.jsonl")
dst = Path("workdir/newmulti_ab/targets_manifest_probe1_uemu_usb.jsonl")
wanted = {"uEmu__utasker_USB"}
rows = []
for line in src.read_text().splitlines():
    if not line.strip():
        continue
    obj = json.loads(line)
    cid = obj.get("case_id") or obj.get("target_id")
    if cid in wanted:
        rows.append(obj)
assert len(rows) == 1, f"expected 1 row, got {len(rows)}"
dst.write_text("".join(json.dumps(r) + "\n" for r in rows))
print("wrote", dst)
PY

OUT=workdir/newmulti_ab/probe_after_touchwidth_uemu_usb
rm -rf "$OUT"

python3 scripts/newmulti_ab/run_newmulti_ab.py \
  --repo . \
  --manifest workdir/newmulti_ab/targets_manifest_probe1_uemu_usb.jsonl \
  --out-root "$OUT" \
  --mode both \
  --jobs 1 \
  --repeats 1 \
  --baseline-run-for 60s \
  --guided-warmup-run-for 20s \
  --probe-run-for 10s \
  --followup-run-for 10s \
  --portfolio-run-for 10s \
  --candidate-run-for 10s \
  --rounds 1 \
  --beam-width 1 \
  --portfolio-max-candidates 1 \
  --max-candidates 1 \
  --llm-mode off \
  --runtime-switch \
  --runtime-switch-window 10s \
  --runtime-switch-min-windows 2 \
  --runtime-switch-plateau-windows 1

python3 scripts/newmulti_ab/summarize_newmulti_ab.py \
  --out-root "$OUT" \
  --csv-out "$OUT/ab_summary.csv" \
  --paired-csv-out "$OUT/ab_paired_summary.csv" \
  --json-out "$OUT/ab_summary.json"

python3 - <<'PY'
import csv
from pathlib import Path
p = Path("workdir/newmulti_ab/probe_after_touchwidth_uemu_usb/all_targets_summary.csv")
rows = list(csv.DictReader(p.open()))
for r in rows:
    print("case:", r["case_id"])
    print("classification:", r["classification"])
    print("coverage_delta:", r["coverage_delta"])
    print("compiled_guidance_count:", r.get("compiled_guidance_count"))
    print("runtime_fire_count:", r.get("runtime_fire_count"))
    print("switch_observer_summary_present:", r.get("switch_observer_summary_present"))
PY

echo "--- generated guidance preview ---"
find "$OUT/uEmu__utasker_USB/rep_01/guided_knowledge" -name "*.guidance.json" -print -exec python3 -m json.tool {} \; | head -160 || true

echo "--- runtime fire log ---"
grep -Rni "\[strategy-runtime\]\|loaded guidance\|fire " \
  "$OUT"/uEmu__utasker_USB/rep_01/guided_knowledge/round_1/parent_0_seed/candidates/*/run.log || true
