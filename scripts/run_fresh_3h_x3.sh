#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
JOBS="${JOBS:-4}"
LLM_MODE="${LLM_MODE:-off}"
LLM_MODEL="${LLM_MODEL:-${OPENAI_MODEL:-}}"
python3 scripts/newmulti_ab/build_newmulti_manifest.py \
  --repo . \
  --out workdir/newmulti_ab/manifest.jsonl \
  --csv-out workdir/newmulti_ab/manifest.csv
cmd=(
  python3 scripts/newmulti_ab/run_newmulti_ab.py
  --repo .
  --manifest workdir/newmulti_ab/manifest.jsonl
  --out-root workdir/newmulti_ab/fresh_3h_x3
  --mode both
  --jobs "$JOBS"
  --repeats 3
  --baseline-run-for 3h
  --guided-warmup-run-for 30m
  --warmup-restarts 1
  --probe-run-for 60s
  --followup-run-for 5m
  --portfolio-run-for 2m
  --candidate-run-for 2m
  --rounds 2
  --beam-width 2
  --max-llm-cycles 1
  --llm-mode "$LLM_MODE"
  --build
)
if [[ -n "$LLM_MODEL" ]]; then
  cmd+=(--llm-model "$LLM_MODEL")
fi
"${cmd[@]}"
python3 scripts/newmulti_ab/summarize_newmulti_ab.py \
  --out-root workdir/newmulti_ab/fresh_3h_x3
