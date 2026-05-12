#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
python3 scripts/newmulti_ab/build_newmulti_manifest.py \
  --repo . \
  --out workdir/newmulti_ab/manifest.jsonl \
  --csv-out workdir/newmulti_ab/manifest.csv
python3 scripts/newmulti_ab/run_newmulti_ab.py \
  --repo . \
  --manifest workdir/newmulti_ab/manifest.jsonl \
  --out-root workdir/newmulti_ab/smoke \
  --mode both \
  --case-filter 'P2IM/CNC' \
  --jobs 1 \
  --repeats 1 \
  --baseline-run-for 10m \
  --guided-warmup-run-for 2m \
  --probe-run-for 30s \
  --followup-run-for 60s \
  --portfolio-run-for 30s \
  --candidate-run-for 30s \
  --llm-mode off \
  --build
python3 scripts/newmulti_ab/summarize_newmulti_ab.py \
  --out-root workdir/newmulti_ab/smoke
