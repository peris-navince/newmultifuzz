#!/usr/bin/env bash
set -euo pipefail

CASE_ID="${1:?usage: $0 <case_id> [total_hours]}"
TOTAL_HOURS="${2:-6}"

REPO="${REPO:-$HOME/Multifuzz}"
MANIFEST="${MANIFEST:-workdir/newmulti_ab/targets_manifest.jsonl}"
MODEL="${OPENAI_MODEL:-gpt-5.4}"
RESUME_STATE="${RESUME_STATE:-}"

# Runtime knobs. Override from environment for smoke tests.
RANDOM_CHUNK_RUN_FOR="${RANDOM_CHUNK_RUN_FOR:-20m}"
SHORT_RUN_FOR="${SHORT_RUN_FOR:-2m}"
LONG_RUN_FOR="${LONG_RUN_FOR:-20m}"
GATE_RUN_FOR="${GATE_RUN_FOR:-2m}"
GATE_REPEATS="${GATE_REPEATS:-2}"
GATE_TOP_K="${GATE_TOP_K:-4}"
TOP_K_REPEAT="${TOP_K_REPEAT:-1}"
MAX_CHAIN_DEPTH="${MAX_CHAIN_DEPTH:-2}"
MATERIALIZE_PRIORITY_MAX="${MATERIALIZE_PRIORITY_MAX:-3}"
MATERIALIZE_MAX_CANDIDATES="${MATERIALIZE_MAX_CANDIDATES:-40}"
SHORT_MAX_CANDIDATES="${SHORT_MAX_CANDIDATES:-40}"
STACK_SHORT_MAX_CANDIDATES="${STACK_SHORT_MAX_CANDIDATES:-40}"
MAX_EPOCHS="${MAX_EPOCHS:-999}"

cd "$REPO"

# Hard preflight before starting.
bash scripts/use_openai_gpt54_17891.sh || {
  echo "[FATAL] GPT-5.4/17891 preflight failed; abort closed-loop run."
  exit 2
}

TS="$(date +%Y%m%d_%H%M%S)"
ROOT="workdir/newmulti_ab/closed_loop_${CASE_ID}_${MODEL}_h${TOTAL_HOURS}_${TS}"
mkdir -p "$ROOT/epochs" "$ROOT/feedback" "$ROOT/state" "$ROOT/logs"

STATE="$ROOT/state/closed_loop_state.json"
HISTORY="$ROOT/decision_history.csv"

if [ -n "$RESUME_STATE" ]; then
  if [ ! -f "$RESUME_STATE" ]; then
    echo "[FATAL] RESUME_STATE does not exist: $RESUME_STATE"
    exit 3
  fi
  cp "$RESUME_STATE" "$STATE"
  echo "[RESUME_STATE] copied $RESUME_STATE -> $STATE"
fi

printf "epoch,case_id,epoch_root,script_success,core_closure_success,final_decision,failed,failure_reason,next_mode,last_action\n" > "$HISTORY"

echo "[ROOT] $ROOT"
echo "[CASE] $CASE_ID"
echo "[TOTAL_HOURS] $TOTAL_HOURS"
echo "[MODEL] $MODEL"
echo "[RANDOM_CHUNK_RUN_FOR] $RANDOM_CHUNK_RUN_FOR"
echo "[SHORT_RUN_FOR] $SHORT_RUN_FOR"
echo "[LONG_RUN_FOR] $LONG_RUN_FOR"
echo "[GATE_RUN_FOR] $GATE_RUN_FOR"
echo "[GATE_REPEATS] $GATE_REPEATS"
echo "[GATE_TOP_K] $GATE_TOP_K"
echo "[TOP_K_REPEAT] $TOP_K_REPEAT"
echo "[MAX_CHAIN_DEPTH] $MAX_CHAIN_DEPTH"
echo "[MATERIALIZE_PRIORITY_MAX] $MATERIALIZE_PRIORITY_MAX"
echo "[MATERIALIZE_MAX_CANDIDATES] $MATERIALIZE_MAX_CANDIDATES"
echo "[SHORT_MAX_CANDIDATES] $SHORT_MAX_CANDIDATES"
echo "[STACK_SHORT_MAX_CANDIDATES] $STACK_SHORT_MAX_CANDIDATES"
echo "[MAX_EPOCHS] $MAX_EPOCHS"

DEADLINE=$(( $(date +%s) + TOTAL_HOURS * 3600 ))
EPOCH=0

while [ "$(date +%s)" -lt "$DEADLINE" ] && [ "$EPOCH" -lt "$MAX_EPOCHS" ]; do
  EPOCH=$((EPOCH + 1))
  EROOT="$ROOT/epochs/epoch_${EPOCH}"
  mkdir -p "$EROOT"

  PRE_FEEDBACK="$ROOT/feedback/pre_epoch_${EPOCH}.md"
  PRE_SCHED="$ROOT/feedback/pre_epoch_${EPOCH}_scheduler.json"

  # Generate feedback from current state before this epoch.
  # Epoch 1 will produce initial "no previous feedback" content.
  python3 scripts/newmulti_ab/closed_loop_state_manager_v1.py \
    --case-id "$CASE_ID" \
    --state "$STATE" \
    --out-feedback-md "$PRE_FEEDBACK" \
    --out-scheduler-json "$PRE_SCHED" \
    --recent 3

  echo
  echo "================================================================================"
  echo "[EPOCH $EPOCH] start $(date)"
  echo "[EPOCH_ROOT] $EROOT"
  echo "[FEEDBACK] $PRE_FEEDBACK"
  echo "[SCHEDULER] $PRE_SCHED"
  echo "================================================================================"

  # Per-epoch preflight, because the reverse tunnel can disappear during long runs.
  bash scripts/use_openai_gpt54_17891.sh || {
    echo "[ERROR] preflight failed before epoch $EPOCH; stop closed-loop run."
    break
  }

  python3 scripts/newmulti_ab/run_llm_chain_closed_loop.py \
    --repo "$REPO" \
    --manifest "$MANIFEST" \
    --case-id "$CASE_ID" \
    --out-root "$EROOT" \
    --llm-model "$MODEL" \
    --feedback-md "$PRE_FEEDBACK" \
    --random-chunk-run-for "$RANDOM_CHUNK_RUN_FOR" \
    --short-run-for "$SHORT_RUN_FOR" \
    --long-run-for "$LONG_RUN_FOR" \
    --gate-run-for "$GATE_RUN_FOR" \
    --gate-repeats "$GATE_REPEATS" \
    --gate-top-k "$GATE_TOP_K" \
    --top-k-repeat "$TOP_K_REPEAT" \
    --max-chain-depth "$MAX_CHAIN_DEPTH" \
    --materialize-priority-max "$MATERIALIZE_PRIORITY_MAX" \
    --materialize-max-candidates "$MATERIALIZE_MAX_CANDIDATES" \
    --short-max-candidates "$SHORT_MAX_CANDIDATES" \
    --stack-short-max-candidates "$STACK_SHORT_MAX_CANDIDATES" \
    --mode closure-smoke \
    2>&1 | tee "$EROOT/run.log" || true

  POST_FEEDBACK="$ROOT/feedback/post_epoch_${EPOCH}.md"
  POST_SCHED="$ROOT/feedback/post_epoch_${EPOCH}_scheduler.json"

  # Ingest final_summary and update state / portfolio / scheduler.
  python3 scripts/newmulti_ab/closed_loop_state_manager_v1.py \
    --case-id "$CASE_ID" \
    --state "$STATE" \
    --epoch-root "$EROOT" \
    --epoch "$EPOCH" \
    --out-feedback-md "$POST_FEEDBACK" \
    --out-scheduler-json "$POST_SCHED" \
    --recent 3

  # Append compact history row.
  python3 - "$EPOCH" "$CASE_ID" "$EROOT" "$STATE" "$HISTORY" <<'PY'
import csv
import json
import sys
from pathlib import Path

epoch, case_id, epoch_root, state_path, history_path = sys.argv[1:]
epoch_root = Path(epoch_root)
state = json.loads(Path(state_path).read_text())
fs_path = epoch_root / "final_summary.json"

if fs_path.exists():
    fs = json.loads(fs_path.read_text())
else:
    fs = {
        "script_success": False,
        "core_closure_success": False,
        "final_decision": "missing_final_summary",
        "failed": True,
        "failure_reason": "final_summary.json missing",
    }

sched = state.get("scheduler", {})

with Path(history_path).open("a", newline="") as f:
    w = csv.writer(f)
    w.writerow([
        epoch,
        case_id,
        str(epoch_root),
        fs.get("script_success"),
        fs.get("core_closure_success"),
        fs.get("final_decision"),
        fs.get("failed"),
        fs.get("failure_reason", ""),
        sched.get("next_mode"),
        sched.get("last_action"),
    ])

print("[DECISION]", fs.get("final_decision"))
print("[NEXT_MODE]", sched.get("next_mode"))
print("[LAST_ACTION]", sched.get("last_action"))
print("[STATE]", state_path)
PY

  echo "[EPOCH $EPOCH] done $(date)"
done

echo
echo "[DONE] closed-loop root: $ROOT"
echo "[HISTORY] $HISTORY"
echo "[STATE] $STATE"
