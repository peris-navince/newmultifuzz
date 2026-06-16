#!/usr/bin/env bash
set -uo pipefail

# Run multiple NewMultiFuzz closed-loop targets with bounded parallelism.
#
# Usage:
#   bash scripts/newmulti_ab/run_multi_target_closed_loop_parallel.sh \
#     targets.txt 12 5
#
# Args:
#   $1 target list file, one case_id per line
#   $2 total wall-clock hours per target, default: 4
#   $3 max epochs per target, default: env MAX_EPOCHS or 2
#
# Environment:
#   PARALLEL=2                 Maximum concurrent targets.
#   PREFLIGHT_RETRIES=3        Initial GPT preflight attempts.
#   PREFLIGHT_RETRY_SLEEP=10   Seconds between initial preflight attempts.
#   FAIL_ON_TARGET_ERROR=0     Set to 1 to return non-zero after all targets finish
#                              when failed/incomplete targets exist.
#
# Important behavior:
#   - A single target failure never stops the remaining target queue.
#   - roots.txt is assembled after all workers finish.
#   - run_status.tsv records every planned target.
#   - Final summary markers are printed even when some targets fail.

TARGET_LIST="${1:?usage: $0 <target_list.txt> [total_hours] [max_epochs]}"
TOTAL_HOURS="${2:-4}"
MAX_EPOCHS_LIMIT="${3:-${MAX_EPOCHS:-2}}"
PARALLEL="${PARALLEL:-2}"
REPO="${REPO:-$HOME/Multifuzz}"
MODEL="${OPENAI_MODEL:-gpt-5.4}"
PREFLIGHT_RETRIES="${PREFLIGHT_RETRIES:-3}"
PREFLIGHT_RETRY_SLEEP="${PREFLIGHT_RETRY_SLEEP:-10}"
FAIL_ON_TARGET_ERROR="${FAIL_ON_TARGET_ERROR:-0}"

is_positive_int() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

if ! is_positive_int "$PARALLEL"; then
  echo "[FATAL] PARALLEL must be a positive integer: $PARALLEL" >&2
  exit 2
fi
if ! is_positive_int "$MAX_EPOCHS_LIMIT"; then
  echo "[FATAL] max_epochs must be a positive integer: $MAX_EPOCHS_LIMIT" >&2
  exit 2
fi
if ! is_positive_int "$PREFLIGHT_RETRIES"; then
  echo "[FATAL] PREFLIGHT_RETRIES must be a positive integer: $PREFLIGHT_RETRIES" >&2
  exit 2
fi

cd "$REPO" || {
  echo "[FATAL] cannot cd to repo: $REPO" >&2
  exit 2
}
source extractor/.venv/bin/activate 2>/dev/null || true

if [[ ! -f "$TARGET_LIST" ]]; then
  echo "[FATAL] target list not found: $TARGET_LIST" >&2
  exit 2
fi

mapfile -t TARGETS < <(
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    { print $1 }
  ' "$TARGET_LIST"
)

PLANNED_COUNT="${#TARGETS[@]}"
if (( PLANNED_COUNT == 0 )); then
  echo "[FATAL] no targets found in: $TARGET_LIST" >&2
  exit 2
fi

preflight_ok=0
for ((attempt = 1; attempt <= PREFLIGHT_RETRIES; attempt++)); do
  echo "[PREFLIGHT] attempt=$attempt/$PREFLIGHT_RETRIES model=$MODEL"
  if bash scripts/use_openai_gpt54_17891.sh; then
    preflight_ok=1
    break
  fi

  if (( attempt < PREFLIGHT_RETRIES )); then
    echo "[WARN] GPT preflight failed; retrying in ${PREFLIGHT_RETRY_SLEEP}s."
    sleep "$PREFLIGHT_RETRY_SLEEP"
  fi
done

if (( preflight_ok == 0 )); then
  echo "[STOP] GPT preflight failed after $PREFLIGHT_RETRIES attempts."
  exit 1
fi

RUN_TAG=$(date +%Y%m%d_%H%M%S)
OUT_DIR="workdir/newmulti_ab/multi_target_closed_loop_${RUN_TAG}"
ROOT_LIST="$OUT_DIR/roots.txt"
STATUS_TSV="$OUT_DIR/run_status.tsv"
ROOT_FRAG_DIR="$OUT_DIR/roots.d"
STATUS_FRAG_DIR="$OUT_DIR/status.d"

mkdir -p "$OUT_DIR" "$ROOT_FRAG_DIR" "$STATUS_FRAG_DIR"
: > "$ROOT_LIST"
printf 'case_id\tstatus\trc\ttee_rc\troot\tlog\tepoch_dirs\tfinal_summaries\tscript_failed_summaries\n' > "$STATUS_TSV"
echo "$OUT_DIR" > workdir/newmulti_ab/latest_multi_target_closed_loop_root.txt

safe_case_name() {
  printf '%s' "$1" | tr '/:' '__'
}

run_one() {
  local case_id="$1"
  local safe_case
  safe_case=$(safe_case_name "$case_id")

  local log="$OUT_DIR/${safe_case}_h${TOTAL_HOURS}.log"
  local root_fragment="$ROOT_FRAG_DIR/${safe_case}.root"
  local status_fragment="$STATUS_FRAG_DIR/${safe_case}.status"
  local rc=0
  local tee_rc=0
  local root=""
  local epoch_dirs=0
  local final_summaries=0
  local script_failed_summaries=0
  local status="FAILED"
  local -a pipeline_status=()

  # Writing the fragment before starting makes started/unstarted accounting robust
  # even when the worker is interrupted unexpectedly.
  printf '%s\tSTARTED\t-\t-\t-\t%s\t0\t0\t0\n' \
    "$case_id" "$log" > "$status_fragment"

  echo
  echo "================================================================================"
  echo "[RUN] CASE=$case_id HOURS=$TOTAL_HOURS MAX_EPOCHS=$MAX_EPOCHS_LIMIT"
  echo "[LOG] $log"
  echo "================================================================================"

  (
    cd "$REPO" || exit 125
    source extractor/.venv/bin/activate 2>/dev/null || true

    MAX_EPOCHS="$MAX_EPOCHS_LIMIT" \
    RANDOM_CHUNK_RUN_FOR="${RANDOM_CHUNK_RUN_FOR:-2m}" \
    SHORT_RUN_FOR="${SHORT_RUN_FOR:-20s}" \
    LONG_RUN_FOR="${LONG_RUN_FOR:-1m}" \
    GATE_RUN_FOR="${GATE_RUN_FOR:-20s}" \
    GATE_REPEATS="${GATE_REPEATS:-1}" \
    GATE_TOP_K="${GATE_TOP_K:-2}" \
    TOP_K_REPEAT="${TOP_K_REPEAT:-1}" \
    MAX_CHAIN_DEPTH="${MAX_CHAIN_DEPTH:-2}" \
    MATERIALIZE_PRIORITY_MAX="${MATERIALIZE_PRIORITY_MAX:-2}" \
    MATERIALIZE_MAX_CANDIDATES="${MATERIALIZE_MAX_CANDIDATES:-8}" \
    SHORT_MAX_CANDIDATES="${SHORT_MAX_CANDIDATES:-8}" \
    STACK_SHORT_MAX_CANDIDATES="${STACK_SHORT_MAX_CANDIDATES:-8}" \
    bash scripts/newmulti_ab/run_single_target_closed_loop_v1.sh \
      "$case_id" "$TOTAL_HOURS"
  ) 2>&1 | tee "$log"

  pipeline_status=("${PIPESTATUS[@]}")
  rc="${pipeline_status[0]:-125}"
  tee_rc="${pipeline_status[1]:-125}"

  # Prefer the explicit [ROOT] marker. Fall back to the final closed-loop root
  # marker so that an interrupted target can still be included in roots.txt.
  root=$(awk '/^\[ROOT\][[:space:]]+/ { print $2; exit }' "$log" 2>/dev/null || true)
  if [[ -z "$root" ]]; then
    root=$(sed -n 's/^\[DONE\] closed-loop root:[[:space:]]*//p' "$log" 2>/dev/null | tail -n 1)
  fi

  if [[ -n "$root" ]]; then
    printf '%s %s %s\n' "$case_id" "$root" "$log" > "$root_fragment"

    if [[ -d "$root/epochs" ]]; then
      epoch_dirs=$(find "$root/epochs" -mindepth 1 -maxdepth 1 \
        -type d -name 'epoch_*' 2>/dev/null | wc -l)
      final_summaries=$(find "$root/epochs" -mindepth 2 -maxdepth 2 \
        -type f -name 'final_summary.json' 2>/dev/null | wc -l)
      script_failed_summaries=$(grep -l \
        '"final_decision"[[:space:]]*:[[:space:]]*"script_failed"' \
        "$root"/epochs/epoch_*/final_summary.json 2>/dev/null | wc -l)
    fi
  fi

  if (( rc != 0 || tee_rc != 0 )); then
    status="FAILED"
  elif [[ -z "$root" ]]; then
    status="FAILED_NO_ROOT"
  elif (( script_failed_summaries > 0 )); then
    status="INCOMPLETE_SCRIPT_FAILED"
  elif (( epoch_dirs > final_summaries )); then
    status="INCOMPLETE_MISSING_SUMMARY"
  else
    status="COMPLETED"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$case_id" "$status" "$rc" "$tee_rc" "${root:--}" "$log" \
    "$epoch_dirs" "$final_summaries" "$script_failed_summaries" \
    > "$status_fragment"

  if [[ "$status" == "COMPLETED" ]]; then
    echo "[DONE] $case_id ROOT=$root STATUS=$status"
  else
    echo "[TARGET_FAILED] $case_id STATUS=$status RC=$rc TEE_RC=$tee_rc ROOT=${root:--}"
  fi

  # Deliberately return success so one failed target cannot terminate the
  # scheduler. The real target result is persisted in run_status.tsv.
  return 0
}

active=0
for case_id in "${TARGETS[@]}"; do
  run_one "$case_id" &
  active=$((active + 1))

  if (( active >= PARALLEL )); then
    # Ignore an unexpected worker-shell error and continue dispatching.
    wait -n || true
    active=$((active - 1))
  fi
done

while (( active > 0 )); do
  wait -n || true
  active=$((active - 1))
done

# Assemble deterministic output files in target-list order.
: > "$ROOT_LIST"
printf 'case_id\tstatus\trc\ttee_rc\troot\tlog\tepoch_dirs\tfinal_summaries\tscript_failed_summaries\n' > "$STATUS_TSV"

for case_id in "${TARGETS[@]}"; do
  safe_case=$(safe_case_name "$case_id")
  root_fragment="$ROOT_FRAG_DIR/${safe_case}.root"
  status_fragment="$STATUS_FRAG_DIR/${safe_case}.status"

  [[ -f "$root_fragment" ]] && cat "$root_fragment" >> "$ROOT_LIST"

  if [[ -f "$status_fragment" ]]; then
    cat "$status_fragment" >> "$STATUS_TSV"
  else
    printf '%s\tUNSTARTED\t-\t-\t-\t-\t0\t0\t0\n' "$case_id" >> "$STATUS_TSV"
  fi
done

STARTED_COUNT=$(awk -F '\t' 'NR > 1 && $2 != "UNSTARTED" { n++ } END { print n+0 }' "$STATUS_TSV")
COMPLETED_COUNT=$(awk -F '\t' 'NR > 1 && $2 == "COMPLETED" { n++ } END { print n+0 }' "$STATUS_TSV")
FAILED_COUNT=$(awk -F '\t' 'NR > 1 && $2 ~ /^FAILED/ { n++ } END { print n+0 }' "$STATUS_TSV")
INCOMPLETE_COUNT=$(awk -F '\t' 'NR > 1 && $2 ~ /^INCOMPLETE/ { n++ } END { print n+0 }' "$STATUS_TSV")
UNSTARTED_COUNT=$((PLANNED_COUNT - STARTED_COUNT))
ROOT_COUNT=$(wc -l < "$ROOT_LIST")

printf '\n'
echo "[BATCH_SUMMARY] planned=$PLANNED_COUNT started=$STARTED_COUNT completed=$COMPLETED_COUNT incomplete=$INCOMPLETE_COUNT failed=$FAILED_COUNT unstarted=$UNSTARTED_COUNT roots=$ROOT_COUNT parallel=$PARALLEL hours=$TOTAL_HOURS max_epochs=$MAX_EPOCHS_LIMIT"
echo "[DONE] OUT_DIR=$OUT_DIR"
echo "[ROOT_LIST] $ROOT_LIST"
echo "[STATUS_TSV] $STATUS_TSV"
cat "$ROOT_LIST"

if [[ "$FAIL_ON_TARGET_ERROR" == "1" ]] && \
   (( FAILED_COUNT > 0 || INCOMPLETE_COUNT > 0 || UNSTARTED_COUNT > 0 )); then
  exit 2
fi

exit 0
