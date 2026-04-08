#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/MultiFuzz"
HF_MANIFEST="$ROOT/hail-fuzz/Cargo.toml"
CFG="$ROOT/benchmarks/P2IM/Console/config.yml"
SEED_DIR="$ROOT/manual_seeds_console"
RUN_BASE="$ROOT/manual_runs_console"
SUMMARY="$RUN_BASE/summary.csv"

mkdir -p "$RUN_BASE"
echo "name,coverage_count,blocks_seen,corpus_inputs,hang_unique,crash_unique,stats_csv" > "$SUMMARY"

run_one_case() {
  local name="$1"
  local seed_path="${2:-}"
  local wd="$RUN_BASE/$name"

  rm -rf "$wd"
  mkdir -p "$wd"

  echo "======================================="
  echo "[*] CASE: $name"
  echo "======================================="

  if [[ -n "$seed_path" ]]; then
    mkdir -p "$wd/imports"
    cp "$seed_path" "$wd/imports/"
    echo "[*] importing seed: $seed_path"

    (
      cd "$ROOT"
      WORKDIR="$wd" \
      MF_IMPORT_DIR="$wd/imports" \
      RUN_FOR=10s \
      cargo run --release --manifest-path "$HF_MANIFEST" -- "$CFG" \
        > "$wd/run.log" 2>&1
    )
  else
    echo "[*] baseline run (no imported seed)"

    (
      cd "$ROOT"
      WORKDIR="$wd" \
      RUN_FOR=10s \
      cargo run --release --manifest-path "$HF_MANIFEST" -- "$CFG" \
        > "$wd/run.log" 2>&1
    )
  fi

  if grep -q "Error running fuzzer" "$wd/run.log"; then
    echo "[ERR] fuzzer failed for $name"
    tail -n 20 "$wd/run.log"
    echo "$name,ERROR,ERROR,ERROR,ERROR,ERROR,$wd/stats.csv" >> "$SUMMARY"
    return
  fi

  local cov="NA"
  local blocks="NA"
  local inputs="NA"
  local hangs="0"
  local crashes="0"

  if [[ -f "$wd/stats.csv" ]]; then
    read -r cov blocks inputs < <(
      awk -F',' 'END{print $7, $8, $9}' "$wd/stats.csv"
    )
  fi

  if [[ -d "$wd/hangs" ]]; then
    hangs=$(find "$wd/hangs" -maxdepth 1 -type f | wc -l)
  fi

  if [[ -d "$wd/crashes" ]]; then
    crashes=$(find "$wd/crashes" -maxdepth 1 -type f | wc -l)
  fi

  echo "$name,$cov,$blocks,$inputs,$hangs,$crashes,$wd/stats.csv" >> "$SUMMARY"

  echo "[*] result: cov=$cov blocks=$blocks inputs=$inputs hangs=$hangs crashes=$crashes"
  echo
}

echo "[*] building hail-fuzz"
(
  cd "$ROOT"
  cargo build --release --manifest-path "$HF_MANIFEST"
)

run_one_case "baseline_10s" ""

for seed in "$SEED_DIR"/*.bin; do
  name="$(basename "$seed" .bin)"
  run_one_case "$name" "$seed"
done

echo
echo "[done] summary written to: $SUMMARY"
cat "$SUMMARY"