# NewMultiFuzz: Runtime-Evidence-Guided MMIO Closed Loop

NewMultiFuzz is a closed-loop fuzzing workflow for MCU firmware rehosting. It combines random exploration with evidence-guided MMIO intervention: the system first runs a target randomly to expose MMIO bottlenecks, builds a scoped context from runtime traces plus SVD/PDF/manual evidence, asks an LLM to propose bounded guidance candidates, materializes them into a runtime-safe guidance schema, validates them, and feeds the result back into the next epoch.

This repository is the cleaned version of the experimental codebase. Historical one-off retry scripts, backup files, and obsolete batch runners have been removed. The retained path is the final validated closed-loop pipeline used in the latest smoke, medium, and 12-hour paired runs.

## 1. What this version keeps

The effective pipeline is:

```text
random fuzzing
  -> MMIO bottleneck detection
  -> scoped context construction from manifest + SVD + PDF + runtime evidence
  -> LLM guidance planning
  -> guidance materialization
  -> short validation
  -> bottleneck-shift analysis
  -> optional depth-2 chain event
  -> guidance-stack validation
  -> repeat gate / long validation
  -> final decision
  -> state-manager feedback
  -> next epoch
```

The latest validated decisions handled by the scheduler are:

- `chain_no_materialized_candidate` -> `random_first / continue_random_or_retarget`
- `gate_no_firing_candidate` -> `retarget`
- `active_but_unstable_hang_or_crash` -> `stabilize`
- `active_but_coverage_regressed` -> `repair / non_degrading_repair`
- `active_but_input_regressed` -> `repair / non_degrading_repair`
- `strong_active_nondegrading_hotspot_reduced` -> `accept`
- `script_failed` / `missing_final_summary` -> infrastructure retry

Two important empty-candidate cases are now handled as normal closed-loop outcomes, not infrastructure failures:

```text
Depth1 materialization empty -> chain_no_materialized_candidate
Depth2 materialization empty -> chain_no_materialized_candidate
```

## 2. Repository layout

```text
Multifuzz/
  hail-fuzz/                         Rust fuzzer runtime and MMIO guidance executor
  extractor/                         fuzz driver, SVD/PDF utilities, legacy adaptive entry points
  analysis/                          static-analysis helpers and cached Ghidra artifacts
  benchmarks/                        benchmark firmware configs and binaries, if bundled
  scripts/
    use_openai_gpt54_17891.sh         GPT proxy preflight helper
    setup_ghidra_env.sh               optional Ghidra environment helper
    newmulti_ab/                      final closed-loop orchestration scripts
  workdir/newmulti_ab/targets_manifest.jsonl
                                     generated manifest for benchmark cases
```

`workdir/` is ignored by default, except the generated manifest. Runtime outputs should stay under `workdir/newmulti_ab/` and should not be committed.

## 3. Retained scripts

The cleaned `scripts/newmulti_ab/` directory intentionally keeps only the final effective path:

```text
run_single_target_closed_loop_v1.sh       main per-target multi-epoch driver
run_llm_chain_closed_loop.py              one epoch of the LLM-guided chain loop
closed_loop_state_manager_v1.py           feedback, scheduler, and portfolio state
run_random_until_bottleneck.py            random warmup and bottleneck detection
build_bottleneck_context.py               scoped context from manifest/SVD/PDF/runtime evidence
llm_plan_guidance_from_context.py         LLM plan generation from context + feedback
materialize_chain_guidance_plan.py        LLM plan -> guidance candidates
materialize_round2_read_actions.py        SAM-specific conservative fallback materializer
run_guidance_short_validation.py          candidate/control short validation
resummarize_short_validation.py           robust validation summary
analyze_bottleneck_shift.py               hotspot migration analysis
create_chain_event_from_shift.py          depth-2 event construction
build_guidance_stack.py                   prefix + depth-2 guidance stacking
score_guidance_stack.py                   stack scoring
repeat_gate_long_candidates.py            repeat gate and long validation
build_newmulti_manifest.py                manifest generation from benchmarks + evidence roots
run_multi_target_closed_loop_parallel.sh  maintained multi-target parallel runner
summarize_closed_loop_roots.py            result summary helper
semantic_residue_check.py                 cross-family semantic-contamination check
check_openai_proxy.sh                     simple proxy/debug helper
```

Removed examples include dated backup files, `run_closure_gated_*`, retry-only scripts, old summary variants, one-off smoke rebuilders, and obsolete budget/adaptive wrappers that are not part of the final validated NewMultiFuzz loop.

## 4. Environment setup

The tested workflow assumes Linux, Python 3, Rust/Cargo, and the local fuzzer build. A typical setup is:

```bash
cd ~/Multifuzz
python3 -m venv extractor/.venv
source extractor/.venv/bin/activate
pip install -r requirements.txt

cd hail-fuzz
cargo build
cd ..
```

For LLM-backed planning through the local proxy used in our experiments:

```bash
export HTTP_PROXY=http://127.0.0.1:17891
export HTTPS_PROXY=http://127.0.0.1:17891
export http_proxy=http://127.0.0.1:17891
export https_proxy=http://127.0.0.1:17891
export ALL_PROXY=http://127.0.0.1:17891
export all_proxy=http://127.0.0.1:17891
export OPENAI_MODEL=gpt-5.4

bash scripts/use_openai_gpt54_17891.sh
```

If you use a different model/proxy, adjust the environment variables and preflight script accordingly.

## 5. Build or refresh the manifest

If `benchmarks/` is present at the repository root, generate the manifest with:

```bash
cd ~/Multifuzz
mkdir -p workdir/newmulti_ab
python3 scripts/newmulti_ab/build_newmulti_manifest.py \
  --repo . \
  --out workdir/newmulti_ab/targets_manifest.jsonl
```

The script also writes a CSV next to the JSONL manifest. A healthy local setup should report all runnable benchmark cases and indicate whether Ghidra/static artifacts and manual evidence are present.

## 6. Single-target smoke

Use this before long runs:

```bash
cd ~/Multifuzz
source extractor/.venv/bin/activate

MAX_EPOCHS=1 \
RANDOM_CHUNK_RUN_FOR=2m \
SHORT_RUN_FOR=20s \
LONG_RUN_FOR=1m \
GATE_RUN_FOR=20s \
GATE_REPEATS=1 \
GATE_TOP_K=2 \
TOP_K_REPEAT=1 \
MAX_CHAIN_DEPTH=2 \
MATERIALIZE_PRIORITY_MAX=2 \
MATERIALIZE_MAX_CANDIDATES=8 \
SHORT_MAX_CANDIDATES=8 \
STACK_SHORT_MAX_CANDIDATES=8 \
bash scripts/newmulti_ab/run_single_target_closed_loop_v1.sh P2IM__Gateway 2
```

A successful smoke should create:

```text
workdir/newmulti_ab/closed_loop_<CASE>_<MODEL>_h<HOURS>_<TIMESTAMP>/
  epochs/epoch_1/final_summary.json
  feedback/post_epoch_1.md
  feedback/post_epoch_1_scheduler.json
  state/closed_loop_state.json
  decision_history.csv
```

## 7. Multi-target medium validation

Create a target list, for example:

```bash
cat > workdir/newmulti_ab/medium_targets.txt <<'TARGETS'
P2IM__Gateway
HALucinator__6LoWPAN_Receiver
MultiFuzz__riot-ccn-lite-relay
TARGETS
```

Run two epochs per target with bounded parallelism:

```bash
cd ~/Multifuzz
source extractor/.venv/bin/activate

PARALLEL=2 \
MAX_EPOCHS=2 \
RANDOM_CHUNK_RUN_FOR=2m \
SHORT_RUN_FOR=20s \
LONG_RUN_FOR=1m \
GATE_RUN_FOR=20s \
GATE_REPEATS=1 \
GATE_TOP_K=2 \
TOP_K_REPEAT=1 \
MAX_CHAIN_DEPTH=2 \
MATERIALIZE_PRIORITY_MAX=2 \
MATERIALIZE_MAX_CANDIDATES=8 \
SHORT_MAX_CANDIDATES=8 \
STACK_SHORT_MAX_CANDIDATES=8 \
bash scripts/newmulti_ab/run_multi_target_closed_loop_parallel.sh \
  workdir/newmulti_ab/medium_targets.txt 4
```

Summarize:

```bash
OUT_DIR=$(cat workdir/newmulti_ab/latest_multi_target_closed_loop_root.txt)
python3 scripts/newmulti_ab/summarize_closed_loop_roots.py \
  --roots "$OUT_DIR/roots.txt"

python3 scripts/newmulti_ab/semantic_residue_check.py \
  --roots "$OUT_DIR/roots.txt" \
  --manifest workdir/newmulti_ab/targets_manifest.jsonl
```

Passing criteria:

```text
BAD: none
RESULT: OK
No final_decision=script_failed
Every epoch has script_success=true and failed=false
```

## 8. Paired 12-hour long run

For long validation, run only a small number of targets in parallel. The latest validated pair was:

```text
P2IM__Gateway
HALucinator__6LoWPAN_Receiver
```

Example:

```bash
cat > workdir/newmulti_ab/long_pair_targets.txt <<'TARGETS'
P2IM__Gateway
HALucinator__6LoWPAN_Receiver
TARGETS

cd ~/Multifuzz
source extractor/.venv/bin/activate

nohup bash -c '
  PARALLEL=2 \
  MAX_EPOCHS=12 \
  RANDOM_CHUNK_RUN_FOR=2m \
  SHORT_RUN_FOR=20s \
  LONG_RUN_FOR=1m \
  GATE_RUN_FOR=20s \
  GATE_REPEATS=1 \
  GATE_TOP_K=2 \
  TOP_K_REPEAT=1 \
  MAX_CHAIN_DEPTH=2 \
  MATERIALIZE_PRIORITY_MAX=2 \
  MATERIALIZE_MAX_CANDIDATES=8 \
  SHORT_MAX_CANDIDATES=8 \
  STACK_SHORT_MAX_CANDIDATES=8 \
  bash scripts/newmulti_ab/run_multi_target_closed_loop_parallel.sh \
    workdir/newmulti_ab/long_pair_targets.txt 12
' > workdir/newmulti_ab/long_pair_launcher.log 2>&1 &
```

Check progress:

```bash
OUT_DIR=$(cat workdir/newmulti_ab/latest_multi_target_closed_loop_root.txt)
tail -80 workdir/newmulti_ab/long_pair_launcher.log
ls -lh "$OUT_DIR"
```

After completion:

```bash
OUT_DIR=$(cat workdir/newmulti_ab/latest_multi_target_closed_loop_root.txt)
python3 scripts/newmulti_ab/summarize_closed_loop_roots.py --roots "$OUT_DIR/roots.txt"
python3 scripts/newmulti_ab/semantic_residue_check.py --roots "$OUT_DIR/roots.txt"
```

## 9. Interpreting results

Useful high-level signals:

- `chain_no_materialized_candidate`: the loop was stable, but no executable candidate reached the next validation stage. This is not a script failure.
- `gate_no_firing_candidate`: candidates were produced but did not fire in repeat gate; scheduler should retarget.
- `active_but_unstable_hang_or_crash`: candidates fired but introduced instability; scheduler should stabilize.
- `active_but_coverage_regressed` / `active_but_input_regressed`: candidates fired but hurt coverage/input; scheduler should repair.
- `strong_active_nondegrading_hotspot_reduced`: strong positive result; scheduler can accept and continue hybrid exploration.

For coverage/effectiveness, do not rely only on `script_success`. Inspect `repeat_gate_stats`, long-validation rows, and the decision portfolio:

```bash
python3 -m json.tool <ROOT>/state/closed_loop_state.json | head -220
cat <ROOT>/decision_history.csv
```

## 10. Latest validated status

The final cleaned code reflects the latest verified behavior:

- 3-family, 2-epoch medium validation passed for STM/P2IM, SAM/HALucinator, and NXP/MultiFuzz representatives.
- 12-hour paired long validation completed with `rc=0` for both `P2IM__Gateway` and `HALucinator__6LoWPAN_Receiver`.
- Both long-run roots reported `BAD_EPOCHS: none`.
- Cross-family semantic residue checks reported `RESULT: OK`.
- HALucinator showed real guided-loop behavior including no-candidate, no-fire, active-regressed, and strong-active outcomes.
- P2IM Gateway remained stable but mostly produced `chain_no_materialized_candidate`, indicating that its remaining issue is candidate effectiveness rather than closed-loop infrastructure.

## 11. Development notes

Do not reintroduce old dated backup scripts into `scripts/newmulti_ab/`. New experiments should either extend the retained core scripts or add clearly named maintained helpers.

Before committing:

```bash
python3 -m py_compile scripts/newmulti_ab/*.py extractor/*.py
find . -type d -name __pycache__ -prune -exec rm -rf {} +
find . -type f -name "*.bak*" -delete
```

Runtime result directories under `workdir/` should not be committed, except the generated manifest if desired.
