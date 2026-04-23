# Budget-Driven Closed-Loop Recommended Parameter Sets

This note gives **practical starting configurations** for the revised long-horizon loop:

1. long warmup to expose the real hotspot region,
2. bounded knowledge + LLM candidate pool construction,
3. short-term breakthrough screening,
4. long-term effect screening,
5. keep a small beam of real winners,
6. re-query / re-plan only on stagnation or hotspot migration.

## Design assumptions

- `beam-width=2` means **two non-control frontiers** survive.
- `winner-run-for` is the **total long-horizon budget per candidate** in the long-term screening phase.
- `winner-run-segment` splits long-horizon runs into checkable chunks.
- `strategy-pool-max-size` should be treated as the **minimum** short-list width; the code now internally keeps at least `max(beam_width + 1, 3)` candidates for short-term screening.

---

## Quick guidance

- **6h**: fastest feedback, good for regression / code validation.
- **12h**: balanced setting, best first serious experiment.
- **24h**: for real long-horizon study once the 12h run is stable.

---

## Recommended configurations

| Budget | Warmup | Short-term screening | Long-term screening | Replan rhythm | Best use |
|---|---:|---:|---:|---|---|
| 6h | 2 × 1200s | 90s per candidate | 2 × 1200s per winner | only on clear stagnation / hotspot migration | quick validation |
| 12h | 3 × 1800s | 120s per candidate | 4 × 1800s per winner | normal setting | balanced main experiment |
| 24h | 3 × 1800s | 120s per candidate | 6 × 1800s per winner | allow more continuation before replan | deeper long-horizon study |

---

## 1) 6-hour recommended run

### Intent
Use this when:
- you just changed `closed_loop.py`,
- you want a same-day sanity check,
- you want to validate that hotspot migration / beam continuation is behaving correctly.

### Recommended values

```text
--total-budget 6h
--warmup-run-for 1200s
--warmup-restarts 2
--candidate-run-for 90s
--probe-run-for 60s
--followup-run-for 90s
--portfolio-run-for 60s
--beam-width 2
--strategy-pool-max-size 3
--winner-run-for 2400s
--winner-run-segment 1200s
```

### Example command

```bash
PYTHONUNBUFFERED=1 python3 -u extractor/closed_loop.py adaptive-mmio-loop \
  --fuzzer-manifest hail-fuzz/Cargo.toml \
  --firmware-config benchmarks/P2IM/Console/config.yml \
  --ghidra-src tools/ghidra \
  --pdf extractor/text/K64.pdf \
  --svd extractor/svd/NXP/NXP-FRDM-K64F/MK64F12.xml \
  --board FRDM-K64F \
  --mcu MK64F12 \
  --benchmark-name P2IM_Console \
  --materialization-mode staged-loop \
  --out-root workdir/console_budget_loop_6h \
  --warmup-run-for 1200s \
  --warmup-restarts 2 \
  --candidate-run-for 90s \
  --probe-run-for 60s \
  --followup-run-for 90s \
  --portfolio-run-for 60s \
  --strategy-pool-max-size 3 \
  --beam-width 2 \
  --total-budget 6h \
  --winner-run-for 2400s \
  --winner-run-segment 1200s \
  --enable-llm-strategy \
  --llm-strategy-mode api \
  --llm-strategy-version v9_long_horizon \
  --llm-strategy-max-candidates 4 \
  --llm-strategy-max-output-tokens 4000 \
  --llm-strategy-max-attempts 2
```

---

## 2) 12-hour recommended run

### Intent
Use this as the **default serious configuration** after the 6h run is stable.

### Recommended values

```text
--total-budget 12h
--warmup-run-for 1800s
--warmup-restarts 3
--candidate-run-for 120s
--probe-run-for 90s
--followup-run-for 120s
--portfolio-run-for 90s
--beam-width 2
--strategy-pool-max-size 3
--winner-run-for 7200s
--winner-run-segment 1800s
```

### Example command

```bash
PYTHONUNBUFFERED=1 python3 -u extractor/closed_loop.py adaptive-mmio-loop \
  --fuzzer-manifest hail-fuzz/Cargo.toml \
  --firmware-config benchmarks/P2IM/Console/config.yml \
  --ghidra-src tools/ghidra \
  --pdf extractor/text/K64.pdf \
  --svd extractor/svd/NXP/NXP-FRDM-K64F/MK64F12.xml \
  --board FRDM-K64F \
  --mcu MK64F12 \
  --benchmark-name P2IM_Console \
  --materialization-mode staged-loop \
  --out-root workdir/console_budget_loop_12h \
  --warmup-run-for 1800s \
  --warmup-restarts 3 \
  --candidate-run-for 120s \
  --probe-run-for 90s \
  --followup-run-for 120s \
  --portfolio-run-for 90s \
  --strategy-pool-max-size 3 \
  --beam-width 2 \
  --total-budget 12h \
  --winner-run-for 7200s \
  --winner-run-segment 1800s \
  --enable-llm-strategy \
  --llm-strategy-mode api \
  --llm-strategy-version v9_long_horizon \
  --llm-strategy-max-candidates 4 \
  --llm-strategy-max-output-tokens 4000 \
  --llm-strategy-max-attempts 2
```

### Why this is the default
- long enough warmup to reveal the true hotspot region,
- short-term screening is still cheap,
- each winner gets a real medium-horizon test,
- still short enough to iterate within a day.

---

## 3) 24-hour recommended run

### Intent
Use this **only after** the 12h configuration is stable.

### Recommended values

```text
--total-budget 24h
--warmup-run-for 1800s
--warmup-restarts 3
--candidate-run-for 120s
--probe-run-for 90s
--followup-run-for 120s
--portfolio-run-for 90s
--beam-width 2
--strategy-pool-max-size 4
--winner-run-for 10800s
--winner-run-segment 1800s
```

### Example command

```bash
PYTHONUNBUFFERED=1 python3 -u extractor/closed_loop.py adaptive-mmio-loop \
  --fuzzer-manifest hail-fuzz/Cargo.toml \
  --firmware-config benchmarks/P2IM/Console/config.yml \
  --ghidra-src tools/ghidra \
  --pdf extractor/text/K64.pdf \
  --svd extractor/svd/NXP/NXP-FRDM-K64F/MK64F12.xml \
  --board FRDM-K64F \
  --mcu MK64F12 \
  --benchmark-name P2IM_Console \
  --materialization-mode staged-loop \
  --out-root workdir/console_budget_loop_24h \
  --warmup-run-for 1800s \
  --warmup-restarts 3 \
  --candidate-run-for 120s \
  --probe-run-for 90s \
  --followup-run-for 120s \
  --portfolio-run-for 90s \
  --strategy-pool-max-size 4 \
  --beam-width 2 \
  --total-budget 24h \
  --winner-run-for 10800s \
  --winner-run-segment 1800s \
  --enable-llm-strategy \
  --llm-strategy-mode api \
  --llm-strategy-version v9_long_horizon \
  --llm-strategy-max-candidates 4 \
  --llm-strategy-max-output-tokens 4000 \
  --llm-strategy-max-attempts 2
```

### Why this differs from 12h
- not much more warmup,
- not much more short screening,
- **much more time goes to long-horizon winner validation and continuation**.

---

## Practical interpretation of the timing

### Warmup
Warmup is for **problem exposure**, not for solving.  
Do not let it consume too much of the total budget.

### Candidate run
This is for **short-term breakthrough screening**.  
It should be just long enough to eliminate obviously weak candidates.

### Winner run
This is the most important budget.  
It is where you decide whether a candidate is:
- only good in the short term,
- or actually good over a longer horizon.

### Winner segment
This is not for fairness.  
It is for **inspection and early interruption**:
- if a winner is still improving, continue it;
- if it stagnates, replan;
- if hotspot family migrates, re-query and rebuild the candidate pool.

---

## Recommended evaluation checkpoints

For every run, inspect at least:

- `adaptive_mmio_loop_summary.json`
- `budget_loop/cycle_*/budget_cycle_summary.json`
- `round_*_summary.json`
- `plan/llm_strategy/llm_strategy_merge_report.json`

Key questions:

1. Did the beam contain **two non-control frontier candidates**?
2. Did the winner(s) actually consume the intended long-horizon budget?
3. Did the primary hotspot migrate?
4. Did the system replan only on stagnation or hotspot migration?
5. Did at least one LLM candidate survive into the long-horizon phase?

---

## Recommendation summary

- Start from **6h** after every major scheduler change.
- Use **12h** as the default experiment once stable.
- Use **24h** only after 12h behavior is satisfactory and reproducible.
