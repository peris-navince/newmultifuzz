# AGENTS.md

## Project goal

This repository contains the MultiFuzz adaptive testing workflow. The current goal is to make the adaptive guided workflow correctly collect observer-side window data and propagate it into:

```text
workdir/newmulti_ab/smoke/P2IM__CNC/rep_01/guided_knowledge/adaptive_guidance_switch_summary.json
```

The desired closed-loop behavior is:

1. Run the relevant smoke workflow.
2. Inspect generated logs and JSON summaries.
3. Confirm whether observer-side data exists under `observer/latest_window_summary.json`.
4. Confirm whether that observer-side data is propagated into `adaptive_guidance_switch_summary.json`.
5. If propagation is missing, fix the actual source-code path.
6. Rebuild or recheck.
7. Re-run the smoke workflow.
8. Repeat until the verification command passes.

## Important directories

- `analysis/`: analysis scripts and result-processing logic.
- `extractor/`: adaptive guidance and closed-loop orchestration logic.
- `hail/`: Rust runtime and `hail-fuzz` binary.
- `workdir/newmulti_ab/`: generated experiment outputs.
- `workdir/newmulti_ab/smoke/P2IM__CNC/rep_01/`: primary smoke-test output path for this task.

## Known bug context

A previous run generated observer-side files such as:

```text
workdir/newmulti_ab/smoke/P2IM__CNC/rep_01/guided_knowledge/round_0_seed/observer/latest_window_summary.json
workdir/newmulti_ab/smoke/P2IM__CNC/rep_01/guided_knowledge/round_1/parent_0_seed/control/observer/latest_window_summary.json
```

However, the outer summary file did not consistently include those observer summaries:

```text
workdir/newmulti_ab/smoke/P2IM__CNC/rep_01/guided_knowledge/adaptive_guidance_switch_summary.json
```

This means the collection side may already work, but the outer switching or aggregation summary side is incomplete.

## Engineering rules

- Do not patch generated JSON output files as the final fix.
- Fix the source code so future runs aggregate observer data correctly.
- Keep changes minimal and high-confidence.
- Do not rewrite unrelated modules.
- Do not change command-line interfaces unless necessary.
- Do not delete existing experiment outputs unless a fresh run is explicitly required.
- Before risky changes, inspect the producer and consumer path for observer data.
- Prefer source-level fixes in the actual runtime or aggregation path.

## Build and syntax checks

After code changes, run:

```bash
cd ~/Multifuzz
python3 -m py_compile extractor/extractor/closed_loop.py
cargo build -p hail-fuzz
```

If additional Python files are modified, also run `python3 -m py_compile` on those files.

## Smoke-test target

Use the existing smoke workflow for:

```text
workdir/newmulti_ab/smoke/P2IM__CNC/rep_01
```

If the original command is discoverable from scripts or logs, reuse it. If not, inspect existing runner scripts and use the closest existing smoke command for `P2IM__CNC`.

## Required verification command

After the smoke run, execute:

```bash
cd ~/Multifuzz

python3 - <<'PY'
import json
from pathlib import Path

p = Path('workdir/newmulti_ab/smoke/P2IM__CNC/rep_01/guided_knowledge/adaptive_guidance_switch_summary.json')
data = json.loads(p.read_text())

windows = data.get('windows', [])
print('summary =', p)
print('windows =', len(windows))
print('top_observer_summary =', bool(data.get('observer_latest_window_summary')))
print('last_window_observer_summary =', bool((windows or [{}])[-1].get('observer_latest_window_summary')))
print('last_window_observer_streams =', len((windows or [{}])[-1].get('observer_latest_window_discovered_streams') or []))

assert len(windows) > 0, 'No windows found in adaptive summary'
assert data.get('observer_latest_window_summary') or (windows and windows[-1].get('observer_latest_window_summary')), \
    'Observer latest window summary was not propagated'
PY
```

## Done criteria

The task is complete only when all of the following are true:

1. The code builds or compiles.
2. The smoke workflow runs to completion.
3. `adaptive_guidance_switch_summary.json` exists.
4. The summary contains observer-side summary data.
5. The final verification command passes.
6. The final report includes:
   - root cause,
   - changed files,
   - commands run,
   - final verification output,
   - remaining limitations, if any.

## Final report format

At the end, report concisely:

```text
Root cause:

Files changed:

Commands run:

Before result:

After result:

Remaining limitations:
```
