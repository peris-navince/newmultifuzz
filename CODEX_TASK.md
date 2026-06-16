# Codex task: close the adaptive summary aggregation loop

## Immediate goal

Take over the current branch and complete an iterative closed loop:

1. Run the relevant smoke test.
2. Inspect generated result files.
3. Check whether observer-side window data is propagated into `adaptive_guidance_switch_summary.json`.
4. If not, identify the source-code path that loses the data.
5. Modify the source code.
6. Rebuild or recheck.
7. Re-run the smoke test.
8. Repeat until the verification command passes.

## Known observed problem

The run generated observer files such as:

```text
workdir/newmulti_ab/smoke/P2IM__CNC/rep_01/guided_knowledge/round_0_seed/observer/latest_window_summary.json
workdir/newmulti_ab/smoke/P2IM__CNC/rep_01/guided_knowledge/round_1/parent_0_seed/control/observer/latest_window_summary.json
```

But the outer summary:

```text
workdir/newmulti_ab/smoke/P2IM__CNC/rep_01/guided_knowledge/adaptive_guidance_switch_summary.json
```

did not properly include those observer summaries.

This suggests that the collection side exists, but the outer switching or aggregation summary side is incomplete.

## Required final check

Run:

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

## Constraints

- Do not only edit generated JSON output.
- Fix source code.
- Keep changes minimal.
- Do not remove useful logs.
- Do not rewrite unrelated execution logic.
- Do not stop after one failed test.
- Inspect, patch, and re-run until the verification command passes.
- At the end, show the exact diff summary and final verification output.

## First instruction to Codex

Use this as the first prompt after starting Codex:

```text
Please read AGENTS.md and CODEX_TASK.md first.

Then take over this task as an iterative closed loop:

1. Inspect the current branch and relevant files.
2. Run the required compile/build checks.
3. Run or discover the smoke command for P2IM__CNC rep_01.
4. Inspect observer outputs and adaptive_guidance_switch_summary.json.
5. If observer data exists but is not propagated into the adaptive summary, fix the source code.
6. Re-run checks and the smoke workflow.
7. Repeat until the verification command in CODEX_TASK.md passes.

Do not only patch generated JSON files. Fix the source code path. Keep changes minimal. At the end, report root cause, changed files, commands run, final verification output, and remaining limitations.
```
