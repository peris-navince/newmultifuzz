# MultiFuzz touch-width trigger repair

This package applies a narrow source-level repair to `extractor/closed_loop.py`.

## Problem addressed

Some generated guidance actions use `on_first_touch(read)` with an action width that does not match the first observed read width for that address. Runtime requires `action.width == buf.len()`, so the first touch misses by width, and later reads with the correct width miss because the trigger is still `on_first_touch`.

## Patch behavior

The patch adds a pre-save guidance repair:

- if action trigger is `on_first_touch(read)`;
- and the first read of that address has a different width from the action width;
- change the trigger to `on_nth_touch(read)` where `n` is the first read touch index with the required width.

It does not relax Rust runtime width checks.

## Apply

```bash
cd ~/Multifuzz
source extractor/.venv/bin/activate
python3 /path/to/apply_touchwidth_repair.py ~/Multifuzz
python3 -m py_compile extractor/closed_loop.py
cargo build -p hail-fuzz
```

## Validate with one target

```bash
cd ~/Multifuzz
bash /path/to/validate_touchwidth_repair.sh ~/Multifuzz
```

Expected improvement: `uEmu__utasker_USB` should ideally move from `guidance_not_consumed` to `guidance_consumed_no_gain` or `improved`, with `runtime_fire_count > 0`.
