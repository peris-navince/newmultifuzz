# Additive-only scaffold v2 for non-Cortex-M targets

This package is **strictly additive**:
- it does **not** modify any existing `hail-fuzz` files;
- it does **not** modify any existing `icicle-cortexm` files;
- it gives you a **parallel** path for non-Cortex-M targets, starting with generic ARM ELF and a Hi3516DV300/Linux profile generator.

## Included new folders
- `icicle-core/`
  - common config structures and a minimal `TargetBackend` trait.
- `icicle-arm-generic/`
  - a new parallel backend skeleton for generic ARM/ELF targets;
  - generic ELF config generation using object segments/sections;
  - a `bootstrap_hi3516_linux()` helper that applies the DTS-derived RAM assumption (`0x82000000`, size `0x20000000`) and optional DTB placement metadata.
- `hail-fuzz-arm-generic/`
  - a separate CLI binary with subcommands:
    - `inspect`
    - `genconfig`
    - `bootstrap-hi3516`
    - `dry-run`

## What this package deliberately does NOT do yet
- It does **not** execute Linux/ARM targets.
- It does **not** touch the current MultiFuzz replay path.
- It does **not** try to retrofit ARM/Linux support into `icicle-cortexm`.
- It does **not** alter the original workspace or top-level `Cargo.toml`.

That is intentional: the goal is to keep the original Cortex-M path unchanged while creating a clean place to grow a second backend.

## Recommended next steps
1. Copy these new folders into the repository root.
2. Build them independently first by entering each folder and running `cargo build`.
3. Only after that, wire them into the top-level workspace if and when you are ready.
4. Use `hail-fuzz-arm-generic bootstrap-hi3516` to generate a first-pass config for the Hi3516DV300 target workdir.
5. In the next iteration, implement a real executor in `icicle-arm-generic` rather than extending `icicle-cortexm`.

## Example usage after copying into the repo
```bash
cd hail-fuzz-arm-generic
cargo run -- bootstrap-hi3516 /home/targets/hi3516dv300_linux --dtb hi3516dv300-demb.dtb
cargo run -- inspect /home/targets/hi3516dv300_linux
cargo run -- dry-run /home/targets/hi3516dv300_linux
```

## Honesty note
This is a **safe architectural continuation**, not a finished port. The value in this package is that it keeps the original system intact while giving you a concrete, compilable place to grow the non-Cortex-M path.


V3 notes:
- Added `[workspace]` to all additive crates so they build standalone under /home/MultiFuzz.
- Fixed `icicle-arm-generic` standalone compile issue.
- `bootstrap-hi3516` now emits Linux boot starter fields: `initial_sp`, `initial_regs` (`r0`, `r1`, `r2`), `boot_protocol` metadata, and a physical alias region `linux_phys_entry`.
- `inspect` now prints `initial_sp`, `initial_regs`, and `linux_boot` so you can validate one thing at a time.
