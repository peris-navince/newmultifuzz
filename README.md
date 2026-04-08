# MultiFuzz

A fuzzing and analysis workspace for MCU firmware rehosting, centered on a closed loop:

1. run baseline fuzzing and observe plateau behavior,
2. recover code-side semantics with **Ghidra headless**,
3. combine those semantics with PDF/SVD evidence,
4. use an **LLM API** to infer structured input contracts,
5. generate candidate multistream seeds/guidance,
6. batch-evaluate candidates and feed the best results back into the next round.

This repository has been cleaned up to support that direction more directly:

- the default Ghidra path now resolves to `./tools/ghidra` first,
- the old one-off UART one-shot shim in `hail-fuzz` has been removed,
- generated workdirs/caches are treated as build artifacts rather than source,
- the current architecture is documented around **Ghidra CLI + LLM API + batch evaluation**, not ad-hoc manual strategies.

---

## Repository layout

```text
MultiFuzz/
  benchmarks/        firmware benchmarks and configs
  extractor/         PDF/SVD evidence extraction and staged orchestration
  analysis/          Ghidra-headless + code-side KG / LLM analysis prototype
  hail-fuzz/         main fuzzer runtime and multistream input handling
  tools/ghidra/      local Ghidra installation (expected default location)
```

### `hail-fuzz/`

The fuzzing runtime for Cortex-M firmware rehosting.

Key responsibilities:

- baseline fuzzing,
- queue/corpus management,
- structured multistream MMIO inputs,
- stream observation,
- guidance execution,
- fixed-point / candidate evaluation support.

### `extractor/`

The evidence and orchestration side.

Key responsibilities:

- build evidence packs from runtime + PDF + SVD,
- construct task context,
- plan candidate strategies,
- compile strategies into runtime-consumable guidance,
- run staged evaluation loops.

### `analysis/`

The code-side semantic analysis prototype.

Key responsibilities:

- run Ghidra headless,
- export structured code facts,
- optionally call an LLM API one function at a time,
- emit graph-like outputs that can later be aligned with extractor evidence.

---

## Current architecture

The intended steady-state workflow is:

```text
baseline fuzz
  -> plateau / hotspot detection
  -> Ghidra headless export
  -> PDF/SVD evidence alignment
  -> LLM contract inference
  -> candidate seed / guidance synthesis
  -> short-budget batch evaluation
  -> promote best candidates
  -> repeat
```

Two principles matter most:

### 1. Evidence first

Candidate generation should be grounded in observed runtime behavior and recovered program semantics, not pure speculation.

### 2. Structured outputs

The LLM should not emit free-form strategy text. It should emit structured contracts or candidate descriptions that can be validated and compiled mechanically.

---

## Ghidra location

The repository now expects Ghidra at:

```text
/home/MultiFuzz/tools/ghidra
```

At runtime, `hail-fuzz` now resolves `GHIDRA_SRC` like this:

1. `./tools/ghidra`
2. `./ghidra`
3. explicit `GHIDRA_SRC` from the environment

So if you run from the repository root, the default path works without extra flags.

---

## Quick start

### Build the fuzzer

```bash
cd /home/MultiFuzz
cargo build --release --manifest-path /home/MultiFuzz/hail-fuzz/Cargo.toml
```

### Run a benchmark from the repository root

```bash
cd /home/MultiFuzz
WORKDIR=/home/MultiFuzz/workdir \
RUN_FOR=30s \
cargo run --release --manifest-path /home/MultiFuzz/hail-fuzz/Cargo.toml -- \
  /home/MultiFuzz/benchmarks/P2IM/Console/config.yml
```

Running from the repository root is important because relative runtime assets are resolved from there.

---

## Extractor orchestration

`extractor/closed_loop.py` still provides the existing staged orchestration entrypoints, but its default Ghidra path now also resolves to the repository-local installation under `tools/ghidra`.

Example:

```bash
cd /home/MultiFuzz/extractor
python3 closed_loop.py run-fuzz \
  --fuzzer-manifest /home/MultiFuzz/hail-fuzz/Cargo.toml \
  --firmware-config /home/MultiFuzz/benchmarks/P2IM/Console/config.yml \
  --workdir /home/MultiFuzz/workdir \
  --run-log /home/MultiFuzz/workdir/run.log
```

You only need `--ghidra-src` if you want to override the repository default.

---

## Analysis / Ghidra headless prototype

See `analysis/README.md` for the code-side Ghidra → LLM → graph prototype.

That module is intended to become the main entrypoint for:

- code-side function recovery,
- MMIO use-site export,
- structured semantic extraction,
- contract inference for candidate seed generation.

---

## What was intentionally removed in this cleanup

This cleanup removes legacy behavior that was convenient for manual experiments but harmful for a reproducible closed loop.

Most importantly:

- the old environment-variable-driven UART one-shot injection path has been removed from `hail-fuzz/src/input.rs`;
- generated caches and workdirs are now clearly treated as disposable artifacts;
- the repository documentation no longer describes the project as primarily a manual hotspot experiment harness.

This keeps the codebase aligned with the current goal: **Ghidra-guided, LLM-mediated, batch-evaluated fuzz input synthesis**.

---

## Notes

- `analysis/out/`, `workdir/`, `hail-fuzz/workdir/`, and extractor cache directories are local artifacts and should not be committed.
- `tools/ghidra/` is intentionally ignored because it is a local installation, not repository source.
- The PDF/SVD extractor and the Ghidra/LLM analysis pipeline are both kept for now because the long-term direction is to fuse them, not to pick only one.
