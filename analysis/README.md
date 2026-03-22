# MultiFuzz Ghidra → LLM → Knowledge Graph prototype

This folder is a **drop-in prototype module** intended to live under the MultiFuzz repository as a
separate pipeline, for example:

```text
MultiFuzz/
  analysis/
    ghidra_kg/
      ...this folder...
```

It is intentionally **separate** from the manual PDF/SVD extractor. The two pipelines should
produce compatible graph entities and be merged later at the schema/query layer.

## What this prototype does

1. Runs **Ghidra headless** on a firmware binary.
2. Exports a structured JSON view of:
   - functions
   - call edges
   - decompiler text
   - disassembly excerpts
   - MMIO-like constant accesses
   - ISR-like functions
3. Optionally sends **one function at a time** to an LLM for code-side semantic extraction.
4. Writes a code-side knowledge graph as JSONL:
   - `kg_nodes.jsonl`
   - `kg_edges.jsonl`
   - `kg_findings.jsonl`

## Design principles

- **One function per LLM request** to reduce confusion.
- **No coupling** to the existing extractor codebase.
- **Optional alignment** with a manual MMIO map exported from the extractor.
- **Debug-first outputs** so you can inspect every stage.

## Quick start

```bash
export OPENAI_API_KEY=...                   # only needed for --relation-mode llm
export OPENAI_BASE_URL=https://api.openai.com/v1
export GHIDRA_HOME=/path/to/ghidra          # optional if auto-detected

python3 run_ghidra_kg.py \
  --binary /path/to/firmware.bin \
  --outdir out/demo \
  --manual-mmio-map /path/to/mmio_map.json \
  --relation-mode llm \
  --llm-model gpt-5.4
```

## Output files

- `ghidra_export.json`: raw Ghidra-side structured export
- `candidate_functions.jsonl`: functions selected for LLM analysis
- `llm_raw/*.json`: raw per-function LLM requests/responses/debug info
- `kg_nodes.jsonl`: graph nodes
- `kg_edges.jsonl`: graph edges
- `kg_findings.jsonl`: risk findings
- `summary.json`: run summary

## Manual MMIO map input

If supplied, `--manual-mmio-map` should point to a JSON file compatible with the existing
extractor's `mmio_map_v1` style, especially fields such as:

- `peripheral`
- `registers[]`
  - `name`
  - `absoluteAddress`
  - `absoluteAddress_hex`
  - `fields[]`

The prototype uses this primarily to resolve MMIO addresses to peripheral/register names.

## Notes

- This version favors **clarity and inspectability** over perfect coverage.
- The Ghidra script uses simple MMIO heuristics based on embedded address ranges.
- The LLM stage is conservative and JSON-only.


## Fast local smoke test without Ghidra

```bash
python3 run_ghidra_kg.py \
  --ghidra-export-json smoke_mock_export.json \
  --outdir out/mock \
  --relation-mode off
```

This exercises the graph-writing path without needing a real Ghidra install or network access.
