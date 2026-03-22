# Evidence-driven closed loop (v4)

Flow:
1. Run MultiFuzz and collect runtime hotspots with the observer.
2. Directly resolve hotspot MMIO addresses against the known-device SVD.
3. Directly locate PDF evidence by reusing the existing per-peripheral extraction pipeline on demand.
4. Build a local evidence pack for the current plateau.
5. Build task context + expose the constrained action/trigger schema to the LLM.
6. Normalize/compile the LLM-selected plan into runtime guidance.
7. Execute the guidance through the hail-fuzz strategy runtime layer.

The runtime schema intentionally constrains the LLM to a fixed set of action/trigger templates.
