# Budget-Driven Adaptive Evidence-Guided Fuzzing for MMIO Hotspots
# 面向 MMIO 热点的总预算驱动自适应证据引导模糊测试

## 1. Overview / 项目概述

### English

This project extends MCU firmware rehosting fuzzing with an **evidence-grounded, staged, adaptive, and now budget-driven long-horizon closed loop** around MMIO hotspots.

The system no longer treats MMIO handling as a one-shot manual patching problem, nor as a purely static knowledge-extraction problem. Instead, it repeatedly runs firmware, observes runtime MMIO bottlenecks, resolves hotspot addresses with SVD and PDF evidence, groups related registers, synthesizes bounded strategy candidates, compares them fairly from the same imported frontier, promotes the best branches, runs the promoted branch for a medium horizon, re-observes the new frontier, and repeats until a total time budget is exhausted.

The current design has evolved beyond the earlier single-round “heuristic hotspot repair” pipeline in four important ways:

1. **Runtime evidence remains primary.** Dynamic hotspots, MMIO access counts, replay traces, guidance firing behavior, and hotspot migration drive what the system tries next.
2. **Candidate generation is hybrid.** Heuristic candidates remain the guaranteed fallback, while an LLM strategy layer can generate bounded multi-register strategies inside an explicit whitelist derived from runtime + SVD + PDF evidence.
3. **Evaluation is no longer only short repair.** The system supports short tournaments, medium-horizon winner runs, long-horizon strategy-pool comparison, and repeated re-planning.
4. **The outer loop is now budget-driven.** Instead of stopping after a fixed number of windows, the long-horizon mode can keep iterating until `--total-budget` is consumed.

The practical goal is not to solve all peripherals at once. The goal is to make the following loop reliable and repeatable:

1. run firmware and observe bottlenecks;
2. extract bounded evidence;
3. build hotspot groups or mixed hotspot families;
4. generate constrained strategy candidates;
5. compare candidates fairly from the same imported frontier;
6. keep the top frontier(s), currently with **beam width = 2**;
7. run the best branch for a medium horizon;
8. re-observe, re-plan, and continue until the global budget ends.

### 中文

本项目面向 MCU 固件重宿主 fuzzing，在 MMIO 热点附近构建一个**基于证据、分阶段、自适应，并且现在已经扩展为总预算驱动的长时闭环系统**。

系统不再把 MMIO 处理看成“一次性手工修补”的问题，也不再把它仅仅视为一个纯静态知识抽取问题。当前流程会反复运行固件，观察运行时 MMIO 卡点，结合 SVD 与 PDF 手册证据解析热点地址，构造相关寄存器组，生成受约束的策略候选，从同一 imported frontier 出发进行公平比较，晋级表现最好的分支，对晋级分支进行中等时长运行，再重新观察新的 frontier，并持续循环直到总时间预算耗尽。

相较于早期“heuristic 热点修补”版本，当前设计已经有四个重要演进：

1. **运行时证据仍然优先。** 动态热点、MMIO 访问次数、replay trace、guidance 触发行为、热点迁移共同决定下一步尝试什么。
2. **候选生成变为混合式。** heuristic 候选仍然是稳定保底；LLM strategy layer 则在 runtime + SVD + PDF 推导出的显式白名单内生成受约束的多寄存器策略。
3. **评估不再只是短时修补。** 系统支持短时 tournament、中等时长 winner run、长视角 strategy-pool 比较，以及重复 re-plan。
4. **外层循环现在由总预算驱动。** 长时模式不再固定跑若干窗口就停止，而是可以持续迭代到 `--total-budget` 被消耗完。

当前工作的目标并不是一次性覆盖所有外设，而是把以下闭环做稳定、做可复现：

1. 运行固件并观察瓶颈；
2. 提取受约束证据；
3. 构造热点组或混合热点家族；
4. 生成受约束候选；
5. 从同一 imported frontier 公平比较候选；
6. 保留最好的 frontier，目前采用 **beam width = 2**；
7. 对获胜分支进行中等时长运行；
8. 重新观察、重新规划，并持续循环直到总预算结束。

---

## 2. Design Principles / 设计原则

### 2.1 Runtime evidence first / 运行时证据优先

### English

The system does not let static priors dominate when runtime traces say otherwise. Strategy generation and evaluation are grounded in three evidence layers:

- **Runtime evidence**: hotspot MMIO addresses, touch counts, width distributions, coverage plateaus, last-PC locality, replay traces, probe/followup behavior, candidate firing behavior, and hotspot migration.
- **SVD evidence**: peripheral instance, register identity, address layout, field positions, register width, access type, and base-address proximity.
- **PDF evidence**: register descriptions, field semantics, ready/busy/status wording, mode transitions, interrupt wording, and local memory-map context.

Runtime evidence determines **what is worth trying now**. SVD and PDF evidence determine **how far the system is allowed to generalize**.

### 中文

系统不会让静态先验在运行时证据已经指向其他方向时仍然主导决策。当前候选生成与评估建立在三层证据之上：

- **运行时证据**：热点 MMIO 地址、touch 次数、宽度分布、coverage 平台期、last-PC 局部性、replay trace、probe/followup 行为、candidate 触发情况、热点迁移。
- **SVD 证据**：外设实例、寄存器身份、地址布局、字段位置、寄存器宽度、访问权限、base address 邻近性。
- **PDF 证据**：寄存器说明、字段语义、ready/busy/status 表述、模式切换、中断描述、局部 memory map 上下文。

运行时证据决定的是**当前最值得尝试什么**；SVD 与 PDF 决定的是**系统可以在多大范围内合法泛化**。

### 2.2 Bounded action space / 受约束动作空间

### English

Neither heuristics nor the LLM are allowed to invent arbitrary runtime DSL syntax. All candidates must eventually compile into the supported structured guidance action space.

The current runtime-safe action families include:

- `mmio_bit_update`
- `mmio_read_override_once`
- `mmio_read_sequence`
- `mmio_write_observe`
- `activate_stage` + `when_stage_active`

Earlier intermediate forms such as helper-like gates may still appear during synthesis, but the current `llm_strategy_layer.py` normalizes them into conservative primitive combinations before runtime execution. This is important because the system previously hit parser-contract mismatches around fields such as `repeat`, `read_value`, and `write_addr`.

### 中文

无论是 heuristic 还是 LLM，都不允许自由发明 runtime DSL 语法。所有候选最终都必须落入 runtime 已支持的结构化 guidance 动作空间。

当前 runtime-safe action 家族包括：

- `mmio_bit_update`
- `mmio_read_override_once`
- `mmio_read_sequence`
- `mmio_write_observe`
- `activate_stage` + `when_stage_active`

早期合成阶段可能会出现 helper-like gate 这类中间形式，但当前 `llm_strategy_layer.py` 会在进入 runtime 前把它们归一化为更保守的 primitive 组合。这一点很重要，因为系统之前曾反复遇到 `repeat`、`read_value`、`write_addr` 等字段导致的 parser/runtime 契约不匹配问题。

### 2.3 Fair comparison from the same prefix / 从同一前缀公平比较

### English

All candidates in a tournament must start from the same imported queue/frontier. Otherwise, candidate quality becomes confounded with corpus luck.

The system therefore preserves:

- a warmup frontier;
- per-cycle import reuse;
- control branches;
- identical short budgets per candidate in the same tournament;
- promoted frontier reuse between cycles.

### 中文

同一 tournament 内所有候选都必须从同一个 imported queue/frontier 出发。否则，候选质量会和语料随机性混在一起，无法公平比较。

因此系统始终保留：

- warmup frontier；
- 每个 cycle 的 import 复用；
- control 分支；
- 同一 tournament 内一致的 per-candidate 短预算；
- cycle 之间复用晋级 frontier。

### 2.4 Evidence-bounded LLM assistance / 受证据约束的 LLM 辅助

### English

The LLM is not an unconstrained policy generator. Its role is bounded to:

- choosing candidate structures inside an allowed register cluster;
- proposing multi-register state-advancing strategies;
- staying inside supported action/trigger families;
- producing JSON that can be linted, sanitized, normalized, compiled, and executed;
- complementing, not replacing, heuristic baseline planning.

### 中文

LLM 不是无限制策略生成器。它的角色被约束为：

- 在 allowed register cluster 内选择候选结构；
- 提出多寄存器、能推动状态前进的策略；
- 严格限制在支持的 action/trigger 家族内；
- 输出可被 lint、sanitize、normalize、compile 并执行的 JSON；
- 作为 heuristic baseline 的补充，而不是替代。

### 2.5 Budget-driven long-horizon iteration / 总预算驱动的长时迭代

### English

The newest design principle is that long-horizon evaluation should not be a single stretched run. It should be a repeated cycle:

```text
bootstrap / warmup
→ short tournament
→ select and keep top beam entries
→ medium-horizon winner run
→ re-observe hotspot frontier
→ re-plan
→ repeat until total budget is exhausted
```

This prevents the system from committing a whole 12h or 24h budget to a short-term winner that may not be good in the long term.

### 中文

最新的设计原则是：长时评估不应该只是把单条 run 拉长，而应该是一个重复循环：

```text
bootstrap / warmup
→ 短时 tournament
→ 选择并保留 top beam entries
→ 中等时长 winner run
→ 重新观察 hotspot frontier
→ 重新规划
→ 持续循环直到总预算耗尽
```

这样可以避免系统把完整 12h 或 24h 预算一次性押在一个短期看起来好的 winner 上。

---

## 3. System Architecture / 系统架构

## 3.1 High-level architecture / 总体结构

### English

The repository now contains five major functional layers:

1. **Fuzz runtime layer** (`hail-fuzz`)
2. **Evidence extraction and context construction layer** (`extractor`)
3. **Strategy planning layer** (heuristic + LLM bounded planning)
4. **Tournament and long-horizon strategy-pool layer**
5. **Budget-driven outer-loop orchestration layer** (`closed_loop.py`)

### 中文

当前仓库整体可以分成五层：

1. **fuzz runtime 层**（`hail-fuzz`）
2. **证据提取与上下文构建层**（`extractor`）
3. **策略规划层**（heuristic + LLM bounded planning）
4. **tournament 与长视角 strategy-pool 层**
5. **总预算驱动外层闭环调度层**（`closed_loop.py`）

## 3.2 Fuzz runtime layer / fuzz runtime 层

### English

The runtime supports:

- baseline fuzzing;
- MMIO observer export;
- structured guidance execution;
- guidance runtime summary export;
- replay trace export;
- imported frontier reuse.

Common environment variables include:

- `GHIDRA_SRC`
- `WORKDIR`
- `RUN_FOR`
- `MF_STREAM_OBSERVER_OUT`
- `MF_MMIO_GUIDANCE_FILE`
- `MF_MMIO_GUIDANCE_SUMMARY_OUT`
- `MF_IMPORT_DIR`

### 中文

当前 runtime 支持：

- baseline fuzz；
- MMIO observer 导出；
- 结构化 guidance 执行；
- guidance runtime summary 导出；
- replay trace 导出；
- imported frontier 复用。

常见环境变量包括：

- `GHIDRA_SRC`
- `WORKDIR`
- `RUN_FOR`
- `MF_STREAM_OBSERVER_OUT`
- `MF_MMIO_GUIDANCE_FILE`
- `MF_MMIO_GUIDANCE_SUMMARY_OUT`
- `MF_IMPORT_DIR`

## 3.3 Evidence and planning layer / 证据与规划层

### English

This layer is centered in `extractor/` and includes:

- address resolution through SVD;
- PDF evidence location with family/instance fallback;
- shared PDF/SVD cache reuse;
- evidence pack construction;
- task context construction;
- hotspot grouping and mixed-family handling;
- heuristic planning;
- LLM strategy prompt construction;
- LLM output lint/sanitize/normalize;
- guidance compilation.

Core files include:

- `closed_loop.py`
- `evidence_builder.py`
- `task_context.py`
- `strategy_catalog.py`
- `strategy_planner.py`
- `guidance_compiler.py`
- `llm_strategy_layer.py`
- `pdf_evidence_locator.py`
- `svd_resolver.py`
- `run_ghidra_kg.py`

### 中文

这一层主要位于 `extractor/`，当前包括：

- 基于 SVD 的地址解析；
- 带 family/instance fallback 的 PDF evidence 定位；
- shared PDF/SVD cache 复用；
- evidence pack 构建；
- task context 构建；
- 热点分组与混合家族处理；
- heuristic planning；
- LLM strategy prompt 构建；
- LLM 输出 lint/sanitize/normalize；
- guidance compile。

核心文件包括：

- `closed_loop.py`
- `evidence_builder.py`
- `task_context.py`
- `strategy_catalog.py`
- `strategy_planner.py`
- `guidance_compiler.py`
- `llm_strategy_layer.py`
- `pdf_evidence_locator.py`
- `svd_resolver.py`
- `run_ghidra_kg.py`

## 3.4 Budget-driven orchestration layer / 总预算驱动调度层

### English

The current `adaptive-mmio-loop` has two execution styles:

1. **Finite pilot mode**: no `--total-budget`; the command behaves like the earlier staged/adaptive loop.
2. **Budget-driven outer-loop mode**: `--total-budget` is provided; the materialized PDF/SVD route runs repeated cycles until the budget is consumed.

In budget-driven materialized mode, the loop creates:

```text
<out-root>/budget_loop/cycle_001/
<out-root>/budget_loop/cycle_002/
...
<out-root>/adaptive_mmio_loop_summary.json
```

Each cycle stores its own planning, tournament, long-horizon windows, and `budget_cycle_summary.json`.

### 中文

当前 `adaptive-mmio-loop` 有两种执行方式：

1. **有限 pilot 模式**：不传 `--total-budget`；命令行为类似早期 staged/adaptive loop。
2. **总预算驱动外层闭环模式**：传入 `--total-budget`；materialized PDF/SVD 路线会持续重复 cycle，直到预算耗尽。

在 budget-driven materialized 模式下，系统会创建：

```text
<out-root>/budget_loop/cycle_001/
<out-root>/budget_loop/cycle_002/
...
<out-root>/adaptive_mmio_loop_summary.json
```

每个 cycle 都有自己的规划、tournament、长视角窗口，以及 `budget_cycle_summary.json`。

---

## 4. Evidence Model / 证据模型

## 4.1 Runtime evidence / 运行时证据

### English

Runtime evidence currently includes:

- top hotspot MMIO addresses;
- read/write counts;
- observed width distributions;
- first/last seen order;
- last-PC locality and replay traces;
- per-candidate runtime firing summaries;
- plateau-like behavior across windows;
- hotspot migration across cycles.

### 中文

当前运行时证据包括：

- 顶层热点 MMIO 地址；
- 读写次数；
- 观察到的宽度分布；
- first/last seen 顺序；
- last-PC 局部性与 replay trace；
- 每个 candidate 的 runtime firing summary；
- 跨窗口的平台期行为；
- 跨 cycle 的热点迁移。

## 4.2 SVD evidence / SVD 证据

### English

SVD evidence provides:

- peripheral instance;
- register identity;
- field offsets and widths;
- register width bytes;
- access permissions;
- base address and layout proximity.

### 中文

SVD 证据提供：

- 外设实例；
- 寄存器身份；
- 字段偏移与位宽；
- 寄存器宽度；
- 访问权限；
- base address 与布局邻近性。

## 4.3 PDF evidence / PDF 证据

### English

PDF evidence is used for:

- register descriptions;
- field semantics;
- ready/busy/status interpretation;
- mode-transition hints;
- local register neighborhood;
- evidence-backed register cluster expansion.

The system supports family fallback such as:

- `UART0 -> UART`
- family-level caches when instance-specific cache is incomplete

Current caveat: some families, such as MCG in recent Console pilots, may resolve through SVD but have incomplete PDF register location. This does not necessarily break the loop, but it weakens evidence quality for LLM planning.

### 中文

PDF 证据主要用于：

- 寄存器说明；
- 字段语义；
- ready/busy/status 的解释；
- mode transition 提示；
- 寄存器局部邻域；
- 基于证据的寄存器簇扩展。

系统支持 family fallback，例如：

- `UART0 -> UART`
- 当 instance-specific cache 不完整时回退到 family 级 cache

当前注意点：近期 Console pilot 中，MCG 等家族可以通过 SVD 地址解析，但 PDF register location 不一定完整。这不会必然破坏闭环，但会削弱 LLM 规划时的证据质量。

## 4.4 Evidence pack / evidence pack

### English

`evidence_pack.json` is the main bounded evidence bundle used by later planning. It is intentionally compact but traceable. It is not a global knowledge base; it is a current-stage planning capsule.

### 中文

`evidence_pack.json` 是后续规划使用的核心受约束证据包。它有意保持紧凑但可追踪。它不是全局知识库，而是一个当前阶段的规划胶囊。

---

## 5. Hotspot Grouping and Mixed Families / 热点分组与混合热点家族

## 5.1 Why grouping is still needed / 为什么仍然需要分组

### English

A hotspot is rarely just one register. A status register often implies control, data, FIFO, or configuration companions. Grouping avoids overfitting to a single polling anchor.

Examples:

- `UART0.S1` with `UART0.D`, `UART0.C2`, `UART0.PFIFO`, `UART0.CFIFO`
- `MCG.S` with `MCG.C1/C2/C4/C6`
- `PORTA.PCR18` as configuration evidence around a peripheral route
- `SMC.PMPROT` or other power/mode registers as longer-horizon configuration bottlenecks

### 中文

热点通常不只是一个寄存器。一个状态寄存器往往隐含着控制、数据、FIFO 或配置伴随寄存器。分组可以避免系统过拟合到单一 polling anchor。

例如：

- `UART0.S1` 与 `UART0.D`、`UART0.C2`、`UART0.PFIFO`、`UART0.CFIFO`
- `MCG.S` 与 `MCG.C1/C2/C4/C6`
- `PORTA.PCR18` 作为外设路由附近的配置证据
- `SMC.PMPROT` 或其他 power/mode 寄存器作为长视角配置瓶颈

## 5.2 Mixed-family handling / 混合热点家族处理

### English

Longer warmup runs revealed that the dominant bottleneck may shift away from the earlier UART-only view. A medium or long pilot may contain mixed addresses from UART, MCG, PORT, and SMC-like configuration regions. The planner therefore avoids assuming that a single family always dominates every stage.

This is expected in from-zero long-horizon runs. A short smoke may show a clean UART polling anchor, while a longer warmup may expose earlier configuration or clocking bottlenecks.

### 中文

更长的 warmup 暴露出：主导瓶颈并不总是停留在早期看到的 UART-only 视角。中等或长时 pilot 中，热点前沿可能同时包含 UART、MCG、PORT、SMC 等配置相关区域。因此，planner 现在必须避免默认“每个阶段都只有单一家族主导”。

这在 from-zero 长时运行中是正常现象。短 smoke 可能看到干净的 UART polling anchor，而更长的 warmup 可能暴露更早期的配置或时钟瓶颈。

## 5.3 Grouping sources / 分组依据

### English

Grouping uses:

- runtime co-occurrence;
- SVD same-instance or same-base proximity;
- PDF local neighborhood and manual semantics;
- fallback naming heuristics;
- dynamic hotspot migration across windows and cycles.

### 中文

分组依据包括：

- 运行时共现；
- SVD 中同实例/同 base 的邻近关系；
- PDF 局部邻域与手册语义；
- 命名启发式兜底；
- 跨窗口与跨 cycle 的动态热点迁移。

---

## 6. Strategy Space / 策略空间

## 6.1 Heuristic strategy families / heuristic 策略家族

### English

Heuristic planning remains the guaranteed fallback and currently covers:

- ready-bit set style polling relief;
- busy-bit clear style polling relief;
- config-bit set/clear/toggle;
- bounded status/data interactions;
- simple control/status gating;
- configuration group candidates for longer warmup hot families.

### 中文

heuristic planning 仍然是稳定保底，当前覆盖：

- ready-bit set 类 polling relief；
- busy-bit clear 类 polling relief；
- config-bit set/clear/toggle；
- 受约束的 status/data 交互；
- 简单 control/status gating；
- 针对更长 warmup 中热点家族的 configuration group 候选。

## 6.2 LLM strategy candidate patterns / LLM 策略候选模式

### English

Current LLM-generated candidates typically fall into these bounded patterns:

- control enable then status-ready observation;
- status/data receive pairing;
- write then status-progress observation;
- FIFO flush/enable then readiness observation;
- configuration convergence candidates for non-UART families;
- multi-stage state convergence candidates such as MCG configuration/status convergence.

### 中文

当前 LLM 生成的候选通常落在这些受约束模式中：

- control enable 后再观察 status-ready；
- status/data 接收配对；
- write 后观察 status-progress；
- FIFO flush/enable 后观察 ready；
- 面向非 UART 家族的 configuration convergence 候选；
- 多阶段状态收敛候选，例如 MCG configuration/status convergence。

## 6.3 Runtime-safe normalization / runtime-safe 归一化

### English

A major recent evolution is that synthesis no longer trusts helper-like actions to survive unchanged. Candidate actions are normalized toward runtime-safe primitives:

- helper-like gates → `mmio_write_observe + mmio_read_sequence`
- repeated overrides → bounded `mmio_read_sequence`
- latent write-trigger chains → `activate_stage + when_stage_active`

This change was necessary because the system repeatedly hit compile/runtime contract mismatches such as missing `repeat`, `read_value`, or `write_addr`.

### 中文

最近一个重要演进是：合成阶段不再默认 helper-like actions 能原样进入 runtime。候选动作会被主动归一化到 runtime-safe primitive 上：

- helper-like gate → `mmio_write_observe + mmio_read_sequence`
- repeated override → 有界的 `mmio_read_sequence`
- 潜在的 write-trigger 链 → `activate_stage + when_stage_active`

这一变化是必要的，因为系统之前反复遇到 compile/runtime 契约不匹配问题，例如 `repeat`、`read_value`、`write_addr` 缺失。

---

## 7. LLM Strategy Layer / LLM 策略层细节

## 7.1 Role / 定位

### English

The LLM strategy layer is a bounded planning adapter, not a free-form generator. It performs:

1. allowed register cluster construction;
2. prompt payload/text construction;
3. LLM API call or JSON-file loading;
4. raw candidate linting;
5. candidate sanitize;
6. unsafe helper downgrade to runtime-safe primitives;
7. augmented task-context injection;
8. normalization through `strategy_planner.py`;
9. merge into `plan.json`;
10. debug artifact emission.

### 中文

LLM strategy layer 是受约束规划适配层，而不是自由生成器。它负责：

1. 构造 allowed register cluster；
2. 构造 prompt payload/text；
3. 调用 LLM API 或加载 JSON 文件；
4. raw candidate lint；
5. candidate sanitize；
6. 将不安全 helper 降级成 runtime-safe primitives；
7. 注入 augmented task context；
8. 交给 `strategy_planner.py` normalize；
9. 合并进 `plan.json`；
10. 输出调试产物。

## 7.2 Debug artifacts / 调试产物

### English

The layer emits:

- `llm_strategy_prompt.json`
- `llm_strategy_prompt.txt`
- `llm_strategy_raw.json`
- `llm_strategy_raw.txt`
- `llm_strategy_lint_raw.json`
- `llm_strategy_lint_sanitized.json`
- `llm_strategy_extracted.json`
- `llm_strategy_augmented_task_context.json`
- `llm_strategy_normalized.json`
- `llm_strategy_rejection_debug.json`
- `llm_strategy_merge_report.json`

These files allow debugging at raw, sanitized, normalized, and merged levels.

### 中文

这一层会输出：

- `llm_strategy_prompt.json`
- `llm_strategy_prompt.txt`
- `llm_strategy_raw.json`
- `llm_strategy_raw.txt`
- `llm_strategy_lint_raw.json`
- `llm_strategy_lint_sanitized.json`
- `llm_strategy_extracted.json`
- `llm_strategy_augmented_task_context.json`
- `llm_strategy_normalized.json`
- `llm_strategy_rejection_debug.json`
- `llm_strategy_merge_report.json`

这些文件允许分别在 raw、sanitized、normalized、merged 层面定位问题。

---

## 8. Budget-Driven Outer Loop / 总预算驱动外层闭环

## 8.1 Why the outer loop was added / 为什么要加入外层闭环

### English

The earlier long-horizon mode could run multiple windows, but it was still fundamentally a finite pilot. It did not fully express the desired experiment structure:

1. warm up from zero;
2. choose the best frontier;
3. plan around current hotspots;
4. run a short tournament;
5. preserve more than one promising branch;
6. run the winner for a medium horizon;
7. re-observe and re-plan;
8. repeat until a 12h/24h budget is exhausted.

The budget-driven outer loop now makes this structure explicit.

### 中文

早期 long-horizon 模式虽然可以跑多个窗口，但本质上仍然是有限 pilot。它没有完整表达我们现在想要的实验结构：

1. 从零 warmup；
2. 选择最好的 frontier；
3. 围绕当前热点规划；
4. 进行短时 tournament；
5. 保留不止一个有希望的分支；
6. 对 winner 做中等时长运行；
7. 重新观察并重新规划；
8. 持续循环直到 12h/24h 总预算耗尽。

budget-driven outer loop 现在把这个结构显式化。

## 8.2 High-level cycle structure / 高层 cycle 结构

### English

When `--total-budget` is provided, the materialized PDF/SVD route enters budget-driven mode.

The loop structure is:

```text
cycle_001:
  bootstrap staged materialization
  short tournament from current frontier
  long-horizon winner windows
  select beam top-2

cycle_002..N:
  import champion frontier from previous cycle
  re-materialize evidence on new hotspot frontier
  short tournament
  long-horizon winner windows
  select beam top-2

stop when total wall-clock budget is exhausted
```

There is intentionally no `--max-cycles`. The loop is governed by `--total-budget`, which keeps parameters simpler and avoids having two competing stopping criteria.

### 中文

当传入 `--total-budget` 时，materialized PDF/SVD 路线会进入总预算驱动模式。

循环结构如下：

```text
cycle_001:
  bootstrap staged materialization
  从当前 frontier 出发进行短时 tournament
  运行 long-horizon winner windows
  选择 beam top-2

cycle_002..N:
  从上一轮 champion frontier import
  针对新的 hotspot frontier 重新 materialize evidence
  短时 tournament
  long-horizon winner windows
  选择 beam top-2

直到总 wall-clock budget 耗尽后停止
```

这里有意不增加 `--max-cycles`。循环由 `--total-budget` 统一控制，减少参数数量，也避免出现两个相互竞争的停止条件。

## 8.3 Beam width = 2 / 保留 beam width = 2

### English

The current long-loop design uses **beam width = 2** by default. This avoids over-committing to a single short-term winner.

The beam is selected from the long-horizon strategy pool using accumulated strategy signals such as:

- credit;
- selected/run window counts;
- cumulative coverage delta;
- cumulative intervention signals;
- action firing/progress signals.

The top entries are stored in each cycle summary and in the final budget-loop summary.

### 中文

当前长闭环默认采用 **beam width = 2**。这样可以避免系统过早押注在一个短期 winner 上。

beam 从 long-horizon strategy pool 中选择，参考信号包括：

- credit；
- selected/run window 次数；
- 累计 coverage delta；
- 累计 intervention signals；
- action firing/progress signals。

top entries 会写入每个 cycle summary 和最终 budget-loop summary。

## 8.4 Winner run and segmentation / winner run 与分段

### English

The winner medium-horizon phase is controlled by:

- `--winner-run-for`
- `--winner-run-segment`

Internally, the number of winner windows is approximately:

```text
ceil(winner-run-for / winner-run-segment)
```

For example:

```text
--winner-run-for 7200s
--winner-run-segment 1800s
```

means approximately four 30-minute windows per cycle.

Segmentation is useful because it gives the system chances to observe coverage trend, hotspot migration, and strategy-pool credit over time rather than treating the winner run as one opaque block.

### 中文

winner 中等时长阶段由以下参数控制：

- `--winner-run-for`
- `--winner-run-segment`

内部 winner windows 数量大约是：

```text
ceil(winner-run-for / winner-run-segment)
```

例如：

```text
--winner-run-for 7200s
--winner-run-segment 1800s
```

表示每个 cycle 约四个 30 分钟窗口。

分段的好处是：系统可以逐段观察 coverage 趋势、热点迁移和 strategy-pool credit，而不是把 winner run 当作一个不可分析的长黑盒。

## 8.5 Stopping rule / 停止规则

### English

The loop stops when:

- total elapsed wall-clock time reaches `--total-budget`; or
- the remaining budget is too small for another meaningful cycle.

The summary is always written to:

```text
<out-root>/adaptive_mmio_loop_summary.json
```

### 中文

循环停止条件是：

- 总 wall-clock 时间达到 `--total-budget`；或
- 剩余预算已经不足以执行一个有意义的 cycle。

最终 summary 总是写入：

```text
<out-root>/adaptive_mmio_loop_summary.json
```

---

## 9. Current Validated Status / 当前已验证状态

## 9.1 Already validated / 已验证内容

### English

The following have been validated in the current repository state:

- Console baseline fuzzing is runnable;
- MMIO observer works;
- SVD address resolution works;
- shared PDF/SVD cache reuse works;
- heuristic candidates are non-empty;
- LLM candidates can be sanitized, normalized, compiled, and executed;
- earlier parser/contract issues such as missing `repeat`, `read_value`, and `write_addr` have been eliminated in the v9 short-smoke path;
- v9 short smoke compiled eight guidance files and executed candidate branches without parser failure;
- medium pilot logs show that longer warmup can shift hotspot families from UART-only to mixed MCG/UART/PORT/SMC, which is now treated as expected behavior rather than a bug;
- the new v10 budget-driven route has been added to `adaptive-mmio-loop` for the materialized PDF/SVD path.

### 中文

当前仓库状态下，已经验证通过的包括：

- Console baseline fuzz 可运行；
- MMIO observer 正常工作；
- SVD 地址解析可用；
- shared PDF/SVD cache 复用可用；
- heuristic 候选非空；
- LLM 候选已经能完成 sanitize、normalize、compile 与 runtime 执行；
- 早期出现过的 `repeat`、`read_value`、`write_addr` 缺失问题，在 v9 短 smoke 路径中已被清掉；
- v9 短 smoke 已成功编译 8 条 guidance，并在无 parser failure 的情况下执行候选分支；
- medium pilot 日志显示，更长 warmup 会把热点从 UART-only 推向 MCG/UART/PORT/SMC 混合家族，这现在被视为预期行为而不是 bug；
- 新的 v10 budget-driven route 已经接入 `adaptive-mmio-loop` 的 materialized PDF/SVD 路线。

## 9.2 Still uncertain / 仍需验证内容

### English

The main uncertainty is no longer parser correctness. It is strategy quality under longer time budgets:

- which candidate families remain effective after 2h winner runs;
- whether beam width = 2 preserves enough diversity;
- whether MCG-like mixed-family planning needs stronger PDF evidence or family bias;
- whether repeated cycles improve final coverage relative to a single long random/control run.

### 中文

当前主要不确定性已经不再是 parser 正确性，而是更长时间预算下的策略质量：

- 哪些候选家族在 2h winner run 后仍然有效；
- beam width = 2 是否能保留足够多样性；
- MCG 这类 mixed-family planning 是否需要更强 PDF evidence 或 family bias；
- 重复 cycle 是否能相比单条长 random/control run 带来更高最终覆盖率。

---

## 10. Typical Commands / 典型命令

## 10.1 Short integrated smoke / 短时集成 smoke

### English

Use this to check parser cleanliness and candidate compilation, not long-term quality.

### 中文

这个命令用于检查 parser 干净程度与候选编译，不用于判断长期策略质量。

```bash
rm -rf workdir/console_llm_strategy_closedloop_smoke_v9

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
  --out-root workdir/console_llm_strategy_closedloop_smoke_v9 \
  --warmup-run-for 120s \
  --candidate-run-for 60s \
  --main-window-count 4 \
  --main-window-run-for 120s \
  --strategy-trial-windows 2 \
  --strategy-pool-max-size 8 \
  --strategy-control-every-windows 2 \
  --adaptive-period-windows 2 \
  --adaptive-plateau-windows 2 \
  --enable-llm-strategy \
  --llm-strategy-mode api \
  --llm-strategy-version v9_smoke \
  --llm-strategy-max-candidates 4 \
  --llm-strategy-max-output-tokens 4000 \
  --llm-strategy-max-attempts 2 \
  2>&1 | tee workdir/console_llm_strategy_closedloop_smoke_v9_driver.log
```

## 10.2 Medium pilot without total-budget / 无总预算中等 pilot

### English

Use this when you want one finite pilot with longer warmup and more long-horizon windows.

### 中文

当你只想跑一轮有限 pilot，但希望 warmup 和 long-horizon windows 更长时，使用这个模式。

```bash
rm -rf workdir/console_llm_strategy_pilot_v9_900s

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
  --out-root workdir/console_llm_strategy_pilot_v9_900s \
  --warmup-run-for 1800s \
  --candidate-run-for 120s \
  --main-window-count 12 \
  --main-window-run-for 180s \
  --strategy-trial-windows 2 \
  --strategy-pool-max-size 8 \
  --strategy-control-every-windows 5 \
  --adaptive-period-windows 3 \
  --adaptive-plateau-windows 2 \
  --probe-run-for 90s \
  --followup-run-for 120s \
  --portfolio-run-for 90s \
  --enable-llm-strategy \
  --llm-strategy-mode api \
  --llm-strategy-version v9_medium_pilot \
  --llm-strategy-max-candidates 4 \
  --llm-strategy-max-output-tokens 4000 \
  --llm-strategy-max-attempts 2 \
  2>&1 | tee workdir/console_llm_strategy_pilot_v9_900s_driver.log
```

## 10.3 Budget-driven 12-hour long loop / 总预算驱动 12 小时长闭环

### English

This is the new recommended mode for long-horizon evaluation. It keeps cycling until the total budget is consumed.

### 中文

这是当前推荐的长时评估模式。它会持续循环直到总预算耗尽。

```bash
rm -rf workdir/console_budget_loop_12h

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
  --candidate-run-for 120s \
  --probe-run-for 90s \
  --followup-run-for 120s \
  --portfolio-run-for 90s \
  --strategy-pool-max-size 2 \
  --beam-width 2 \
  --total-budget 12h \
  --winner-run-for 7200s \
  --winner-run-segment 1800s \
  --enable-llm-strategy \
  --llm-strategy-mode api \
  --llm-strategy-version v9_long_horizon \
  --llm-strategy-max-candidates 4 \
  --llm-strategy-max-output-tokens 4000 \
  --llm-strategy-max-attempts 2 \
  2>&1 | tee workdir/console_budget_loop_12h_driver.log
```

## 10.4 Budget-driven 24-hour version / 总预算驱动 24 小时版本

### English

For a 24h run, usually only change `--total-budget` and `--out-root`:

### 中文

如果要跑 24h，通常只需要改 `--total-budget` 和 `--out-root`：

```bash
--out-root workdir/console_budget_loop_24h \
--total-budget 24h
```

Keep `--winner-run-for 7200s` and `--winner-run-segment 1800s` unless there is a specific reason to make winner windows longer.

除非有特别原因，否则先保持 `--winner-run-for 7200s` 和 `--winner-run-segment 1800s`，不要一开始就把 winner window 拉得过长。

---

## 11. Time Budget Interpretation / 时间预算解释

### English

Important parameters:

- `--total-budget`: total wall-clock budget for the outer loop.
- `--warmup-run-for`: bootstrap/initial seed run duration in a materialized cycle.
- `--candidate-run-for`: short tournament duration per candidate branch.
- `--winner-run-for`: medium-horizon winner budget per cycle.
- `--winner-run-segment`: segment/window size for the winner phase.
- `--beam-width`: number of top branches retained as beam entries. Current recommended value: `2`.

Approximate winner window count:

```text
winner_window_count = ceil(winner-run-for / winner-run-segment)
```

For example:

```text
winner-run-for = 7200s
winner-run-segment = 1800s
winner_window_count = 4
```

The actual wall-clock time also includes evidence construction, Ghidra reuse/generation, PDF/SVD lookup, LLM calls, JSON writing, and process shutdown slack.

### 中文

关键参数含义：

- `--total-budget`：外层闭环总 wall-clock 预算。
- `--warmup-run-for`：materialized cycle 中 bootstrap/initial seed run 时长。
- `--candidate-run-for`：短时 tournament 中每个候选分支的运行时间。
- `--winner-run-for`：每个 cycle 中 winner 中等时长运行预算。
- `--winner-run-segment`：winner phase 的分段窗口大小。
- `--beam-width`：保留的 top branch 数量。当前推荐值是 `2`。

winner window 数量大约为：

```text
winner_window_count = ceil(winner-run-for / winner-run-segment)
```

例如：

```text
winner-run-for = 7200s
winner-run-segment = 1800s
winner_window_count = 4
```

实际 wall-clock 时间还包括 evidence 构建、Ghidra 复用/生成、PDF/SVD 查询、LLM 调用、JSON 写入以及进程退出 slack。

---

## 12. Key Artifacts / 关键产物

### English

Key artifacts under `--out-root`:

```text
adaptive_mmio_loop_summary.json
budget_loop/
  cycle_001/
    budget_cycle_summary.json
    bootstrap/
      report/staged_loop_summary.json
      materialized_long_horizon_summary.json
  cycle_002/
    budget_cycle_summary.json
    replan/
      ...
```

Important files to inspect:

- `adaptive_mmio_loop_summary.json`
- `budget_loop/cycle_*/budget_cycle_summary.json`
- `report/round_*_summary.json`
- `materialized_long_horizon_summary.json`
- `evidence_pack.json`
- `task_context.json`
- `plan.json`
- `guidance_index.json`
- `guidance_runtime_summary.json`
- `plan/llm_strategy/llm_strategy_merge_report.json`
- `plan/llm_strategy/llm_strategy_normalized.json`

### 中文

`--out-root` 下的关键产物：

```text
adaptive_mmio_loop_summary.json
budget_loop/
  cycle_001/
    budget_cycle_summary.json
    bootstrap/
      report/staged_loop_summary.json
      materialized_long_horizon_summary.json
  cycle_002/
    budget_cycle_summary.json
    replan/
      ...
```

建议重点检查：

- `adaptive_mmio_loop_summary.json`
- `budget_loop/cycle_*/budget_cycle_summary.json`
- `report/round_*_summary.json`
- `materialized_long_horizon_summary.json`
- `evidence_pack.json`
- `task_context.json`
- `plan.json`
- `guidance_index.json`
- `guidance_runtime_summary.json`
- `plan/llm_strategy/llm_strategy_merge_report.json`
- `plan/llm_strategy/llm_strategy_normalized.json`

---

## 13. Practical Checks / 实用检查命令

### 13.1 Check that the budget loop started / 检查 budget loop 是否启动

```bash
cat workdir/console_budget_loop_12h/adaptive_mmio_loop_summary.json
find workdir/console_budget_loop_12h/budget_loop -name budget_cycle_summary.json | sort
```

### 13.2 Check parser cleanliness / 检查 parser 是否干净

```bash
grep -n "failed to parse guidance\|missing field \`write_addr\`\|missing field \`repeat\`\|missing field \`read_value\`" \
  workdir/console_budget_loop_12h_driver.log
```

Expected result: no output.

期望结果：没有输出。

### 13.3 Inspect beam and final frontier / 查看 beam 与最终 frontier

```bash
python3 - <<'PY'
import json
from pathlib import Path
p = Path('workdir/console_budget_loop_12h/adaptive_mmio_loop_summary.json')
d = json.loads(p.read_text())
print('mode:', d.get('mode'))
print('elapsed:', d.get('elapsed_budget_secs'))
print('beam_width:', d.get('beam_width'))
print('cycles:', len(d.get('cycles', [])))
print('final_queue_dir:', d.get('final_queue_dir'))
print('\nfinal beam:')
for x in d.get('final_beam') or []:
    print(x.get('name') or x.get('selected_strategy_name'), 'credit=', x.get('credit'))
PY
```

### 13.4 Inspect each cycle / 查看每个 cycle

```bash
python3 - <<'PY'
import json
from pathlib import Path
for p in sorted(Path('workdir/console_budget_loop_12h/budget_loop').glob('cycle_*/budget_cycle_summary.json')):
    d = json.loads(p.read_text())
    print('\n==', p)
    print('cycle:', d.get('cycle_index'))
    print('kind:', d.get('kind'))
    print('elapsed_after:', d.get('elapsed_budget_after_cycle_secs'))
    print('champion_queue:', d.get('champion_queue_dir'))
    print('beam:')
    for x in d.get('beam') or []:
        print('  ', x.get('name') or x.get('selected_strategy_name'), 'credit=', x.get('credit'))
PY
```

---

## 14. Common Failure Modes / 常见失败类型

### English

Earlier common failures included:

- `invalid_guidance`
- `unsupported_action`
- missing parser fields such as `repeat`, `read_value`, `write_addr`
- empty candidate sets
- unfair comparison from inconsistent import frontiers

Current practical failure modes are shifting toward:

- `no_effect` candidates;
- `weak_effect` candidates;
- strategy quality divergence;
- hotspot-family drift in longer runs;
- incomplete PDF evidence for some families such as MCG;
- too-small budgets that make the control baseline look artificially low;
- over-commitment to one short-term winner if beam width is too small.

### 中文

早期常见失败包括：

- `invalid_guidance`
- `unsupported_action`
- parser 字段缺失，如 `repeat`、`read_value`、`write_addr`
- 空候选集
- import frontier 不一致导致比较不公平

当前更常见的实际问题正在转向：

- `no_effect` 候选；
- `weak_effect` 候选；
- 策略质量分化；
- 更长运行中的热点家族漂移；
- 某些家族（如 MCG）PDF evidence 覆盖不足；
- 预算过短导致 control baseline 看起来异常偏低；
- beam width 太小导致系统过早押注在一个短期 winner 上。

---

## 15. Recommended Validation Plan / 推荐验证计划

### 15.1 Before 12h / 12 小时前

### English

Before committing to a 12h run:

1. run `python3 -m py_compile extractor/closed_loop.py extractor/llm_strategy_layer.py`;
2. run a short smoke and confirm no parser failure;
3. run one medium pilot and check that baseline coverage recovers from the very short-smoke range;
4. run the 12h budget loop with `beam-width=2`.

### 中文

进入 12h 前建议：

1. 跑 `python3 -m py_compile extractor/closed_loop.py extractor/llm_strategy_layer.py`；
2. 跑短 smoke，确认没有 parser failure；
3. 跑一个中等 pilot，确认 baseline coverage 不再停留在极短 smoke 的偏低区间；
4. 用 `beam-width=2` 跑 12h budget loop。

### 15.2 For 12h / 12 小时测试

### English

For the first true long-horizon experiment:

- use `--total-budget 12h`;
- use `--winner-run-for 7200s`;
- use `--winner-run-segment 1800s`;
- keep `--beam-width 2`;
- keep driver logging with `tee`.

Do not add `--max-cycles`; the loop is intentionally governed by `--total-budget` only.

### 中文

第一次真正长时实验建议：

- 使用 `--total-budget 12h`；
- 使用 `--winner-run-for 7200s`；
- 使用 `--winner-run-segment 1800s`；
- 保持 `--beam-width 2`；
- 用 `tee` 保存 driver log。

不要再增加 `--max-cycles`；当前设计有意只用 `--total-budget` 作为外层停止条件。

### 15.3 For 24h and longer / 24 小时及更长

### English

For 24h+ experiments, change only:

- `--total-budget`;
- `--out-root`;
- optionally `--winner-run-for` if 2h winner phases are too short.

Avoid changing many knobs at once. Otherwise, it becomes hard to attribute improvements or regressions.

### 中文

对于 24h+ 实验，优先只改：

- `--total-budget`；
- `--out-root`；
- 如果 2h winner phase 确实太短，再考虑改 `--winner-run-for`。

不要一次改太多参数，否则后面很难判断提升或退化来自哪里。

---

## 16. Final Summary / 最终总结

### English

The current system has evolved from a basic staged hotspot-repair loop into a **budget-driven long-horizon closed loop** with bounded LLM expansion, runtime-safe normalization, fair tournament comparison, strategy-pool evaluation, beam preservation, medium-horizon winner runs, and repeated re-planning.

The most important milestone already achieved is not perfect strategy quality. It is that the pipeline can now close the loop:

- observe hotspots;
- build evidence;
- generate bounded candidates;
- normalize and compile them;
- execute candidates without parser collapse;
- compare branches fairly;
- preserve promising frontiers;
- re-plan under a global time budget.

This makes the next stage possible: measuring whether repeated evidence-guided cycles outperform simple long random/control fuzzing over 12h, 24h, or longer.

### 中文

当前系统已经从一个基础 staged hotspot-repair loop，演化成一个**总预算驱动的长时闭环系统**：它具备受限 LLM 扩展、runtime-safe normalization、公平 tournament 比较、strategy-pool 评估、beam 保留、中等时长 winner run，以及重复 re-plan 能力。

当前最重要的里程碑不是策略质量已经完美，而是系统现在已经能真正闭环：

- 观察热点；
- 构建证据；
- 生成受约束候选；
- normalize 并 compile；
- 在不再因 parser mismatch 崩掉的情况下执行候选；
- 公平比较分支；
- 保留有希望的 frontier；
- 在全局时间预算下重新规划。

这使得下一阶段成为可能：评估这种重复证据引导 cycle 是否能在 12h、24h 或更长时间尺度上，优于简单的长时间 random/control fuzzing。
