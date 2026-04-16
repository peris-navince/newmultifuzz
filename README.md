# Staged and Adaptive Evidence-Guided Fuzzing for MMIO Hotspots
# 面向 MMIO 热点的分阶段与自适应证据引导模糊测试

## 1. Overview / 项目概述

### English

This project extends MCU firmware rehosting fuzzing with an **evidence-grounded, staged, and now adaptive** strategy loop around MMIO hotspots.

The system no longer treats MMIO handling as a one-shot manual patching problem, nor as a purely static knowledge-extraction problem. Instead, it runs firmware, observes runtime MMIO bottlenecks, resolves hotspot addresses with SVD and PDF evidence, groups related registers, synthesizes bounded strategy candidates, and compares them fairly from the same imported frontier.

The current design has evolved beyond the earlier “heuristic hotspot repair” pipeline in three important ways:

1. **Runtime evidence remains primary**, but the system now supports richer hotspot families and mixed hotspot clusters instead of assuming a single peripheral family will always dominate.
2. **Candidate generation is hybrid**: heuristic candidates remain the guaranteed fallback, while an LLM strategy layer can generate bounded multi-register strategies inside an explicit whitelist derived from runtime + SVD + PDF evidence.
3. **Evaluation is no longer only short single-round repair**: the system now supports warmup-frontier reuse, adaptive tournaments, strategy-pool style long-horizon comparison, and promotion based on measured outcomes.

The practical goal is not to solve all peripherals at once, but to make the loop reliable and repeatable:

- run firmware and observe bottlenecks,
- extract bounded evidence,
- build hotspot groups or mixed hotspot families,
- generate constrained strategy candidates,
- compare them from the same imported frontier,
- keep the branches that measurably help execution move forward.

### 中文

本项目面向 MCU 固件重宿主 fuzzing，在 MMIO 热点附近构建一个**基于证据、分阶段、并逐步演化为自适应**的策略闭环。

系统不再把 MMIO 处理看成“一次性手工修补”的问题，也不再把它仅仅视为一个纯静态知识抽取问题。当前流程会先运行固件，观察运行时 MMIO 卡点，再结合 SVD 与 PDF 手册证据解析热点地址，构造相关寄存器组，生成受约束的策略候选，并从同一 imported frontier 出发进行公平比较。

相较于早期“heuristic 热点修补”版本，当前设计已经有三方面演进：

1. **运行时证据仍然优先**，但系统现在能处理更复杂的热点族与混合热点簇，而不再默认只有单一外设家族主导卡点。
2. **候选生成变为混合式**：heuristic 候选仍然是稳定保底；同时引入了 LLM strategy layer，在 runtime + SVD + PDF 推导出的显式白名单内生成受约束的多寄存器策略。
3. **评估不再只是短时单轮修补**：系统现在支持 warmup frontier 复用、自适应 tournament、strategy-pool 风格的长时比较，以及基于实测结果的晋级。

当前工作的目标并不是一次性覆盖所有外设，而是把以下闭环做稳定、做可复现：

- 运行固件并观察瓶颈，
- 提取受约束证据，
- 构造热点组或混合热点家族，
- 生成受约束候选，
- 从同一 imported frontier 公平比较，
- 保留那些确实能推动执行向前的分支。

---

## 2. Design Principles / 设计原则

### 2.1 Runtime evidence first / 运行时证据优先

### English

The system does not let static priors dominate when runtime traces say otherwise.

Candidate generation and evaluation are grounded in three evidence layers:

- **Runtime evidence**: hotspot MMIO addresses, touch counts, coverage plateaus, last-PC locality, probe/followup behavior, candidate firing behavior.
- **SVD evidence**: peripheral instance, register identity, address layout, field positions, register width, access type.
- **PDF evidence**: register descriptions, field semantics, ready/busy wording, mode transitions, interrupt wording, local memory-map context.

Runtime evidence determines **what is worth trying now**. SVD and PDF evidence determine **how far the system is allowed to generalize**.

### 中文

系统不会让静态先验在运行时证据已经指向其他方向时仍然主导决策。

当前候选生成与评估建立在三层证据之上：

- **运行时证据**：热点 MMIO 地址、touch 次数、coverage 平台期、last-PC 局部性、probe/followup 行为、candidate 的触发情况。
- **SVD 证据**：外设实例、寄存器身份、地址布局、字段位置、寄存器位宽、访问权限。
- **PDF 证据**：寄存器说明、字段语义、ready/busy 表述、模式切换、中断描述、局部 memory map 上下文。

运行时证据决定的是**当前最值得尝试什么**；SVD 与 PDF 决定的是**系统可以在多大范围内合法泛化**。

### 2.2 Bounded action space / 受约束动作空间

### English

Neither heuristics nor the LLM are allowed to invent arbitrary runtime DSL syntax. All candidate strategies must eventually compile into the supported structured guidance action space.

At the current stage, supported action families include runtime primitives such as:

- `mmio_bit_update`
- `mmio_read_override_once`
- `mmio_read_sequence`
- `mmio_write_observe`
- stage activation + `when_stage_active`

The system previously allowed more gate-like forms during synthesis, but the current pipeline normalizes them into more conservative primitive combinations before runtime execution when necessary.

### 中文

无论是 heuristic 还是 LLM，都不允许自由发明 runtime DSL 语法。所有候选最终都必须落入 runtime 已支持的结构化 guidance 动作空间。

当前支持的动作族主要包括：

- `mmio_bit_update`
- `mmio_read_override_once`
- `mmio_read_sequence`
- `mmio_write_observe`
- stage 激活 + `when_stage_active`

系统早期曾允许在合成阶段保留一些更像 gate 的中间形式，但当前版本在必要时会先将其归一化为更保守的 primitive 组合，再交给 runtime 执行。

### 2.3 Fair comparison from the same prefix / 从同一前缀公平比较

### English

All candidates must start from the same imported queue/frontier. This is a hard requirement. Otherwise, candidate quality becomes confounded with corpus luck.

The system therefore preserves:

- a warmup frontier,
- per-round import reuse,
- control branches,
- identical per-candidate short budgets inside the same tournament.

### 中文

所有候选都必须从同一个 imported queue/frontier 出发。这是硬约束。否则，候选质量会和语料随机性混在一起，无法公平比较。

因此系统始终保留：

- warmup frontier，
- 每轮 import 复用，
- control 分支，
- 同一 tournament 内一致的 per-candidate 短预算。

### 2.4 Evidence-bounded LLM assistance / 受证据约束的 LLM 辅助

### English

The LLM is not allowed to act as an unconstrained policy generator. Its role is bounded to:

- choosing candidate structures within an allowed register cluster,
- proposing multi-register state-advancing strategies,
- staying inside supported action/trigger families,
- producing JSON that can be normalized and compiled.

Heuristics remain the guaranteed fallback. The LLM augments the candidate space; it does not replace the evidence pipeline.

### 中文

LLM 不能作为无限制策略生成器。它的角色被约束为：

- 在允许的寄存器簇内选择候选结构，
- 提出多寄存器、能推动状态前进的策略，
- 严格限制在支持的 action/trigger 家族内，
- 输出可被 normalize 和 compile 的 JSON。

heuristic 仍然是稳定保底；LLM 的作用是扩展候选空间，而不是替代证据管线。

### 2.5 Iterative stabilization / 迭代式稳定化

### English

The system is intentionally developed through short validation loops:

1. single-file unit validation,
2. compile-time validation,
3. short integrated smoke,
4. repeated short-run regression,
5. medium pilot,
6. only then long-horizon run.

This is deliberate: parser correctness must be solved before strategy quality, and strategy quality must be checked before long-duration evaluation.

### 中文

系统刻意采用短闭环逐步稳定的开发方式：

1. 单文件单测，
2. 编译层验证，
3. 短时 integrated smoke，
4. 重复短跑回归，
5. 中等时长 pilot，
6. 最后才进入长时 run。

这是有意为之的：必须先解决 parser/契约问题，再解决策略质量问题；而策略质量确认后，才适合进入长时间评估。

---

## 3. System Architecture / 系统架构

## 3.1 High-level architecture / 总体结构

### English

The repository now contains four major functional layers:

1. **Fuzz runtime layer** (`hail-fuzz`)
2. **Evidence extraction and context construction layer** (`extractor`)
3. **Strategy planning layer** (heuristic + LLM bounded planning)
4. **Tournament and adaptive orchestration layer** (`closed_loop.py`)

### 中文

当前仓库整体可以分成四层：

1. **fuzz runtime 层**（`hail-fuzz`）
2. **证据提取与上下文构建层**（`extractor`）
3. **策略规划层**（heuristic + LLM bounded planning）
4. **tournament 与自适应调度层**（`closed_loop.py`）

## 3.2 Fuzz runtime layer / fuzz runtime 层

### English

The runtime supports:

- baseline fuzzing,
- MMIO observer export,
- structured guidance execution,
- guidance runtime summary export,
- replay trace export,
- imported frontier reuse.

Relevant environment variables commonly include:

- `GHIDRA_SRC`
- `WORKDIR`
- `RUN_FOR`
- `MF_STREAM_OBSERVER_OUT`
- `MF_MMIO_GUIDANCE_FILE`
- `MF_MMIO_GUIDANCE_SUMMARY_OUT`
- `MF_IMPORT_DIR`

### 中文

当前 runtime 支持：

- baseline fuzz，
- MMIO observer 导出，
- 结构化 guidance 执行，
- guidance runtime summary 导出，
- replay trace 导出，
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

This layer is centered in `extractor/` and now includes:

- address resolution through SVD,
- PDF evidence location with family/instance fallback,
- shared PDF/SVD cache reuse,
- evidence pack construction,
- task context construction,
- hotspot grouping and mixed-family handling,
- heuristic planning,
- LLM strategy prompt construction,
- LLM output sanitization and normalization,
- guidance compilation.

Core files now include:

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

这一层主要位于 `extractor/`，当前已经包括：

- 基于 SVD 的地址解析，
- 带 family/instance fallback 的 PDF evidence 定位，
- shared PDF/SVD cache 复用，
- evidence pack 构建，
- task context 构建，
- 热点分组与混合家族处理，
- heuristic planning，
- LLM strategy prompt 构建，
- LLM 输出的 sanitize / normalize，
- guidance compile。

核心文件目前包括：

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

## 3.4 LLM strategy layer / LLM 策略层

### English

The LLM strategy layer is no longer just a prompt dumper. It now performs a complete bounded planning pass:

1. build an allowed register cluster around the current hotspot,
2. build prompt payload and text,
3. call the LLM (or load JSON),
4. lint raw candidates,
5. sanitize addresses, triggers, widths, and candidate structure,
6. expand or downgrade unsupported helper forms into runtime-safe primitives,
7. inject augmented register nodes into task context,
8. normalize with the shared planner,
9. merge normalized candidates back into the plan,
10. emit debug artifacts for every stage.

This layer is the main place where unsupported LLM outputs are turned into runtime-compatible strategies.

### 中文

LLM strategy layer 现在已经不是简单的 prompt 输出器，而是一个完整的受约束规划通道：

1. 围绕当前热点构造 allowed register cluster，
2. 构造 prompt payload 与 prompt text，
3. 调用 LLM（或加载 JSON），
4. 对 raw candidates 做 lint，
5. 对地址、trigger、位宽与候选结构做 sanitize，
6. 将不安全或不兼容的 helper 形式扩展/降级成 runtime-safe primitives，
7. 把 augmented register nodes 注入 task context，
8. 交给共享 planner 做 normalize，
9. 把 normalized candidates 合并回 plan，
10. 为每一步输出调试产物。

这一层目前是把 LLM 输出转换为 runtime 兼容策略的关键位置。

---

## 4. Evidence Model / 证据模型

## 4.1 Runtime evidence / 运行时证据

### English

Runtime evidence currently includes:

- top hotspot MMIO addresses,
- read/write counts,
- width distributions,
- first/last seen order,
- last-PC locality and replay traces,
- per-candidate runtime firing summaries,
- plateau-like behavior across windows.

### 中文

当前运行时证据包括：

- 顶层热点 MMIO 地址，
- 读写次数，
- 宽度分布，
- first/last seen 顺序，
- last-PC 局部性与 replay trace，
- 每个 candidate 的 runtime firing summary，
- 跨窗口的平台期行为。

## 4.2 SVD evidence / SVD 证据

### English

SVD evidence provides:

- peripheral instance,
- register identity,
- field offsets and widths,
- register width bytes,
- access permissions,
- base address and layout proximity.

### 中文

SVD 证据提供：

- 外设实例，
- 寄存器身份，
- 字段偏移与位宽，
- 寄存器宽度，
- 访问权限，
- base address 与布局邻近性。

## 4.3 PDF evidence / PDF 证据

### English

PDF evidence is used for:

- register descriptions,
- field semantics,
- ready/busy/status interpretation,
- mode-transition hints,
- local register neighborhood,
- evidence-backed register cluster expansion.

The current system supports family fallback such as:

- `UART0 -> UART`
- family-level caches when instance-specific cache is incomplete

### 中文

PDF 证据主要用于：

- 寄存器说明，
- 字段语义，
- ready/busy/status 的解释，
- mode transition 提示，
- 寄存器局部邻域，
- 基于证据的寄存器簇扩展。

当前系统支持 family fallback，例如：

- `UART0 -> UART`
- 当 instance-specific cache 不完整时回退到 family 级 cache

## 4.4 Evidence pack / evidence pack

### English

`evidence_pack.json` is the main bounded evidence bundle used by later planning. It is intentionally compact but traceable. It is not a global knowledge base; it is a current-stage planning capsule.

### 中文

`evidence_pack.json` 是后续规划使用的核心受约束证据包。它有意保持紧凑但可追踪。它不是全局知识库，而是一个当前阶段的规划胶囊。

---

## 5. Hotspot Grouping and Mixed Families / 热点分组与混合热点家族

## 5.1 Why grouping is still needed / 为什么仍然需要分组

### English

A hotspot is rarely just one register. A status register often implies control, data, or FIFO companions. Grouping remains necessary to avoid overfitting to a single polling anchor.

Examples:

- `UART0.S1` with `UART0.D`, `UART0.C2`, `UART0.PFIFO`, `UART0.CFIFO`
- `MCG.S` with `MCG.C1/C2/C4/C6`

### 中文

热点通常不只是一个寄存器。一个状态寄存器往往隐含着控制、数据或 FIFO 伴随寄存器。因此，分组仍然是避免过拟合到单一 polling anchor 的关键。

例如：

- `UART0.S1` 与 `UART0.D`、`UART0.C2`、`UART0.PFIFO`、`UART0.CFIFO`
- `MCG.S` 与 `MCG.C1/C2/C4/C6`

## 5.2 Why mixed-family handling became necessary / 为什么现在需要支持混合热点家族

### English

Longer warmup runs revealed that the dominant bottleneck may shift away from the earlier UART-only view. In medium pilots, the hotspot frontier can contain mixed addresses from UART, MCG, PORT, and SMC-like configuration areas. The planner must therefore avoid assuming that a single family always dominates every stage.

### 中文

更长的 warmup 暴露出：主导瓶颈并不总是停留在早期看到的 UART-only 视角。中等时长 pilot 中，热点前沿可能同时包含 UART、MCG、PORT、SMC 等配置相关地址。因此，planner 现在必须避免默认“每个阶段都只有单一家族主导”。

## 5.3 Grouping sources / 分组依据

### English

Grouping uses:

- runtime co-occurrence,
- SVD same-instance or same-base proximity,
- PDF local neighborhood and manual semantics,
- fallback naming heuristics.

### 中文

分组依据包括：

- 运行时共现，
- SVD 中同实例/同 base 的邻近关系，
- PDF 局部邻域与手册语义，
- 命名启发式兜底。

## 5.4 Group kinds / 分组类型

### English

Current group kinds include, but are not limited to:

- `polling_group`
- `status_data_group`
- `status_config_group`
- `config_group`
- mixed configuration convergence groups in longer runs

### 中文

当前分组类型包括但不限于：

- `polling_group`
- `status_data_group`
- `status_config_group`
- `config_group`
- 在更长运行中出现的混合 configuration convergence groups

---

## 6. Strategy Space / 策略空间

## 6.1 Heuristic strategy families / heuristic 策略家族

### English

Heuristic planning remains the guaranteed fallback and currently covers:

- ready-bit set style polling relief,
- busy-bit clear style polling relief,
- config-bit set/clear/toggle,
- bounded status/data interactions,
- simple control/status gating.

### 中文

heuristic planning 仍然是稳定保底，当前覆盖：

- ready-bit set 类 polling relief，
- busy-bit clear 类 polling relief，
- config-bit set/clear/toggle，
- 受约束的 status/data 交互，
- 简单 control/status gating。

## 6.2 LLM strategy candidate patterns / LLM 策略候选模式

### English

Current LLM-generated candidates typically fall into these bounded patterns:

- control enable then status-ready observation,
- status/data receive pairing,
- write then status-progress observation,
- FIFO flush/enable then readiness observation,
- configuration convergence candidates for non-UART families.

### 中文

当前 LLM 生成的候选通常落在这些受约束模式中：

- control enable 后再观察 status-ready，
- status/data 接收配对，
- write 后观察 status-progress，
- FIFO flush/enable 后观察 ready，
- 面向非 UART 家族的 configuration convergence 候选。

## 6.3 Runtime-safe normalization / runtime-safe 归一化

### English

A major recent evolution is that synthesis no longer trusts helper-like actions to survive unchanged. Candidate actions are normalized toward runtime-safe primitives, for example:

- helper-like gates → `mmio_write_observe + mmio_read_sequence`
- repeated overrides → bounded `mmio_read_sequence`
- latent write-trigger chains → `activate_stage + when_stage_active`

This change was necessary because the system repeatedly hit compile/runtime contract mismatches such as missing fields or parser-only helper expectations.

### 中文

最近一个重要演进是：合成阶段不再默认 helper-like actions 能原样进入 runtime。候选动作会被主动归一化到 runtime-safe primitive 上，例如：

- helper-like gate → `mmio_write_observe + mmio_read_sequence`
- repeated override → 有界的 `mmio_read_sequence`
- 潜在的 write-trigger 链 → `activate_stage + when_stage_active`

这一变化是必要的，因为系统之前反复遇到 compile/runtime 契约不匹配问题，例如字段缺失或 parser 只认特定 helper 形式。

---

## 7. LLM Strategy Layer / LLM 策略层细节

## 7.1 What the LLM should not do / LLM 不该做什么

### English

The LLM should not:

- invent new runtime DSL syntax,
- introduce arbitrary peripheral addresses,
- ignore the allowed register cluster,
- bypass normalization,
- bypass compile-time/runtime validation.

### 中文

LLM 不应该：

- 发明新的 runtime DSL 语法，
- 引入任意外设地址，
- 忽略 allowed register cluster，
- 绕过 normalization，
- 绕过 compile/runtime 校验。

## 7.2 What the LLM should do / LLM 应该做什么

### English

The LLM should:

- stay inside the allowed register cluster,
- propose state-advancing multi-register candidates,
- use supported action families only,
- generate candidate JSON that can be sanitized and normalized,
- complement the heuristic baseline rather than replace it.

### 中文

LLM 应该：

- 严格限制在 allowed register cluster 内，
- 提出能推动状态前进的多寄存器候选，
- 只使用支持的 action 家族，
- 输出可被 sanitize/normalize 的 candidate JSON，
- 作为 heuristic baseline 的补充，而不是替代。

## 7.3 Current LLM integration order / 当前 LLM 接入顺序

### English

The current order is:

1. heuristic baseline planning,
2. LLM bounded expansion,
3. sanitize and normalization,
4. compile to guidance,
5. compare inside the same tournament.

### 中文

当前接入顺序是：

1. heuristic baseline planning，
2. LLM bounded expansion，
3. sanitize 与 normalization，
4. compile 为 guidance，
5. 在同一 tournament 内比较。

## 7.4 Debug artifacts emitted by the LLM layer / LLM 层调试产物

### English

The LLM strategy layer now emits a full artifact chain, including:

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

This makes the pipeline debuggable at raw, sanitized, normalized, and merged stages.

### 中文

当前 LLM strategy layer 会输出完整调试链，包括：

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

因此现在可以分别在 raw、sanitized、normalized、merged 四个层面定位问题。

---

## 8. Adaptive and Staged Loop / 分阶段与自适应循环

## 8.1 Core loop / 核心闭环

### English

The current main orchestration command is:

```bash
python3 extractor/closed_loop.py adaptive-mmio-loop ...
```

At a high level, the loop does:

1. warmup fuzzing,
2. observer export,
3. evidence pack construction,
4. task context construction,
5. candidate planning (heuristic + optional LLM bounded expansion),
6. guidance compile,
7. candidate tournament from a shared imported frontier,
8. promotion and continuation.

### 中文

当前主调度命令是：

```bash
python3 extractor/closed_loop.py adaptive-mmio-loop ...
```

高层流程如下：

1. warmup fuzzing，
2. observer 导出，
3. evidence pack 构建，
4. task context 构建，
5. 候选规划（heuristic + 可选 LLM bounded expansion），
6. guidance compile，
7. 从共享 imported frontier 出发进行 candidate tournament，
8. 晋级与继续推进。

## 8.2 Why the loop was redesigned / 为什么这条闭环需要重构

### English

The system moved away from a single-hypothesis repair path because a wrong but bounded static guess could still silently dominate the pipeline. The current loop therefore keeps control branches and compares bounded candidates as a portfolio.

### 中文

系统之所以从“单一路径修补器”演化出来，是因为实践表明：一个方向错误但形式合法的静态假设，仍然可能悄悄主导整条链路。因此当前闭环保留 control 分支，并把受约束候选作为一个 portfolio 来比较。

## 8.3 Adaptive long-horizon behavior / 自适应长视角行为

### English

The current codebase has evolved beyond single-round short smoke. It now supports:

- longer warmup,
- repeated windows,
- strategy-pool style comparison,
- hotspot migration observation,
- promotion based on actual performance rather than only static plausibility.

### 中文

当前代码已经超出了单轮短 smoke 的阶段，支持：

- 更长的 warmup，
- 多个连续窗口，
- strategy-pool 风格比较，
- 热点迁移观察，
- 基于实际效果而不是静态合理性的晋级。

---

## 9. Current Validated Status / 当前已验证状态

## 9.1 What is already validated / 已验证内容

### English

The following are already validated in the current repository state:

- baseline fuzzing for Console is runnable,
- MMIO observer is working,
- SVD address resolution is working,
- shared PDF/SVD cache reuse is working,
- heuristic candidates are non-empty,
- LLM candidates can now be sanitized, normalized, compiled, and executed,
- earlier parser/contract issues such as missing `repeat`, `read_value`, and `write_addr` have been eliminated in the current short smoke path,
- v9 short smoke successfully compiled 8 guidance files and executed all candidate branches without parser failure.

### 中文

当前仓库状态下，已经验证通过的包括：

- Console 的 baseline fuzz 可运行，
- MMIO observer 正常工作，
- SVD 地址解析可用，
- shared PDF/SVD cache 复用可用，
- heuristic 候选非空，
- LLM 候选现在已经能完成 sanitize、normalize、compile 与 runtime 执行，
- 早期出现过的 `repeat`、`read_value`、`write_addr` 缺失问题，在当前短 smoke 路径中已被清掉，
- v9 短 smoke 已成功编译 8 条 guidance，并在无 parser failure 的情况下执行所有候选分支。

## 9.2 What is not yet stable enough / 仍未完全稳定的部分

### English

The current main uncertainty is no longer parser correctness, but strategy quality under longer time budgets. Candidate quality still diverges:

- some LLM candidates become effective,
- some only weakly fire,
- some run correctly but do not translate into coverage.

Longer warmup also revealed that hotspot families may shift toward mixed MCG/UART/PORT/SMC regions, which changes the planning problem itself.

### 中文

当前主要不确定性已经不再是 parser 正确性，而是更长时间预算下的策略质量。候选质量仍然存在明显分化：

- 有些 LLM 候选会变成 effective，
- 有些只会触发但不涨 coverage，
- 有些虽然运行正确但并不能转化成收益。

更长的 warmup 还暴露出：热点家族可能转向 MCG/UART/PORT/SMC 混合区域，这会改变规划问题本身。

---

## 10. Typical Workflow / 典型使用流程

## 10.1 Main entry / 主入口

```bash
python3 extractor/closed_loop.py adaptive-mmio-loop \
  --fuzzer-manifest hail-fuzz/Cargo.toml \
  --firmware-config benchmarks/P2IM/Console/config.yml \
  --ghidra-src tools/ghidra \
  --pdf extractor/text/K64.pdf \
  --svd extractor/svd/NXP/NXP-FRDM-K64F/MK64F12.xml \
  --board FRDM-K64F \
  --mcu MK64F12 \
  --benchmark-name P2IM_Console \
  --materialization-mode staged-loop \
  --out-root workdir/console_run \
  --warmup-run-for 900s \
  --warmup-restarts 1 \
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
  --portfolio-intervention-coverage-slack 64 \
  --enable-llm-strategy \
  --llm-strategy-mode api \
  --llm-strategy-version v9_medium_pilot \
  --llm-strategy-max-candidates 4 \
  --llm-strategy-max-output-tokens 4000 \
  --llm-strategy-max-attempts 2
```

## 10.2 Recommended validation ladder / 推荐验证阶梯

### English

Recommended validation order:

1. unit-test `llm_strategy_layer.py`,
2. check `normalized.json`,
3. run short smoke,
4. ensure no parser failure remains,
5. run repeated short regressions,
6. run a medium pilot,
7. only then run a multi-hour job.

### 中文

推荐的验证顺序：

1. 先做 `llm_strategy_layer.py` 单测，
2. 检查 `normalized.json`，
3. 跑短 smoke，
4. 确认不再有 parser failure，
5. 做重复短跑回归，
6. 再跑中等 pilot，
7. 最后才进入多小时长跑。

---

## 11. Key Artifacts / 关键产物

### English

The most important artifacts to inspect are:

- `evidence_pack.json`
- `task_context.json`
- `plan.json`
- `guidance_index.json`
- `guidance_runtime_summary.json`
- `round_*_summary.json`
- `adaptive_mmio_loop_summary.json`
- LLM strategy artifacts under `plan/llm_strategy/`

### 中文

建议重点检查的文件包括：

- `evidence_pack.json`
- `task_context.json`
- `plan.json`
- `guidance_index.json`
- `guidance_runtime_summary.json`
- `round_*_summary.json`
- `adaptive_mmio_loop_summary.json`
- `plan/llm_strategy/` 下的 LLM 调试产物

---

## 12. Common Failure Modes / 常见失败类型

### English

Earlier common failures included:

- `invalid_guidance`
- `unsupported_action`
- missing parser fields such as `repeat`, `read_value`, `write_addr`
- empty candidate sets
- unfair comparison from inconsistent import frontiers

Current practical failure modes are shifting toward:

- no-effect candidates,
- weak-effect candidates,
- strategy quality divergence,
- hotspot-family drift in longer runs,
- PDF evidence incompleteness for some families (for example MCG cache coverage).

### 中文

早期常见失败包括：

- `invalid_guidance`
- `unsupported_action`
- parser 字段缺失，如 `repeat`、`read_value`、`write_addr`
- 空候选集
- import frontier 不一致导致比较不公平

当前更常见的实际问题正在转向：

- `no_effect` 候选，
- `weak_effect` 候选，
- 策略质量分化，
- 更长运行中的热点家族漂移，
- 某些家族（如 MCG）PDF evidence 覆盖不足。

---

## 13. Recommended Next Steps / 下一步建议

### Short term / 短期

### English

- Keep the current v9 code path stable.
- Continue repeated short-run regression to ensure parser cleanliness remains stable.
- Measure whether the same LLM winners remain effective across multiple short runs.

### 中文

- 保持当前 v9 代码路径稳定，
- 继续做重复短跑回归，确认 parser 层面持续无错误，
- 观察相同 LLM 优胜者是否能在多轮短跑中持续保持 effective。

### Mid term / 中期

### English

- Run medium pilots with longer warmup and more windows.
- Measure whether control baseline recovers toward the previously observed higher coverage range.
- Evaluate whether mixed-family planning should remain unconstrained or be family-biased per stage.

### 中文

- 用更长 warmup 和更多窗口跑中等时长 pilot，
- 观察 control baseline 是否回升到之前更高的 coverage 区间，
- 评估混合家族规划是否应该继续保持开放，还是在每阶段做 family bias。

### Long term / 长期

### English

- Move from parser-stability tuning to strategy-quality tuning.
- Learn which candidate families consistently win under longer budgets.
- Use those wins to refine template priors, group quotas, and promotion policy.
- Only after that commit to multi-hour or overnight runs as the standard mode.

### 中文

- 从 parser 稳定性调优转向策略质量调优，
- 观察哪些候选家族能在更长预算下持续获胜，
- 再据此回调 template priors、group quota 与 promotion policy，
- 最后再把多小时/过夜长跑变成标准模式。

---

## 14. Final Summary / 最终总结

### English

The current system has evolved from a basic staged hotspot-repair loop into a hybrid evidence-guided planning framework with bounded LLM expansion, runtime-safe normalization, and adaptive tournament-style evaluation.

The most important milestone already achieved is not “perfect strategies,” but a **stable closed loop**:

- hotspots can be observed,
- evidence can be built,
- bounded candidates can be produced,
- candidates can be compiled and executed,
- branches can be compared fairly,
- and the pipeline no longer collapses on parser mismatches.

This makes the next phase possible: strategy-quality improvement under longer horizons.

### 中文

当前系统已经从一个基础的 staged hotspot-repair loop，演化成一个带有受限 LLM 扩展、runtime-safe normalization 与自适应 tournament 评估的混合证据驱动规划框架。

当前最重要的里程碑并不是“策略已经完美”，而是已经建立起一个**稳定闭环**：

- 热点能被观察到，
- 证据能被构建，
- 受约束候选能被生成，
- 候选能被编译和执行，
- 分支能被公平比较，
- 整条管线不再因为 parser mismatch 而崩掉。

这才使得下一阶段成为可能：在更长时间尺度上继续提升策略质量。
