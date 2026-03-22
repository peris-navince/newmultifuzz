Staged Evidence-Guided Fuzzing for MMIO Hotspots
面向 MMIO 热点的分阶段证据引导模糊测试
1. Overview / 项目概述

English

This project extends fuzzing for MCU firmware rehosting by introducing an evidence-guided, staged strategy loop around MMIO hotspots. Instead of trying to build a global knowledge base first, the system runs baseline fuzzing, observes hotspot MMIO accesses, resolves them with SVD and PDF manual evidence, groups related hotspot registers, generates bounded strategy candidates, and evaluates them in short tournaments starting from the same checkpoint.

The key idea is to avoid “from-scratch reruns with hand-written one-off tricks” and move toward a repeatable loop:

Run fuzzing until a plateau or stable hotspot region appears.
Extract hotspot evidence from runtime, SVD, and PDF.
Build hotspot groups rather than treating registers independently.
Generate constrained strategy candidates.
Start all candidates from the same prefix corpus/checkpoint.
Run short-budget comparisons and promote the best branch(es).
Continue to the next hotspot stage.

中文

本项目面向 MCU 固件重宿主 fuzzing，目标是在 MMIO 热点附近引入一个证据驱动、分阶段推进的策略闭环。系统不再先尝试构建全局知识库，而是先运行 baseline fuzz，观察热点 MMIO 访问，再结合 SVD 和 PDF 手册证据解析热点寄存器，将相关热点寄存器分组，生成受约束的策略候选，并从同一个 checkpoint 出发做短预算竞争。

核心思想是避免“从零重新跑 + 手工写一次性技巧”，而转向一个可重复的闭环：

先跑 fuzz，直到 coverage 平台期或稳定热点出现。
从运行时、SVD、PDF 中提取热点证据。
不再把寄存器孤立处理，而是构造成热点组。
生成受约束的策略候选。
所有候选从同一个前缀 corpus / checkpoint 出发。
进行短预算比较，选出表现最好的分支。
继续推进到下一个热点阶段。
2. Design Principles / 设计原则
2.1 Evidence-first / 证据优先

English

The system does not let the model invent strategies from pure speculation. Strategy generation is grounded in three evidence sources:

Runtime evidence: hotspot MMIO addresses, access frequencies, and plateau behavior.
SVD evidence: peripheral instance, register identity, fields, addresses, and register layout.
PDF evidence: register descriptions, field semantics, ready/busy/interrupt wording, and local context.

中文

系统不允许模型凭空猜策略。策略生成必须建立在三类证据上：

运行时证据：热点 MMIO 地址、访问频率、coverage 停滞行为。
SVD 证据：外设实例、寄存器身份、字段、地址和寄存器布局。
PDF 证据：寄存器说明、字段语义、ready/busy/interrupt 等描述及上下文。
2.2 Template-constrained / 模板约束

English

The LLM is not allowed to invent arbitrary strategy syntax. It must choose from predefined strategy templates and parameter slots.

This means:

the runtime only executes structured guidance,
the compiler only translates validated candidate structures,
the model only chooses among allowed templates and parameters.

中文

LLM 不允许自由发明策略语法，只能在预定义模板和参数槽位中进行选择。

这意味着：

runtime 只执行结构化 guidance，
compiler 只翻译已校验的候选结构，
模型只在允许的模板和参数中做选择。
2.3 Group-based reasoning / 基于分组的推理

English

Hotspots are not treated as isolated registers. A single high-frequency status register often implies related data or control registers. Therefore, strategy planning operates on hotspot groups, not just single hotspot registers.

中文

热点不再被视为孤立寄存器。一个高频状态寄存器通常意味着相关的数据寄存器或控制寄存器也参与了当前卡点。因此，策略规划基于热点组而不是单独的热点寄存器。

2.4 Prefix reuse / 前缀复用

English

Candidates should not start from scratch. They should reuse the queue/corpus accumulated before reaching the hotspot region. Candidate evaluation must start from the same checkpoint so comparisons are fair.

中文

候选策略不应该从零开始。它们应复用在到达热点区域之前积累下来的 queue/corpus。所有候选都应从同一个 checkpoint 出发，这样比较才公平。

3. Current Architecture / 当前架构
3.1 Fuzzing side (hail-fuzz) / fuzz 端

English

The fuzzing runtime supports:

baseline fuzzing,
MMIO stream observation,
structured guidance loading,
guidance runtime summary,
prefix import via imported queue/corpus.

Key runtime-related environment variables:

GHIDRA_SRC
WORKDIR
RUN_FOR
MF_STREAM_OBSERVER_OUT
MF_MMIO_GUIDANCE_FILE
MF_MMIO_GUIDANCE_SUMMARY_OUT
MF_IMPORT_DIR

中文

当前 fuzz runtime 支持：

baseline fuzz，
MMIO stream observer，
结构化 guidance 加载，
guidance runtime summary，
通过导入 queue/corpus 复用前缀语料。

关键环境变量包括：

GHIDRA_SRC
WORKDIR
RUN_FOR
MF_STREAM_OBSERVER_OUT
MF_MMIO_GUIDANCE_FILE
MF_MMIO_GUIDANCE_SUMMARY_OUT
MF_IMPORT_DIR
3.2 Extractor side (extractor) / 提取与规划端

English

The extractor side currently contains the main pipeline logic:

build evidence pack from observer + SVD + PDF,
build task context,
build hotspot groups,
generate heuristic strategy candidates,
compile candidates into runtime guidance,
run staged loop and evaluate candidates.

Main files include:

closed_loop.py
evidence_builder.py
task_context.py
strategy_catalog.py
strategy_planner.py
guidance_compiler.py
pdf_evidence_locator.py
svd_resolver.py

中文

提取与规划端目前负责主要流程：

从 observer + SVD + PDF 构建 evidence pack，
构建 task context，
构建 hotspot groups，
生成 heuristic 策略候选，
将候选编译成 runtime guidance，
执行 staged loop 并评估候选。

主要文件包括：

closed_loop.py
evidence_builder.py
task_context.py
strategy_catalog.py
strategy_planner.py
guidance_compiler.py
pdf_evidence_locator.py
svd_resolver.py
4. Hotspot Grouping / 热点分组
4.1 Why grouping is needed / 为什么需要分组

English

A hotspot is rarely just one register. For example:

UART0.S1 may be the polling anchor,
UART0.D may be a data companion,
UART0.PFIFO may be a FIFO-related companion.

Similarly:

MCG.S may be a status anchor,
MCG.C1/C2/C4 may be configuration companions.

If only one register is modeled, important dependencies are missed.

中文

热点通常不是一个单独寄存器。例如：

UART0.S1 可能是轮询锚点，
UART0.D 可能是数据伴随寄存器，
UART0.PFIFO 可能是 FIFO 相关伴随寄存器。

类似地：

MCG.S 可能是状态锚点，
MCG.C1/C2/C4 可能是配置伴随寄存器。

如果只建模一个寄存器，就会丢失关键依赖关系。

4.2 Grouping sources / 分组依据

English

Grouping is determined by multiple sources together:

Runtime co-occurrence
registers that repeatedly appear together in hotspot windows;
SVD structure
same peripheral instance,
address proximity,
role-like names such as status/data/control/fifo;
PDF evidence
explicit semantic relations from manual descriptions;
Naming heuristics
fallback rules like S1 + D, S + C1/C2/C4, GPIOx bank groups.

中文

分组由多种来源共同决定：

运行时共现
在热点窗口中反复一起出现的寄存器；
SVD 结构
同一外设实例，
地址邻近，
status/data/control/fifo 等角色化命名；
PDF 证据
手册中显式描述的语义关系；
命名启发式
如 S1 + D、S + C1/C2/C4、GPIOx bank group 等兜底规则。
4.3 Group kinds / 分组类型

English

Current group types include:

polling_group
status_data_group
status_config_group
config_group

中文

当前支持的分组类型包括：

polling_group
status_data_group
status_config_group
config_group
5. Strategy Templates / 策略模板
5.1 Why templates / 为什么使用模板

English

Templates define the bounded action space. Instead of generating unconstrained policies, the system maps each hotspot group type to a limited set of strategy templates.

This keeps the system:

explainable,
compilable,
testable,
safe for staged iteration.

中文

模板用于定义受约束的动作空间。系统不会让模型自由生成无限制策略，而是将每类热点组映射到有限的策略模板集合。

这样系统就能保持：

可解释，
可编译，
可测试，
适合分阶段迭代。
5.2 Example templates / 示例模板

English

For status/data groups such as UART:

poll_ready_bit_set
poll_busy_bit_clear
status_then_data
status_then_config

For config groups:

config_bit_toggle
config_bit_set
config_bit_clear

中文

对于 UART 这类状态+数据组：

poll_ready_bit_set
poll_busy_bit_clear
status_then_data
status_then_config

对于配置组：

config_bit_toggle
config_bit_set
config_bit_clear
5.3 Current status / 当前状态

English

At the current stage, heuristic planning already generates group-based candidates. The planner no longer returns empty candidate lists for the observed UART/MCG/GPIO hotspot layout. However, template coverage is still incomplete and must grow iteratively.

中文

在当前阶段，heuristic planner 已经能够基于热点组生成候选。对于目前观察到的 UART/MCG/GPIO 热点布局，planner 不再返回空候选列表。但模板覆盖仍然不完整，需要逐步迭代扩展。

6. Role of the LLM / LLM 的定位
6.1 What the LLM should not do / LLM 不该做什么

English

The LLM should not:

invent new runtime DSL syntax,
produce arbitrary low-level actions,
ignore the strategy catalog,
directly control the fuzzing runtime.

中文

LLM 不应该：

发明新的 runtime DSL 语法，
生成任意低层动作，
忽略策略目录，
直接控制 fuzz runtime。
6.2 What the LLM should do / LLM 应该做什么

English

The LLM should operate inside the bounded group/template space:

rank candidate templates for a hotspot group,
choose likely fields/bits,
choose trigger families,
optionally expand with a small number of additional bounded candidates.

The recommended integration order is:

Heuristic baseline
LLM rerank
LLM bounded expansion

中文

LLM 应该在受限的 group/template 空间内工作：

对某个热点组内的模板进行排序，
选择更可能的字段/位，
选择更合理的触发族，
可选地补充少量受限的新候选。

推荐的接入顺序是：

Heuristic 保底
LLM rerank
LLM bounded expansion
7. Staged Loop / 分阶段循环
7.1 Why staged loop / 为什么要分阶段循环

English

A single full rerun per candidate is wasteful and unfair. The system should instead:

run to a hotspot plateau,
checkpoint the corpus,
fork candidate branches from the same checkpoint,
run short-budget tournaments,
promote top branches,
continue to the next hotspot.

中文

每个 candidate 都完整重跑一遍既浪费又不公平。系统应改为：

先跑到热点平台期，
保存 checkpoint，
从同一个 checkpoint 分叉出多个候选分支，
进行短预算竞争，
晋级表现更好的分支，
继续推进到下一个热点。
7.2 Current staged-loop status / 当前 staged-loop 状态

English

The staged loop currently supports:

seed round,
prefix import,
shared PDF/SVD cache,
heuristic candidate generation,
guidance compilation,
candidate evaluation,
automatic verdict extraction.

It already records:

imported seed count,
coverage summary,
parse errors,
unsupported action errors,
candidate verdicts such as:
control
invalid_guidance
unsupported_action
no_effect
effective

中文

当前 staged loop 已支持：

seed round，
前缀导入，
共享 PDF/SVD cache，
heuristic 候选生成，
guidance 编译，
candidate 评估，
自动 verdict 提取。

它已经能自动记录：

导入 seed 数量，
coverage 摘要，
guidance 解析错误，
不支持动作错误，
候选 verdict，例如：
control
invalid_guidance
unsupported_action
no_effect
effective
8. Current Progress / 当前进度
Already completed / 已完成

English

Baseline fuzzing for the P2IM Console benchmark runs successfully.
MMIO hotspot observation is working.
SVD address resolution works.
PDF evidence location has been fixed for instance/family mismatches such as:
UART0 -> UART
GPIOB vs GPIOA
Hotspot grouping has been introduced.
Group-based heuristic candidate generation works.
Guidance compilation now validates generated guidance files.
Staged-loop now supports:
shared cache,
binary execution,
import logging,
automated control/candidate verdicts.

中文

P2IM Console benchmark 的 baseline fuzz 已可稳定运行。
MMIO 热点观察已打通。
SVD 地址解析可用。
PDF 证据定位已修复实例/家族不匹配问题，例如：
UART0 -> UART
GPIOB 与 GPIOA 区分
已引入热点分组。
基于分组的 heuristic 候选生成已可工作。
guidance 编译阶段已增加文件合法性校验。
staged-loop 已支持：
共享 cache，
直接执行 binary，
import 日志，
自动 control/candidate verdict。
Not yet complete / 尚未完成

English

Template coverage is still limited.
Cross-peripheral or richer dependency modeling is still incomplete.
Some advanced group templates may compile but still require runtime support.
LLM rerank/expansion is not yet integrated into the main loop.
Scoring and promotion still need more tuning.

中文

模板覆盖仍然有限。
跨外设或更丰富的依赖建模仍不完整。
某些高级 group template 虽然能生成，但可能仍需 runtime 支持。
LLM rerank/expansion 尚未接入主循环。
评分和晋级策略仍需继续调优。
9. Typical Workflow / 典型使用流程
9.1 Baseline or staged-loop entry / 入口

English
Typical entry scripts include:

closed_loop.py run-fuzz
closed_loop.py build-evidence
closed_loop.py build-context
closed_loop.py plan
closed_loop.py compile
closed_loop.py staged-loop

中文
典型入口包括：

closed_loop.py run-fuzz
closed_loop.py build-evidence
closed_loop.py build-context
closed_loop.py plan
closed_loop.py compile
closed_loop.py staged-loop
9.2 Example staged-loop command / 示例 staged-loop 命令
python3 closed_loop.py staged-loop \
  --fuzzer-manifest /home/MultiFuzz/hail-fuzz/Cargo.toml \
  --firmware-config /home/MultiFuzz-benchmarks/benchmarks/P2IM/Console/ \
  --ghidra-src /home/MultiFuzz/tools/ghidra \
  --pdf /home/MultiFuzz/extractor/text/K64.pdf \
  --svd /home/MultiFuzz/extractor/svd/NXP/NXP-FRDM-K64F/MK64F12.xml \
  --board NXP-FRDM-K64F \
  --mcu MK64F12 \
  --benchmark-name P2IM-Console \
  --out-root /tmp/console_staged_loop \
  --initial-run-for 180s \
  --candidate-run-for 60s \
  --rounds 2 \
  --beam-width 2 \
  --top-k 8 \
  --plan-mode heuristic \
  --max-candidates 6 \
  --default-after-reads 192
10. Testing and Validation / 测试与验证
10.1 What to validate first / 先验证什么

English
The recommended validation order is:

baseline fuzz runs correctly;
observer output is produced;
evidence pack is non-empty;
hotspot groups are reasonable;
plan candidates are non-empty;
compile produces valid guidance files;
run-fuzz can import seeds;
staged-loop can produce verdicts automatically.

中文
推荐的验证顺序是：

baseline fuzz 能正确运行；
observer 能产出结果；
evidence pack 非空；
hotspot groups 合理；
plan candidates 非空；
compile 能生成合法 guidance；
run-fuzz 能导入 seeds；
staged-loop 能自动给出 verdict。
10.2 Practical checks / 实用检查项

English
Important artifacts to inspect:

evidence_pack.json
task_context.json
plan.json
guidance_index.json
guidance_runtime_summary.json
round_*_summary.json
staged_loop_summary.json

中文
建议重点检查这些文件：

evidence_pack.json
task_context.json
plan.json
guidance_index.json
guidance_runtime_summary.json
round_*_summary.json
staged_loop_summary.json
10.3 Common failure modes / 常见失败类型

English

invalid_guidance: generated guidance cannot be parsed or is empty;
unsupported_action: runtime does not support a generated action type;
no_effect: candidate runs but produces no visible effect;
unfair comparison: candidates do not start from the same imported prefix;
over-narrow planner: planner returns empty candidates or only a single hotspot family.

中文

invalid_guidance：生成的 guidance 为空或无法解析；
unsupported_action：runtime 不支持某个生成动作；
no_effect：candidate 能运行但没有可见效果；
比较不公平：候选没有从同一个前缀 checkpoint 出发；
planner 过窄：返回空候选或只覆盖单一热点类型。
11. Recommended Next Steps / 下一步建议
Short term / 短期

English

Keep using heuristic group-based planning as the non-empty fallback.
Improve per-group quota so strong groups do not monopolize all candidates.
Verify runtime support for advanced templates such as status-then-data actions.
Continue staged tournament experiments with control branches.

中文

继续保留基于分组的 heuristic planner 作为非空保底。
优化 per-group quota，避免最强热点组占满全部候选。
验证 runtime 对高级模板（如 status-then-data）的支持。
继续在带 control 的 staged tournament 中测试候选效果。
Mid term / 中期

English

Integrate LLM rerank into the group/template pipeline.
Add bounded LLM expansion within the allowed template catalog.
Improve scoring with hotspot migration and dependency satisfaction signals.
Expand template coverage iteratively based on winning candidates.

中文

将 LLM rerank 接入 group/template 管线。
在允许模板目录内加入受限的 LLM 扩展能力。
用热点迁移与依赖满足信号改进评分。
根据胜出候选逐步扩展模板覆盖。
Long term / 长期

English

Support richer multi-register and cross-peripheral strategies.
Learn reusable group-template priors from previous winning rounds.
Move from heuristic-only staged search to evidence-grounded hybrid planning with LLM assistance.

中文

支持更丰富的多寄存器与跨外设策略。
从历史优胜轮次中学习可复用的 group-template 先验。
从纯 heuristic staged search 逐步过渡到带 LLM 辅助的证据驱动混合规划。
12. Final Summary / 最终总结

English

This work is not trying to solve all peripherals or all strategies in one shot. The current system is intentionally iterative. The immediate goal is to make the loop reliable:

detect hotspots,
group related registers,
generate bounded candidates,
compare them fairly from the same prefix,
and promote the better branches.

Once this loop is stable, LLM assistance can be introduced in a controlled way for reranking and bounded candidate expansion.

中文

这项工作并不是要一次性解决所有外设、所有寄存器和所有策略。当前系统本来就是一个逐步迭代的过程。当前最重要的目标是让闭环稳定可靠：

发现热点，
对相关寄存器分组，
生成受约束候选，
从同一前缀公平比较，
将表现更好的分支晋级。

在这个闭环稳定之后，再以受控方式引入 LLM 做 rerank 和受限候选扩展。