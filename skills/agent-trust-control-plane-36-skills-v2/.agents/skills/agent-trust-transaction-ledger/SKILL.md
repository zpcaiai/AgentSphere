---
name: agent-trust-transaction-ledger
description: 实现 Agent Trust & Compliance Control Plane 的 Execution Ledger、幂等Key、资源版本、Saga补偿、条件回滚、重试恢复和人工恢复状态。用于 Batch 09，防止长任务因超时、响应丢失、重复消息或恢复执行产生重复副作用。不要把业务成功与单次执行成功混为一谈。
compatibility: 需要 Rust、PostgreSQL、Batch 01/03/05/06/07，推荐Temporal用于长流程编排但Ledger核心不得依赖内存状态。
metadata:
  project: agent-trust-control-plane
  batch: "09"
  version: "2.0.0"
---
# Batch 09：幂等、补偿事务与Unknown Outcome Recovery
# 任务
为每个有副作用的Action建立可恢复、可去重、可审计的执行事实源；在正向执行前登记补偿，在故障后安全重试、条件补偿或明确进入人工恢复。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 09
- 处理重复Tool调用、网络重试或任务恢复
- 实现Saga、Compensation、Rollback
- 解决执行成功但响应丢失
- 实现资源版本和Compare-and-Swap

# 非目标
- 不声称所有物理动作可逆
- 不自动覆盖其他合法操作者的后续修改
- 不把失败记录删除
- 不以数据库事务包裹不可控外部系统来伪造原子性

# 前置依赖
- Batch 01 Execution/Compensation状态
- Batch 03 action_hash
- Batch 05 EffectClass与compensation binding
- Batch 06 Authorization
- Batch 07执行结果

# 强制安全原则
1. 同tenant+idempotency_key+action_hash唯一
2. 相同key不同action hash必须冲突拒绝
3. 正向动作前持久化执行意图与补偿计划
4. 副作用结果未知时状态为UNKNOWN而非FAILED
5. 补偿自身幂等并遵守资源前置条件
6. 无法证明安全回滚时进入MANUAL_RECOVERY_REQUIRED

# 建议目录

```text
rust/crates/transaction-ledger
rust/crates/idempotency
rust/crates/compensation-runtime
schemas/execution
migrations/transaction-ledger
conformance-tests/transactions
threat-scenarios/retry-recovery
```

# 必须实现的公共接口

```text
ExecutionLedger.reserve(ExecutionIntent)->Reservation
ExecutionLedger.mark_started/succeeded/failed/unknown
IdempotencyService.lookup_or_reserve
CompensationPlanner.plan(tool_snapshot, prepared_state)
CompensationRunner.execute(plan)
RecoveryScanner.reconcile(stale_executions)
```

# 第1步：数据模型
- executions、execution_attempts、idempotency_records、compensation_plans、resource_versions
- 用唯一约束和事务锁保证并发去重
- 保存result/evidence引用，不在Ledger存大输出

# 第2步：幂等Key
- Key包含tenant、task、step、tool version、canonical args和target version
- 客户端Key必须命名空间化且受长度限制
- 对PURE/IDEMPOTENT/COMPENSATABLE/IRREVERSIBLE采用不同重试策略

# 第3步：执行协议
- reserve→register compensation→commit→execute→verify→finalize
- 执行前再次校验Authorization与resource version
- 响应丢失时通过外部operation id或verify方法对账

# 第4步：补偿与条件回滚
- LIFO补偿多步骤Saga
- Coding使用baseline SHA、branch和workspace snapshot
- 工业使用only_if_current_value/resource version条件
- IRREVERSIBLE要求审批、备份、双确认或禁止自动执行

# 第5步：恢复扫描
- 对超时RUNNING和UNKNOWN状态定期reconcile
- 读取外部系统事实，不凭Agent叙述判断
- 恢复任务不得生成新幂等Key绕过旧记录

# 第6步：人工恢复
- 生成待处理步骤、影响范围、最后已知状态和建议操作
- 人工操作后必须录入证据并重新Evaluator

# 第7步：故障注入
- 进程在各持久化边界崩溃
- 数据库提交成功但响应失败
- 外部成功、记录失败
- 重复队列消息和乱序消息
- 补偿失败与部分成功

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 并发提交同Key 100次只执行一次
- 同Key不同payload返回冲突
- 外部成功响应丢失后不重复副作用
- 补偿重复执行不破坏状态
- 资源已被他人修改时自动回滚拒绝
- 重启后Recovery Scanner能收敛所有非终态记录

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Ledger Schema与迁移
- Rust幂等和补偿库
- Temporal/工作流适配接口
- Coding和工业补偿样例
- 故障注入测试集
- Manual Recovery Runbook

# 完成Gate
- 所有副作用Tool声明EffectClass
- 无补偿计划的COMPENSATABLE动作不得执行
- UNKNOWN状态不能被自动当作成功或失败
- 重复执行测试有外部副作用计数证据
- 恢复扫描无永久僵尸状态
- 人工恢复状态和Evidence完整

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Ledger处理“是否执行过、结果是否确定、如何补偿”，并用fencing token、outbox/inbox和资源版本解决重试与并发，不把网络超时直接当作失败。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03
- **implementation dependencies**：Batch 01, Batch 03, Batch 05
- **runtime integrations**：Batch 07, Batch 08, Batch 10, Batch 29
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - UNKNOWN是一级状态，必须查询目标事实或进入人工恢复。
- 正向动作前持久化幂等键、预条件和补偿计划。
- 补偿是新的受控Action，也需要Policy、幂等和Evidence。

    ## 新增或强化的模型

    - ExecutionIntent
- ExecutionFence
- IdempotencyRecord
- UnknownOutcomeCase
- CompensationPlan
- RecoveryDecision
- OutboxEvent

    ## 必须落盘的接口

    - ExecutionLedger
- IdempotencyService
- FencingTokenIssuer
- OutcomeResolver
- CompensationCoordinator
- RecoveryCaseService

    ## 新增负向测试与故障注入

    - 成功后响应丢失、数据库提交与消息发送之间崩溃、双Worker竞争、陈旧fence、补偿重复。
- 工业值被第三方改变时条件回滚不得覆盖新状态。
- 不可逆动作必须有人工审批、降低影响或明确禁止自动执行。

    ## v2.0完成Gate

    - 重复10次只有一次真实副作用。
- UNKNOWN、MANUAL_RECOVERY_REQUIRED有查询、告警和Runbook。
- Outbox/Inbox与数据库事务一致性有故障注入证据。

    任何“完成”声明必须附`IMPLEMENTATION_STATUS.json`、真实命令退出码、测试报告和Evidence引用。规范文件完成不等于产品代码完成。

# Codex执行顺序
1. 读取`AGENTS.md`、现有架构、构建文件、数据库迁移和相关Batch接口。
2. 输出不超过一页的现状盘点和增量实施顺序，然后立即开始落盘。
3. 优先完成最小纵向闭环，再补负向安全、故障注入、文档和Evidence。
4. 每次改动后运行最小相关测试；最终运行该Batch全部Gate。
5. 不静默修改公共契约；需要修改时同时更新Batch 01 Schema、生成代码和兼容性测试。

# Codex最终报告格式
1. **Implemented**：实际完成的模块、接口和安全不变量；
2. **Files changed**：按代码、Schema、迁移、测试、文档分组；
3. **Commands run**：只列真实执行的命令、退出码和关键结果；
4. **Security evidence**：负向测试、故障注入、隔离/权限/幂等证据；
5. **Compatibility**：公共契约、协议和数据迁移影响；
6. **Unresolved risks**：只列有证据且尚未解决的问题，禁止用“全部完成”掩盖；
7. **Next integration**：Batch 10 Completion Evaluator、Batch 17 Approval、Batch 22 Incident Replay。
