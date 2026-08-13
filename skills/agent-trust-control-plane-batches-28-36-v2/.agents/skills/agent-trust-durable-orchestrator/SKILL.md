---
name: agent-trust-durable-orchestrator
description: 实现持久化Agent任务编排器、唯一状态机所有权、长任务暂停恢复取消、持续授权和副作用协调。用于Batch 29，把Gateway、PEP、Approval、Credential、Sandbox、Ledger、Trace与Evaluator串成唯一可恢复纵向闭环。
compatibility: 推荐Python + Temporal SDK + PostgreSQL；Rust Runtime Supervisor作为执行端。需要Batch 01—10及Batch 17接口。
metadata:
  project: agent-trust-control-plane
  batch: "29"
  version: "2.0.0"
---

# Batch 29：Durable Runtime Orchestrator与Continuous Task State

# 任务

建立全系统唯一的持久化Task/Step状态机和执行编排入口。任何协议、Agent、UI或Evaluator都只能提交命令或判定，不能直接修改任务终态。

完成本Skill时必须在当前目标仓库实现真实代码、Schema、数据库迁移、测试、部署配置、Runbook和Evidence；不得只提交设计、空接口、TODO或模拟通过报告。先盘点现有实现并增量集成，禁止创建第二套平行架构。

# 触发条件

- 实现或修复长任务工作流、暂停恢复取消、重试和Saga协调
- 解决多个服务争抢Task状态、审批等待与执行恢复不一致
- 把Coding和工业Agent接入同一纵向执行链

# 非目标

- 不在Orchestrator中实现LLM推理算法
- 不替代Rust进程级Kill和资源隔离
- 不保存真实目标系统Secret
- 不允许Temporal状态代替Batch09副作用事实账本

# 依赖分类

- **contract dependencies**：Batch 01, Batch 03, Batch 09, Batch 10
- **implementation dependencies**：Batch 02, Batch 04, Batch 05, Batch 06, Batch 07, Batch 08, Batch 09, Batch 10, Batch 17
- **runtime integrations**：Batch 11, Batch 12, Batch 13, Batch 14, Batch 15, Batch 16, Batch 21, Batch 23, Batch 24, Batch 25, Batch 26, Batch 27, Batch 34, Batch 35, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

# 权威边界与安全不变量

- Orchestrator是Task/Step状态转换的唯一调用者；Transition Service执行Batch01守卫。
- Batch09 Ledger是副作用是否发生的事实源；Workflow重放不能重复副作用。
- Batch10 Evaluator只产生结果，Orchestrator根据Gate写Task终态。
- 每个长任务持有Authorization Lease；风险或Policy变化触发重新授权。

# 建议目录

- `python/runtime-orchestrator`
- `java/transition-service`
- `workflows/task-runtime`
- `tests/orchestrator`
- `docs/runbooks/orchestrator`

# 核心模型

- TaskRuntimeRecord
- StepRuntimeRecord
- WorkflowCommand
- WorkflowEvent
- AuthorizationCheckpoint
- ApprovalWaitState
- RecoveryCursor
- CancellationPlan

# 必须实现的接口

- TaskCommandApi.create/pause/resume/cancel/kill
- TaskTransitionService.request_transition
- PolicyCheckpointPort
- ApprovalWaitPort
- CredentialLeasePort
- ExecutionLedgerPort
- EvaluatorPort
- EvidencePort

# 实施步骤

## 第1步

实现TaskWorkflow与StepWorkflow，所有Activity使用稳定幂等键。

## 第2步

固化SignedGoal和PlanManifest；计划变更生成新plan_hash并使旧审批/租约失效。

## 第3步

在PRE_APPROVAL、PRE_EXECUTION、长运行心跳和风险事件处设置AuthorizationCheckpoint。

## 第4步

实现Approval等待、超时、拒绝、重新规划和职责升级。

## 第5步

执行前向Batch09登记Intent/Fence；执行后根据Ledger事实处理成功、UNKNOWN或补偿。

## 第6步

实现Pause、Resume、Cancel和Kill：Cancel走安全补偿，Kill立即调用Rust Supervisor并吊销凭证。

## 第7步

实现Evaluator Gate与Task终态写入；Evidence缺失时不得COMPLETED。

## 第8步

为服务重启、Worker切换和Temporal replay建立确定性测试。


# 数据、错误与可观测要求

- 所有跨服务对象带`schema_version`，安全决策、配置、Policy、Pack和模型带不可变版本或Digest。
- 错误使用稳定机器码、`trace_id`和安全摘要；不得回显Secret、完整敏感输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换、人工动作和恢复写入Batch 10/19证据链。
- 所有队列、缓存、连接池、分页和后台任务有界；超载时拒绝或受控降级。
- Production profile失败关闭；Dev bypass必须显式、醒目且CI证明无法进入生产构建。
- 所有Task完成声明由Batch 29状态机和Batch 10 Evidence共同证明。

# 必须实现的测试矩阵

- 同一Task并发提交两个命令只允许合法状态转换
- 审批等待期间Policy、资源版本或Plan变化后旧Grant失效
- Activity成功但回执丢失，Workflow重放不重复副作用
- Cancel与Kill竞态、子任务级联、凭证吊销延迟
- Orchestrator、Temporal、Postgres任一重启后的恢复
- Evaluator PASS但硬Gate证据缺失时进入NEEDS_HUMAN

# 必须执行的故障注入

- 在每个Activity边界注入进程崩溃
- 数据库提交前后网络分区
- Approval服务超时与重复回调
- Ledger返回UNKNOWN
- Evidence后端不可用
- Rust Supervisor失联

# 必须提交的交付物

- 可运行TaskWorkflow/StepWorkflow
- Transition Service与数据库迁移
- 命令API与OpenAPI
- Temporal worker和部署配置
- 状态转换/恢复/取消端到端测试
- 运行时Runbook与Evidence样例

# 完成Gate

- 只有Orchestrator可请求Task终态转换
- 重放和重试不重复副作用
- Pause/Resume/Cancel/Kill语义通过故障注入
- Coding与Industrial Simulator共享同一Workflow
- 每个终态都有状态、Ledger和Evidence一致性证明

以下情况一律不得标记完成：核心路径仍为TODO；只提交接口无实现；关键测试被skip；使用Mock声称真实隔离、真实协议、真实灾备或真实临床/工业验证通过；无法提供实际运行命令、退出码、报告和Evidence；存在已知高危旁路而未失败关闭。

# Codex执行顺序

1. 读取`AGENTS.md`、公共契约、依赖DAG、现有架构和相关Batch接口。
2. 输出不超过一页的现状盘点与增量实施顺序，然后立即开始落盘。
3. 先完成最小纵向闭环，再完成负向安全、故障注入、可观测、文档和Evidence。
4. 每次修改后运行最小相关测试；最终运行本Batch全部Gate和跨Batch契约测试。
5. 不静默修改公共契约；需要修改时同步更新Batch 01 Schema、生成代码、兼容测试和Traceability Matrix。
6. 更新`IMPLEMENTATION_STATUS.json`，状态只能是`NOT_STARTED`、`IN_PROGRESS`、`BLOCKED`或`EVIDENCE_VERIFIED`。

# Codex最终报告格式

1. **Implemented**：实际完成的模块、接口和不变量；
2. **Files changed**：按代码、Schema、迁移、测试、部署和文档分组；
3. **Commands run**：真实命令、退出码、关键结果和报告路径；
4. **Security evidence**：负向测试、故障注入、隔离/权限/幂等/恢复证据；
5. **Compatibility**：契约、协议、数据库、Policy、Pack和部署影响；
6. **Unresolved risks**：有证据但未解决的问题与阻断级别；
7. **Next integration**：下一依赖Batch、接口和迁移要求。

规范文件完成不等于产品代码完成。没有真实Evidence时禁止使用“全部实现”“生产可用”或“通过认证”等表述。
