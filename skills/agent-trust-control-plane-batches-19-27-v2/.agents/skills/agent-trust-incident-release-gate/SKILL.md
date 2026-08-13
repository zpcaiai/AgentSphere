---
name: agent-trust-incident-release-gate
description: 实现Agent安全Incident响应、隔离、凭证吊销、Logical/Sandbox/Live Replay、根因分析、回归重认证和统一Production Release Gate。用于 Batch 22，把前述安全、协议、合规和领域证据汇聚为唯一上线门槛。
compatibility: 需要Batch 09/10/17/19/21、工作流引擎、部署平台和CI/CD。
metadata:
  project: agent-trust-control-plane
  batch: "22"
  version: "2.0.0"
---
# Batch 22：Incident、Replay与Release Gate Engine
# 任务
形成从异常发现、即时遏制、完整调查、修复验证到重新上线的闭环，并阻止缺少证据或未通过领域Gate的版本进入生产。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 22
- 建设Incident Console和Replay
- 制定Production Release Gate
- 事故后重新认证和回归

# 非目标
- 不默认在Replay中产生真实副作用
- 不允许手工跳过Gate而无break-glass证据
- 不把关闭Incident等同根因解决
- 不销毁事故现场证据

# 前置依赖
- Batch 09 Ledger
- Batch 10 Evidence
- Batch 17 Approval
- Batch 19 Audit
- Batch 21 Detection

# 强制安全原则
1. Incident控制在Agent进程之外
2. Kill/隔离/吊销可独立执行
3. Logical Replay无副作用
4. Sandbox Replay使用复制数据和测试凭证
5. Live Replay需新Authorization和审批
6. Release Gate基于机器可验证Evidence

# 建议目录

```text
java/compliance-service/incidents
python/replay-runtime
rust/crates/incident-control
web/incident-console
release-gates
conformance-tests/release
docs/operations
```

# 必须实现的公共接口

```text
IncidentService.create/contain/resolve
ContainmentController.kill/revoke/isolate
ReplayService.logical/sandbox/live
RootCauseReport.publish
ReleaseGate.evaluate
RecertificationRunner.run
```

# 第1步：Incident生命周期
- DETECTED、TRIAGED、CONTAINED、INVESTIGATING、REMEDIATING、RECERTIFYING、CLOSED
- 明确owner、severity、scope和时间线

# 第2步：即时遏制
- Kill任务、撤销凭证、隔离MCP/Pack/Model、冻结Artifact
- 操作幂等且有审计

# 第3步：证据保全
- 保存链头、快照、进程/网络摘要、配置和版本
- 限制访问与Legal Hold

# 第4步：Replay
- Logical重演Policy/状态
- Sandbox重演Tool与Evaluator
- Live仅在必要且重新审批后执行

# 第5步：根因和改进
- 区分触发事件、系统缺陷、检测缺口和恢复问题
- 每项改进关联测试/Policy/Pack版本

# 第6步：Release Gate
- 契约、身份、Policy、Sandbox、幂等、回滚、Trace、Threat、Compliance、Domain Evaluator
- Gate输出签名Release Certificate

# 第7步：重新认证
- 受影响规则和邻近场景回归
- 失败版本不可部署
- 紧急例外有到期和补偿控制

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 检测器触发到Kill/吊销链路演练
- Logical Replay零外部副作用
- Sandbox Replay不访问生产资源
- Gate缺少任一必要Evidence失败
- 手工篡改Release Certificate被拒绝
- 事故修复后相关回归自动执行

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Incident Service/Console
- Containment Controller
- Replay Runtime
- Root Cause模板
- Release Gate引擎
- Release Certificate和Runbook

# 完成Gate
- 重大Incident可重建完整时间线
- 遏制操作经过演练
- Replay安全边界有测试
- 所有生产部署需有效Certificate
- break-glass有到期与事后复核
- 修复不只关闭告警而增加回归证据

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Batch 22只实现Incident、Replay与Release Gate Engine，不再声称是全系统最终生产认证；最终Closure属于Batch 36。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 10, Batch 19
- **implementation dependencies**：Batch 09, Batch 10, Batch 17, Batch 19, Batch 21
- **runtime integrations**：Batch 33, Batch 34, Batch 35, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - Incident自动隔离、Credential吊销、Evidence保全和责任时间线。
- Logical Replay默认无副作用；Sandbox Replay隔离；Live Replay必须重新授权和审批。
- Release Gate是可版本化引擎，消费Control/Test/Evidence，不代表所有Domain已通过。

    ## 新增或强化的模型

    - Incident
- ContainmentAction
- ReplayPlan
- ReplayRun
- RootCauseFinding
- Remediation
- ReleaseGateDefinition
- GateRun

    ## 必须落盘的接口

    - IncidentService
- ContainmentController
- ReplayEngine
- RootCauseWorkflow
- ReleaseGateEngine
- RecertificationTrigger

    ## 新增负向测试与故障注入

    - 告警风暴、隔离失败、Evidence缺失、Replay产生副作用、Gate规则变更、修复未覆盖回归。
- 重大Incident可重建完整时间线。
- Gate输出可被Batch36组合但不能自签最终证书。

    ## v2.0完成Gate

    - 名称和文档明确“Engine”。
- Incident→Remediation→Policy/Test更新→再认证闭环。
- 所有Live Replay有新Authorization Lease。

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
7. **Next integration**：Batch 23—27 Domain Release Gates、Batch 28 Marketplace认证。
