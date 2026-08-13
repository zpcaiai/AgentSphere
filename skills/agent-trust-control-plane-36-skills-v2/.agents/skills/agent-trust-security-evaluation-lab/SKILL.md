---
name: agent-trust-security-evaluation-lab
description: 建立Agent安全评测与红队实验室、攻击场景DSL、恶意MCP/Prompt/Memory/凭证/沙箱语料、回归基准和检测度量。用于Batch 33，证明Control Plane控制有效而非只存在。
compatibility: Python评测框架 + Rust攻击执行器 + 隔离环境；需要Batch 10、12、20、21、22、32。
metadata:
  project: agent-trust-control-plane
  batch: "33"
  version: "2.0.0"
---

# Batch 33：Agent Security Evaluation与Red-Team Lab

# 任务

建立可重复、可量化、版本化的Agent攻击与故障评测体系，为每个发布版本输出检测率、阻断率、误报率、恢复时间和Evidence完整性。

完成本Skill时必须在当前目标仓库实现真实代码、Schema、数据库迁移、测试、部署配置、Runbook和Evidence；不得只提交设计、空接口、TODO或模拟通过报告。先盘点现有实现并增量集成，禁止创建第二套平行架构。

# 触发条件

- 进行Agent red team、security eval或威胁回归
- 验证MCP、Prompt Injection、Memory poisoning和Credential exfiltration
- 为销售、审计和Production Gate生成安全基准

# 非目标

- 不在生产租户直接执行破坏性攻击
- 不以单次演示代替统计评测
- 不把模型Judge自评分当唯一安全证据
- 不公开真实客户Secret或漏洞细节

# 依赖分类

- **contract dependencies**：Batch 01, Batch 10, Batch 20, Batch 21, Batch 22, Batch 32
- **implementation dependencies**：Batch 10, Batch 12, Batch 20, Batch 21, Batch 22, Batch 32
- **runtime integrations**：Batch 23, Batch 24, Batch 25, Batch 26, Batch 27, Batch 28, Batch 34, Batch 35, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

# 权威边界与安全不变量

- 场景必须声明目标、前置条件、攻击步骤、预期控制、成功/失败判据和清理。
- 所有攻击运行在隔离租户、沙箱或数字孪生。
- 安全指标与版本、配置、Policy、模型和Pack Digest绑定。

# 建议目录

- `python/security-evals`
- `rust/redteam-runner`
- `scenarios/attack-dsl`
- `datasets/security`
- `reports/security-baselines`

# 核心模型

- AttackScenario
- AttackStep
- ExpectedControl
- EvalCampaign
- SecurityMetric
- Finding
- RegressionBaseline
- RemediationLink

# 必须实现的接口

- ScenarioCompiler
- RedTeamRunner
- AttackDatasetRegistry
- MetricCalculator
- BaselineComparator
- FindingService

# 实施步骤

## 第1步

设计攻击场景DSL和安全测试向量格式。

## 第2步

建立Prompt Injection、Goal Hijack、Tool Abuse、Credential Movement、Memory Poisoning、A2A cascading、Sandbox escape和Slow Exfiltration场景。

## 第3步

实现确定性攻击执行和模型生成变体，所有变体记录seed与版本。

## 第4步

测量prevent/detect/contain/recover四阶段指标。

## 第5步

关联失败到Control ID、Policy、Batch和Remediation。

## 第6步

建立版本基线、误报样本、回归阈值和发布阻断。

## 第7步

将Domain Pack专属场景接入同一Harness。


# 数据、错误与可观测要求

- 所有跨服务对象带`schema_version`，安全决策、配置、Policy、Pack和模型带不可变版本或Digest。
- 错误使用稳定机器码、`trace_id`和安全摘要；不得回显Secret、完整敏感输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换、人工动作和恢复写入Batch 10/19证据链。
- 所有队列、缓存、连接池、分页和后台任务有界；超载时拒绝或受控降级。
- Production profile失败关闭；Dev bypass必须显式、醒目且CI证明无法进入生产构建。
- 所有Task完成声明由Batch 29状态机和Batch 10 Evidence共同证明。

# 必须实现的测试矩阵

- 场景自身可重复性与清理完整性
- 恶意MCP工具声明/行为不一致
- 多Agent递归委派和级联故障
- 低速分片外传与编码混淆
- 检测服务关闭后的基础守卫
- 误报导致业务中断和恢复

# 必须执行的故障注入

- 评测Runner崩溃
- 攻击清理失败
- 数据集损坏
- 模型Provider不可用
- 部分Evidence丢失

# 必须提交的交付物

- Attack Scenario DSL
- Red-Team Runner
- 版本化安全数据集
- Campaign CLI/API
- Security Baseline Report
- Finding/Remediation工作流

# 完成Gate

- 至少覆盖公共与五个Domain Pack威胁
- 指标可重复并有置信区间/样本数
- 高危回归阻断发布
- 攻击环境与生产隔离
- 每个失败可追踪到修复和再测试

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
