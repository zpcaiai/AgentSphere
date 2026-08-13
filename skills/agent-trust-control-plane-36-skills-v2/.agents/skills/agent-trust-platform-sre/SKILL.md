---
name: agent-trust-platform-sre
description: 实现Agent Control Plane的SRE、SLO、容量、HA、灾备、升级、备份恢复、故障降级和多部署模式。用于Batch 34，使安全控制平面自身在故障下可靠且失败语义正确。
compatibility: Kubernetes/VM/离线部署均可；Rust/Java/Python服务、PostgreSQL、消息系统和对象存储。需要Batch 02、04、06—10、19、22、29。
metadata:
  project: agent-trust-control-plane
  batch: "34"
  version: "2.0.0"
---

# Batch 34：Platform SRE、HA、DR与Deployment

# 任务

把各Batch零散的超时、重试和失败关闭要求汇总为可验证的平台可靠性工程，确保安全服务故障不会造成静默旁路或不必要地阻断紧急安全动作。

完成本Skill时必须在当前目标仓库实现真实代码、Schema、数据库迁移、测试、部署配置、Runbook和Evidence；不得只提交设计、空接口、TODO或模拟通过报告。先盘点现有实现并增量集成，禁止创建第二套平行架构。

# 触发条件

- 设计生产部署、SLO、HA、DR、备份恢复和容量
- 处理Policy/Evidence/Ledger/Orchestrator故障语义
- 实施升级、Schema迁移、Canary和Rollback

# 非目标

- 不承诺未经压测的无限规模
- 不把所有组件拆成独立微服务
- 不以单区Docker Compose作为生产HA
- 不让可观测系统故障静默放宽授权

# 依赖分类

- **contract dependencies**：Batch 01, Batch 10, Batch 19, Batch 22, Batch 29
- **implementation dependencies**：Batch 02, Batch 04, Batch 06, Batch 07, Batch 08, Batch 09, Batch 10, Batch 19, Batch 22, Batch 29
- **runtime integrations**：Batch 16, Batch 24, Batch 25, Batch 35, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

# 权威边界与安全不变量

- 定义每类动作在依赖故障下的fail-closed、local-WAL、degraded-read或emergency-allow策略。
- Ledger、Identity、Policy snapshot和Orchestrator状态有明确RPO/RTO。
- Emergency Stop与危险停止必须优先执行并可靠补证据。

# 建议目录

- `deploy/kubernetes`
- `deploy/private`
- `deploy/offline`
- `sre/slo`
- `sre/chaos`
- `docs/runbooks`
- `capacity/models`

# 核心模型

- ServiceSlo
- DependencyFailurePolicy
- CapacityProfile
- BackupManifest
- RecoveryPlan
- UpgradePlan
- DeploymentTopology

# 必须实现的接口

- HealthContract
- ReadinessGate
- DependencyFailureResolver
- BackupController
- RecoveryVerifier
- UpgradeOrchestrator

# 实施步骤

## 第1步

定义业务SLI、安全SLI、延迟、可用性、阻断、恢复和Evidence完整性SLO。

## 第2步

为Gateway、PEP、Identity、Ledger、Orchestrator、Evidence和Approval设计HA拓扑。

## 第3步

建立容量模型、队列/连接池上限、背压和租户配额。

## 第4步

定义依赖故障矩阵：只读、普通写、高风险写、Emergency Stop、新Credential。

## 第5步

实现备份、恢复、PITR、对象存储完整性和密钥恢复。

## 第6步

建立Schema/API/Policy/Pack升级、Canary和自动回滚。

## 第7步

运行Chaos：节点、区、网络、时钟、证书、存储、消息系统和依赖故障。

## 第8步

支持SaaS、私有、离线和边缘混合部署。


# 数据、错误与可观测要求

- 所有跨服务对象带`schema_version`，安全决策、配置、Policy、Pack和模型带不可变版本或Digest。
- 错误使用稳定机器码、`trace_id`和安全摘要；不得回显Secret、完整敏感输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换、人工动作和恢复写入Batch 10/19证据链。
- 所有队列、缓存、连接池、分页和后台任务有界；超载时拒绝或受控降级。
- Production profile失败关闭；Dev bypass必须显式、醒目且CI证明无法进入生产构建。
- 所有Task完成声明由Batch 29状态机和Batch 10 Evidence共同证明。

# 必须实现的测试矩阵

- 区域故障、数据库主备切换、消息积压、对象存储不可用
- Policy服务中断、Evidence后端中断、证书过期、KMS不可用
- 升级一半失败、Schema不兼容、回滚
- 高并发长任务与租户噪声邻居
- 断网边缘与中央恢复后的证据对账

# 必须执行的故障注入

- kill -9关键服务
- 延迟/丢包/分区
- 磁盘满
- 时钟漂移
- CPU/内存耗尽
- 证书和密钥轮换失败

# 必须提交的交付物

- SLO/SLI目录
- HA/DR架构和IaC
- 容量模型和压测脚本
- Chaos suite
- Backup/Restore验证报告
- 升级/回滚Runbook

# 完成Gate

- RTO/RPO经真实恢复演练验证
- 安全依赖故障没有静默ALLOW
- Emergency安全动作不被普通审计故障阻断
- 容量和背压有证据
- 至少一种私有/离线部署完成端到端验证

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
