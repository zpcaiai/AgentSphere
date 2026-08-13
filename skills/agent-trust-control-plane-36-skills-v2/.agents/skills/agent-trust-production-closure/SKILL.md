---
name: agent-trust-production-closure
description: 执行全系统Production Closure：依赖图、需求追踪、端到端、性能、HA/DR、安全红队、Domain Pack、升级回滚和证据认证。用于Batch 36，只有本Batch通过后才允许声明整个平台生产完成。
compatibility: 需要Batch 01—35的实际代码、部署和Evidence；不是文档汇总Batch。
metadata:
  project: agent-trust-control-plane
  batch: "36"
  version: "2.0.0"
---

# Batch 36：Full-System Production Closure与最终认证

# 任务

对完整Agent Trust & Compliance Control Plane进行最终联合验收，生成可验证Production Closure Certificate，并明确未通过项和适用范围。

完成本Skill时必须在当前目标仓库实现真实代码、Schema、数据库迁移、测试、部署配置、Runbook和Evidence；不得只提交设计、空接口、TODO或模拟通过报告。先盘点现有实现并增量集成，禁止创建第二套平行架构。

# 触发条件

- 准备正式上线、重大版本发布或客户生产验收
- 需要证明Batch 01—35真实实现而非只有Skill文档
- 执行全系统回归、红队、灾备和Domain Pack认证

# 非目标

- 不接受“代码已生成”作为通过
- 不跳过失败测试或用Mock证明真实隔离
- 不对未测试环境/Domain做泛化声明
- 不自动宣称法律或监管认证

# 依赖分类

- **contract dependencies**：Batch 01, Batch 10, Batch 19
- **implementation dependencies**：Batch 22, Batch 23, Batch 24, Batch 25, Batch 26, Batch 27, Batch 28, Batch 29, Batch 30, Batch 31, Batch 32, Batch 33, Batch 34, Batch 35
- **runtime integrations**：无
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

# 权威边界与安全不变量

- 最终证书绑定commit、镜像Digest、Policy/Pack/Prompt/模型版本、部署拓扑和测试Evidence。
- 任何P0安全缺口、未知副作用、不可恢复数据问题或关键Evidence缺失阻断发布。
- 证书有范围、环境、有效期、例外和撤销条件。

# 建议目录

- `release/closure`
- `release/evidence`
- `release/certificates`
- `tests/full-system`
- `reports/production-readiness`

# 核心模型

- ClosureScope
- ReleaseCandidate
- GateResult
- Exception
- ResidualRisk
- ProductionCertificate
- CertificateRevocation

# 必须实现的接口

- ClosureRunner
- EvidenceCollector
- GateAggregator
- CertificateSigner
- ExceptionAuthority
- CertificateRegistry

# 实施步骤

## 第1步

验证36 Batch文件、依赖DAG、公共契约和生成代码一致。

## 第2步

构建所有产物并验证SBOM、签名、Provenance和漏洞Gate。

## 第3步

运行Coding、Industrial、Energy、Medical、Sensitive Pack的代表性端到端场景。

## 第4步

运行多租户隔离、权限负向、幂等、UNKNOWN、补偿、Pause/Cancel/Kill。

## 第5步

运行Batch33完整安全Campaign并比较基线。

## 第6步

运行Batch34容量、HA、DR、备份恢复、升级和回滚。

## 第7步

验证Control Catalog与Evidence Graph完整，所有Gate可追踪。

## 第8步

执行数据迁移、配置迁移和旧版本兼容。

## 第9步

汇总例外、残余风险、Owner、到期和补偿控制。

## 第10步

签发范围明确的Production Closure Certificate并登记撤销条件。


# 数据、错误与可观测要求

- 所有跨服务对象带`schema_version`，安全决策、配置、Policy、Pack和模型带不可变版本或Digest。
- 错误使用稳定机器码、`trace_id`和安全摘要；不得回显Secret、完整敏感输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换、人工动作和恢复写入Batch 10/19证据链。
- 所有队列、缓存、连接池、分页和后台任务有界；超载时拒绝或受控降级。
- Production profile失败关闭；Dev bypass必须显式、醒目且CI证明无法进入生产构建。
- 所有Task完成声明由Batch 29状态机和Batch 10 Evidence共同证明。

# 必须实现的测试矩阵

- 从Agent请求到业务Evaluator的全链路
- 跨协议相同Action一致性
- 所有Domain写操作失败和补偿
- 大规模并发与噪声租户
- 区域故障和恢复
- 红队高危场景
- 升级/回滚数据一致性
- 证书离线验证与篡改检测

# 必须执行的故障注入

- 在全链路每个关键边界kill服务
- 网络分区与时钟漂移
- Policy/Identity/Evidence/KMS不可用
- 第三方Model/MCP/工业协议异常
- 数据库和对象存储恢复

# 必须提交的交付物

- Production Readiness Report
- 完整Gate结果
- Evidence Bundle
- Residual Risk Register
- Release Runbook
- Production Closure Certificate
- Certificate Revocation Procedure

# 完成Gate

- Batch 01—35均有真实实现Evidence，不是仅有SKILL.md
- 依赖、Traceability、Threat-Control和Control-Evidence矩阵全部通过
- P0/P1 Gate无未授权跳过
- HA/DR/红队/Domain联合测试通过
- 证书范围、例外和有效期明确且可离线验证

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
