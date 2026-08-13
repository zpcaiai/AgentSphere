---
name: agent-trust-audit-retention
description: 实现企业审计、日志留存、Legal Hold、冷热存储、证据导出和离线验证。用于 Batch 19，把Batch 10事件链转化为按租户、数据等级和合规Profile管理的长期审计资产。不要将可观测日志与法律/安全审计证据混为一体。
compatibility: 需要Batch 10 Evidence、Batch 18数据治理、PostgreSQL/ClickHouse/OpenSearch/对象存储中的适用组合。
metadata:
  project: agent-trust-control-plane
  batch: "19"
  version: "2.0.0"
---
# Batch 19：审计留存、Control Catalog与Evidence Graph
# 任务
建立可查询、可保留、可删除、可冻结、可导出且可独立验证的审计系统，在保护敏感数据的同时支持事故调查、客户审计和合规证明。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 19
- 建设审计日志、留存策略、Legal Hold
- 导出Evidence Package
- 实现不可篡改存储或离线验证

# 非目标
- 不把所有Debug日志永久保存
- 不允许删除覆盖Legal Hold
- 不让审计查询绕过租户/字段权限
- 不声称Hash链等同外部时间戳或法律结论

# 前置依赖
- Batch 10 SignedAuditEvent/Evidence
- Batch 18 classification/retention
- Batch 04审计身份

# 强制安全原则
1. 安全审计与普通应用日志分流
2. 事件原始内容、索引和Artifact各自有classification
3. 每次查询和导出本身被审计
4. Legal Hold优先于删除/过期
5. 证据导出包含manifest、hash、签名和验证工具
6. 租户隔离贯穿索引、对象存储和缓存

# 建议目录

```text
java/compliance-service/audit
rust/crates/audit-ingestion
rust/crates/evidence-export
schemas/retention
migrations/audit
conformance-tests/audit
docs/compliance/audit
```

# 必须实现的公共接口

```text
AuditIngest.append_batch
RetentionPolicy.resolve
LegalHoldService.place/release
AuditQuery.search
EvidenceExporter.export
OfflineVerifier.verify
DeletionService.delete_with_proof
```

# 第1步：存储分层
- PostgreSQL保存事务索引、ClickHouse分析、OpenSearch搜索、对象存储大Artifact
- 按现有栈选择，不强制全部引入

# 第2步：留存策略
- 按事件类型、租户、领域、数据分类和合规Profile
- 保留、归档、删除和匿名化任务可重试

# 第3步：Legal Hold
- 指定task/user/resource/time range
- 冻结相关索引和Artifact
- 释放需要独立权限与Evidence

# 第4步：查询权限
- 字段级和资源级访问
- 安全错误避免泄露资源存在性
- 大查询配额和审计

# 第5步：证据导出
- 自包含manifest、Schema版本、链头、签名、Artifact列表和验证CLI
- 可选择脱敏视图但保留变换证明

# 第6步：删除证明
- 记录删除范围、Policy、执行结果和无法删除的受保护项目
- 不伪造不可变外部备份已删除

# 第7步：备份与灾备
- 加密、密钥轮换、恢复演练和完整性抽检

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 篡改索引或Artifact检测
- 跨租户查询/对象路径访问拒绝
- Legal Hold期间删除失败
- Retention任务重试幂等
- Evidence在隔离环境离线验证
- 审计查询和导出自身事件完整

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Audit ingestion/query
- Retention/Legal Hold服务
- Evidence Exporter与Verifier
- 存储迁移
- 灾备/删除/审计Runbook
- 合规Profile样例

# 完成Gate
- 审计事件丢失有告警和失败策略
- Evidence可离线验证
- Legal Hold不可被普通管理员绕过
- 租户隔离测试通过
- 留存和删除有可重放记录
- 敏感字段访问受控

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    从“日志存储”升级为Control Catalog + Evidence Graph：每个治理控制连接Policy、测试、运行证据、Owner、状态和外部规范映射。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 10
- **implementation dependencies**：Batch 10, Batch 18
- **runtime integrations**：Batch 20, Batch 22, Batch 31, Batch 34, Batch 35, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - Evidence不可篡改、可验证、可查询，但敏感原文最小保存。
- Retention、Deletion与Legal Hold有明确优先级。
- 合规映射是证据组织，不自动宣称获得认证。

    ## 新增或强化的模型

    - ControlDefinition
- ControlImplementation
- ControlTest
- EvidenceNode
- EvidenceEdge
- RetentionPolicy
- LegalHold
- AuditExportManifest

    ## 必须落盘的接口

    - ControlCatalog
- EvidenceGraph
- RetentionEngine
- LegalHoldService
- AuditExportService
- IntegrityVerifier

    ## 新增负向测试与故障注入

    - 事件篡改/删除/重排、跨租户查询、Legal Hold下删除、时钟漂移、对象存储版本回退。
- 导出包离线校验且不含无权限Secret。
- 控制失去运行证据后状态自动降级。

    ## v2.0完成Gate

    - Requirement→Control→Policy→Test→Evidence可追踪。
- 日志留存与数据最小化不矛盾，有分级策略。
- 支持后续Batch31、33、36引用Control ID。

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
7. **Next integration**：Batch 22 Incident与Release Gate。
