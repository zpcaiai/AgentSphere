---
name: agent-trust-domain-pack-sdk-marketplace
description: 实现Domain Pack SDK、脚手架、测试Harness、签名发布、私有Marketplace、安装审批、版本兼容、灰度、升级和撤销。用于 Batch 28，让新行业Pack在不修改公共内核的情况下标准化交付和认证。
compatibility: 需要Batch 20供应链、Batch 22 Release Gate、CLI/Java Registry/Vue管理台。
metadata:
  project: agent-trust-control-plane
  batch: "28"
  version: "2.0.0"
---
# Batch 28：Domain Pack Marketplace与Lifecycle Governance
# 任务
把行业风险模型、Tool、Policy、Compensation、Evaluator和Threat Scenarios产品化为可开发、可验证、可签名、可安装、可升级和可撤销的标准扩展。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 28
- 建设Domain Pack SDK或Marketplace
- 新建行业Pack
- 发布、安装、升级或撤销Pack

# 非目标
- 不允许Marketplace安装即获得生产权限
- 不允许Pack修改公共PEP/Sandbox核心
- 不把下载量当安全质量
- 不支持未声明任意代码执行

# 前置依赖
- Batch 20 Pack签名供应链
- Batch 22 Release Gate
- Batch 05 Registry
- Batch 10 Evaluator SDK

# 强制安全原则
1. 新Pack不修改公共内核即可安装
2. 每个写Tool有EffectClass、Approval和Compensation/不可逆说明
3. 每个Pack有Evaluator和Threat Tests
4. 安装权限与租户环境分离
5. 版本使用SemVer+immutable digest
6. 撤销和升级可影响分析并安全回滚

# 建议目录

```text
sdk/domain-pack
cli/agent-pack
java/pack-marketplace
web/pack-console
templates/domain-pack
conformance-tests/marketplace
docs/sdk
```

# 必须实现的公共接口

```text
PackScaffold.create
PackValidator.validate
PackTestHarness.run
Marketplace.publish/search/install
PackApproval.approve
PackLifecycle.activate/upgrade/rollback/revoke
CompatibilityMatrix.compute
```

# 第1步：SDK
- Manifest类型、Tool/Policy/Evaluator/Compensation/Mapping/Threat API
- Rust/Python/Java helper和示例

# 第2步：脚手架
- CLI生成目录、最小安全默认、测试和CI
- 禁止生成allow-all策略或任意Shell示例

# 第3步：测试Harness
- Schema、Contract、Policy负向、Sandbox、幂等、Evaluator、Threat和Evidence
- 支持本地和CI一致运行

# 第4步：Marketplace
- 私有Registry优先、publisher和tenant隔离
- 搜索展示权限、风险、兼容和认证状态

# 第5步：安装审批
- Permission Diff、数据/网络/Secret/Tool范围
- 按环境激活，不自动生产

# 第6步：升级回滚
- 兼容矩阵、数据迁移、canary、上一版本保留
- 安全缺陷可紧急撤销

# 第7步：认证
- 调用Batch 22 Gate生成Pack Certificate
- 证书绑定digest、测试集和环境

# 第8步：开发者体验
- 文档、示例、诊断、可重复构建
- Telemetry不上传私有Pack内容除非授权

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 脚手架生成Pack通过最小测试
- 缺Evaluator/EffectClass/Threat Tests验证失败
- 权限扩大升级需要重新审批
- 跨租户私有Pack不可见
- 撤销后不能新建任务
- 回滚恢复旧版本并保持Evidence

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Domain Pack SDK
- CLI脚手架
- Test Harness
- Marketplace服务/控制台
- 安装审批与Lifecycle
- Pack Certificate和开发文档

# 完成Gate
- 新Pack无需改核心
- 所有生产Pack有有效Certificate
- 安装不自动提权
- 升级权限差异可见
- 撤销/回滚经过演练
- Coding/Industrial/Energy/Medical/Sensitive Packs通过SDK重构验证

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Batch 28只负责已由Batch20 SDK验证和签名的Domain Pack的发布、安装、审批、灰度、升级、撤销和生态治理。

    ## 依赖分类

    - **contract dependencies**：Batch 20
- **implementation dependencies**：Batch 20, Batch 23, Batch 24, Batch 25, Batch 26, Batch 27
- **runtime integrations**：Batch 30, Batch 31, Batch 35, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 安装不等于启用；启用不等于生产授权。
- Pack权限扩大、网络/数据声明变化必须重新审查。
- 撤销可阻止新任务并按策略处理运行中任务。

    ## 新增或强化的模型

    - MarketplaceListing
- PackRelease
- Installation
- Activation
- UpgradePlan
- CanaryResult
- RevocationNotice
- PublisherTrust

    ## 必须落盘的接口

    - MarketplaceService
- InstallationService
- ActivationController
- UpgradeOrchestrator
- PublisherTrustService
- PackRevocationController

    ## 新增负向测试与故障注入

    - 恶意发布者、同名抢注、依赖混淆、升级权限扩大、回滚失败、撤销传播、租户隔离。
- Pack不能绕过公共PEP/Sandbox/Evidence。
- Marketplace不可自动赋予生产Credential。

    ## v2.0完成Gate

    - SDK职责已移至Batch20。
- 23—27 Pack可通过同一生命周期安装与回滚。
- 生态治理、许可、漏洞通知和Publisher责任清晰。

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
7. **Next integration**：全部28 Batch闭环完成；后续进入真实代码实现、Pilot和持续认证。
