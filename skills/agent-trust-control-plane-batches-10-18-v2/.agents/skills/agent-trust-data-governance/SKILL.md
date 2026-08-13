---
name: agent-trust-data-governance
description: 实现 Agent Trust & Compliance Control Plane 的数据分类、字段标签、Prompt/Trace/Artifact/Model/Tool信息流Policy、跨域审批、DLP和私有/离线/混合部署配置。用于 Batch 18，防止敏感数据通过Agent上下文、模型或工具出站。
compatibility: 需要Batch 06 PEP、Batch 08 Proxy、Batch 10 Evidence、Batch 15 Model Gateway，可选DLP/密钥管理和国产基础设施适配环境。
metadata:
  project: agent-trust-control-plane
  batch: "18"
  version: "2.0.0"
---
# Batch 18：数据分级、跨域与部署治理
# 任务
把数据分类和流向作为运行时授权维度，确保每个字段从来源到Prompt、模型、Tool、Trace、Artifact和导出都有可验证的允许路径与留存规则。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 18
- 处理数据出境、跨域、私有部署
- 实现DLP、日志脱敏、字段级权限
- 控制敏感数据进入模型/Prompt/Artifact

# 非目标
- 不假设所有文本可完全自动分类
- 不因脱敏而伪造数据完整性
- 不把合规标签仅做UI装饰
- 不允许管理员全局关闭安全审计

# 前置依赖
- Batch 06 Policy Context
- Batch 08响应过滤
- Batch 10 Artifact/Evidence
- Batch 15模型路由

# 强制安全原则
1. 分类标签随数据派生和Artifact传播
2. 流向Policy默认拒绝未知高敏感数据
3. Secret永不进入模型上下文
4. 公共模型不得接收被禁止出境/受限数据
5. Trace只保存允许的摘要/hash/ref
6. DLP失败时高风险导出失败关闭

# 建议目录

```text
rust/crates/data-guard
python/data-classifiers
schemas/data-classification
policies/data-governance
conformance-tests/data-flow
docs/compliance/data
```

# 必须实现的公共接口

```text
DataClassifier.classify
LabelPropagator.merge
DataFlowPolicy.evaluate
PromptGuard.sanitize
ArtifactExportGuard.inspect
CrossDomainApproval.require
RetentionResolver.resolve
```

# 第1步：分类体系
- PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED/REGULATED和领域子标签
- 字段、记录、文件、Artifact与数据集级标签
- 来源可信度和人工覆盖审计

# 第2步：信息流图
- Source→Prompt→Model→Tool→Trace→Artifact→Export
- 每条边有允许目的、地域、租户、保留和脱敏规则

# 第3步：Prompt Guard
- Secret和敏感字段剥离/替换引用
- 保留语义需要时在私有模型处理
- 记录变换hash和可逆性权限

# 第4步：Trace与Artifact
- 字段白名单、结构化脱敏、tokenization
- Artifact下载与导出重新授权
- 水印/签名和retention

# 第5步：跨域
- 定义source/target trust zone和jurisdiction
- 跨域需Policy、审批和Evidence
- 禁止通过MCP/HTTP redirect绕过

# 第6步：部署Profile
- SaaS、VPC、on-prem、offline、hybrid
- 每Profile校验依赖、外连、更新和遥测行为
- 离线模式不得静默使用公共API

# 第7步：DLP与分类器
- 确定性规则优先，模型分类作为辅助
- 误报/漏报反馈和人工复核
- 大文件分块但保持整体标签

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- Secret/PII/工业敏感样本在Prompt、Trace、Artifact、Model各路径测试
- 公共模型Fallback出站被拒绝
- 跨租户/跨域导出审批测试
- 重定向和压缩/编码逃逸DLP测试
- 离线部署无外连测试
- 分类器不可用时未知敏感数据失败关闭

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- 数据标签Schema
- Data Guard和Policy
- Prompt/Artifact Guard
- 部署Profiles
- DLP测试语料
- 数据流与留存文档

# 完成Gate
- 关键数据流均有机器可执行Policy
- Secret零进入模型/普通日志
- 私有/离线Profile有网络证据
- 跨域动作可审计
- 分类不确定性不被当低风险
- Domain Pack可扩展标签而不覆盖核心

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    提供统一数据分类、字段标签、跨域规则、模型/Tool/Trace出站治理和部署模式Policy；通过Port被Batch 15/16消费，避免相互构建依赖。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03, Batch 06
- **implementation dependencies**：Batch 01, Batch 04, Batch 06, Batch 10
- **runtime integrations**：Batch 15, Batch 16, Batch 17, Batch 19, Batch 31, Batch 32, Batch 35
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 数据标签从来源到Prompt、Tool、Artifact、Trace传播。
- Secret、受限个人数据和工业敏感数据默认最小暴露。
- 部署模式支持SaaS、私有、离线、混合且共享核心代码。

    ## 新增或强化的模型

    - DataLabel
- DataLineageRef
- CrossDomainRequest
- DeploymentPolicy
- RetentionLabel
- DlpFinding
- DataPolicyDecision

    ## 必须落盘的接口

    - DataClassificationService
- DataPolicyPortImpl
- CrossDomainApprovalService
- DlpScanner
- DeploymentPolicyResolver

    ## 新增负向测试与故障注入

    - 标签丢失、字段嵌套绕过、压缩/编码出站、跨域重放、模型Fallback、Trace泄密。
- Unknown分类按高风险处理。
- 离线部署不隐式访问公网依赖。

    ## v2.0完成Gate

    - Batch 15和16通过接口接入，无循环依赖。
- 数据Policy有版本、测试、影子评估和Evidence。
- 删除、留存和Legal Hold交由Batch19协调。

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
7. **Next integration**：Batch 19日志留存、Batch 26医疗和Batch 27敏感交互。
