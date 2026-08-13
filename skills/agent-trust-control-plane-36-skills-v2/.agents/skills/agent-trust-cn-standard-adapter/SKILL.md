---
name: agent-trust-cn-standard-adapter
description: 实现面向中国智能体互联规范的版本化Adapter骨架。用于 Batch 14，映射国内Agent身份编码、注册发现、能力描述、交互和Tool调用到统一Identity/Capability/Action IR，并生成兼容矩阵与映射损失报告。不要将核心业务写死在单一标准版本。
compatibility: 需要Batch 11 Adapter SDK、可配置Schema/字段映射、企业内网服务发现测试环境。规范版本可能变化，必须以版本包和测试向量驱动。
metadata:
  project: agent-trust-control-plane
  batch: "14"
  version: "2.0.0"
---
# Batch 14：中国智能体标准Adapter
# 任务
使Control Plane能够适配国内标准和企业扩展，同时保持内部IR稳定、权限与安全逻辑不分叉，并为标准演进提供可测试的升级路径。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 14
- 接入国内Agent身份/发现/能力规范
- 建设私有Agent注册中心
- 建立国内标准与MCP/A2A映射

# 非目标
- 不臆造未发布标准字段
- 不声称所有国内规范完全等价
- 不将厂商私有字段加入核心IR
- 不因生态兼容降低安全Gate

# 前置依赖
- Batch 01/03公共IR
- Batch 04 Identity
- Batch 05 Registry
- Batch 11 Adapter SDK

# 强制安全原则
1. 每个标准版本独立Schema包和hash
2. 映射到内部IR后仍执行统一PEP
3. 身份编码只作为标识，不自动等同可信认证
4. 扩展字段保存在命名空间extensions
5. 无法映射的安全字段导致拒绝或人工审查
6. 禁止把实现与某一家厂商API耦合

# 建议目录

```text
protocol-adapters/cn-agent-standard
schemas/cn-standard-versions
conformance-tests/cn-standard
docs/protocols/cn-standard
compatibility/cn-standard
```

# 必须实现的公共接口

```text
CnIdentityMapper
CnCapabilityMapper
CnDiscoveryAdapter
CnInteractionAdapter
CnToolCallAdapter
CompatibilityReporter
ExtensionNamespaceRegistry
```

# 第1步：版本资产
- 导入用户/官方提供的具体版本Schema和示例
- 记录来源、发布日期、hash和许可
- 无可靠规范内容时只建Adapter骨架和待填版本包，不伪造字段

# 第2步：身份与注册发现
- 映射Agent ID、组织、生命周期、endpoint和信任证据
- 注册、更新、吊销和健康状态进入统一Registry

# 第3步：能力和Tool
- 能力描述映射Capability IR
- Tool输入输出Schema映射并计算loss score
- 区分发现与授权

# 第4步：交互映射
- 任务、消息、事件、错误、流式和取消语义
- 数据跨域和租户字段显式进入Policy Context

# 第5步：企业扩展
- 使用vendor/enterprise namespace
- 扩展不能覆盖核心安全字段

# 第6步：兼容矩阵
- 国内版本↔内部IR↔MCP/A2A能力对照
- 生成不可映射项、降级行为和测试覆盖

# 第7步：升级策略
- 双版本并行、迁移工具、回滚和灰度
- Schema变化触发Conformance和Policy回归

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 身份编码伪造不能提升trust
- 未知标准版本拒绝或隔离
- 扩展字段覆盖核心字段失败
- 同一能力跨MCP/国内Adapter规范化结果对比
- 数据跨域字段缺失时高风险调用拒绝
- 版本升级和回滚测试

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- 版本化Adapter骨架
- Version Package格式
- 兼容矩阵生成器
- Mapping Loss报告
- 企业扩展Registry
- 升级Runbook

# 完成Gate
- 核心安全逻辑无国内/国外分叉
- 未获得具体规范内容时不伪造“完整实现”
- 标准版本变化只影响Adapter/Mapping
- 发现不等于授权
- 兼容损失可见并有Gate
- 私有部署和审计字段可传递

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    以版本包适配国内智能体身份、描述、发现、交互和工具调用规范；不硬编码未确认字段，不把身份编码当作认证凭证。

    ## 依赖分类

    - **contract dependencies**：Batch 11
- **implementation dependencies**：Batch 01, Batch 03, Batch 04, Batch 05, Batch 06, Batch 11
- **runtime integrations**：Batch 18, Batch 19, Batch 30
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 官方/客户提供的规范版本、Schema、样例和许可被记录Hash。
- CN Adapter与MCP/A2A共享内部IR和PEP，不形成国内版安全分叉。
- 企业扩展使用命名空间且不能覆盖核心安全字段。

    ## 新增或强化的模型

    - CnStandardVersionBundle
- CnIdentityClaim
- CnCapabilityDescription
- CnDiscoveryRecord
- CnMappingLossReport
- CnExtensionNamespace

    ## 必须落盘的接口

    - CnIdentityMapper
- CnCapabilityMapper
- CnDiscoveryAdapter
- CnInteractionAdapter
- CnToolCallAdapter
- CompatibilityReporter

    ## 新增负向测试与故障注入

    - 身份编码伪造、未知版本、扩展覆盖、跨域字段缺失、双版本灰度与回滚。
- 与MCP/A2A相同能力的规范化结果对比。
- 无可靠规范内容时只交付骨架，不伪造“完整兼容”。

    ## v2.0完成Gate

    - 标准变化只影响版本包和Adapter。
- 发现、注册、认证、授权四者明确分离。
- 兼容损失可量化并能阻断高风险降级。

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
7. **Next integration**：Batch 18数据跨域治理、Batch 19合规证据。
