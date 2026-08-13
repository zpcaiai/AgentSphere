---
name: agent-trust-model-gateway
description: 实现国产、海外、私有和本地模型的统一Model Gateway。用于 Batch 15，根据数据等级、地域、部署要求、模型批准状态、能力、成本和延迟执行确定性Policy，再由Python路由器优化选择。不要让Fallback降低数据安全等级。
compatibility: 需要Rust网关、Python模型路由、Batch 04身份、Batch 06 PEP、Batch 18数据分类接口，以及至少两个Mock/真实模型Provider测试适配器。
metadata:
  project: agent-trust-control-plane
  batch: "15"
  version: "2.0.0"
---
# Batch 15：Unified Model Gateway与模型合规路由
# 任务
将模型调用纳入同一身份、策略、预算、Trace和证据控制，统一OpenAI兼容、国产厂商、本地推理等接口，并确保敏感数据不会因智能路由或Fallback离开允许边界。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 15
- 统一国产/海外/私有模型
- 实现模型路由、Fallback、Token成本
- 控制数据出境或模型版本

# 非目标
- 不从零实现推理引擎
- 不把模型质量评分当安全授权
- 不记录完整敏感Prompt
- 不允许Provider Adapter绕过数据Policy

# 前置依赖
- Batch 02 Gateway
- Batch 04 Identity
- Batch 06 PEP
- Batch 10 Trace
- Batch 18 Data Governance接口

# 强制安全原则
1. 先确定性过滤允许Provider，再做质量/成本优化
2. Fallback只能在同等或更严格数据边界内
3. 模型版本和endpoint必须批准并可吊销
4. Prompt/response按数据策略脱敏或引用
5. Provider key不进入Agent进程
6. 流式中断、重试和计费可审计

# 建议目录

```text
rust/crates/model-gateway
python/model-router
protocol-adapters/model-providers
schemas/model-manifest
conformance-tests/model-gateway
docs/models
```

# 必须实现的公共接口

```text
ModelProviderAdapter.generate/stream/embeddings
ModelPolicyFilter.allowed_candidates
ModelRouter.rank
BudgetManager.reserve/finalize
PromptDataGuard.inspect
ProviderRegistry.approve/revoke
```

# 第1步：Provider Manifest
- 记录provider/model/version/region/deployment/capabilities/data terms/endpoint digest
- 区分public API、VPC、on-prem和local

# 第2步：请求IR
- task type、data classification、jurisdiction、required capabilities、latency/cost budget、allowed providers
- Prompt正文放受控payload，Policy使用摘要和标签

# 第3步：确定性过滤
- 数据出境、私有部署、租户批准、模型状态、Tool calling和结构化输出要求
- 无候选时明确失败，不自动放宽

# 第4步：智能路由
- Python根据历史Eval、延迟、成本和负载排序
- 路由算法输出可解释score，不拥有越权能力

# 第5步：流式代理和重试
- 统一SSE/chunk语义
- 请求hash、provider request id、token usage
- 重试保持幂等并防止双重计费

# 第6步：Prompt/Response保护
- Secret、PII、工业敏感字段检查
- 上下文窗口和输出大小限制
- 防止Provider返回控制指令直接执行

# 第7步：预算和审计
- 租户/任务预算、预留和结算
- 模型版本、输入摘要hash、输出artifact、路由理由进入Evidence

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- RESTRICTED数据不会进入public API
- Fallback不会从私有模型降级到公共模型
- Provider key和敏感Prompt不进日志
- Provider超时/流断开/重复响应测试
- 未批准模型与版本立即拒绝
- 预算并发预留不超支

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Model Gateway
- Provider Adapter SDK和至少两个Adapter
- Model Manifest/Registry
- Python Router
- 数据和预算Guard
- 模型路由Evidence

# 完成Gate
- 数据边界优先于性能成本
- Fallback安全不降级
- 模型和版本可追溯、可吊销
- Token/成本计量与Provider对账
- 敏感Prompt不进入普通Trace
- 路由质量可由Evaluator持续更新但不改Policy

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Model Gateway统一国产、海外、私有和本地模型访问，但不与Batch 18形成构建环：它依赖Batch 01定义的DataPolicyPort，Batch 18是可插拔生产实现。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03, Batch 06
- **implementation dependencies**：Batch 02, Batch 04, Batch 05, Batch 06, Batch 08, Batch 10
- **runtime integrations**：无
- **optional integrations**：Batch 18, Batch 31, Batch 32

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 数据等级、地域、部署模式、模型批准状态和能力共同决定路由。
- Fallback不能降低数据安全、地域或审计要求。
- 模型请求、响应和Tool calling受大小、超时、成本和内容出口控制。

    ## 新增或强化的模型

    - ModelRequestEnvelope
- ModelRouteDecision
- ProviderProfile
- DataPolicyDecisionRef
- CostBudget
- FallbackPlan
- ModelEvidence

    ## 必须落盘的接口

    - ModelGateway
- ProviderAdapter
- DataPolicyPort
- RoutePlanner
- CostMeter
- ModelVersionResolver

    ## 新增负向测试与故障注入

    - 敏感数据路由到未批准外部模型、Fallback越权、Provider响应混淆、流式中断、Token成本失控。
- Batch 18未部署时使用保守本地策略并拒绝未知数据等级。
- 模型版本漂移触发Evidence与再评估。

    ## v2.0完成Gate

    - 没有Batch15↔18构建依赖环。
- 每次模型调用可追溯到Provider、模型版本、路由理由和数据Policy。
- 不保存无需留存的完整Prompt/Response。

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
7. **Next integration**：Batch 18 Data Governance、各Domain Pack模型策略。
