---
name: agent-trust-a2a-agui-adapter
description: 实现 A2A Agent委派与AG-UI事件Adapter。用于 Batch 13，保持跨Agent身份、权限上限、任务责任链、流式事件、审批、暂停恢复和Artifact语义一致。不要允许子Agent或前端提升权限或伪造控制结果。
compatibility: 需要Batch 04身份、Batch 10事件、Batch 11 Adapter SDK、WebSocket/SSE与A2A测试端。
metadata:
  project: agent-trust-control-plane
  batch: "13"
  version: "2.0.0"
---
# Batch 13：A2A与AG-UI Adapter
# 任务
支持Agent协作和人与Agent实时交互，同时保证委派链可追责、子任务权限不超过父任务、UI事件不能成为授权事实源。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 13
- 接入A2A Agent Card/Task
- 接入AG-UI流式事件
- 实现子Agent委派或前端审批交互

# 非目标
- 不允许Agent Card自声明可信等级
- 不把UI点击直接当作有效审批
- 不允许子Agent获得父Agent未批准的资源
- 不在Adapter内保存业务状态机真相

# 前置依赖
- Batch 04 Identity
- Batch 06 PEP
- Batch 10 Trace
- Batch 11 Adapter SDK

# 强制安全原则
1. delegated scope是父授权、子能力和Policy的交集
2. 每层委派有签名Delegation Token和最大深度
3. 跨Agent Trace保留root task和parent step
4. UI只展示和提交意图，审批事实由Batch 17服务签名
5. 断线重连使用event sequence和resume token
6. 重复事件不重复副作用

# 建议目录

```text
protocol-adapters/a2a
protocol-adapters/ag-ui
rust/crates/delegation-runtime
web/shared/agui-client
conformance-tests/a2a-agui
docs/protocols/a2a-agui
```

# 必须实现的公共接口

```text
DelegationService.delegate/revoke
AgentCardNormalizer.to_capability_ir
A2ATaskAdapter.submit/cancel/status
AgUiEventStream.publish/resume
ApprovalIntent.submit
DelegationChain.verify
```

# 第1步：A2A Agent Card
- 验证publisher、endpoint和能力声明
- 映射Capability IR并标注信任与已知限制
- Card变化触发重新评估

# 第2步：委派Token
- 绑定parent task/step、child agent、allowed tools/resources、ttl、budget、max depth
- 子Agent再委派只能进一步收窄

# 第3步：任务与状态映射
- A2A状态映射到内部Task/Step，不允许远端直接写COMPLETED
- 远端结果必须进入Evaluator

# 第4步：AG-UI事件
- 定义plan、tool request、approval required、execution status、artifact、evaluation、incident事件
- 事件携带sequence、trace和安全展示字段

# 第5步：审批交互
- 前端提交approve intent到Batch 17
- 服务返回签名Approval event后UI才显示生效

# 第6步：断线恢复
- 服务端事件日志和resume token
- 过期token回退到安全快照，不重复命令

# 第7步：预算与滥用
- 限制委派层数、Token、调用次数、时间和资源范围

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 子Agent请求父任务外资源被拒绝
- 伪造Agent Card和Delegation Token被拒绝
- 前端伪造approved事件不生效
- WebSocket重复/乱序/断线恢复测试
- 远端返回completed但Evaluator失败时内部不完成
- 委派撤销后子Agent后续调用失败

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- A2A/AG-UI Adapter
- Delegation Runtime
- Agent Card映射
- 事件Schema与客户端
- 断线恢复测试
- 委派威胁模型

# 完成Gate
- 权限不随委派扩大
- 完整责任链和Trace可验证
- UI不是授权真相源
- 重复和乱序事件无重复副作用
- 远端状态不绕过Evaluator
- 委派撤销及时生效

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    A2A负责受限委派，AG-UI负责可验证的人机交互；两者都不能绕过授权、审批或状态机。

    ## 依赖分类

    - **contract dependencies**：Batch 11
- **implementation dependencies**：Batch 03, Batch 04, Batch 05, Batch 06, Batch 10, Batch 11
- **runtime integrations**：Batch 17, Batch 21, Batch 29
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 子Agent通过DelegationEnvelope获得不超过父任务的工具、资源、成本和风险预算。
- UI提交审批必须由Batch 17/6服务端验证，客户端事件不能成为授权事实。
- 跨Agent Trace保留委派链、责任链和模型/版本。

    ## 新增或强化的模型

    - AgentCardSnapshot
- DelegationRequest
- DelegationToken
- A2ATaskLink
- AgUiEventEnvelope
- UiApprovalIntent

    ## 必须落盘的接口

    - A2AAdapter
- DelegationLimiter
- AgentCardVerifier
- AgUiStreamAdapter
- UiEventAuthenticator

    ## 新增负向测试与故障注入

    - 子Agent提权、递归委派爆炸、预算绕过、Agent Card漂移、UI伪造Approval、断线重放。
- 父任务取消后所有子任务和Delegation Token失效。
- 跨租户Agent发现默认不可见。

    ## v2.0完成Gate

    - 委派权限集合证明不超过父授权。
- UI事件和后端授权事实严格分离。
- A2A/AG-UI版本兼容和取消语义有端到端证据。

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
7. **Next integration**：Batch 17审批、Batch 21跨Agent异常检测。
