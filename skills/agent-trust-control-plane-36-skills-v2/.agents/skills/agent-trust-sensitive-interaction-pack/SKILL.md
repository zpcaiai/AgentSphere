---
name: agent-trust-sensitive-interaction-pack
description: 实现属灵、心理情绪、未成年人、导师/牧者协作等高敏感交互的Risk Pack。用于 Batch 27，控制隐私收集、操纵性语言、过度依赖、越权替代专业人员、危机升级、人工接管、引文证据和最小共享。
compatibility: 需要Batch 17/18/19、敏感交互政策、人工支持流程。危机热线信息必须由运行产品按用户地区使用可靠来源动态获取，不能硬编码在Pack。
metadata:
  project: agent-trust-control-plane
  batch: "27"
  version: "2.0.0"
---
# Batch 27：Sensitive Interaction Risk Pack
# 任务
让敏感交互Agent在帮助用户时保持透明、非操纵、最小数据、可退出、可人工接管，并把高风险或不确定情况升级给合适的人，而非扩大自身权威。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。 本Domain Pack必须复用公共身份、PEP、审批、Sandbox、Proxy、Ledger、Trace、Kill Switch和Evidence，不复制、不旁路公共安全内核。
# 触发条件
- 实现Batch 27
- 属灵星球敏感功能
- 心理情绪支持或导师协作
- 未成年人或危机升级
- 对话安全Evaluator

# 非目标
- 不替代牧者、医生、心理专业人员或紧急服务
- 不诊断用户身份/健康/属灵状态
- 不通过羞耻、恐惧、依赖推动留存
- 不未经同意共享私密记录

# 前置依赖
- Batch 17 Approval/Human takeover
- Batch 18 Data Governance
- Batch 19 Audit
- Batch 21 Anomaly Detection

# 强制安全原则
1. 收集最小必要信息且说明用途
2. 用户可查看、纠正、删除或退出长期记忆
3. Agent明确身份和能力限制
4. 高风险信号触发人工/紧急升级而非继续普通对话
5. 引文和教义/专业内容有来源与版本
6. 未成年人采用更严格默认和监护/组织Policy

# 建议目录

```text
domain-packs/sensitive-interaction
policies/sensitive-interaction
python/evaluator-runtime/sensitive
threat-scenarios/sensitive
conformance-tests/domain/sensitive
docs/domain/sensitive
```

# 必须实现的公共接口

```text
sensitive.content_retrieve
sensitive.reflection_generate
sensitive.human_handoff
sensitive.mentor_review_request
sensitive.crisis_escalate
SensitiveInteractionEvaluator.evaluate
```

# 第1步：风险分类
- 一般反思、敏感隐私、高风险建议、危机、未成年人
- 为每级定义允许Tool、数据、人工介入和留存

# 第2步：对话边界
- 禁止权威冒充、绝对化保证、孤立用户、经济/情感操纵
- 提供可退出和人工帮助路径

# 第3步：隐私与共享
- 最小记录、敏感字段加密、按目的授权
- 牧者/导师只看最小必要摘要并有用户/组织规则

# 第4步：证据与内容治理
- 圣经/神学/专业材料引用、上下文和版本
- 争议观点标注立场，不伪装唯一共识

# 第5步：危机与人工接管
- 识别高风险信号后暂停普通自动建议
- 调用产品内地区化可靠热线/人工流程
- 记录最小安全Evidence

# 第6步：未成年人
- 年龄不确定时采用保守默认
- 限制私密一对一、长期依赖和敏感记忆
- 遵守部署组织政策

# 第7步：Evaluator
- 操纵、过度依赖、越权、隐私、证据、升级时机和人工交接
- 红队长对话而非单轮

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 诱导Agent要求用户远离家人/专业人员时拒绝
- Agent不能承诺绝对保密或神圣权威
- 敏感记录未经授权不共享
- 高风险信号触发handoff并停止普通流程
- 文档Prompt Injection不改变安全边界
- 未成年人场景采用更严格策略

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Sensitive Pack
- 风险分级和Policy
- Human handoff接口
- 内容证据规则
- 长对话红队集
- Sensitive Evaluator与治理文档

# 完成Gate
- 不建立操纵性留存机制
- 高风险升级路径经过演练
- 隐私和最小共享测试通过
- Agent身份与限制透明
- 长期对话异常可检测
- 组织/专家审核后再启用高敏感功能

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Sensitive Interaction Pack治理属灵、心理情绪、未成年人和高风险建议场景，防止操纵、过度依赖、隐私扩张和专业越权。

    ## 依赖分类

    - **contract dependencies**：Batch 20
- **implementation dependencies**：Batch 04, Batch 05, Batch 06, Batch 07, Batch 08, Batch 09, Batch 10, Batch 17, Batch 18, Batch 19, Batch 20, Batch 29, Batch 32
- **runtime integrations**：Batch 21, Batch 22, Batch 28, Batch 33, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 最小必要信息、关系边界、人类导师/牧者/专业人员协作和危机升级。
- 神学/知识引用有来源、立场和版本，不把Agent当作终极权威。
- 高风险危机由明确流程升级，不由模型单独判断结束。

    ## 新增或强化的模型

    - SensitiveConversationContext
- RelationshipBoundary
- SourceCitation
- HumanEscalation
- ConsentRecord
- InteractionRiskFinding

    ## 必须落盘的接口

    - SensitivePolicyPack
- ConsentService
- CitationVerifier
- EscalationRouter
- InteractionEvaluator

    ## 新增负向测试与故障注入

    - 操纵性语言、依赖诱导、隐私过度收集、错误引用、未成年人保护、未经许可共享、危机升级失败。
- Memory污染和删除使用Batch32。
- 人工接管后Agent停止高风险推进。

    ## v2.0完成Gate

    - 使用Batch20 SDK。
- 敏感信息与Trace最小化。
- 危机、同意和共享有可审计责任链。

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
7. **Next integration**：属灵星球及其他敏感产品按组织政策定制。
