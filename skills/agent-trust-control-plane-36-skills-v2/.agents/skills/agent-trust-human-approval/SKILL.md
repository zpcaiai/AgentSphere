---
name: agent-trust-human-approval
description: 实现企业级Human-in-the-loop审批服务和Rust Approval Enforcement。用于 Batch 17，支持动作、范围、升级、双人和紧急审批，绑定精确Action Hash、资源版本、Policy版本、风险和有效期。不要使用“批准Agent继续完成任务”这类模糊授权。
compatibility: 需要Java/Spring Boot或现有企业后端、Rust验证库、Vue审批台、Batch 04身份、Batch 06 PEP、Batch 10 Evidence。
metadata:
  project: agent-trust-control-plane
  batch: "17"
  version: "2.0.0"
---
# Batch 17：Enterprise Human Approval与职责分离
# 任务
让所有需要人工承担责任的副作用，在执行前获得范围明确、不可篡改、不可重复使用、符合职责分离的审批，并在执行时再次验证。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 17
- 开发审批台和审批API
- 实现双人审批、升级审批或紧急审批
- 将审批绑定Action/Resource/Policy

# 非目标
- 不允许Agent自批
- 不把聊天回复当审批
- 不批准开放式未来动作
- 不允许审批绕过最新资源状态和Policy重检

# 前置依赖
- Batch 04身份与角色
- Batch 06 obligations
- Batch 10 Evidence
- 企业组织/资源所有权数据

# 强制安全原则
1. 审批绑定action_hash、resource version、policy bundle和environment
2. 任何绑定字段变化审批失效
3. single-use原子消费
4. 职责分离和风险等级决定审批人集合
5. 审批过期/撤销/角色变化即时生效
6. 执行前重新Policy和资源状态检查

# 建议目录

```text
java/approval-service
rust/crates/approval-verifier
web/approval-console
schemas/approval
conformance-tests/approval
docs/governance/approval
```

# 必须实现的公共接口

```text
ApprovalService.request/approve/reject/revoke
ApproverResolver.resolve
ApprovalVerifier.verify_and_consume
ApprovalPolicy.evaluate_requirements
NotificationAdapter.send
EmergencyApproval.audit
```

# 第1步：审批模型
- Action、Scope、Escalation、Dual、Emergency类型
- 明确允许Tool/资源/参数范围、次数、时间窗和最大风险

# 第2步：审批人解析
- 基于tenant、资源owner、角色、值班和职责分离
- Agent owner不一定有生产审批权
- 双人审批要求独立subject

# 第3步：审批页面
- Coding展示diff、命令、网络、回滚
- 工业展示当前/目标值、范围、联锁、物理影响
- 隐藏Secret，显示Evidence引用

# 第4步：签名和消费
- 服务签发不可篡改Approval Token/Record
- Rust PEP在执行前原子verify-and-consume
- scope approval维护用量和过期

# 第5步：变更与撤销
- 参数、计划、Policy、资源版本、审批人角色变化导致失效
- 支持任务Cancel/Kill自动撤销

# 第6步：紧急流程
- break-glass要求强认证、理由、短TTL、事后复核和告警
- 不得降低不可执行的安全联锁

# 第7步：通知和SLA
- 待审、过期、拒绝和升级通知
- 通知失败不等于审批失败，但不得自动批准

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 参数篡改、资源版本变化和Policy升级使审批无效
- 审批重复消费并发测试
- 错误租户/角色/同一人双签拒绝
- 伪造UI事件和聊天文本不生效
- 过期、撤销和Kill联动
- break-glass完整审计测试

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Approval Service和数据库
- Rust Verifier
- Vue审批台
- Approver Resolver
- 通知接口
- 职责分离策略和审计Evidence

# 完成Gate
- 所有高风险写动作有明确审批或显式禁止
- 不存在模糊全任务授权
- 审批消费原子且单次
- 执行前双重重检
- UI无法伪造事实
- 紧急审批有事后复核与证据

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Batch 17在Batch 06 Minimal Approval Kernel上实现企业级审批治理，不重新定义Execution Grant。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 06
- **implementation dependencies**：Batch 04, Batch 06, Batch 10
- **runtime integrations**：Batch 13, Batch 18, Batch 21, Batch 22, Batch 29, Batch 31, Batch 35
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 组织、角色、资源Owner、职责分离、双人审批、代理审批和Break-glass。
- 审批UI只提交意图；服务端生成/消费不可伪造Grant。
- 高风险审批人不能是发起Agent或同一不允许角色。

    ## 新增或强化的模型

    - ApprovalCase
- ApprovalPolicy
- ApproverResolution
- SeparationOfDutiesRule
- BreakGlassCase
- ApprovalSla

    ## 必须落盘的接口

    - EnterpriseApprovalService
- ApproverResolver
- SoDEngine
- DelegatedApproverService
- BreakGlassController

    ## 新增负向测试与故障注入

    - 自我审批、串谋角色、审批重放、过期代理、资源Owner变化、双人审批同一主体。
- Break-glass有最短TTL、事后复核和完整证据。
- 与Batch06 Grant格式兼容。

    ## v2.0完成Gate

    - 审批职责解析有确定性测试。
- 任何参数、资源、Plan或Policy变化重新审批。
- MVP审批与企业审批可无缝迁移。

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
7. **Next integration**：Batch 19审计、Batch 23/24领域审批视图。
