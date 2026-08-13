---
name: agent-trust-runtime-anomaly-detection
description: 实现长任务Agent的实时异常轨迹检测。用于 Batch 21，检测目标漂移、范围扩大、凭证移动、沙箱逃逸、重复副作用、审计抑制、资源枚举和数据外泄，并触发告警、Pause或Kill。不要只依赖模型自我解释。
compatibility: 需要Batch 10事件流、Batch 07系统事件、Batch 08网络/凭证事件、Rust实时规则和Python语义检测。
metadata:
  project: agent-trust-control-plane
  batch: "21"
  version: "2.0.0"
---
# Batch 21：异常轨迹检测与Continuous Authorization
# 任务
在单次Tool调用合法但整条轨迹异常时及时发现并阻断，建立确定性规则、统计基线和语义模型的分层检测体系。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 21
- 检测Intent Drift、Scope Expansion、Credential Movement
- 建设Agent SOC/异常告警
- 触发自动Pause或Kill

# 非目标
- 不把所有探索行为当攻击
- 不让LLM detector直接执行生产动作
- 不隐藏误报和不确定性
- 不替代PEP的事前授权

# 前置依赖
- Batch 07 Supervisor
- Batch 08 Proxy
- Batch 10 Trace
- Batch 18数据标签

# 强制安全原则
1. 基础安全规则不依赖模型可用性
2. 每个告警包含输入Evidence、规则/模型版本和置信度
3. 自动Kill只对高确定性高影响场景
4. 检测器不能读取超出其最小数据范围
5. 安全事件不可被Agent关闭
6. 误报反馈有审计且不能直接白名单所有行为

# 建议目录

```text
rust/crates/runtime-detectors
python/anomaly-detectors
schemas/risk-signal
threat-scenarios/runtime
conformance-tests/anomaly
web/incident-console
```

# 必须实现的公共接口

```text
SignalIngest.consume
RuleDetector.evaluate
SemanticTrajectoryDetector.score
RiskAggregator.update
ResponseController.pause/kill/alert
BaselineStore.get/update
```

# 第1步：风险信号
- Tool、resource、network、file、credential、policy deny、approval、process和telemetry事件
- 统一task/step/agent/time窗口

# 第2步：确定性检测
- 访问Metadata、宿主路径、日志关闭、未注册Executor、凭证写文件、重复副作用
- 命中即高风险

# 第3步：范围和目标漂移
- 比较signed goal/plan与资源集合演化
- 建立allowed expansion和审批边界
- 语义模型输出辅助score

# 第4步：凭证移动
- Secret读取、复制、跨Agent/文件/网络传播、错误audience使用
- 与Batch 04/08事件关联

# 第5步：统计与序列
- 调用速率、失败模式、域名数量、资源枚举、循环
- 按Agent类型和Domain建立基线

# 第6步：响应策略
- INFO/WARN/HIGH/CRITICAL
- 告警、要求审批、Pause、Kill和Incident
- 执行动作由受控Response Controller完成

# 第7步：反馈与评测
- 标注、误报/漏报、回放测试、阈值版本
- 防止攻击者利用反馈快速放宽

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 已知逃逸/SSRF/凭证外泄场景触发
- 合法大仓库扫描不被错误Kill的基线测试
- 模型检测器不可用时规则仍工作
- 事件乱序/延迟/重复处理
- 自动响应权限和签名验证
- 对抗性编码、分段外泄和慢速枚举

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Risk Signal Schema
- Rust规则引擎
- Python语义/统计检测器
- Risk Aggregator
- Response Controller
- Threat Scenario corpus与评测报告

# 完成Gate
- 关键逃逸场景检测率有可重复证据
- 自动Kill规则少而明确
- 检测器失败不关闭PEP/Sandbox
- 误报可见并可回放
- 所有响应进入Evidence
- 告警跨租户隔离

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    检测异常后必须触发Continuous Authorization，不只是生成告警；系统能收窄Lease、暂停新Tool、吊销Credential或Kill。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03, Batch 06, Batch 10
- **implementation dependencies**：Batch 04, Batch 06, Batch 10, Batch 17
- **runtime integrations**：Batch 29, Batch 31, Batch 33, Batch 35
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 确定性规则负责高置信实时阻断，Python语义模型负责补充评分。
- 风险聚合基于完整轨迹、资源扩张、Credential移动、网络/文件行为。
- 自动阻断必须记录Reason、证据和恢复条件。

    ## 新增或强化的模型

    - TrajectoryState
- RiskSignal
- RiskAggregate
- AuthorizationAdjustment
- LeaseRevocation
- AnomalyCase

    ## 必须落盘的接口

    - TrajectoryMonitor
- RiskAggregator
- ContinuousAuthorizationController
- LeaseAdjuster
- RuntimeResponseController

    ## 新增负向测试与故障注入

    - Intent Drift、Scope Expansion、Credential Movement、Sandbox Evasion、Slow Exfiltration、Audit Suppression。
- 检测服务失败时基础PEP规则仍生效。
- 误报导致Pause后可审计恢复，旧Lease不能复用。

    ## v2.0完成Gate

    - 风险事件与Batch04/06/08/17/29闭环。
- 检测性能、误报率、阻断延迟有基线。
- 模型不能自行放宽权限。

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
7. **Next integration**：Batch 22 Incident、各Domain Pack专用异常规则。
