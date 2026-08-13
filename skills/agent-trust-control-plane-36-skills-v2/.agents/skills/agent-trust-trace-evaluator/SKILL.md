---
name: agent-trust-trace-evaluator
description: 实现 Agent Trust & Compliance Control Plane 的端到端Trace、审计事件规范、Hash证据链、Artifact引用、公共完成硬门槛和可插拔Domain Completion Evaluator。用于 Batch 10，证明Agent做过什么以及任务是否真正完成。不要把Tool返回成功直接等同Task完成。
compatibility: 需要 Rust OpenTelemetry、Python evaluator runtime、PostgreSQL/ClickHouse或现有观测后端、对象存储，以及Batch 01—09接口。
metadata:
  project: agent-trust-control-plane
  batch: "10"
  version: "2.0.0"
---
# Batch 10：Trace、Evidence与Evaluator Governance
# 任务
形成从目标、身份、策略、审批、凭证、执行、补偿到业务结果的完整证据链，并用确定性硬门槛加领域Evaluator决定PASS、FAIL、NEEDS_HUMAN或ROLLED_BACK。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 10
- 建设Trace、回放、Evidence Package
- 实现任务完成Evaluator
- 解决工具成功但业务未完成
- 需要审计证据或跨服务关联

# 非目标
- 不把完整Secret/Prompt/源码写入Telemetry
- 不依赖LLM自评作为唯一完成证据
- 不允许Trace采样丢掉安全关键事件
- 不把Observability UI当作执行控制

# 前置依赖
- Batch 01 Evidence/Evaluation契约
- Batch 02 Trace上下文
- Batch 04身份事件
- Batch 06 Policy结果
- Batch 07/08/09执行事实

# 强制安全原则
1. 安全关键事件100%记录或执行失败关闭
2. 事件payload大内容使用受控Artifact引用
3. event_hash包含previous_hash和规范化内容
4. Evidence Package可离线验证
5. Task COMPLETED只允许Evaluation PASS
6. Evaluator必须列出硬门槛和具体Evidence引用

# 建议目录

```text
rust/crates/audit-events
rust/crates/evidence-chain
python/evaluator-runtime
schemas/evidence
schemas/evaluation
conformance-tests/evidence
docs/evaluation
```

# 必须实现的公共接口

```text
AuditSink.append(SignedAuditEvent)
EvidenceBuilder.build(task_id)->EvidencePackage
EvidenceVerifier.verify(package)->VerificationReport
Evaluator.evaluate(EvaluationInput)->EvaluationResult
DomainEvaluatorPlugin.manifest/checks/evaluate
ArtifactStore.put/get_signed_ref
```

# 第1步：事件模型
- 定义TaskCreated、PlanGenerated、PolicyEvaluated、ApprovalDecision、CredentialIssued、ToolPrepared、ToolExecuted、Compensation、Evaluation等
- 事件包含actor、source service、trace/span、payload hash和schema version

# 第2步：OpenTelemetry
- 统一Span命名和属性白名单
- 跨Gateway、PEP、Sandbox、Proxy、Ledger传播
- 禁止将Tool arguments作为普通属性；只记录hash和受控摘要

# 第3步：证据链
- 对每个Task维护顺序号和previous_event_hash
- 签名链头和Evidence Manifest
- 处理并发事件的确定性排序或分支Merkle结构
- 提供离线verify命令

# 第4步：Artifact管理
- 构建日志、测试报告、Diff、遥测窗口写对象存储
- Artifact包含content hash、media type、classification、retention和access policy

# 第5步：公共Evaluator硬门槛
- 身份有效、Tool已注册、Policy允许、审批匹配、凭证有效、Trace完整、Ledger终态明确、无未处理高危告警
- 任一硬门槛失败直接FAIL或NEEDS_HUMAN

# 第6步：领域Evaluator插件
- Python插件受版本、签名和超时限制
- 输出结构化checks、score、findings、evidence_refs
- LLM judge只能作为辅助软检查，必须保存模型版本和输入摘要

# 第7步：完成状态写入
- Evaluation PASS后由受控服务转换Task状态
- 防止Agent自行写COMPLETED
- Evaluator失败或超时时不得默认通过

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 篡改任意事件或Artifact后离线验证失败
- 丢失审批/Policy事件时Evaluator不通过
- Tool成功但编译失败的Coding任务为FAIL
- 工业写入ACK但遥测未收敛为FAIL/NEEDS_HUMAN
- Evaluator超时、崩溃和不确定结果测试
- 敏感字段扫描和高基数Telemetry检查

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- 事件Schema与OTel instrumentation
- Evidence链和离线验证CLI
- Artifact Store接口
- 公共Evaluator runtime
- Coding/Industrial示例Evaluator
- Evidence Package样例和审计文档

# 完成Gate
- Completed任务100%有可验证Evidence Package
- 安全关键事件无采样丢失
- 篡改检测和敏感字段测试通过
- Evaluator结果可重复或解释差异
- Agent无直接完成状态写权限
- Domain Pack可以注册Evaluator而不修改核心

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Trace和Evidence证明发生过什么；Evaluator证明业务目标是否达成。Evaluator本身必须版本化、校准、独立治理，不能由执行Agent的同一模型作为唯一裁判。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03, Batch 09
- **implementation dependencies**：Batch 01, Batch 03, Batch 09
- **runtime integrations**：Batch 19, Batch 21, Batch 22, Batch 23, Batch 24, Batch 25, Batch 26, Batch 27, Batch 29, Batch 33
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - Evidence事件使用Hash链/签名并关联Goal、Plan、Policy、Approval、Credential、Execution。
- Evaluator只能返回判定和证据，Task终态由Batch 29状态机写入。
- 硬Gate由确定性检查优先；模型Judge仅作为受控补充。

    ## 新增或强化的模型

    - EvidenceEvent
- EvidencePackage
- EvaluatorManifest
- CalibrationDatasetRef
- EvaluationRun
- DisputeCase
- EvidenceIntegrityReport

    ## 必须落盘的接口

    - TraceIngestor
- EvidenceChainVerifier
- EvaluatorRuntime
- HardGateEvaluator
- JudgeProviderPort
- EvaluationDisputeService

    ## 新增负向测试与故障注入

    - 篡改、删除、重排事件；证据后端延迟；Evaluator超时、漂移、不同Judge不一致。
- 执行Agent与Judge相同模型时要求第二独立证据或人工复核。
- PASS但缺少硬Gate证据必须降为NEEDS_HUMAN。

    ## v2.0完成Gate

    - Evaluator版本、阈值、数据集和模型可追溯。
- 存在准确率/误报/漏报基线和回滚。
- Evidence Package可离线验证且不泄露Secret。

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
7. **Next integration**：Batch 19审计留存、Batch 21异常检测、Batch 22生产Release Gate。
