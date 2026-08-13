---
name: agent-trust-medical-risk-pack
description: 实现医疗Agent的最小必要数据访问、患者身份/治疗关系、敏感字段、临床证据、人工复核、模型版本和审计Risk Pack。用于 Batch 26，首阶段仅支持检索、摘要、编码辅助、文档生成和风险提示，不开放自主诊断、处方或治疗控制。
compatibility: 需要Batch 18数据治理、Batch 17审批、私有部署、医疗测试数据和组织法律/临床团队确认。不得把本Skill视为医疗合规或临床认证结论。
metadata:
  project: agent-trust-control-plane
  batch: "26"
  version: "2.0.0"
---
# Batch 26：Medical Agent Risk Pack
# 任务
在不越过临床责任边界的前提下，让医疗Agent只访问具有合法关系和最小必要范围的数据，输出可追溯证据并由合格人员复核。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。 本Domain Pack必须复用公共身份、PEP、审批、Sandbox、Proxy、Ledger、Trace、Kill Switch和Evidence，不复制、不旁路公共安全内核。
# 触发条件
- 实现Batch 26
- 医疗文档/检索/编码Agent
- 患者数据权限与脱敏
- 临床人工复核和证据链

# 非目标
- 不自主诊断
- 不自主开药/改药
- 不直接控制医疗设备
- 不以模型输出替代临床人员
- 不宣称自动满足任何特定法域全部法规

# 前置依赖
- Batch 18 Data Governance
- Batch 17 Approval
- Batch 15 Model Gateway
- Batch 19 Audit

# 强制安全原则
1. 患者身份和治疗关系在每次访问时验证
2. 只返回任务最小必要字段
3. 模型必须符合部署和数据地域Policy
4. 所有临床相关输出标注来源、时间、模型/知识版本和不确定性
5. 高风险建议必须人工复核
6. 患者数据不进入公共日志或未经批准模型

# 建议目录

```text
domain-packs/medical
policies/medical
python/evaluator-runtime/medical
threat-scenarios/medical
conformance-tests/domain/medical
docs/domain/medical
```

# 必须实现的公共接口

```text
medical.patient_context_read
medical.document_search
medical.summary_generate
medical.coding_suggest
medical.risk_flag
medical.review_request
MedicalEvaluator.evaluate
```

# 第1步：角色与关系
- 患者、医生、护士、编码员、管理员、Agent
- 治疗关系、委托、紧急访问和最小必要范围

# 第2步：数据分类
- 身份、诊断、药物、影像、基因、支付等子标签
- 字段级脱敏和purpose of use

# 第3步：Tool边界
- 只读检索、摘要、编码建议、文档草稿、风险标记
- 写入正式病历/订单需独立审批和人工确认

# 第4步：模型与知识
- 批准模型、私有部署、知识库版本、引用和过期检查
- 检索证据不足时明确NEEDS_HUMAN

# 第5步：人工复核
- 展示原文证据和差异
- 记录reviewer、决定、修改和时间
- 禁止暗示已由医生确认

# 第6步：Evaluator
- 患者匹配、证据完整、事实一致、遗漏风险、敏感泄漏、review完成
- 使用去标识测试集和专家抽样

# 第7步：审计与安全
- break-glass、异常批量访问、跨患者枚举、导出限制
- Legal Hold和患者请求按组织Policy处理

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 错误患者/无治疗关系访问拒绝
- 批量枚举与越权字段拒绝
- 受限数据不进入公共模型/Trace
- 无证据临床结论Evaluator失败
- 人工复核缺失不能完成高风险任务
- Prompt Injection in medical document不能调用额外Tool

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Medical Pack
- 角色/治疗关系Policy
- 数据标签
- 只读Tool集合
- Review Workflow
- Medical Evaluator和安全测试集

# 完成Gate
- 首版无自主诊断/处方/治疗
- 真实部署前由组织临床/法律/安全审查
- 最小必要和患者隔离测试通过
- 高风险输出有人工复核
- 证据和模型版本可追溯
- 敏感数据路径有完整Evidence

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Medical Pack首阶段限定信息检索、摘要、编码辅助、文档生成和风险提示，所有诊断/处方/治疗动作默认禁止或强人工控制。

    ## 依赖分类

    - **contract dependencies**：Batch 20
- **implementation dependencies**：Batch 04, Batch 05, Batch 06, Batch 07, Batch 08, Batch 09, Batch 10, Batch 17, Batch 18, Batch 19, Batch 20, Batch 29
- **runtime integrations**：Batch 21, Batch 22, Batch 28, Batch 32, Batch 33, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 患者身份、治疗关系、最小必要访问、字段脱敏和审计。
- 模型、知识来源、Prompt和临床证据版本可追溯。
- 高风险建议必须有人类专业角色承担最终决策。

    ## 新增或强化的模型

    - PatientContextRef
- CareRelationship
- ClinicalDataScope
- ClinicalEvidenceRef
- HumanReview
- MedicalRiskFinding

    ## 必须落盘的接口

    - ClinicalAccessPolicy
- MedicalToolProvider
- EvidenceRetriever
- HumanReviewService
- MedicalEvaluator

    ## 新增负向测试与故障注入

    - 患者错配、越权访问、敏感字段泄漏、无证据结论、过期知识、模型版本漂移、跨域导出。
- 不得以模拟测试宣称临床有效性。
- 未人工复核的高风险输出不能进入业务系统。

    ## v2.0完成Gate

    - 明确非诊疗边界和禁止动作。
- 数据最小化、私有部署和删除/留存闭环。
- 使用Batch32知识来源与Prompt Provenance。

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
7. **Next integration**：按具体医疗场景和法域另行认证。
