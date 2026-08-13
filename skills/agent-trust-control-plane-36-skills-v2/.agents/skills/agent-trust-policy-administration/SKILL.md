---
name: agent-trust-policy-administration
description: 实现Policy Administration Point、策略编辑评审、静态分析、模拟、影子评估、影响分析、灰度发布、回滚和例外到期。用于Batch 31，把Batch 06 PEP升级为企业可治理的Policy生命周期。
compatibility: Java/Spring Boot或Rust服务 + OPA/Cedar工具链 + Vue；需要Batch 06、17、18、21、30。
metadata:
  project: agent-trust-control-plane
  batch: "31"
  version: "2.0.0"
---

# Batch 31：Policy Administration、Simulation与Change Governance

# 任务

建立安全策略从编写、验证、评审、模拟、发布到撤销的完整生命周期，在不影响PEP确定性的前提下控制策略变更风险。

完成本Skill时必须在当前目标仓库实现真实代码、Schema、数据库迁移、测试、部署配置、Runbook和Evidence；不得只提交设计、空接口、TODO或模拟通过报告。先盘点现有实现并增量集成，禁止创建第二套平行架构。

# 触发条件

- 建设Policy Studio、PAP、policy-as-code CI
- 评估规则修改会阻断哪些Agent/Task
- 处理临时例外、灰度、回滚和策略覆盖率

# 非目标

- 不在PAP执行真实Tool
- 不允许UI直接修改生产PEP缓存
- 不自动把自然语言转成未经评审的生产Policy
- 不替代Batch06本地硬守卫

# 依赖分类

- **contract dependencies**：Batch 01, Batch 06
- **implementation dependencies**：Batch 06, Batch 17, Batch 18, Batch 21, Batch 30
- **runtime integrations**：Batch 22, Batch 33, Batch 35, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

# 权威边界与安全不变量

- Policy Bundle是不可变签名产物；环境Promotion通过引用Digest完成。
- Simulation与Shadow Evaluation永不产生真实副作用。
- 例外必须绑定Owner、范围、原因、到期和补偿控制。

# 建议目录

- `java/policy-admin`
- `policies/source`
- `policies/tests`
- `web/policy-studio`
- `reports/policy-impact`

# 核心模型

- PolicySource
- PolicyBundle
- PolicyChange
- Review
- SimulationRun
- ImpactReport
- ExceptionGrant
- Promotion
- Rollback

# 必须实现的接口

- PolicyAdminApi
- PolicyCompiler
- StaticAnalyzer
- SimulationEngine
- ImpactAnalyzer
- PromotionController
- ExceptionService

# 实施步骤

## 第1步

实现Policy source repository、版本、签名和审批工作流。

## 第2步

构建语法、类型、死规则、冲突、过宽ALLOW和不可达规则静态分析。

## 第3步

使用历史/合成Action与Batch33场景运行Simulation。

## 第4步

实现Shadow Evaluation：记录新旧决策差异但不改变执行。

## 第5步

生成受影响Agent、Tool、资源、租户、任务和风险级别报告。

## 第6步

实施dev→staging→canary→production Promotion与自动回滚。

## 第7步

管理例外到期、Owner、范围和持续补偿控制。

## 第8步

将Bundle Digest发布到PEP并验证缓存一致性。


# 数据、错误与可观测要求

- 所有跨服务对象带`schema_version`，安全决策、配置、Policy、Pack和模型带不可变版本或Digest。
- 错误使用稳定机器码、`trace_id`和安全摘要；不得回显Secret、完整敏感输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换、人工动作和恢复写入Batch 10/19证据链。
- 所有队列、缓存、连接池、分页和后台任务有界；超载时拒绝或受控降级。
- Production profile失败关闭；Dev bypass必须显式、醒目且CI证明无法进入生产构建。
- 所有Task完成声明由Batch 29状态机和Batch 10 Evidence共同证明。

# 必须实现的测试矩阵

- 策略冲突、循环引用、未知字段、默认ALLOW、例外无到期
- 大规模历史Action模拟和差异准确性
- Canary错误率/拒绝率触发回滚
- PAP故障不改变PEP已签名安全快照
- 跨租户策略泄漏和越权编辑
- Policy bundle签名/rollback攻击

# 必须执行的故障注入

- 编译器崩溃
- 发布中网络分区
- 部分PEP更新
- 审查服务不可用
- 历史数据缺失

# 必须提交的交付物

- Policy Admin API
- Policy Studio最小页面
- 编译/静态分析/模拟工具
- Impact Report
- Promotion与Rollback流水线
- Policy CI模板

# 完成Gate

- 生产Bundle不可被原地修改
- 变更前有模拟和影响报告
- 高风险变更有职责分离审批
- PEP能验证Bundle Digest与版本
- 例外自动到期并产生Evidence

以下情况一律不得标记完成：核心路径仍为TODO；只提交接口无实现；关键测试被skip；使用Mock声称真实隔离、真实协议、真实灾备或真实临床/工业验证通过；无法提供实际运行命令、退出码、报告和Evidence；存在已知高危旁路而未失败关闭。

# Codex执行顺序

1. 读取`AGENTS.md`、公共契约、依赖DAG、现有架构和相关Batch接口。
2. 输出不超过一页的现状盘点与增量实施顺序，然后立即开始落盘。
3. 先完成最小纵向闭环，再完成负向安全、故障注入、可观测、文档和Evidence。
4. 每次修改后运行最小相关测试；最终运行本Batch全部Gate和跨Batch契约测试。
5. 不静默修改公共契约；需要修改时同步更新Batch 01 Schema、生成代码、兼容测试和Traceability Matrix。
6. 更新`IMPLEMENTATION_STATUS.json`，状态只能是`NOT_STARTED`、`IN_PROGRESS`、`BLOCKED`或`EVIDENCE_VERIFIED`。

# Codex最终报告格式

1. **Implemented**：实际完成的模块、接口和不变量；
2. **Files changed**：按代码、Schema、迁移、测试、部署和文档分组；
3. **Commands run**：真实命令、退出码、关键结果和报告路径；
4. **Security evidence**：负向测试、故障注入、隔离/权限/幂等/恢复证据；
5. **Compatibility**：契约、协议、数据库、Policy、Pack和部署影响；
6. **Unresolved risks**：有证据但未解决的问题与阻断级别；
7. **Next integration**：下一依赖Batch、接口和迁移要求。

规范文件完成不等于产品代码完成。没有真实Evidence时禁止使用“全部实现”“生产可用”或“通过认证”等表述。
