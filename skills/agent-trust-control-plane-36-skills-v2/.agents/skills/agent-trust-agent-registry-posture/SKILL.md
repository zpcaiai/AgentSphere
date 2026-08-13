---
name: agent-trust-agent-registry-posture
description: 实现企业Agent Registry、发现、Owner/Sponsor、资产关系图、Shadow Agent发现与安全姿态管理。用于Batch 30，统一治理Agent、MCP Server、模型、Tool、Memory、Knowledge和运行环境资产。
compatibility: 推荐Java/Spring Boot + PostgreSQL/图查询，Rust/Python采集器；需要Batch 04、05、11、14、20。
metadata:
  project: agent-trust-control-plane
  batch: "30"
  version: "2.0.0"
---

# Batch 30：Agent Registry、Discovery与Posture Management

# 任务

建立企业Agent资产事实源和持续姿态管理，回答“有哪些Agent、谁负责、使用什么模型/工具/数据、拥有什么权限、当前是否健康合规”。

完成本Skill时必须在当前目标仓库实现真实代码、Schema、数据库迁移、测试、部署配置、Runbook和Evidence；不得只提交设计、空接口、TODO或模拟通过报告。先盘点现有实现并增量集成，禁止创建第二套平行架构。

# 触发条件

- 建设Agent inventory、registry、discovery或posture dashboard
- 发现Shadow Agent、无Owner Agent或下线后仍有权限的Agent
- 为企业审计、授权审查和Marketplace提供资产关系

# 非目标

- 不替代Tool Registry
- 不把网络发现结果自动标记为可信Agent
- 不直接执行Tool或签发Credential
- 不依据Agent自述给出生产信任

# 依赖分类

- **contract dependencies**：Batch 01, Batch 04, Batch 05, Batch 11
- **implementation dependencies**：Batch 04, Batch 05, Batch 11, Batch 14, Batch 20
- **runtime integrations**：Batch 21, Batch 28, Batch 31, Batch 35, Batch 36
- **optional integrations**：Batch 12, Batch 13

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

# 权威边界与安全不变量

- Agent Registry管理Agent资产；Batch05管理Tool/Capability资产。
- 发现记录、注册记录、认证身份和授权状态是四类不同事实。
- 所有Agent必须有Owner、Sponsor、生命周期、环境和BOM。

# 建议目录

- `java/agent-registry`
- `rust/discovery-collectors`
- `python/posture-analysis`
- `web/agent-inventory`
- `tests/agent-registry`

# 核心模型

- AgentAsset
- AgentInstance
- AgentBom
- Ownership
- DiscoveryObservation
- Registration
- PostureFinding
- LifecycleRecord
- RelationshipEdge

# 必须实现的接口

- AgentRegistryApi
- DiscoveryIngestApi
- OwnershipResolver
- AgentBomService
- PostureEngine
- LifecycleController
- RelationshipGraphQuery

# 实施步骤

## 第1步

定义Agent、实例、Endpoint、MCP Server、模型、Prompt、Memory、Knowledge、Tool和Pack关系。

## 第2步

实现显式注册、协议发现、网络/日志观察和导入四类来源，并保留provenance。

## 第3步

建立Owner/Sponsor解析、确认和逾期升级。

## 第4步

生成Agent BOM并关联Batch20供应链Digest。

## 第5步

实现Shadow、Orphan、Dormant、Overprivileged、Drifted和Revoked-but-active姿态规则。

## 第6步

将Agent生命周期变化传播到Batch04 Token、Batch06授权和Batch28 Pack激活。

## 第7步

提供Inventory、关系图、风险查询和审计导出。


# 数据、错误与可观测要求

- 所有跨服务对象带`schema_version`，安全决策、配置、Policy、Pack和模型带不可变版本或Digest。
- 错误使用稳定机器码、`trace_id`和安全摘要；不得回显Secret、完整敏感输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换、人工动作和恢复写入Batch 10/19证据链。
- 所有队列、缓存、连接池、分页和后台任务有界；超载时拒绝或受控降级。
- Production profile失败关闭；Dev bypass必须显式、醒目且CI证明无法进入生产构建。
- 所有Task完成声明由Batch 29状态机和Batch 10 Evidence共同证明。

# 必须实现的测试矩阵

- 伪造发现记录不能提升trust
- 同一Agent多协议/多Endpoint去重与冲突
- Owner删除、组织迁移和跨租户不可见
- 下线Agent仍活动、凭证未撤销和Pack已撤销
- BOM组件漂移触发姿态告警
- 大量资产导入和分页/搜索性能

# 必须执行的故障注入

- 采集器离线与重复上报
- Registry数据库故障
- 事件乱序
- Owner目录不可用
- 协议发现返回恶意数据

# 必须提交的交付物

- Agent Registry服务和迁移
- Discovery Collector SDK
- Agent BOM schema
- Posture Rule Engine
- Inventory API/UI最小页面
- 资产关系与风险Evidence

# 完成Gate

- 每个生产Agent有Owner、Sponsor、BOM和生命周期
- Shadow Agent发现不自动授权
- 资产变化能触发授权/凭证收敛
- 跨租户隔离和大规模查询通过
- 与Tool Registry无数据所有权冲突

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
