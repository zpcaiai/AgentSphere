---
name: agent-trust-memory-prompt-provenance
description: 实现Agent Memory、Prompt模板和Knowledge来源的版本、来源、信任、隔离、写入权限、污染检测、删除与回滚。用于Batch 32，治理Memory poisoning、Prompt漂移和RAG来源风险。
compatibility: Java/Python服务 + 向量库/对象存储适配；需要Batch 04、06、10、18、19、20。
metadata:
  project: agent-trust-control-plane
  batch: "32"
  version: "2.0.0"
---

# Batch 32：Memory、Prompt与Knowledge Provenance

# 任务

让所有进入Agent上下文的长期Memory、System Prompt、Skill Prompt和Knowledge文档具备可追溯来源、版本、信任级别、租户隔离和安全生命周期。

完成本Skill时必须在当前目标仓库实现真实代码、Schema、数据库迁移、测试、部署配置、Runbook和Evidence；不得只提交设计、空接口、TODO或模拟通过报告。先盘点现有实现并增量集成，禁止创建第二套平行架构。

# 触发条件

- 建设Agent memory、RAG、Prompt registry或知识库治理
- 检测Memory poisoning、Prompt injection或知识过期
- 实现删除、TTL、隔离、回滚和引用证据

# 非目标

- 不保存模型私有推理链
- 不把所有聊天默认变成长时Memory
- 不允许检索文档直接成为系统指令
- 不以向量相似度替代权限过滤

# 依赖分类

- **contract dependencies**：Batch 01, Batch 03, Batch 10, Batch 18, Batch 19, Batch 20
- **implementation dependencies**：Batch 04, Batch 06, Batch 10, Batch 18, Batch 19, Batch 20
- **runtime integrations**：Batch 15, Batch 21, Batch 26, Batch 27, Batch 33, Batch 35, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

# 权威边界与安全不变量

- Memory写入是受控Tool Action，需要Policy、数据分类和Evidence。
- Prompt模板与Knowledge快照是Batch20签名供应链产物。
- 检索先做tenant/resource授权，再做相似度搜索。

# 建议目录

- `java/context-governance`
- `python/memory-security`
- `prompts/registry`
- `knowledge/manifests`
- `tests/context-security`

# 核心模型

- MemoryEntry
- MemoryWriteRequest
- PromptManifest
- KnowledgeSource
- KnowledgeSnapshot
- TrustLabel
- QuarantineRecord
- DeletionTombstone

# 必须实现的接口

- MemoryPolicyService
- MemoryStoreProxy
- PromptRegistry
- KnowledgeRegistry
- RetrievalAuthorizer
- PoisoningDetector
- ContextAssembler

# 实施步骤

## 第1步

定义Memory类型、用途、TTL、Owner、来源、数据等级和可见范围。

## 第2步

所有写入通过Canonical Action和PEP；记录写入者、依据和版本。

## 第3步

实现Prompt Registry、签名、审批、灰度和回滚。

## 第4步

建立Knowledge source trust、抓取/导入provenance、快照和过期策略。

## 第5步

ContextAssembler按权限、信任、数据等级和token预算组装上下文。

## 第6步

检测指令注入、来源冲突、异常重复、跨租户污染和敏感数据。

## 第7步

实现Quarantine、版本回滚、用户删除和Legal Hold协调。


# 数据、错误与可观测要求

- 所有跨服务对象带`schema_version`，安全决策、配置、Policy、Pack和模型带不可变版本或Digest。
- 错误使用稳定机器码、`trace_id`和安全摘要；不得回显Secret、完整敏感输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换、人工动作和恢复写入Batch 10/19证据链。
- 所有队列、缓存、连接池、分页和后台任务有界；超载时拒绝或受控降级。
- Production profile失败关闭；Dev bypass必须显式、醒目且CI证明无法进入生产构建。
- 所有Task完成声明由Batch 29状态机和Batch 10 Evidence共同证明。

# 必须实现的测试矩阵

- 跨租户向量检索、metadata过滤缺失、Memory伪造Owner
- 恶意文档要求泄密/改目标、编码混淆和间接Injection
- Prompt版本漂移、未签名模板、过期Knowledge
- 删除后缓存/索引残留、Legal Hold冲突
- Agent自行写入提升权限或永久化恶意指令

# 必须执行的故障注入

- 向量库部分写入
- 索引与对象存储不一致
- 删除事件丢失
- Poisoning detector不可用
- Prompt registry回滚

# 必须提交的交付物

- Memory/Prompt/Knowledge schemas
- Context Governance服务
- Prompt与Knowledge Registry
- Retrieval Authorization adapter
- Poisoning测试集
- 删除/隔离/回滚Runbook

# 完成Gate

- 任何上下文项可追溯来源和版本
- Memory写入/读取遵循最小权限
- 未授权文档不能因相似度被检索
- 污染可隔离和回滚
- 敏感数据删除与Evidence留存边界明确

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
