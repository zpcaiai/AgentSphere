---
name: agent-trust-enterprise-control-console
description: 实现企业Control API、租户组织项目治理和统一管理台，整合Agent Inventory、Tool、Policy、Credential、Task、Approval、Trace、Evidence、Incident、Compliance与Pack。
compatibility: Java/Spring Boot + Vue 3/TypeScript；需要Batch 17、19、22、29、30、31、34，按需接入28/32/33。
metadata:
  project: agent-trust-control-plane
  batch: "35"
  version: "2.0.0"
---

# Batch 35：Enterprise Control API与Unified Management Console

# 任务

把分散能力形成一个可运营、可授权、可审计的企业产品平面，同时保持管理面与Rust执行面隔离。

完成本Skill时必须在当前目标仓库实现真实代码、Schema、数据库迁移、测试、部署配置、Runbook和Evidence；不得只提交设计、空接口、TODO或模拟通过报告。先盘点现有实现并增量集成，禁止创建第二套平行架构。

# 触发条件

- 建设管理后台、统一API、租户/组织/项目/角色
- 整合审批、Trace、策略、Agent资产和Incident页面
- 实现配额、License、Webhook和企业系统集成

# 非目标

- 前端不能直接调用Sandbox/Executor
- 管理API不能绕过PEP修改执行事实
- 不在UI显示未经授权的Secret或完整敏感Prompt
- 不以管理员角色默认跨租户

# 依赖分类

- **contract dependencies**：Batch 01, Batch 10, Batch 17, Batch 19, Batch 22, Batch 29, Batch 30, Batch 31, Batch 34
- **implementation dependencies**：Batch 17, Batch 19, Batch 22, Batch 29, Batch 30, Batch 31, Batch 34
- **runtime integrations**：Batch 36
- **optional integrations**：Batch 28, Batch 32, Batch 33

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

# 权威边界与安全不变量

- 管理面配置通过签名版本和受控发布进入执行面。
- 所有写操作有RBAC/ABAC、CSRF防护、审计和职责分离。
- Task、Execution和Evidence事实来自对应权威服务，不在后台复制成为新事实源。

# 建议目录

- `java/enterprise-control-api`
- `java/tenant-service`
- `java/integration-service`
- `web/admin-console`
- `web/shared-components`
- `tests/enterprise-e2e`

# 核心模型

- Tenant
- Organization
- Project
- Environment
- Role
- Quota
- License
- Webhook
- AdminAction
- DashboardView

# 必须实现的接口

- TenantApi
- OrganizationApi
- ProjectApi
- AdminBff
- IntegrationApi
- WebhookService
- QuotaService

# 实施步骤

## 第1步

实现租户、组织、项目、环境、Owner/Sponsor、角色和权限。

## 第2步

提供统一BFF/API聚合各权威服务，禁止直接数据库联表破坏边界。

## 第3步

实现Agent Inventory、Tool Registry、Policy Studio、Credential Session、Task Runtime、Approval Inbox。

## 第4步

实现Trace/Evidence Explorer、Risk Alert、Incident、Compliance Control、Domain Pack和Deployment页面。

## 第5步

建立搜索、分页、导出、脱敏和跨租户防护。

## 第6步

接入企业IAM、通知、工单、SIEM和Webhook。

## 第7步

实现配额、成本、License和API Key生命周期。

## 第8步

完成可访问性、国际化和操作审计。


# 数据、错误与可观测要求

- 所有跨服务对象带`schema_version`，安全决策、配置、Policy、Pack和模型带不可变版本或Digest。
- 错误使用稳定机器码、`trace_id`和安全摘要；不得回显Secret、完整敏感输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换、人工动作和恢复写入Batch 10/19证据链。
- 所有队列、缓存、连接池、分页和后台任务有界；超载时拒绝或受控降级。
- Production profile失败关闭；Dev bypass必须显式、醒目且CI证明无法进入生产构建。
- 所有Task完成声明由Batch 29状态机和Batch 10 Evidence共同证明。

# 必须实现的测试矩阵

- 跨租户IDOR、越权批量导出、CSRF/XSS、Webhook伪造
- 管理员修改Policy/Pack/Approval的职责分离
- 后端部分不可用时页面降级不显示伪成功
- 大规模Trace搜索和分页
- 敏感字段按角色脱敏
- 浏览器端不能伪造执行状态

# 必须执行的故障注入

- 聚合服务超时
- 某权威服务不可用
- IAM目录故障
- 通知重复/丢失
- 前端断线重连

# 必须提交的交付物

- Enterprise Control API
- Vue统一管理台
- 租户/组织/角色迁移
- BFF与SDK
- 企业集成适配
- E2E安全测试

# 完成Gate

- 不存在前端直连执行面
- 所有管理写入有审计和授权
- 统一管理台覆盖核心运营流程
- 跨租户和敏感导出通过红队
- UI显示的完成状态与Evidence权威事实一致

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
