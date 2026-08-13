---
name: agent-trust-tool-credential-proxy
description: 实现 Agent Trust & Compliance Control Plane 的 Tool Proxy与Credential Broker。用于 Batch 08，让Agent不接触Git、数据库、云、HTTP或工业系统的真实凭证，由受控代理执行参数过滤、短期凭证交换、响应脱敏、出站限制和访问审计。不要在此Skill中实现Agent规划或通用API管理平台。
compatibility: 需要 Rust、Batch 04身份凭证、Batch 05 Tool Snapshot、Batch 06 ExecutionAuthorization、Vault/KMS可选、PostgreSQL和外部系统测试容器。
metadata:
  project: agent-trust-control-plane
  batch: "08"
  version: "2.0.0"
---
# Batch 08：Target Credential Broker与Tool Proxy
# 任务
把所有需要Secret或外部授权的Tool调用收口到不可绕过的代理边界，使用代执行或窄化后的临时凭证完成操作，并在返回Agent前完成输出Schema验证和敏感信息过滤。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 08
- Agent需要访问Git、数据库、云API、HTTP或OPC UA
- 需要消除Prompt中的凭证
- 实现Secret Broker、代执行、Token Exchange或返回脱敏

# 非目标
- 不向Agent暴露Vault token或数据库密码
- 不提供任意TCP转发
- 不取代Batch 06 Policy Decision
- 不在Proxy内实现业务Agent规划

# 前置依赖
- Batch 04 VerifiedIdentity与CredentialHandle
- Batch 05 ResolvedToolSnapshot
- Batch 06 ExecutionAuthorization
- Batch 07受控执行环境

# 强制安全原则
1. Proxy只接受有效且未过期ExecutionAuthorization
2. 真实Secret只在Proxy/Secret Provider受控内存中存在
3. 每个Connector使用固定目的和Schema，不提供任意主机端口
4. 请求和响应均按Tool版本Schema验证
5. 输出脱敏发生在持久化Trace和返回Agent之前
6. Proxy权限不能宽于Action、Policy、Approval和Credential scope交集

# 建议目录

```text
rust/crates/tool-proxy-core
rust/crates/credential-broker
rust/crates/proxy-git
rust/crates/proxy-database
rust/crates/proxy-http
rust/crates/proxy-industrial
conformance-tests/tool-proxy
docs/security/credential-proxy
```

# 必须实现的公共接口

```text
ToolProxy.execute(AuthorizedToolRequest)->SanitizedToolResult
SecretProvider.resolve(CredentialHandle)->SecretLease
Connector.prepare/execute/verify/revoke
ResponseFilter.apply(tool_snapshot, raw_result)->sanitized_result
TokenExchange.exchange(subject_token, target_audience, scope)->lease
```

# 第1步：公共代理管线
- 验证Authorization签名、TTL、action_hash、tool/version和executor profile
- 解析Connector，不允许Agent提供任意URL或驱动名称
- 获取短期Secret Lease，设置硬超时和最大响应大小
- 执行后立即撤销或释放Lease

# 第2步：Git代理
- 限定组织、仓库、分支和操作
- 禁止读取Actions Secrets、组织管理和受保护分支写入
- 支持read、create task branch、push受限branch、create PR等高层操作
- 记录commit SHA和remote response evidence

# 第3步：数据库代理
- 采用预注册DSN和数据库角色
- SQL优先使用模板/AST参数化，不允许直接拼接任意SQL
- 表、列、行级范围和最大返回行数
- 事务只读默认；写入必须有resource version和幂等Key

# 第4步：HTTP/云代理
- 域名、方法、路径和Content-Type allowlist
- 禁止Metadata地址、环回、私网绕过和DNS rebinding
- Token audience绑定目标服务
- 限制重定向、上传量和返回量

# 第5步：工业代理
- 只接预注册Asset/Node/Topic/Register
- 读写分离；写入使用compare-and-set和最新状态
- 安全联锁、报警和范围由工业Pack再次验证

# 第6步：响应脱敏与DLP
- 按字段Schema、Secret指纹、熵和已知模式过滤
- 原始大结果写受控Artifact Store，Agent仅拿引用
- 检测Tool返回的恶意Prompt/指令并标记untrusted content

# 第7步：连接池与隔离
- 连接池按tenant、credential profile和target隔离
- 不得跨租户复用带会话状态连接
- 超时、取消和Kill传播到底层连接

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- Agent无法通过错误Tool参数指定其他主机
- SQL注入、路径穿越、SSRF、DNS rebinding测试
- 跨租户连接池污染测试
- 返回结果包含Token/密码时被过滤且原始内容不进Trace
- Kill中断正在执行的网络请求并撤销Lease
- Secret Provider不可用时高风险动作失败关闭

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- 公共Proxy管线
- 至少Git、Database、HTTP三种Connector与工业接口骨架
- SecretLease和Token Exchange实现
- DLP/Response Filter
- Connector conformance testkit
- 访问审计与Runbook

# 完成Gate
- Agent进程无法获得真实Secret
- 任意网络/数据库旁路测试失败
- 输出脱敏先于Trace落盘
- 连接池租户隔离有并发证据
- 所有Lease在成功、失败、超时、Kill路径释放
- Connector只能由签名Tool Snapshot选择

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Batch 08管理目标系统Credential与代执行，不管理Agent登录身份。Agent永远不接触原始Git、数据库、云、模型或工业Secret。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03, Batch 04, Batch 05, Batch 06
- **implementation dependencies**：Batch 04, Batch 05, Batch 06, Batch 07
- **runtime integrations**：Batch 09, Batch 10, Batch 15, Batch 16, Batch 29
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - Workload Identity通过token exchange换取任务/步骤/资源绑定的Credential Lease。
- 优先代执行；必须下发时使用最短TTL、最小audience、单用途和可撤销凭证。
- 请求参数和响应字段均经过Tool-specific filter。

    ## 新增或强化的模型

    - CredentialRequest
- CredentialLease
- TokenExchangeRecord
- ProxyExecutionRequest
- ResponseFilterResult
- SecretExposureFinding

    ## 必须落盘的接口

    - CredentialBroker
- TokenExchangePort
- ToolProxy
- SecretInjector
- ResponseFilter
- CredentialRevoker

    ## 新增负向测试与故障注入

    - Secret进入stdout、stderr、Trace、Prompt、Artifact、core dump或环境继承。
- 跨资源使用、租约重放、并发超限、Kill后复用、目标系统返回嵌套Secret。
- Vault/KMS不可用时不同风险Tool按策略失败关闭。

    ## v2.0完成Gate

    - 原始Secret不可由Agent读取。
- 所有Credential使用与task/step/action/trace绑定。
- 与Batch 04职责和数据库表完全分离。

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
7. **Next integration**：Batch 12 MCP Security Proxy、Batch 15 Model Gateway、Batch 16 Industrial Gateway。
