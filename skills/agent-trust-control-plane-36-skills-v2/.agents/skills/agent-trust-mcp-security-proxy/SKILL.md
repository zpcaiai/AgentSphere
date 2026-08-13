---
name: agent-trust-mcp-security-proxy
description: 实现受控MCP Client/Server Adapter和MCP Security Proxy。用于 Batch 12，完成MCP Server注册、Tool Schema快照、版本差异、输入输出验证、Server信任、恶意内容过滤、限流和凭证隔离。不要让第三方MCP Server直接获得Agent或企业高权限。
compatibility: 需要Batch 08 Tool Proxy、Batch 11 Adapter SDK、Rust异步网络栈、MCP协议测试端与Sandbox。
metadata:
  project: agent-trust-control-plane
  batch: "12"
  version: "2.0.0"
---
# Batch 12：MCP Adapter与Security Proxy
# 任务
在兼容MCP的同时，把第三方Server视为不可信供应链组件；冻结可审计Tool声明，验证实际行为，并将所有调用重新纳入身份、Policy、Proxy、Trace和Evaluator。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 12
- 接入第三方MCP Server
- 开发MCP安全网关
- 检测Tool Schema变化、恶意返回内容或未声明外连

# 非目标
- 不把MCP能力发现等同授权
- 不信任Server返回的管理员指令
- 不将MCP进程与Control Plane同权限运行
- 不允许任意stdio命令自动安装

# 前置依赖
- Batch 05 Tool Registry
- Batch 08 Proxy
- Batch 10 Evidence
- Batch 11 SDK

# 强制安全原则
1. 每个Server和Tool版本有固定Schema hash
2. Schema或二进制变化默认冻结待审
3. MCP返回内容标记untrusted并不得改变系统目标
4. 真实凭证由Tool Proxy持有
5. stdio/http Server均运行在限定Profile
6. 调用仍需Batch 06 Authorization

# 建议目录

```text
protocol-adapters/mcp
rust/crates/mcp-security-proxy
schemas/mcp-server-manifest
conformance-tests/mcp
threat-scenarios/mcp
docs/protocols/mcp
```

# 必须实现的公共接口

```text
McpRegistry.register/approve/revoke
McpProxy.list_tools/call_tool/read_resource
SchemaSnapshot.compare
ServerAttestor.verify
McpContentScanner.classify
BehaviorVerifier.compare_declared_effect
```

# 第1步：Server注册
- 记录来源、publisher、transport、binary/image digest、permissions和network endpoints
- 执行签名/SBOM/漏洞检查并分配trust tier

# 第2步：Tool快照
- 抓取Tool列表和JSON Schema并规范化hash
- 映射为Batch 05 Tool版本，声明EffectClass和risk
- 名称冲突使用server namespace

# 第3步：调用管线
- MCP request→Action IR→PEP→Tool Proxy→Server
- 输入输出双向Schema、大小、深度和内容限制
- 禁止Server让客户端直接连接新地址

# 第4步：恶意内容检测
- 识别要求泄露Secret、绕过审批、修改系统指令、调用额外Tool的返回文本
- 将内容与控制指令通道分离

# 第5步：行为验证
- 在Sandbox运行探针，检查文件、网络和副作用是否与Manifest一致
- 声明只读但检测到写入时自动隔离和吊销

# 第6步：变更治理
- Schema、binary、endpoint或权限变化生成diff和重新审批
- 紧急撤销立即阻断新调用

# 第7步：可观测与限流
- 每Server/Tool租户配额、超时、熔断
- 记录server digest、tool hash和sanitized result evidence

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 恶意Schema、重复键、超深JSON和超大返回拒绝
- Server返回Prompt Injection不进入控制指令
- Server尝试访问未声明网络/文件被Sandbox阻断
- Tool声明只读实际写入触发吊销
- Server升级后旧批准不能复用
- 低信任Server无法取得真实Secret

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- MCP Adapter和Proxy
- Server/Tool Registry扩展
- Schema Snapshot/Diff
- Content Scanner
- Sandbox行为验证器
- MCP威胁场景和Runbook

# 完成Gate
- 所有MCP调用经过统一IR和PEP
- 第三方Server无法绕过Proxy
- 变更后默认冻结
- 恶意内容和Secret泄漏测试通过
- Tool实际副作用可审计
- Server撤销传播到运行时

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    MCP Security Proxy把第三方Server视为不可信供应链与运行时主体，校验Schema、实现、返回内容、网络行为和Credential边界。

    ## 依赖分类

    - **contract dependencies**：Batch 11
- **implementation dependencies**：Batch 03, Batch 05, Batch 06, Batch 07, Batch 08, Batch 10, Batch 11
- **runtime integrations**：Batch 21, Batch 33
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - Tool列表和Schema快照签名；变更默认冻结。
- Tool声明只读但观察到写副作用属于高危行为不一致。
- 返回的Prompt/资源文本标注来源并进入Batch 32隔离与Injection检测。

    ## 新增或强化的模型

    - McpServerRegistration
- ToolSchemaSnapshot
- BehaviorAttestation
- TrustProfile
- ContentProvenance
- ServerQuarantineRecord

    ## 必须落盘的接口

    - McpProxy
- McpSchemaVerifier
- BehaviorMonitor
- ContentSanitizer
- ServerTrustResolver
- McpQuarantineService

    ## 新增负向测试与故障注入

    - 恶意Tool描述、Schema漂移、参数走私、返回Prompt Injection、Server重定向、数据外传。
- 低信任Server只能在受限Sandbox/无真实Credential模式运行。
- MCP断线和重连不重复副作用。

    ## v2.0完成Gate

    - 所有MCP调用仍走Canonical Action、PEP、Ledger和Evidence。
- Server信任不能由Server自声明。
- 提供恶意MCP测试集并接入Batch 33。

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
7. **Next integration**：Batch 20 Pack供应链、Batch 21异常轨迹。
