---
name: agent-trust-protocol-adapter-sdk
description: 实现 Agent Trust & Compliance Control Plane 的 Protocol Adapter SDK、Manifest、生命周期、能力/身份/错误映射和Conformance Test Kit。用于 Batch 11，让MCP、A2A、AG-UI、国内标准及企业私有协议只能转换到统一IR，不能绕过Control Plane。
compatibility: 需要 Rust或多语言Adapter运行时、Batch 01/03/05、JSON Schema/Protobuf测试工具。
metadata:
  project: agent-trust-control-plane
  batch: "11"
  version: "2.0.0"
---
# Batch 11：Protocol Adapter SDK与一致性测试
# 任务
建立可插拔但受控的协议适配边界，使外部协议升级只影响Adapter，并用统一一致性测试保证身份、Tool、流式事件、错误和取消语义不丢失。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 11
- 新增协议Adapter
- 统一MCP/A2A/AG-UI/国内标准
- 建立Adapter插件、Manifest或测试套件

# 非目标
- 不在Adapter内做Policy旁路
- 不允许Adapter直接调用Sandbox或Tool Proxy
- 不把外部协议对象直接写入领域业务
- 不承诺所有协议字段无损等价

# 前置依赖
- Batch 01契约
- Batch 03 Action IR
- Batch 05 Capability/Tool Registry

# 强制安全原则
1. Adapter输出必须通过Canonical Action IR验证
2. 外部Identity只能映射为未信任或已验证上下文，不可自提权
3. 无法映射字段必须记录loss report
4. 取消、超时、流式和错误语义必须显式转换
5. Adapter代码和Manifest签名、版本绑定
6. Adapter没有Executor或Secret权限

# 建议目录

```text
rust/crates/protocol-core
rust/crates/adapter-runtime
schemas/protocol-adapter
protocol-adapters/test-fixtures
conformance-tests/protocol-adapters
docs/protocols
```

# 必须实现的公共接口

```text
ProtocolAdapter.discover_capabilities
normalize_identity
parse_request
to_action_ir
from_action_result
map_error
stream_events
health_check
AdapterManifest.verify
```

# 第1步：SDK与Manifest
- 定义adapter_id、protocol、versions、entrypoint、permissions、network needs、schema hashes
- 声明支持的流式、取消、委派和Artifact能力

# 第2步：运行时隔离
- Adapter进程或WASM使用最小权限
- 只开放IR提交和结果回传通道
- 限制CPU、内存、网络和动态依赖

# 第3步：映射规则
- Identity、Capability、Tool、Task、Error、Stream和Artifact逐项映射
- 生成Mapping Coverage和Loss Report

# 第4步：版本协商
- 支持协议版本范围和feature negotiation
- 未知关键feature拒绝，不静默忽略安全字段

# 第5步：Conformance Kit
- Golden request/response、非法Schema、取消、流式断连、重复消息、错误映射
- 验证Adapter无法直连Executor

# 第6步：兼容性矩阵
- 记录外部版本、内部IR版本、映射质量和已知限制
- CI自动检测Schema变化

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 恶意Adapter尝试调用Executor被权限拒绝
- 外部身份伪造高trust_level被降级/拒绝
- 未知关键字段和版本测试
- 流式中断与取消保持任务状态一致
- Mapping Loss Report完整
- Adapter升级不改变同输入Canonical hash，除非有明确迁移

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Adapter SDK和runtime
- Manifest Schema
- Conformance Test Kit
- 示例Echo Adapter
- 映射覆盖报告格式
- 协议版本和安全指南

# 完成Gate
- 所有生产Adapter通过Conformance
- Adapter权限声明与实际调用一致
- 无法无损映射时不会静默通过
- 协议升级不修改核心PEP/Sandbox
- Adapter签名和版本可追溯
- 至少为Batch 12—14提供稳定接口

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Adapter SDK只负责协议语义与内部IR之间的映射，不得拥有授权、Credential、执行或Task状态写权限。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03, Batch 05
- **implementation dependencies**：Batch 01, Batch 03, Batch 05
- **runtime integrations**：Batch 12, Batch 13, Batch 14, Batch 16, Batch 30
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 所有Adapter输出ActionDraft、CapabilityDraft、IdentityClaim或ProtocolEvent。
- 映射损失必须显式报告；安全字段无法映射时拒绝或人工审查。
- 版本和扩展命名空间隔离。

    ## 新增或强化的模型

    - AdapterManifest
- ProtocolVersionBundle
- MappingResult
- MappingLoss
- ConformanceVector
- AdapterHealth

    ## 必须落盘的接口

    - ProtocolAdapter
- CapabilityMapper
- IdentityClaimMapper
- ErrorMapper
- StreamingMapper
- ConformanceRunner

    ## 新增负向测试与故障注入

    - 协议fuzz、未知版本、字段覆盖、流式中断、取消语义、错误码混淆。
- Adapter尝试直连Executor或写Task状态在架构测试中失败。
- 不同Adapter同语义Canonical Action对比。

    ## v2.0完成Gate

    - 提供SDK、示例Adapter、测试向量和兼容矩阵。
- Adapter权限最小化并可Sandbox。
- 升级只影响版本包和映射，不分叉核心Policy。

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
7. **Next integration**：Batch 12 MCP、Batch 13 A2A/AG-UI、Batch 14国内标准。
