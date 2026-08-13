---
name: agent-trust-gateway
description: 实现 Agent Trust & Compliance Control Plane 的 Rust Agent Gateway，作为HTTP、WebSocket、gRPC、MCP等Agent请求的唯一受控入口。用于 Batch 02，包括认证上下文接入、多租户隔离、限流、超时、熔断、请求去重、Trace传播、流式代理和安全失败策略。不要在此Skill中实现完整Action IR、Tool Registry、OPA策略或Sandbox内部逻辑。
compatibility: Codex CLI/desktop/IDE；需要 Rust、git、Docker/Podman。生产级网络与隔离测试优先在Linux CI运行；应接入Batch 04生产Identity Verifier，dev verifier只能由显式开发profile启用。
metadata:
  project: agent-trust-control-plane
  batch: "02"
  version: "2.0.0"
---

# Batch 02：Rust Agent Gateway与Admission Control

# 任务
实现 Rust `Agent Gateway`，使它成为所有Agent、协议Adapter和外部调用进入Control Plane的唯一入口。Gateway只负责可靠、安全地接入和交给后续管线，不在内部复制Action IR、Registry、Policy或Executor业务规则。

完成本Skill时必须在当前仓库实现真实代码、测试、配置和文档；不得只输出设计、伪代码、空接口或TODO。先检查现有实现并增量修改，禁止创建第二套平行架构。

# 前置依赖

优先消费 `$agent-trust-contracts` 生成的公共类型。若Batch 01尚未完成：

- 先实现最小接口适配层；
- 不复制完整DTO；
- 在代码中标记明确替换点；
- 不得以“临时”为由允许生产匿名访问。

接入Batch 04身份服务，同时保留以下测试边界：

```text
IdentityVerifier trait
DevSignedVerifier（仅dev feature）
ProductionIdentityVerifier（生产配置必需）
RejectAllVerifier（无法建立身份信任时默认）
```

生产配置未提供真实Verifier时，进程必须启动失败，而不是降级匿名。

# 核心边界

Gateway负责：

- HTTP、WebSocket、gRPC入口；
- 请求体与Header大小限制；
- TLS终止或mTLS对接；
- 身份上下文验证接口；
- Tenant解析与隔离；
- 请求限流、并发限制、超时、熔断；
- 请求ID、Trace Context和Idempotency Key传播；
- 流式响应转发；
- 安全日志与基础计量；
- 将请求交给 `ActionIngressService`。

Gateway不负责：

- Agent规划；
- Tool Schema业务校验；
- Policy Decision；
- Human Approval；
- 沙箱执行；
- 业务Evaluator；
- 保存原始Secret或完整Prompt。

# 建议目录

若仓库已有Rust workspace则融入；否则创建：

```text
rust/crates/
├── gateway-api/
├── gateway-core/
├── gateway-auth/
├── gateway-limits/
├── gateway-streaming/
├── gateway-observability/
└── gateway-testkit/
```

使用当前稳定兼容版本，并将解析结果锁定在`Cargo.lock`。优先使用：Tokio、Axum、Tower、Hyper、Tonic、Serde、Rustls、OpenTelemetry。不要在Skill中机械固定过时minor版本。

# 第一步：定义入口接口

建立明确trait：

```rust
#[async_trait]
pub trait IdentityVerifier: Send + Sync {
    async fn verify(&self, request: &RequestParts) -> Result<IdentityContext, GatewayError>;
}

#[async_trait]
pub trait ActionIngressService: Send + Sync {
    async fn submit(&self, envelope: IngressEnvelope) -> Result<IngressResponse, GatewayError>;
}

pub trait TenantResolver: Send + Sync {
    fn resolve(&self, identity: &IdentityContext, headers: &HeaderMap)
        -> Result<TenantContext, GatewayError>;
}
```

`IngressEnvelope`至少包含：

```text
request_id
trace_context
identity_context
tenant_context
protocol
content_type
schema_version
idempotency_key
received_at
payload_ref或受限payload
```

不让HTTP handler直接调用具体Registry、OPA或Sandbox。

# 第二步：实现中间件顺序

中间件顺序必须显式测试。建议：

```text
1. Connection/TLS metadata
2. Request ID
3. Trace extraction
4. Header/body size guard
5. Authentication
6. Tenant resolution
7. Per-tenant concurrency limit
8. Rate limit
9. Global timeout/deadline
10. Protocol/content validation
11. Idempotency precheck接口
12. ActionIngressService
13. Safe response mapping
14. Metrics and audit summary
```

注意：

- 认证前日志不得记录请求体；
- 限流Key不得只使用可伪造Header；
- Trace ID无效时生成新值并记录安全事件；
- 客户端Deadline只能收紧服务器Deadline，不能延长；
- 错误响应不得泄露内部堆栈、Token、Policy文本或资源存在性。

# 第三步：HTTP API

至少实现：

```text
POST /v1/actions
GET  /v1/actions/{action_id}
POST /v1/actions/{action_id}:cancel
POST /v1/actions/{action_id}:kill
GET  /v1/streams/{task_id}        WebSocket/SSE二选一，保留扩展接口
GET  /healthz
GET  /readyz
GET  /metrics                     仅内网或管理监听器
```

规则：

- `/healthz`只表示进程存活；
- `/readyz`验证关键依赖，不泄露依赖细节；
- `/metrics`不得公开到Agent数据平面；
- cancel和kill必须进入Runtime接口，不能仅更新数据库状态；
- action查询必须进行Tenant与Owner检查，避免IDOR。

# 第四步：gRPC与协议入口

建立gRPC服务或清晰预留：

```text
SubmitAction
GetAction
CancelAction
KillAction
StreamTaskEvents
```

所有协议入口必须复用同一 `IngressEnvelope` 和中间件语义。不得出现HTTP有认证、gRPC绕过认证的双轨实现。

MCP、A2A等Adapter只能调用Gateway公开的内部接口或经过受保护的loopback/mTLS通道，不能直连Executor。

# 第五步：多租户隔离

至少实现：

- `TenantContext`由已验证身份与可信映射得出；
- 禁止仅相信客户端传入的`X-Tenant-Id`；
- 每租户独立限流和并发配额；
- 所有存储查询必须携带tenant_id；
- 缓存Key包含tenant_id；
- Trace和Metric避免高基数Secret标签；
- 对不存在资源与无权限资源返回一致的安全错误策略。

建立负向测试：Tenant A无法查询、取消、Kill Tenant B任务。

# 第六步：限流、并发、超时和熔断

至少支持：

```text
global_connection_limit
per_tenant_request_rate
per_agent_concurrency
per_tool预留配额接口
max_body_bytes
max_stream_duration
request_timeout
downstream_timeout
queue_wait_timeout
```

规则：

- 有界队列；队列满时拒绝，不无限堆积；
- 取消Future时确保下游收到取消信号；
- 流式连接设置空闲超时与最大持续时间；
- 熔断器按下游依赖隔离，不能一个服务拖垮全部入口；
- 限流错误携带安全的重试建议，不暴露其他租户负载。

# 第七步：请求去重和幂等接口

Gateway只做precheck和传播，不在本Batch实现完整Transaction Ledger。

要求：

- 写动作要求`Idempotency-Key`或由可信客户端生成；
- Key长度、字符集和租户范围受控；
- 同tenant、同key、不同payload hash必须拒绝为冲突；
- 将Key传给Batch 09 Ledger；
- 网络重试不得在Gateway自动改变Key；
- 请求体Hash使用规范化后的IR Hash接口，Batch 03完成前使用明确临时Hash并记录迁移任务。

# 第八步：Trace与安全日志

至少生成Span：

```text
gateway.request
gateway.authenticate
gateway.resolve_tenant
gateway.rate_limit
gateway.normalize_protocol
gateway.submit_action
gateway.stream
```

属性限制：

- 允许：tenant_hash、agent_type、protocol、route、status、latency、request_bytes；
- 禁止：Authorization、Cookie、原始Token、完整arguments、完整Prompt、源码、患者数据；
- 错误只记录机器码和安全摘要；
- 日志结构化JSON，并支持trace_id关联。

# 第九步：安全错误模型

至少实现：

```text
GATEWAY_UNAUTHENTICATED
GATEWAY_FORBIDDEN
GATEWAY_TENANT_MISMATCH
GATEWAY_RATE_LIMITED
GATEWAY_CONCURRENCY_LIMITED
GATEWAY_BODY_TOO_LARGE
GATEWAY_UNSUPPORTED_PROTOCOL
GATEWAY_DEADLINE_EXCEEDED
GATEWAY_IDEMPOTENCY_CONFLICT
GATEWAY_DOWNSTREAM_UNAVAILABLE
GATEWAY_PRODUCTION_IDENTITY_NOT_CONFIGURED
```

HTTP/gRPC映射必须稳定，并为客户端区分可重试与不可重试，但不得泄露内部资源信息。

# 第十步：测试

## 单元与集成测试

至少覆盖：

- 中间件顺序；
- 未认证请求；
- production无Verifier时启动失败；
- 伪造tenant header；
- 跨租户IDOR；
- 超大Body/Header；
- 慢请求和slowloris防护；
- per-tenant限流；
- 下游超时与熔断；
- 重复Idempotency Key；
- WebSocket/SSE断线；
- Trace上下文非法输入；
- 错误响应不含Secret。

## 性能基线

使用仓库现有压测工具；若没有，可加入`oha`或`k6`脚本。至少记录：

```text
并发连接
吞吐量
P50/P95/P99延迟
错误率
内存峰值
超时下资源释放
```

不为了追求数字跳过TLS、认证或限流。性能报告必须说明环境。

# 第十一步：部署与配置

实现分离监听器：

```text
data plane listener
management listener
```

配置优先级明确，Secret只从环境引用或Secret provider加载。提供：

- example配置；
- Dockerfile；
- 非root用户；
- read-only root filesystem兼容；
- readiness/liveness；
- graceful shutdown；
- SIGTERM后停止接收新请求并等待有界时间；
- shutdown后调用Runtime取消接口。

# 必须提交的文件

- Rust Gateway crates；
- 配置Schema与example；
- HTTP/gRPC接口；
- IdentityVerifier和ActionIngressService trait；
- 中间件与安全错误；
- 单元、集成、负向与压测脚本；
- Dockerfile和部署示例；
- `docs/gateway/security-boundary.md`；
- `docs/gateway/operations.md`。

# 完成Gate

- 所有入口经过同一身份、租户、限流和Trace链；
- production不能以匿名或dev verifier启动；
- 跨租户查询、取消和Kill全部拒绝；
- Body、并发、队列、时间和流式连接都有上限；
- 错误和日志无Secret；
- cancel/kill调用真实Runtime接口；
- Gateway不直接调用具体Sandbox；
- 单测、集成测试、负向测试和基础压测通过；
- graceful shutdown不会遗留无限等待请求。

# v2.0修订与闭环补强

    ## 修订定位

    Gateway只承担接入、认证前置、流量治理和请求标准化，不拥有业务状态机，不直接执行Tool，也不能把网络成功误写成任务成功。

    ## 依赖分类

    - **contract dependencies**：Batch 01
- **implementation dependencies**：Batch 01
- **runtime integrations**：Batch 03, Batch 04, Batch 05, Batch 06, Batch 09, Batch 10, Batch 29
- **optional integrations**：Batch 15, Batch 30, Batch 34

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 所有入口统一转换为InboundEnvelope并转交Action IR/Orchestrator。
- 租户、Agent实例、Trace和Request ID必须在入口绑定且不可被下游覆盖。
- Gateway不得签发目标系统Credential；只验证Workload Identity并调用Batch 08。

    ## 新增或强化的模型

    - InboundEnvelope
- AdmissionDecision
- StreamingSessionLease
- GatewayRateLimitKey
- RequestReplayRecord

    ## 必须落盘的接口

    - AdmissionControlPort
- IdentityVerifierPort
- ActionNormalizerPort
- OrchestratorSubmissionPort
- StreamBackpressureController

    ## 新增负向测试与故障注入

    - 跨租户IDOR、伪造forwarded headers、HTTP request smuggling、超大body、慢速上传与WebSocket滥用。
- Gateway重启、客户端重试和响应丢失不会重复提交副作用Action。
- 下游不可用时有界排队并返回稳定错误码，不无限缓存。

    ## v2.0完成Gate

    - 没有业务状态写入或Executor直连代码。
- 限流、熔断、超时和流式背压都有指标、测试和Runbook。
- 生产模式缺少真实IdentityVerifier时拒绝启动。

    任何“完成”声明必须附`IMPLEMENTATION_STATUS.json`、真实命令退出码、测试报告和Evidence引用。规范文件完成不等于产品代码完成。

# Codex最终报告格式

1. **Ingress surface**：实际实现的HTTP/gRPC/stream接口；
2. **Security boundary**：认证、租户、限流、超时顺序；
3. **Files changed**；
4. **Tests and load results**；
5. **Secret/log review**；
6. **Production blockers**：尤其是Batch 04真实身份Verifier；
7. **Next integration**：Batch 03 Action IR、Batch 05 Registry、Batch 09 Ledger的接口点。
