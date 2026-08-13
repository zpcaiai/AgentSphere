---
name: agent-trust-sandbox-runtime
description: 实现 Agent Trust & Compliance Control Plane 的 Rust Sandbox Runtime与Runtime Supervisor。用于 Batch 07，包括WASM与OCI/gVisor执行适配、CPU/内存/PID/磁盘/网络/文件限制、临时凭证注入、心跳与租约、暂停/取消/Kill、子进程树清理、结果采集和安全销毁。不要自研完整容器运行时，也不要把业务工作流或Policy Decision写入Sandbox层。
compatibility: Codex CLI/desktop/IDE；需要 Rust、Linux生产/CI、cgroup v2、OCI运行时，推荐gVisor runsc；macOS只允许开发mock和非生产单测，不得声称具有Linux生产隔离。
metadata:
  project: agent-trust-control-plane
  batch: "07"
  version: "2.0.0"
---

# Batch 07：Sandbox Runtime、Runtime Supervisor与Kill Switch

# 任务
实现Rust可信执行底座：`Sandbox Runtime`和`Runtime Supervisor`。它只接受Batch 06签发的有效`ExecutionAuthorization`，创建短生命周期隔离环境，严格限制资源和访问，执行Tool，持续监测，并保证Pause、Cancel和Kill真正作用于进程、网络、凭证和子进程树。

完成本Skill时必须在当前仓库实现真实代码、测试、配置和文档；不得只输出设计、伪代码、空接口或TODO。先检查现有实现并增量修改，禁止创建第二套平行架构。

# 边界与原则

1. **不要自研容器内核。** Rust负责控制、验证和生命周期，隔离使用成熟WASM Runtime、OCI Runtime、gVisor或微虚拟机；
2. **默认无网络、只读根文件系统、非root、无宿主Secret、无Docker Socket；**
3. **Executor不接受裸ToolCall。** 必须验证ExecutionAuthorization、Action Hash、Tool Snapshot Hash、有效期和single-use；
4. **Tool只能使用注册的Executor模板。** 禁止Agent直接传任意Shell字符串；
5. **资源全部有上限。** CPU、内存、PID、磁盘、文件、输出、时间、网络、并发；
6. **Kill位于Agent进程之外。** 即使Agent或Sandbox无响应也可终止；
7. **凭证短期注入、最小范围、自动吊销和销毁；**
8. **结果与Artifact经过输出校验和DLP接口；**
9. **macOS fallback不是生产沙箱。** 必须在文档和运行状态中显式标记；
10. **工业写动作不在通用代码容器里直连PLC。** 通过Industrial Gateway executor profile执行。


# 前置依赖

- Batch 05 Tool/Executor Snapshot；
- Batch 06签名ExecutionAuthorization；
- Linux CI用于验证namespace、cgroup、seccomp、进程树和网络隔离。

# 建议目录

```text
rust/crates/
├── sandbox-core/
├── sandbox-wasm/
├── sandbox-oci/
├── sandbox-gvisor/
├── runtime-supervisor/
├── resource-limits/
├── credential-injector/
├── artifact-gateway/
└── sandbox-testkit/

sandbox-profiles/
├── coding-no-network.yaml
├── coding-build-egress.yaml
├── wasm-plugin.yaml
└── industrial-gateway.yaml
```

# 第一步：定义公共接口

```rust
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    async fn prepare(&self, req: PrepareRequest) -> Result<PreparedSandbox, SandboxError>;
    async fn start(&self, prepared: PreparedSandbox) -> Result<ExecutionHandle, SandboxError>;
    async fn inspect(&self, handle: &ExecutionHandle) -> Result<ExecutionSnapshot, SandboxError>;
    async fn pause(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError>;
    async fn resume(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError>;
    async fn cancel(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError>;
    async fn kill(&self, handle: &ExecutionHandle) -> Result<ControlReceipt, SandboxError>;
    async fn collect(&self, handle: ExecutionHandle) -> Result<ExecutionResult, SandboxError>;
    async fn destroy(&self, sandbox_id: &SandboxId) -> Result<DestroyReceipt, SandboxError>;
}
```

`PrepareRequest`至少包含：

```text
ExecutionAuthorization
ResolvedToolSnapshot
ExecutorTemplate
SandboxProfile
NetworkProfile
FilesystemProfile
CredentialRefs
ResourceLimits
WorkspaceSnapshotRef
TraceContext
```

# 第二步：ExecutionAuthorization验证

在任何资源创建前验证：

- 签名和issuer；
- action_hash；
- tool snapshot hash；
- policy decision；
- approval绑定；
- resource_version；
- sandbox/network/credential profile；
- limits；
- issued_at/expires_at；
- single-use和replay ledger；
- tool未被revoke；
- executor implementation digest匹配。

验证失败不得创建Sandbox、挂载目录或获取凭证。

# 第三步：Executor模板，禁止任意Shell

定义注册模板，例如：

```yaml
executor_id: coding-maven-test
kind: oci
image_digest: sha256:...
entrypoint: ["/usr/bin/mvn"]
argument_schema:
  allowed:
    - "test"
    - "-q"
working_directory: /workspace
shell: false
```

规则：

- 默认`execve`参数数组，不经过shell；
- 若确需shell，使用专门HIGH风险Tool和严格模板；
- Agent不能覆盖entrypoint、mount、runtime、capability、seccomp或网络；
- 环境变量白名单；
- 禁止`LD_PRELOAD`、动态loader等危险变量，除非专门profile；
- OCI image使用digest，不使用floating tag。

# 第四步：WASM Sandbox

使用Wasmtime/WASI Component Model实现低风险插件执行。

要求：

- 默认无网络和宿主文件系统；
- 只暴露显式capability；
- fuel/epoch interruption限制CPU；
- memory/table/stack限制；
- stdout/stderr上限；
- host function白名单；
- 每次执行新Store或明确隔离实例；
- component hash与Registry一致；
- Trap映射为稳定错误码；
- 超时和Kill可中断。

适用于数据转换、规则插件和可控Skill，不用于编译大型仓库。

# 第五步：OCI/gVisor Sandbox

Rust不重写OCI runtime；实现受控wrapper。生产建议gVisor `runsc`或等效隔离。

最低配置：

```text
non-root UID/GID
read-only rootfs
no-new-privileges
all Linux capabilities dropped
seccomp allowlist profile
cgroup v2 CPU/memory/pids/io limits
private PID/mount/IPC/UTS/network namespaces
no host network
no Docker/Podman socket
no host home or root mounts
ephemeral workspace
tmpfs for temporary secret material
bounded stdout/stderr
bounded execution time
```

不得把`--privileged`作为开发便利方案提交。

# 第六步：Filesystem Broker

实现：

- mount plan来自SandboxProfile，不来自Agent；
- workspace使用任务独立快照；
- 只读输入与可写输出分离；
- 路径规范化、防穿越和symlink race；
- 禁止设备文件、proc敏感接口和宿主socket；
- 文件数量、单文件和总空间上限；
- 结果只通过Artifact Gateway导出；
- destroy后验证工作目录和tmpfs清理。

对于Coding：每Task独立branch/worktree/snapshot，不共享可写Workspace。

# 第七步：Network Egress

默认`none`。允许网络时：

- 使用独立Egress Proxy或受控网络namespace；
- 域名、IP、端口、协议allowlist；
- 禁止云metadata地址、localhost旁路、Unix socket旁路；
- DNS解析与重绑定防护；
- 重定向重新评估；
- 请求/响应大小、连接数、带宽、总上传量限制；
- 记录目标Hash和统计，不记录敏感payload；
- 网络profile来自PEP obligation；
- Kill时立即断开网络。

# 第八步：Credential Injector

凭证不写入普通环境变量或持久层。优先：

- 短期Token；
- tmpfs文件；
- memfd或受控Unix socket代理；
- Tool Proxy代执行。

要求：

- 只在Sandbox已准备且执行即将开始时获取；
- 记录credential ref，不记录值；
- 使用后或Pause/Cancel/Kill时吊销；
- 禁止进入stdout/stderr、Trace和Artifact；
- 对日志运行Secret扫描；
- destroy后验证不存在残留。

# 第九步：Runtime Supervisor状态机

至少实现：

```text
CREATED
PREPARING
READY
RUNNING
PAUSE_REQUESTED
PAUSED
RESUME_REQUESTED
CANCEL_REQUESTED
CANCELLING
KILL_REQUESTED
KILLED
SUCCEEDED
FAILED
TIMED_OUT
COLLECTING
DESTROYING
DESTROYED
ORPHANED
MANUAL_RECOVERY_REQUIRED
```

守卫：

- `SUCCEEDED`仅表示进程结果，不表示Task完成；
- Kill优先级高于Pause/Cancel；
- Cancel执行可控收尾，Kill立即终止；
- 超时触发Cancel，超过grace period后Kill；
- ORPHANED必须由reconciler处理；
- 状态变化使用原子持久化或租约，防止双Supervisor控制同一执行。

# 第十步：心跳、租约与僵尸任务

实现：

- supervisor lease；
- sandbox heartbeat；
- process liveness；
- bounded renewal；
- owner crash后reconciler；
- lease过期后禁止两个owner同时继续；
- orphan扫描；
- recovery policy：reattach、kill或manual recovery；
- 所有恢复动作写Evidence。

# 第十一步：真正的Pause、Cancel和Kill

## Pause

- 停止调度新子步骤；
- 可冻结进程或应用协作暂停；
- 暂停/吊销短期凭证；
- 网络默认断开或按profile；
- 保存恢复所需状态；
- 不承诺所有外部副作用可暂停。

## Cancel

- 发送优雅终止；
- 停止新副作用；
- 等待有限grace period；
- 调用上层补偿接口；
- 销毁凭证和Sandbox；
- 生成取消证据。

## Kill

- 立即撤销凭证；
- 断开网络；
- 终止PID namespace/cgroup内全部进程；
- 防止子进程逃逸；
- 隔离输出；
- 标记Incident接口；
- 验证无残留进程、mount、cgroup和凭证。

在Linux优先使用可靠进程组/cgroup/pidfd等机制，不只向父PID发送SIGKILL。

# 第十二步：结果与Artifact

`ExecutionResult`至少包含：

```text
execution_id
status
exit_code
started_at/finished_at
resource_usage
stdout_ref/stderr_ref（截断标志）
artifact_refs
workspace_diff_ref
runtime_profile_hash
image/component digest
network summary
credential refs used
cleanup receipt
```

要求：

- stdout/stderr有上限和截断；
- 输出Schema按Batch 05 Tool Snapshot验证；
- Artifact导出前运行路径、类型、大小和DLP接口；
- 不自动导出整个Workspace；
- cleanup receipt进入Evidence。

# 第十三步：工业Gateway执行类型

工业动作使用：

```text
kind: industrial_gateway
```

Sandbox Runtime负责验证Authorization和调用受控Gateway，不把OPC UA证书交给Agent容器。

要求：

- Gateway identity/mTLS；
- asset/tag/node/register映射；
- conditional write；
- resource version；
- prepare/commit/verify；
- Kill阻断后续命令；
- 真实安全联锁不由Agent修改；
- 第一版仅Simulator或Digital Twin。

# 第十四步：错误码

至少实现：

```text
SANDBOX_AUTHORIZATION_INVALID
SANDBOX_AUTHORIZATION_REPLAYED
SANDBOX_PROFILE_DENIED
SANDBOX_IMAGE_DIGEST_MISMATCH
SANDBOX_RESOURCE_LIMIT_INVALID
SANDBOX_PREPARE_FAILED
SANDBOX_START_FAILED
SANDBOX_TIMEOUT
SANDBOX_OUTPUT_LIMIT_EXCEEDED
SANDBOX_NETWORK_DENIED
SANDBOX_FILESYSTEM_DENIED
SANDBOX_CREDENTIAL_INJECTION_FAILED
SANDBOX_CANCEL_FAILED
SANDBOX_KILL_FAILED
SANDBOX_CLEANUP_INCOMPLETE
SANDBOX_ORPHANED
SANDBOX_PRODUCTION_ISOLATION_UNAVAILABLE
```

# 第十五步：测试与威胁场景

## 基础

- WASM正常、Trap、超时、内存超限；
- OCI正常、非零退出、超时；
- stdout/stderr超限；
- 磁盘/PID/内存/CPU限制；
- graceful shutdown；
- owner崩溃与reconciler。

## 隔离负向

- 读取`/etc/shadow`；
- 访问Docker socket；
- 挂载宿主home；
- 访问metadata service；
- 访问未允许公网；
- symlink路径穿越；
- fork bomb；
- 子进程脱离父进程；
- 修改seccomp/cgroup；
- 读取其他任务Workspace；
- Secret写入日志或Artifact；
- Kill后仍有进程或网络连接；
- 重放ExecutionAuthorization；
- image digest被替换。

## 平台真实性

- macOS测试必须标记`non-production isolation`；
- Linux CI运行真实cgroup/seccomp/gVisor测试；
- 若CI环境不支持gVisor，测试必须明确skip原因并保留专用安全CI，不能把mock当通过。

# 必须提交的文件

- Sandbox Runtime与Supervisor crates；
- WASM和OCI/gVisor adapters；
- Sandbox/Profile Schema；
- Resource limit、Filesystem、Network、Credential模块；
- Pause/Cancel/Kill和reconciler；
- Artifact Gateway接口；
- Coding和Industrial Simulator executor样例；
- 隔离负向测试；
- `docs/sandbox/threat-model.md`；
- `docs/sandbox/production-requirements.md`；
- `docs/sandbox/operations-runbook.md`。

# 完成Gate

- 裸ToolCall无法执行；
- ExecutionAuthorization单次、短期且Hash绑定；
- 默认无网络、非root、只读rootfs、无宿主socket；
- Agent不能覆盖entrypoint和隔离参数；
- CPU/内存/PID/磁盘/输出/时间全部有上限；
- Kill终止全部子进程并断开网络、吊销凭证；
- cleanup receipt证明资源释放；
- Secret不出现在日志和Artifact；
- Linux真实隔离测试通过；
- macOS fallback不被标记生产；
- Coding命令和Industrial Simulator动作共用同一Supervisor和Evidence接口。

# v2.0修订与闭环补强

    ## 修订定位

    Sandbox是ExecutionAuthorization之后的确定性执行边界；Supervisor管理真实进程树、资源、租约、Kill和Artifact出口，不承担Agent规划。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03, Batch 06
- **implementation dependencies**：Batch 01, Batch 03, Batch 06
- **runtime integrations**：Batch 08, Batch 09, Batch 10, Batch 29, Batch 34
- **optional integrations**：Batch 16

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 默认非root、只读rootfs、无公网、最小挂载、无Docker socket。
- 暂停、取消、Kill语义不同；Kill必须在Agent进程外部生效。
- 工业Emergency Stop不能被一般审计故障阻断，但必须写本地WAL并后补证据。

    ## 新增或强化的模型

    - SandboxProfile
- ExecutionLease
- ProcessTreeHandle
- ResourceBudget
- ArtifactExportRequest
- LocalSafetyJournal

    ## 必须落盘的接口

    - SandboxRuntime
- RuntimeSupervisor
- ProcessTreeKiller
- FilesystemBroker
- EgressBroker
- ArtifactGateway

    ## 新增负向测试与故障注入

    - 宿主文件、metadata service、namespace逃逸、fork bomb、磁盘填满、子进程孤儿、网络DNS rebinding。
- Kill后所有子进程、网络和Credential引用失效。
- Evidence后端故障时低风险/高风险/紧急动作按分级策略运行。

    ## v2.0完成Gate

    - 真实Linux CI验证namespace/cgroup/seccomp或所选微虚拟机，不用Mock冒充。
- 任意Shell不是公共Tool；命令来自版本化Executor模板。
- Artifact离开Sandbox前通过大小、类型、DLP和Policy检查。

    任何“完成”声明必须附`IMPLEMENTATION_STATUS.json`、真实命令退出码、测试报告和Evidence引用。规范文件完成不等于产品代码完成。

# Codex最终报告格式

1. **Runtime architecture**；
2. **Isolation guarantees and non-guarantees**；
3. **Pause/Cancel/Kill behavior**；
4. **Files/profiles changed**；
5. **Linux security tests**；
6. **Cleanup and secret evidence**；
7. **Open production risks**；
8. **Integration**：PEP Authorization、Ledger、Evaluator和Industrial Gateway接口。
