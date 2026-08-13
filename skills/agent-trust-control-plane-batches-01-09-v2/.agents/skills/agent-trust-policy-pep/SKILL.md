---
name: agent-trust-policy-pep
description: 实现 Agent Trust & Compliance Control Plane 的 Rust Policy Enforcement Point，并对接OPA/Rego或兼容策略决策服务。用于 Batch 06，强制执行Tool白名单、参数/资源/环境/数据/轨迹策略、审批义务、沙箱义务、执行前重检、失败关闭和Kill/Pause义务。不要用于编写Agent Prompt、企业审批业务页面或Sandbox内部实现。
compatibility: Codex CLI/desktop/IDE；需要 Rust、OPA CLI或兼容PDP、PostgreSQL可选、git、Docker/Podman。应消费 Batch 03 Verified Action和 Batch 05 ResolvedToolSnapshot。
metadata:
  project: agent-trust-control-plane
  batch: "06"
  version: "2.0.0"
---

# Batch 06：Policy Enforcement与Minimal Approval Kernel

# 任务
实现不可绕过的 `Policy Enforcement Point (PEP)`。Policy Decision Point可使用OPA/Rego或兼容引擎，但Rust PEP负责构造唯一PolicyInput、验证Decision、执行Obligations、阻断绕过并在执行前重新检查。

完成本Skill时必须在当前仓库实现真实代码、测试、配置和文档；不得只输出设计、伪代码、空接口或TODO。先检查现有实现并增量修改，禁止创建第二套平行架构。


# 前置依赖

- Batch 03 Verified Action与Policy Input；
- Batch 05签名ResolvedToolSnapshot；
- OPA/Rego或兼容PDP测试环境。

# 核心边界

```text
Verified Action
   + Resolved Tool Snapshot
   + Fresh Resource State
   + Identity/Tenant Context
   + Trajectory Risk
            ↓
       Rust PEP
            ↓
       Policy PDP
            ↓
Validated Decision + Obligations
            ↓
Approval / Credential / Sandbox / Executor
```

强制原则：

1. **PEP在Agent进程之外。** Agent不能关闭、替换或跳过；
2. **PDP不可用时失败关闭。** 特别是任何写动作、高风险动作和生产动作；
3. **Policy检查至少两次。** 审批前、真实执行前；状态敏感场景还需持续授权；
4. **Decision不是普通JSON。** 必须严格Schema、签名/来源、版本和TTL校验；
5. **ALLOW不代表无限制。** Obligations必须被强制执行；
6. **缓存不能覆盖吊销、状态变化或高风险重检；**
7. **未知Decision、未知Obligation、未知Risk默认拒绝；**
8. **本地确定性守卫先于远程PDP。** 基础大小、路径、版本、租户和Schema错误无需发送到OPA；
9. **所有决策进入Trace和Evidence，但不得记录Secret；**
10. **策略文本不由Agent生成后自动上线。** 策略变更属于治理流程。

# 建议目录

```text
rust/crates/
├── policy-pep-core/
├── policy-client-opa/
├── policy-obligations/
├── policy-state-provider/
├── policy-cache/
└── policy-testkit/

policies/
├── common/
├── coding/
├── industrial/
└── tests/
```

# 第一步：定义PolicyInput唯一构造路径

只允许从Batch 03官方函数和Batch 05快照构造。至少包含：

```text
subject:
  agent identity, owner, tenant, roles, trust level
intent:
  operation, goal hash, justification code
agent:
  type, instance, model, version, deployment
resource:
  canonical selector, owner tenant, version, current state
 tool:
  exact id/version, risk, effect, schema hash, implementation digest
arguments:
  validated normalized arguments
 environment:
  dev/staging/production, simulation, region, network zone
 data:
  classification, jurisdiction, export constraints
 trajectory:
  accumulated resources, scope delta, anomaly scores
 runtime:
  time, budget, prior approvals, prior executions
 registry:
  snapshot hash/revision
```

不得把HTTP Header、未验证Agent文本或原始MCP响应直接作为可信字段。

# 第二步：定义Decision契约

至少支持：

```text
ALLOW
DENY
REQUIRE_APPROVAL
PAUSE
KILL
```

Decision包含：

```text
decision_id
decision
reason_codes
policy_version
policy_bundle_hash
input_hash
evaluated_at
expires_at或ttl
obligations
risk_summary
```

PEP验证：

- input_hash等于当前PolicyInput Hash；
- policy版本允许；
- decision未过期；
- obligation均为已知类型；
- PDP identity可信；
- 必要时验证Decision签名或mTLS来源；
- ALLOW对HIGH/CRITICAL仍满足本地硬门槛。

# 第三步：Obligation执行器

至少实现：

```text
RequireApproval
UseSandboxProfile
UseNetworkProfile
UseFilesystemProfile
UseCredentialProfile
MaxExecutionTime
MaxResultBytes
RedactFields
RequireFreshResourceState
RequireResourceVersion
RequireDualApproval
RequireSimulation
PauseTask
KillTask
EmitSecurityAlert
SetRetryLimit
RequireEvaluator
```

定义：

```rust
#[async_trait]
pub trait ObligationHandler: Send + Sync {
    fn kind(&self) -> ObligationKind;
    async fn enforce(&self, obligation: &Obligation, ctx: &EnforcementContext)
        -> Result<EnforcementReceipt, PolicyError>;
}
```

任何未知或执行失败的强制Obligation都必须拒绝执行。

# 第四步：本地硬守卫

即使PDP返回ALLOW，PEP仍必须拒绝：

- tool snapshot已吊销或digest变化；
- tenant不一致；
- production使用dev identity verifier；
- arguments未通过Registry Schema；
- write action没有idempotency key；
- HIGH/CRITICAL动作缺resource_version或fresh state；
- IRREVERSIBLE动作无显式高风险审批策略；
- Agent请求修改Policy、审计、身份或Kill组件且未使用专门管理路径；
- Secret内联；
- 状态机不允许执行；
- Action Hash与Approval/Decision不一致。

# 第五步：两阶段与持续授权

实现两个明确阶段：

```text
PRE_APPROVAL
PRE_EXECUTION
```

流程：

1. PRE_APPROVAL：基于当前Action、Registry和状态决定是否拒绝或发起审批；
2. Approval绑定action_hash、resource_version、policy_version；
3. PRE_EXECUTION：重新读取Registry revocation、resource state、identity/token状态和trajectory risk；
4. 重新执行Policy；
5. 验证Approval仍匹配且未过期；
6. 强制Obligations；
7. 生成`ExecutionAuthorization`，短TTL、单次使用；
8. Executor只接受有效Authorization。

对于长任务/工业动作，提供持续授权接口：

```text
check_lease(action_id, execution_id, latest_state, latest_risk)
```

命中Pause/Kill条件时调用Runtime Supervisor，而非仅告警。

# 第六步：OPA/Rego对接

实现PDP client：

- 有界连接池；
- 短超时；
- mTLS；
- bundle/version health；
- response schema validation；
- input/result hash；
- 指标与断路器；
- 不记录完整敏感input。

策略目录至少包含：

## Common

- 默认拒绝；
- tenant匹配；
- tool状态；
- data classification；
- production身份；
- CRITICAL动作；
- policy/audit/identity保护资源。

## Coding

- repo allowlist；
- branch非main/master；
- path allow/deny；
- `.env`、证书、CI workflow保护；
- 最大修改文件数、删除行数；
- 网络默认关闭；
- push/deploy要求审批。

## Industrial

- asset allowlist；
- tag/node/register allowlist；
- 值域；
- 最大delta/rate；
- simulation优先；
- alarm/interlock/mode前置条件；
- stale state拒绝；
- commit要求审批；
- safety system修改默认拒绝。

# 第七步：缓存策略

Decision缓存仅在明确安全范围内：

- Key包含tenant、agent、action_hash、registry snapshot、policy bundle、resource version、trajectory risk version；
- HIGH/CRITICAL和写动作执行前不使用过期缓存；
- Revoke、identity吊销、policy更新、resource变化立即失效；
- PDP不可用时不把旧ALLOW无限延长；
- PURE/LOW只读可在配置允许的短TTL内使用，并记录degraded evidence。

# 第八步：ExecutionAuthorization

PEP成功后签发：

```text
execution_authorization_id
action_hash
tool snapshot hash
policy decision id
approval id(s)
resource version
sandbox/network/credential profile
limits
issued_at
expires_at
single_use
signature
```

Executor必须验证该对象，而不能只检查布尔`allowed=true`。

测试可使用固定签名Provider；production必须接入Batch 04真实签名与凭证Provider。

# 第九步：审计事件

至少发出：

```text
PolicyInputBuilt
PolicyEvaluationRequested
PolicyDecisionReceived
PolicyDecisionRejected
ObligationEnforced
ApprovalRequired
PreExecutionRecheck
ExecutionAuthorized
ExecutionDenied
TaskPauseRequested
TaskKillRequested
```

事件包含Hash和引用，不包含原始Secret。

# 第十步：错误码

至少实现：

```text
POLICY_LOCAL_GUARD_DENIED
POLICY_PDP_UNAVAILABLE
POLICY_DECISION_INVALID
POLICY_DECISION_EXPIRED
POLICY_INPUT_HASH_MISMATCH
POLICY_UNKNOWN_OBLIGATION
POLICY_OBLIGATION_FAILED
POLICY_APPROVAL_REQUIRED
POLICY_APPROVAL_MISMATCH
POLICY_RESOURCE_STATE_STALE
POLICY_REGISTRY_REVOKED
POLICY_EXECUTION_AUTH_INVALID
POLICY_FAIL_CLOSED
POLICY_KILL_TRIGGERED
```

# 第十一步：测试

## Policy unit tests

使用`opa test`覆盖允许和拒绝路径，每条策略至少有正、负、边界值测试。

## Rust tests

至少覆盖：

- PDP返回ALLOW但本地硬守卫拒绝；
- PDP超时/坏JSON/未知Decision；
- 决策input hash不匹配；
- obligation未知或执行失败；
- 审批后参数改变；
- 审批后resource_version改变；
- Registry在执行前Revoke；
- identity在执行前吊销；
- 缓存跨tenant污染；
- HIGH动作使用旧缓存；
- Pause/Kill义务调用真实Supervisor mock；
- ExecutionAuthorization重复使用；
- Policy Bundle更新；
- 80/80.1值域边界、路径穿越、branch混淆。

## Bypass tests

- HTTP、gRPC、MCP和内部调用均必须经过PEP；
- 直接调用Executor缺Authorization失败；
- 修改Action JSON字段顺序不改变授权Hash；
- 修改任何语义字段使旧Decision/Approval失效。

# 必须提交的文件

- Rust PEP crates；
- OPA client；
- Obligation handlers；
- ExecutionAuthorization；
- Common/Coding/Industrial Rego策略；
- OPA与Rust测试；
- 审计事件；
- `docs/policy/enforcement-flow.md`；
- `docs/policy/fail-closed.md`；
- `docs/policy/authoring-guide.md`。

# 完成Gate

- 所有执行路径都需要ExecutionAuthorization；
- 策略检查在审批前和执行前各执行一次；
- PDP不可用时写动作和高风险动作失败关闭；
- Unknown Decision/Obligation拒绝；
- Approval、Action、Resource、Policy Hash严格绑定；
- HIGH/CRITICAL执行前使用fresh state；
- Pause/Kill义务真实调用Runtime接口；
- 直接调用Executor无法绕过；
- Common、Coding、Industrial策略正负测试通过；
- Trace和Evidence可关联每次决策。

# v2.0修订与闭环补强

    ## 修订定位

    PEP不仅调用PDP，还必须执行本地硬守卫、Obligation和持续授权租约；同时实现可用于首个MVP的Minimal Approval Kernel，Batch 17只在其上增加企业治理。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03, Batch 05
- **implementation dependencies**：Batch 01, Batch 03, Batch 05
- **runtime integrations**：Batch 04, Batch 17, Batch 21, Batch 29, Batch 31
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - Policy Decision与Enforcement分离；OPA/Cedar不可用时本地高风险守卫仍生效。
- PRE_APPROVAL与PRE_EXECUTION双重检查；长任务按Lease或风险事件重新授权。
- Minimal Approval Grant绑定action_hash、resource_version、policy_snapshot、expiry和single_use。

    ## 新增或强化的模型

    - PolicyInput
- PolicyDecision
- ObligationSet
- ExecutionAuthorization
- MinimalApprovalGrant
- AuthorizationRecheckRequest

    ## 必须落盘的接口

    - PolicyDecisionPointPort
- PolicyEnforcementPoint
- LocalHardGuard
- MinimalApprovalKernel
- ContinuousAuthorizationPort

    ## 新增负向测试与故障注入

    - 参数编码、路径穿越、URL重定向、大小写/Unicode绕过、PDP超时和缓存污染。
- 审批后Action、资源版本、Policy或Plan变化使Grant失效。
- 风险升高触发Lease收窄、Pause或Kill，不能只告警。

    ## v2.0完成Gate

    - 没有PEP批准的ExecutionAuthorization，Sandbox/Proxy拒绝执行。
- Minimal Approval端到端可运行；Batch 17可替换审批解析而不改变执行Grant格式。
- Policy管理、模拟和发布不塞入PEP，交由Batch 31。

    任何“完成”声明必须附`IMPLEMENTATION_STATUS.json`、真实命令退出码、测试报告和Evidence引用。规范文件完成不等于产品代码完成。

# Codex最终报告格式

1. **Enforcement path**；
2. **Local guards vs PDP rules**；
3. **Obligations and authorization token**；
4. **Files/policies changed**；
5. **Tests and bypass evidence**；
6. **Fail-closed behavior**；
7. **Next integration**：Batch 07 Sandbox和未来Batch 17 Approval。
