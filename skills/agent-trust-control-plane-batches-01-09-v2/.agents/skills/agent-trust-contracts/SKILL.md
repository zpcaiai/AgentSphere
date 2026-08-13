---
name: agent-trust-contracts
description: 设计并实现 Agent Trust & Compliance Control Plane 的跨语言公共契约、状态机、JSON Schema、Protobuf和生成代码。用于 Batch 01、新建或修复 Task、Action、Tool、Policy、Approval、Execution、Evidence、Evaluation 等共享模型，以及 Rust/Python/Java/TypeScript 契约一致性测试。不要用于实现具体网关、策略执行或沙箱业务逻辑。
compatibility: Codex CLI/desktop/IDE；需要 git、Rust、Python、Java、Node.js、protoc 或 Buf。可在 macOS/Linux 开发，CI 必须能运行全部契约生成与一致性测试。
metadata:
  project: agent-trust-control-plane
  batch: "01"
  version: "2.0.0"
---

# Batch 01：公共契约、Signed Goal、Plan与Authorization Lease

# 任务
实现或修复 Agent Trust & Compliance Control Plane 的公共契约层。把跨 Rust、Python、Java、TypeScript 的共享对象、状态机、错误码、版本规则和生成流程固化为唯一、可测试、可演进的契约。

完成本Skill时必须在当前仓库实现真实代码、测试、配置和文档；不得只输出设计、伪代码、空接口或TODO。先检查现有实现并增量修改，禁止创建第二套平行架构。

# 触发条件

在以下任务中使用本 Skill：

- 初始化 Batch 01；
- 新增或修改 Task、Step、AgentIdentity、Action、ToolCall、PolicyDecision、Approval、Execution、Compensation、Trace、Evidence、EvaluationResult；
- 解决多语言 DTO 不一致、字段漂移、枚举不一致或序列化兼容问题；
- 建立 JSON Schema、Protobuf、OpenAPI 或生成代码流水线；
- 为后续 Gateway、Action IR、Registry、PEP、Sandbox 建立稳定接口。

不要在本 Skill 中实现：真实身份签发、Tool Registry数据库、OPA策略、沙箱执行、业务Agent或管理页面。


# 前置依赖

- 当前仓库的构建系统、现有Schema/Proto和语言模块；
- 本Batch是后续Batch的契约根，不依赖后续实现；若已有公共契约必须迁移合并，不得复制。

# 强制原则

1. **先检查现有仓库，再增量修改。** 不要在已有项目中平行创建第二套模型。
2. **生成文件不可手工编辑。** 所有生成文件在文件头标记来源和生成命令。
3. **跨服务边界禁止使用无约束的字符串表达安全语义。** Risk、Effect、Status、Decision、DataClass等必须是枚举或受控值对象。
4. **未知高风险枚举值必须失败关闭。** 不得把未知值静默映射为 LOW、ALLOW 或 COMPLETED。
5. **所有时间使用 UTC RFC 3339；所有ID使用不可猜测的UUID/ULID；金额与计量值显式携带单位。**
6. **Task完成与Tool执行成功分离。** `ExecutionStatus=SUCCEEDED` 不得自动推导 `TaskStatus=COMPLETED`。
7. **版本必须显式。** 每个跨边界对象至少包含 `schema_version`；事件包含 `event_version`。
8. **兼容性优先采用新增可选字段；禁止复用字段编号、枚举编号或已发布语义。**
9. **身份契约必须由Batch 04真实实现消费。** 任何production profile不得默认接受匿名身份、共享长期Token或测试签名器。
10. **不把Secret、完整Prompt、完整源码或患者/工业敏感数据作为公共Trace字段。** 只定义脱敏值、Hash和Artifact引用。

# 目标目录

优先适配现有目录；若仓库尚未初始化，创建：

```text
schemas/
├── json/
│   ├── common.schema.json
│   ├── identity.schema.json
│   ├── action.schema.json
│   ├── tool.schema.json
│   ├── policy.schema.json
│   ├── approval.schema.json
│   ├── execution.schema.json
│   ├── evidence.schema.json
│   └── evaluation.schema.json
├── proto/
│   └── agenttrust/v1/*.proto
└── examples/
    ├── valid/
    └── invalid/

generated/
├── rust/
├── python/
├── java/
└── typescript/

scripts/
├── generate-contracts.sh
├── check-generated.sh
└── check-contract-parity.py

conformance-tests/contracts/
```

# 第一步：仓库与契约盘点

执行：

1. 查找已有 `proto`、`schema`、`openapi`、DTO、Pydantic、Java Record、TypeScript interface 和 Rust struct；
2. 输出一份简短映射：对象名、当前来源、消费者、冲突字段、拟保留来源；
3. 选择并记录权威来源：
   - JSON输入、Policy输入和Artifact格式：JSON Schema 2020-12；
   - 服务间RPC：Protobuf v3；
   - HTTP接口：由服务模型生成或维护OpenAPI，但不得成为第三套语义来源；
4. 若已有权威Schema，迁移到统一目录，不要无理由改名。

# 第二步：定义核心标识与值对象

至少实现以下受控类型：

```text
TaskId, StepId, ActionId, AgentInstanceId, TenantId,
ToolId, ToolVersion, CapabilityId, PolicyVersion,
ApprovalId, ExecutionId, TraceId, ArtifactRef,
SchemaVersion, ResourceVersion, IdempotencyKey
```

至少实现以下枚举，并固定序号或字符串值：

```text
TaskStatus:
CREATED, PLANNED, POLICY_CHECKED, APPROVAL_PENDING,
APPROVED, RUNNING, PAUSE_REQUESTED, PAUSED,
CANCEL_REQUESTED, CANCELLING, KILL_REQUESTED, KILLED,
VERIFYING, COMPLETED, DENIED, FAILED,
EVALUATION_FAILED, COMPENSATING, ROLLED_BACK,
NEEDS_HUMAN, MANUAL_RECOVERY_REQUIRED

ExecutionStatus:
PREPARED, RUNNING, SUCCEEDED, FAILED, TIMED_OUT,
CANCELLED, KILLED, COMPENSATING, COMPENSATED,
COMPENSATION_FAILED, UNKNOWN

RiskLevel: LOW, MEDIUM, HIGH, CRITICAL
EffectClass: PURE, IDEMPOTENT, COMPENSATABLE, IRREVERSIBLE
Decision: ALLOW, DENY, REQUIRE_APPROVAL, PAUSE, KILL
DataClassification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, REGULATED
EvaluationStatus: PASS, FAIL, NEEDS_HUMAN, ROLLED_BACK, MANUAL_RECOVERY_REQUIRED
```

规则：

- 不使用负数、浮点数或可变文本表示枚举；
- Protobuf枚举的0值必须是 `*_UNSPECIFIED`，并在执行路径拒绝；
- 已发布编号永不复用；
- JSON Schema设置严格枚举和 `additionalProperties: false`，扩展点必须显式定义为 `extensions`。

# 第三步：定义八类公共对象

## 1. AgentIdentity

至少包含：

```text
agent_type
agent_instance_id
organization_id
tenant_id
owner_subject
model_provider
model_id
agent_version
deployment_environment
trust_level
auth_context_ref
issued_at
expires_at
schema_version
```

不要包含原始Token或私钥。

## 2. Task与Step

Task至少包含：原始目标摘要、目标Hash、创建者、租户、状态、当前步骤、预算约束、环境、expected_outcome、创建/更新时间。

Step至少包含：step_id、序号、意图、前置步骤、风险等级、状态、计划Tool、资源范围、审批要求、结果引用。

## 3. Action与ToolCall

Action至少包含：

```text
action_id, task_id, step_id, agent_identity,
intent, tool_ref, arguments, resource,
environment, current_state_ref, risk_context,
expected_outcome, requested_at, schema_version
```

`arguments`可为JSON对象，但必须在后续Batch 05根据Tool版本的Schema验证。公共Schema只要求它是对象并限制最大深度、键数量和总大小。

## 4. PolicyDecision

至少包含：decision、reason_codes、human_readable_summary、obligations、policy_version、policy_bundle_hash、evaluated_at、input_hash、ttl、decision_id。

Obligation必须是受控对象，至少支持：

```text
require_approval
sandbox_profile
network_profile
credential_profile
max_timeout_ms
max_result_bytes
redact_fields
require_fresh_resource_state
pause_task
kill_task
```

## 5. Approval

至少包含：approval_id、task_id、step_id、action_hash、resource_version、policy_version、decision、approver_subject、approver_roles、expires_at、single_use、used_at、reason。

## 6. Execution与Compensation

Execution至少包含：execution_id、action_hash、idempotency_key、executor_profile、status、attempt、started_at、finished_at、result_ref、error_code、resource_version_before/after。

Compensation至少包含：compensation_id、forward_execution_id、tool_ref、arguments_hash、precondition、status、result_ref。

## 7. Trace与Evidence

Trace事件至少包含：event_id、event_type、task_id、step_id、trace_id、span_id、timestamp、actor、payload_ref、payload_hash、previous_event_hash、event_hash、signature_ref。

Evidence Package至少包含：task、plan_hash、identity_refs、policy_decisions、approvals、executions、compensations、artifact_refs、evaluation、chain_head_hash、created_at。

## 8. EvaluationResult

至少包含：status、score、hard_gate_results、findings、evidence_refs、evaluator_id、evaluator_version、evaluated_at。

不得只返回自由文本结论。

# 第四步：状态机与转换守卫

在Schema旁建立机器可测试的状态转换表，例如 `schemas/state-machines/task-transitions.yaml`。

最低守卫：

- `COMPLETED`只能从`VERIFYING`进入，且Evaluation为PASS；
- `RUNNING`前必须存在允许决策；需要审批时必须存在未过期且未使用的匹配审批；
- `KILLED`不能自动进入`COMPLETED`；
- `FAILED`且已有副作用时必须进入`COMPENSATING`或`MANUAL_RECOVERY_REQUIRED`；
- `ROLLED_BACK`必须附带补偿验证证据；
- 未知状态不得继续执行。

为Rust、Python、Java至少生成或实现同一组状态转换测试向量。

# 第五步：生成与构建流程

实现单一入口：

```bash
./scripts/generate-contracts.sh
./scripts/check-generated.sh
```

要求：

1. 生成过程可重复，连续运行两次Git工作区无变化；
2. CI中生成后执行`git diff --exit-code`；
3. 生成Rust、Python、Java、TypeScript类型；
4. 生成文件包含版本和源文件路径；
5. 对外公开的Schema生成可读文档或字段表；
6. 锁定生成器版本，记录在工具配置或容器镜像中。

不要依赖开发者本机未声明的全局插件。优先使用Buf或仓库内固定版本的protoc插件；若现有项目已有成熟生成链，沿用并补齐锁定。

# 第六步：契约一致性测试

至少建立：

1. **Golden JSON round-trip**：四种语言读取同一合法样例，再序列化并比较规范化结果；
2. **Invalid corpus**：未知枚举、缺字段、多余字段、超长字符串、深层嵌套、非法时间、空ID、NaN/Infinity、错误版本；
3. **Backward compatibility**：当前版本读取上一个已发布minor版本样例；
4. **Breaking-change detection**：删除字段、改变必填、收窄枚举、改变字段编号时CI失败；
5. **State-machine tests**：非法转换全部拒绝；
6. **Sensitive-field tests**：公共Trace对象不存在token/password/private_key等原始字段。

# 第七步：错误码规范

创建稳定错误码，例如：

```text
CONTRACT_INVALID_SCHEMA
CONTRACT_UNKNOWN_VERSION
CONTRACT_UNKNOWN_ENUM
CONTRACT_EXTRA_FIELD
CONTRACT_STATE_TRANSITION_DENIED
CONTRACT_SIZE_LIMIT_EXCEEDED
CONTRACT_GENERATED_CODE_STALE
CONTRACT_SIGNATURE_FORMAT_INVALID
```

错误响应必须同时包含：机器码、相关字段路径、trace_id、可安全展示的摘要。不得把Secret或完整输入回显到错误中。

# 第八步：CI Gate

CI至少执行：

```bash
./scripts/generate-contracts.sh
./scripts/check-generated.sh
python scripts/check-contract-parity.py
cargo test --workspace
pytest -q conformance-tests/contracts/python
./gradlew test
npm test -- --runInBand
```

按现有构建工具调整命令，但不得跳过任一语言的契约验证。若某语言模块尚未创建，生成最小可编译消费者和测试，不要只留下空目录。

# 必须提交的文件

- 公共Schema与Proto；
- 四语言生成代码或明确的生成配置；
- 状态转换表；
- 合法和非法样例；
- 生成脚本；
- 契约一致性测试；
- 错误码文档；
- `docs/contracts/versioning.md`；
- `docs/contracts/security-invariants.md`。

# 完成Gate

只有全部满足才算完成：

- 四种语言编译通过；
- 生成过程可重复；
- 合法样例四语言一致；
- 非法样例全部被拒绝；
- Breaking-change检查有效；
- 状态机非法转换全部失败；
- Production配置不存在匿名身份默认值；
- 没有手工编辑生成文件；
- 文档说明权威Schema、版本策略和迁移路径。

# v2.0修订与闭环补强

    ## 修订定位

    把Batch 01从“DTO与Schema集合”提升为全系统的意图、计划、委派和授权事实根。任务状态只能由受控Transition Service推进，任何Agent、Gateway、Evaluator都不能直接写终态。

    ## 依赖分类

    - **contract dependencies**：无
- **implementation dependencies**：无
- **runtime integrations**：无
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - SignedGoal是用户原始目标的不可变快照；PlanManifest记录计划版本、步骤图和风险预算；DelegationEnvelope限制子Agent权限；AuthorizationLease是持续授权的可撤销租约。
- TaskStatus与ExecutionStatus严格分离；Evaluator只能给出EvaluationResult，不能直接完成Task。
- 公共契约不得包含真实Secret、完整敏感Prompt或可执行任意命令字符串。

    ## 新增或强化的模型

    - SignedGoal(goal_id, normalized_goal, goal_hash, constraints, approved_by, signed_at)
- PlanManifest(plan_id, goal_hash, plan_hash, steps, max_scope, risk_budget, cost_budget, valid_until)
- DelegationEnvelope(parent_agent, child_agent, delegated_tools, delegated_resources, budget_ceiling, expiry)
- AuthorizationLease(lease_id, task_id, goal_hash, plan_hash, policy_snapshot, allowed_tools, allowed_resources, revocation_epoch, valid_until)
- StateTransitionRequest与StateTransitionResult；仅Orchestrator/Transition Service可消费。

    ## 必须落盘的接口

    - ContractVersionRegistry
- StateTransitionGuard
- GoalSigner/GoalVerifier port
- PlanHasher
- AuthorizationLeaseVerifier

    ## 新增负向测试与故障注入

    - 目标文本、约束或计划任一变化都会改变对应Hash并使旧审批/租约失效。
- 子Agent委派权限不能超过父任务授权上限。
- 未知枚举、未知EffectClass和缺少schema_version在高风险路径失败关闭。
- 跨Rust/Python/Java/TypeScript验证Canonical JSON、时间、金额、单位和枚举完全一致。

    ## v2.0完成Gate

    - 存在SignedGoal、PlanManifest、DelegationEnvelope、AuthorizationLease的Schema、Proto、生成代码和测试。
- 状态转换表明确唯一写入者并被后续Batch 29消费。
- SYSTEM_CAPABILITIES与Traceability Matrix能引用公共契约ID。

    任何“完成”声明必须附`IMPLEMENTATION_STATUS.json`、真实命令退出码、测试报告和Evidence引用。规范文件完成不等于产品代码完成。

# Codex最终报告格式

完成后输出：

1. **Implemented**：实际实现的契约对象和生成链；
2. **Files changed**：按Schema、生成器、测试、文档分组；
3. **Commands run**：列出实际命令和结果；
4. **Compatibility**：兼容与破坏性变更结论；
5. **Security evidence**：未知枚举、非法转换、敏感字段测试结果；
6. **Open risks**：只列尚未解决且有证据的问题；
7. **Next dependency**：说明Batch 02/03/05可消费的具体接口。
