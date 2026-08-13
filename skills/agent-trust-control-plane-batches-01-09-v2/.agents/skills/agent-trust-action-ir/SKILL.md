---
name: agent-trust-action-ir
description: 实现 Agent Trust & Compliance Control Plane 的 Unified Agent Action IR，包括严格类型、规范化、JSON Schema校验、稳定Hash、签名信封、版本迁移和Policy输入生成。用于 Batch 03，把MCP、A2A、国内标准、HTTP或工业协议动作转换为唯一内部动作模型。不要在此Skill中实现具体协议Adapter、Tool Registry数据库、Policy Decision或执行器。
compatibility: Codex CLI/desktop/IDE；需要 Rust、git、JSON Schema测试工具。应消费 Batch 01公共契约，并为后续Registry、PEP、Approval、Ledger和Evidence提供稳定接口。
metadata:
  project: agent-trust-control-plane
  batch: "03"
  version: "2.0.0"
---

# Batch 03：Typed Unified Agent Action IR

# 任务
实现不可含糊、可验证、可签名、可版本化的 `Unified Agent Action IR`。所有外部协议必须先转换成Action IR，后续Tool Registry、Policy PEP、Approval、Sandbox和Audit只能消费规范化IR，不能消费原始协议请求。

完成本Skill时必须在当前仓库实现真实代码、测试、配置和文档；不得只输出设计、伪代码、空接口或TODO。先检查现有实现并增量修改，禁止创建第二套平行架构。

# 架构不变量

```text
External Protocol
      ↓
Protocol Adapter
      ↓
Untrusted Action Draft
      ↓
Parse + Structural Validation
      ↓
Normalize + Semantic Validation
      ↓
Canonical Action IR
      ↓
Hash + Signature Verification
      ↓
Registry / PEP / Approval / Executor
```

强制规则：

1. Adapter不得直接调用Executor；
2. 原始请求不得作为Policy主输入；
3. 规范化前后都保留安全Hash和版本；
4. 同语义输入必须产生同一canonical hash；
5. 未知版本、未知枚举、重复键、NaN/Infinity、超限嵌套全部拒绝；
6. Action IR不携带真实Secret，只携带credential reference；
7. 发现Capability不等于授权；IR不包含“默认允许”语义；
8. 高风险字段必须强类型，不使用自由文本。


# 前置依赖

- Batch 01公共契约、Schema版本规则和生成类型；
- 当前仓库已有协议输入与Policy输入接口。

# 建议目录

```text
rust/crates/action-ir/
├── src/
│   ├── lib.rs
│   ├── model.rs
│   ├── draft.rs
│   ├── normalize.rs
│   ├── validate.rs
│   ├── canonical.rs
│   ├── hash.rs
│   ├── signature.rs
│   ├── migration.rs
│   ├── policy_input.rs
│   └── error.rs
├── tests/
│   ├── golden.rs
│   ├── invalid.rs
│   ├── canonicalization.rs
│   ├── migration.rs
│   └── fuzz.rs
└── fuzz/

schemas/json/action.schema.json
schemas/examples/action/
```

# 第一步：定义Draft与Canonical模型

区分：

```text
ActionDraft：来自外部Adapter，仍是不可信输入
CanonicalAction：完成结构、语义、Registry预校验和规范化后的不可变对象
```

CanonicalAction至少包含：

```rust
pub struct CanonicalAction {
    pub schema_version: SchemaVersion,
    pub action_id: ActionId,
    pub task_id: TaskId,
    pub step_id: StepId,
    pub agent: AgentIdentityRef,
    pub intent: Intent,
    pub tool: ToolRef,
    pub arguments: StrictJsonObject,
    pub resource: ResourceSelector,
    pub environment: ExecutionEnvironment,
    pub current_state: Option<ResourceStateRef>,
    pub risk: RiskContext,
    pub data: DataContext,
    pub expected_outcome: ExpectedOutcome,
    pub credential_refs: Vec<CredentialRef>,
    pub requested_at: DateTime<Utc>,
    pub extensions: BTreeMap<String, RestrictedExtension>,
}
```

关键类型：

- `ToolRef`必须包含tool_id和精确tool_version；禁止只写“latest”进入执行；
- `ResourceSelector`使用受控scheme，例如repo、file、database、opcua、mqtt、http；
- `Intent`包含goal_hash、operation、justification_code和可选安全摘要；
- `ExecutionEnvironment`包含tenant、deployment、region/zone、simulation标志；
- `RiskContext`包含declared_risk、trajectory_risk_ref、scope_delta；
- `DataContext`包含classification、jurisdiction、export_constraints；
- `ExpectedOutcome`必须机器可评估，不只是一段自然语言。

# 第二步：严格JSON解析

要求：

- 拒绝重复JSON键；
- 拒绝非UTF-8；
- 拒绝NaN、Infinity和非标准数字；
- 限制Body大小、最大深度、数组长度、字符串长度、对象键数；
- `additionalProperties: false`；
- 扩展只能进入显式`extensions`命名空间；
- 解析错误返回字段路径和稳定错误码，不回显完整敏感值。

若Serde默认行为不能检测重复键，增加自定义Deserializer或预解析层，不要忽略该风险。

# 第三步：规范化

规范化规则必须文档化并有Golden测试：

- Unicode使用明确规范形式；
- ID和协议scheme大小写规则固定；
- 时间转UTC并保留毫秒或微秒精度规则；
- URL规范化但不得错误合并不同安全资源；
- 文件路径只做词法规范化，不解析到宿主真实路径；
- 数值保持精确语义，工程量使用decimal/string或整数+scale，避免浮点Hash漂移；
- Map使用确定性排序；
- 删除无语义空白，但不改变自由文本内容；
- 不自动填入扩大权限的默认值；
- 缺省安全字段采用最严格值或直接拒绝。

# 第四步：Canonical JSON与Hash

使用稳定、公开、可测试的canonical JSON方案，例如RFC 8785 JCS兼容实现。计算：

```text
action_hash = SHA-256(canonical_json(CanonicalAction without volatile transport fields))
```

明确哪些字段进入Hash。通常必须进入：

```text
schema_version
task_id
step_id
agent identity ref
tool id/version
arguments
resource
environment
current state version
risk/data context
expected outcome
credential reference constraints
```

不得进入：

```text
HTTP request id
网络连接信息
非语义日志时间
服务器接收延迟
```

提供：

```rust
fn canonical_bytes(action: &CanonicalAction) -> Result<Vec<u8>, ActionIrError>;
fn action_hash(action: &CanonicalAction) -> Result<ActionHash, ActionIrError>;
```

相同语义、不同JSON字段顺序必须得到同一Hash。

# 第五步：签名信封

定义：

```text
SignedActionEnvelope
├── canonical_action
├── action_hash
├── signer_id
├── signature_algorithm
├── key_id
├── signature
├── signed_at
└── expires_at
```

第一版支持成熟算法和库，例如Ed25519。不要自研密码学。

验证顺序：

1. Schema/version；
2. Canonical bytes；
3. Hash匹配；
4. key_id信任与吊销接口；
5. 签名；
6. 时间窗口；
7. signer与agent/adapter绑定；
8. replay/idempotency接口。

测试可使用固定测试KeyProvider；production profile必须接入Batch 04受管KeyProvider与轮换、吊销配置。

# 第六步：语义验证

建立可组合Validator：

```rust
pub trait ActionValidator: Send + Sync {
    fn validate(&self, draft: &ActionDraft, ctx: &ValidationContext)
        -> Result<Vec<ValidationFinding>, ActionIrError>;
}
```

至少验证：

- task/step关联；
- tenant一致；
- tool版本格式；
- resource scheme与tool domain合理；
- simulation与production矛盾；
- expected_outcome存在可验证指标；
- credential ref不越过资源范围；
- current_state需要时包含resource_version；
- data classification与environment基本一致性；
- scope_delta不能为未知并默认为0；
- CRITICAL动作必须标记不可自动执行或需要后续审批义务。

注意：Tool参数Schema最终由Batch 05 Registry验证；本Batch只做通用限制和接口。

# 第七步：PolicyInput生成

提供唯一转换：

```rust
fn to_policy_input(
    action: &CanonicalAction,
    registry: &ResolvedToolSnapshot,
    runtime: &RuntimeContext,
    trajectory: &TrajectoryRiskSnapshot,
) -> PolicyInput;
```

PolicyInput必须包含：

```text
subject
intent
tool
arguments
resource
environment
current_state
data_classification
trajectory_risk
registry_snapshot_hash
```

不得让各调用点自行拼接OPA JSON，避免字段缺失和策略绕过。

# 第八步：版本与迁移

采用显式版本策略，例如`agenttrust.action.v1`。

规则：

- Parser支持当前版本与有限历史版本；
- 迁移是单向、纯函数、可测试；
- 不允许在执行时静默丢字段；
- 无损迁移失败时拒绝或进入NEEDS_HUMAN，不猜测；
- 每次迁移记录source_version、target_version、migration_id和前后Hash；
- Breaking change创建新major schema，不复用旧语义。

建立迁移测试语料。

# 第九步：错误模型

至少实现：

```text
ACTION_IR_PARSE_FAILED
ACTION_IR_DUPLICATE_KEY
ACTION_IR_UNKNOWN_VERSION
ACTION_IR_UNKNOWN_ENUM
ACTION_IR_SIZE_LIMIT_EXCEEDED
ACTION_IR_NORMALIZATION_FAILED
ACTION_IR_SEMANTIC_INVALID
ACTION_IR_HASH_MISMATCH
ACTION_IR_SIGNATURE_INVALID
ACTION_IR_SIGNER_UNTRUSTED
ACTION_IR_EXPIRED
ACTION_IR_MIGRATION_LOSSY
ACTION_IR_POLICY_INPUT_FAILED
```

所有错误携带trace_id、字段路径、reason_code和安全摘要。

# 第十步：测试与Fuzz

必须覆盖：

## Golden

- Coding action；
- Industrial read action；
- Industrial conditional write action；
- 相同语义不同字段顺序；
- 多语言Batch 01样例。

## Invalid corpus

- 重复键；
- 路径穿越；
- URL混淆；
- Unicode同形异义测试；
- 超深JSON；
- 巨大数组；
- 未知枚举；
- tool_version=`latest`；
- Secret内联；
- production动作标记simulation；
- resource tenant不一致；
- Hash或签名篡改。

## Property/Fuzz

- 任意字段顺序Hash稳定；
- parse→normalize→serialize幂等；
- malformed input不panic；
- 迁移不丢已承诺字段；
- `cargo fuzz`或`proptest`覆盖Parser、Canonicalizer、Migration。

# 第十一步：公共API

至少提供：

```rust
pub fn parse_draft(bytes: &[u8], limits: &ParseLimits) -> Result<ActionDraft, ActionIrError>;
pub fn normalize(draft: ActionDraft, ctx: &NormalizationContext) -> Result<CanonicalAction, ActionIrError>;
pub fn validate(action: &CanonicalAction, ctx: &ValidationContext) -> Result<ValidationReport, ActionIrError>;
pub fn canonical_bytes(action: &CanonicalAction) -> Result<Vec<u8>, ActionIrError>;
pub fn hash(action: &CanonicalAction) -> Result<ActionHash, ActionIrError>;
pub fn verify_envelope(envelope: &SignedActionEnvelope, keys: &dyn KeyProvider) -> Result<VerifiedAction, ActionIrError>;
pub fn to_policy_input(...) -> Result<PolicyInput, ActionIrError>;
```

`VerifiedAction`构造函数不得公开，只有完整验证流程能创建。

# 必须提交的文件

- `action-ir` crate；
- JSON Schema与样例；
- Canonicalization文档；
- Hash字段清单；
- 签名信封和KeyProvider接口；
- 版本迁移框架；
- PolicyInput转换；
- Golden、Invalid、Fuzz测试；
- `docs/action-ir/security-model.md`；
- `docs/action-ir/versioning.md`。

# 完成Gate

- 外部输入不能直接构造`VerifiedAction`；
- 重复键、未知版本、未知枚举和超限输入全部拒绝；
- Canonical Hash在字段顺序变化下稳定；
- 签名篡改测试失败关闭；
- 迁移显式且无静默字段丢失；
- PolicyInput只有一个官方构造路径；
- IR不包含真实Secret；
- Parser和Canonicalizer Fuzz无panic；
- Coding和Industrial样例均通过。

# v2.0修订与闭环补强

    ## 修订定位

    统一IR采用Common Action Envelope + Typed Domain Payload，避免随着行业扩展形成巨型万能Schema。Canonical Action是所有Policy、Approval、Ledger和Evidence的唯一事实输入。

    ## 依赖分类

    - **contract dependencies**：Batch 01
- **implementation dependencies**：Batch 01
- **runtime integrations**：Batch 05, Batch 06, Batch 29
- **optional integrations**：Batch 11, Batch 20

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - Adapter只能产生ActionDraft；Normalizer验证后生成不可变CanonicalAction。
- Payload类型由Type Registry注册，例如coding.patch.v1、industrial.setpoint.v1。
- Canonicalization、Hash和签名实现只有一套。

    ## 新增或强化的模型

    - ActionEnvelope(common metadata)
- TypedPayload(type_id, schema_version, data)
- CanonicalAction
- ActionMigrationRecord
- MappingLossReport

    ## 必须落盘的接口

    - PayloadTypeRegistry
- ActionNormalizer
- Canonicalizer
- ActionSigner/Verifier
- ActionMigrationService

    ## 新增负向测试与故障注入

    - 重复JSON key、Unicode混淆、NaN/Infinity、深度炸弹、超大整数和不同键顺序。
- 不同Adapter对同一语义产生相同CanonicalAction。
- Payload类型冲突、版本降级和未知扩展失败关闭。

    ## v2.0完成Gate

    - 所有执行链只接受CanonicalAction，不接受原始协议JSON。
- Canonical Action Hash被Approval、AuthorizationLease、Ledger和Trace共同引用。
- Fuzz与属性测试覆盖解析、规范化和迁移。

    任何“完成”声明必须附`IMPLEMENTATION_STATUS.json`、真实命令退出码、测试报告和Evidence引用。规范文件完成不等于产品代码完成。

# Codex最终报告格式

1. **IR model**：核心对象与不变量；
2. **Canonicalization and hash**；
3. **Signature and versioning**；
4. **Files changed**；
5. **Tests/fuzz run**；
6. **Security findings**；
7. **Integration contracts**：Gateway、Registry、PEP和Approval如何消费。
