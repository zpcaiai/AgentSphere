---
name: agent-trust-tool-registry
description: 实现 Agent Trust & Compliance Control Plane 的 Tool与Capability Registry。用于 Batch 05，包括不可变Tool版本、严格输入输出Schema、风险与副作用分类、Executor/Approval/Compensation绑定、Capability Manifest、签名与吊销、缓存和Registry快照。不要用于实现Agent Gateway、OPA策略决策、Sandbox执行或业务Agent规划。
compatibility: Codex CLI/desktop/IDE；需要 Rust、PostgreSQL、git、Docker/Podman。应消费 Batch 01公共契约和 Batch 03 Verified Action IR。
metadata:
  project: agent-trust-control-plane
  batch: "05"
  version: "2.0.0"
---

# Batch 05：Tool与Capability Registry

# 任务
实现统一Tool与Capability Registry，使任何Agent只能够发现和请求已注册、已发布、未吊销、版本精确、Schema可验证的Tool。Registry提供事实与快照，不自行替代Policy PEP或Approval。

完成本Skill时必须在当前仓库实现真实代码、测试、配置和文档；不得只输出设计、伪代码、空接口或TODO。先检查现有实现并增量修改，禁止创建第二套平行架构。

# 安全原则

1. **默认拒绝。** 未注册、未发布、版本模糊、已吊销Tool都不能执行。
2. **发布版本不可变。** 修改Schema、风险、Executor、网络或副作用语义必须发布新版本。
3. **Capability Discovery不等于Authorization。** 发现结果不能被当作允许决策。
4. **Tool Schema必须严格。** 默认`additionalProperties: false`；扩展必须显式。
5. **每个Tool必须声明副作用类型。** 不允许UNKNOWN进入生产。
6. **每个写Tool必须声明幂等策略、审批策略和补偿能力，或显式标记IRREVERSIBLE。**
7. **Tool实现与声明必须可绑定。** 使用manifest hash、executor image digest或binary digest，禁止只信任名称。
8. **吊销优先于缓存。** 高风险路径必须能及时感知revoke。
9. **Registry不可包含真实凭证。** 只保存credential profile引用。
10. **协议Adapter不能直接注册并立即启用生产Tool。** 发布需要治理流程和签名。


# 前置依赖

- Batch 01公共契约；
- Batch 03 Canonical/Verified Action IR；
- PostgreSQL或现有可靠注册存储。

# 建议目录

```text
rust/crates/
├── tool-registry-core/
├── tool-registry-store/
├── tool-registry-api/
├── tool-schema-validator/
└── tool-registry-testkit/

migrations/tool-registry/
examples/tools/
├── coding/
└── industrial/
```

# 第一步：定义生命周期

Tool Version状态：

```text
DRAFT → VALIDATED → SIGNED → ACTIVE → DEPRECATED → REVOKED
```

规则：

- DRAFT不可被生产Action解析；
- ACTIVE版本不可修改，只能新建版本；
- DEPRECATED可按Policy允许已有任务继续，但不得作为默认发现结果；
- REVOKED立即拒绝新执行，高风险进行中任务触发Pause/Kill义务接口；
- 状态变更写入审计事件；
- 不允许从REVOKED恢复为ACTIVE，必须发布新版本。

Capability生命周期使用同类状态，但Capability本身不授予权限。

# 第二步：数据模型

至少创建：

```text
tools
tool_versions
capabilities
capability_versions
capability_tools
executor_profiles
credential_profiles
approval_profiles
compensation_bindings
tool_signatures
registry_events
registry_snapshots
```

`tool_versions`至少包含：

```text
tool_id
tool_version
status
domain
display_name
description
input_schema
output_schema
schema_hash
effect_class
risk_level
executor_profile_id
credential_profile_id
approval_profile_id
compensation_tool_id/version
timeout_limit_ms
result_size_limit
network_profile_ref
filesystem_profile_ref
implementation_digest
publisher_id
signature_ref
created_at
activated_at
revoked_at
```

数据库约束：

- `UNIQUE(tool_id, tool_version)`；
- ACTIVE记录不可UPDATE关键字段，使用DB trigger或应用+审计双重保护；
- compensation tool必须存在且状态符合要求；
- PURE Tool不能声明写权限profile；
- IRREVERSIBLE Tool必须为HIGH或CRITICAL，并要求明确审批或deny-by-default；
- schema_hash与实际Schema匹配。

# 第三步：Tool Manifest格式

定义可签名Manifest：

```yaml
tool_id: coding.run-tests
tool_version: 1.0.0
domain: coding
status: draft
input_schema: {...}
output_schema: {...}
effect_class: IDEMPOTENT
risk_level: MEDIUM
executor_profile: coding-sandbox-maven
credential_profile: none
approval_profile: medium-default
compensation: null
limits:
  timeout_ms: 900000
  max_result_bytes: 10485760
implementation:
  kind: container
  digest: sha256:...
```

使用canonical serialization计算manifest hash。签名覆盖所有安全相关字段。

# 第四步：Registry API与trait

至少提供：

```rust
#[async_trait]
pub trait ToolRegistry: Send + Sync {
    async fn resolve_exact(&self, tenant: &TenantId, tool: &ToolRef)
        -> Result<ResolvedToolSnapshot, RegistryError>;
    async fn validate_arguments(&self, snapshot: &ResolvedToolSnapshot, args: &StrictJsonObject)
        -> Result<(), RegistryError>;
    async fn discover_capabilities(&self, query: CapabilityQuery)
        -> Result<Vec<CapabilityDescriptor>, RegistryError>;
    async fn snapshot(&self, refs: &[ToolRef])
        -> Result<RegistrySnapshot, RegistryError>;
    async fn is_revoked(&self, tool: &ToolRef, digest: &Digest)
        -> Result<bool, RegistryError>;
}
```

HTTP管理接口至少支持：

```text
POST /v1/tools:draft
POST /v1/tools/{id}/versions/{version}:validate
POST /v1/tools/{id}/versions/{version}:sign
POST /v1/tools/{id}/versions/{version}:activate
POST /v1/tools/{id}/versions/{version}:deprecate
POST /v1/tools/{id}/versions/{version}:revoke
GET  /v1/tools/{id}/versions/{version}
GET  /v1/capabilities
```

管理接口与Agent数据平面分离，写操作必须使用Batch 04身份与企业后台授权；无法验证管理身份时production写接口默认禁用。

# 第五步：严格Schema验证

输入输出使用JSON Schema 2020-12。要求：

- 编译Schema并缓存；
- 激活前运行Schema meta-validation；
- 输入拒绝额外字段、错误类型、超限长度和非法格式；
- 对数字工程量定义单位和范围；
- 输出同样验证，防止Tool返回未声明敏感字段；
- Schema引用只能来自可信Registry或固定bundle，禁止运行时任意远程`$ref`；
- 限制正则复杂度和Schema深度，防止ReDoS/资源消耗；
- Validation错误只返回路径和规则，不回显Secret值。

# 第六步：ResolvedToolSnapshot

执行管线不能长期依赖可变查询结果。每次Action解析后生成不可变快照：

```text
ResolvedToolSnapshot
├── tool id/version
├── schema hash
├── manifest hash
├── effect/risk
├── executor profile
├── credential profile
├── approval profile
├── compensation binding
├── limits
├── implementation digest
├── registry revision
└── resolved_at
```

该快照进入：

- Action Hash补充或Execution Plan Hash；
- PolicyInput；
- Approval Hash；
- Execution Ledger；
- Evidence Package。

执行前再次检查revocation和关键digest。

# 第七步：Capability Registry

Capability Manifest至少包含：

```text
capability_id/version
description
input/output contract
required tool refs
optional tool refs
risk summary
supported protocols
domain pack id/version
publisher/signature
compatibility
```

发现API允许按domain、protocol、risk和tenant可见范围过滤，但返回结果必须附带：

```text
discovery_only: true
authorization_required: true
```

不为Agent返回其无权知道的内部敏感Tool描述。

# 第八步：Executor与实现绑定

支持实现类型：

```text
wasm_component
oci_container
internal_service
http_proxy
mcp_server
industrial_gateway
```

要求：

- OCI使用不可变digest，不使用floating tag进入生产；
- WASM记录component hash；
- internal service使用mTLS identity和service version；
- MCP记录server identity、manifest hash、schema snapshot；
- industrial gateway记录gateway identity和protocol mapping version；
- implementation digest不匹配时执行拒绝。

# 第九步：缓存与吊销

实现本地只读缓存，但遵循：

- Cache key包含tenant、tool id/version、registry revision；
- ACTIVE manifest可缓存；
- revocation使用短TTL、push invalidation或双重检查；
- HIGH/CRITICAL动作执行前强制在线revocation check；
- Registry不可用时：
  - 新解析动作默认拒绝；
  - 已有PURE低风险快照可按明确策略短期使用；
  - 写动作不允许仅凭过期缓存执行。

# 第十步：样例Tool

至少注册并测试：

## Coding

```text
coding.repo-read              PURE / LOW
coding.search-code            PURE / LOW
coding.apply-patch            COMPENSATABLE / MEDIUM
coding.run-build              IDEMPOTENT / MEDIUM
coding.run-tests              IDEMPOTENT / MEDIUM
```

## Industrial Simulator

```text
industrial.read-tag           PURE / LOW
industrial.read-alarm         PURE / LOW
industrial.prepare-setpoint   PURE / MEDIUM
industrial.commit-setpoint    COMPENSATABLE / HIGH
industrial.restore-setpoint   IDEMPOTENT或COMPENSATABLE / HIGH
```

`commit-setpoint`参数必须包含asset_id、tag、value、expected_current_value、resource_version。

# 第十一步：错误码

至少实现：

```text
REGISTRY_TOOL_NOT_FOUND
REGISTRY_VERSION_REQUIRED
REGISTRY_VERSION_NOT_ACTIVE
REGISTRY_TOOL_REVOKED
REGISTRY_SCHEMA_INVALID
REGISTRY_ARGUMENT_INVALID
REGISTRY_OUTPUT_INVALID
REGISTRY_MANIFEST_HASH_MISMATCH
REGISTRY_SIGNATURE_INVALID
REGISTRY_IMPLEMENTATION_DIGEST_MISMATCH
REGISTRY_COMPENSATION_INVALID
REGISTRY_UNAVAILABLE_FAIL_CLOSED
```

# 第十二步：测试

必须覆盖：

- 未知Tool、未知版本和`latest`拒绝；
- ACTIVE版本不可变；
- Revoke后缓存失效；
- 额外参数、边界值和错误类型；
- 输出包含未声明Secret字段；
- 远程`$ref`拒绝；
- implementation digest变化；
- compensation绑定不存在；
- PURE Tool错误声明写credential profile；
- Capability发现不产生授权；
- Tenant隔离；
- Registry数据库故障时写动作失败关闭；
- 并发激活和版本冲突。

# 必须提交的文件

- Registry Rust crates；
- PostgreSQL migration；
- Tool/Capability Manifest Schema；
- 管理API和只读解析trait；
- 签名与快照实现；
- 缓存与revocation；
- Coding/Industrial样例；
- 测试和种子数据；
- `docs/registry/lifecycle.md`；
- `docs/registry/security-model.md`；
- `docs/registry/tool-authoring.md`。

# 完成Gate

- 未注册、模糊版本、非ACTIVE和REVOKED Tool全部拒绝；
- ACTIVE版本不可变；
- 输入和输出都严格验证；
- ResolvedToolSnapshot可重复Hash；
- 高风险执行前可实时检查吊销；
- Implementation使用不可变digest；
- Capability发现与授权严格分离；
- 写动作在Registry不可用时失败关闭；
- Coding与Industrial样例通过端到端解析测试。

# v2.0修订与闭环补强

    ## 修订定位

    Registry是Tool与Capability的不可变版本事实源，同时记录实现Digest、EffectClass、风险、权限声明和兼容性；发现能力绝不等同授权。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03
- **implementation dependencies**：Batch 01, Batch 03
- **runtime integrations**：Batch 06, Batch 08, Batch 11, Batch 20, Batch 30
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 已激活版本不可原地修改；Schema、实现、权限或网络声明变化生成新版本。
- Tool声明必须绑定Executor Profile、Credential Profile、Approval Policy和Compensation。
- 注册信息与真实实现不一致时冻结调用并触发Incident。

    ## 新增或强化的模型

    - ToolManifest
- CapabilityManifest
- ImplementationAttestation
- CompatibilityReport
- RegistrySnapshot
- RevocationRecord

    ## 必须落盘的接口

    - ToolRegistry
- CapabilityRegistry
- ManifestVerifier
- CompatibilityChecker
- RegistrySnapshotPublisher

    ## 新增负向测试与故障注入

    - 同名Tool冲突、Schema宽化、EffectClass降级、实现Digest漂移、撤销传播和缓存陈旧。
- Capability发现后未授权调用必须仍被PEP拒绝。
- Registry不可用时高风险新调用失败关闭；可配置只读缓存有TTL和签名。

    ## v2.0完成Gate

    - 每个写Tool都有EffectClass、补偿或不可逆说明。
- Registry Snapshot带签名、版本和可回滚记录。
- Batch 30 Agent Registry与本Batch边界明确：Agent资产和Tool资产分别治理。

    任何“完成”声明必须附`IMPLEMENTATION_STATUS.json`、真实命令退出码、测试报告和Evidence引用。规范文件完成不等于产品代码完成。

# Codex最终报告格式

1. **Registry model and lifecycle**；
2. **Resolved snapshot and hash**；
3. **Schema validation evidence**；
4. **Files/migrations changed**；
5. **Tests run**；
6. **Revocation/fail-closed evidence**；
7. **Next integration**：Batch 06 PEP和Batch 07 Executor消费接口。
