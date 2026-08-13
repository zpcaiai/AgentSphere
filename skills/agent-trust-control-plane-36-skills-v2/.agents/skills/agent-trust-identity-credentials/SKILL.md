---
name: agent-trust-identity-credentials
description: 实现 Agent Trust & Compliance Control Plane 的 Agent身份、工作负载身份、短期任务凭证、mTLS/OIDC/JWT验证、凭证签发与吊销。用于 Batch 04，把用户、Agent实例、Task、Step、Tool和Resource绑定为不可冒用、可过期、可撤销的运行身份。不要在此Skill中实现企业CRUD后台、Tool业务执行或模型推理。
compatibility: Codex CLI/desktop/IDE；需要 Rust、Java或现有IAM集成、PostgreSQL、OIDC/JWKS测试服务，可选SPIFFE/SPIRE与Vault。生产配置禁止共享长期Service Account。
metadata:
  project: agent-trust-control-plane
  batch: "04"
  version: "2.0.0"
---
# Batch 04：Agent Identity与Workload Credential
# 任务
建立每个Agent运行实例和每个任务步骤的可验证身份，签发最小范围、短生命周期、用途受限的凭证，并确保Pause、Cancel、Kill、审批失效和任务结束时凭证能被即时撤销。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 04
- 接入OIDC、mTLS、SPIFFE或企业IAM
- 消除共享Git/云/数据库/工业管理员Token
- 实现任务绑定Token、使用次数和Audience限制
- 为Gateway、PEP、Credential Proxy提供生产身份上下文

# 非目标
- 不把原始密码或私钥交给Agent
- 不实现企业组织全部CRUD
- 不实现Tool Proxy代执行细节
- 不允许Prompt承担身份认证

# 前置依赖
- Batch 01公共Identity/Task契约
- Batch 02 Gateway的IdentityVerifier接口
- Batch 03稳定Action Hash；若尚未合并，先以版本化接口适配，不复制模型

# 强制安全原则
1. 每个Agent Instance、Task和Step身份唯一
2. production禁止匿名、测试Key和共享长期Token
3. Token必须绑定tenant、agent、task、allowed audience和expiry
4. 凭证权限不得超过创建者与Task已批准范围
5. 撤销优先于本地缓存；无法确认有效性时高风险动作失败关闭
6. Token、私钥、Cookie和证书私钥不得进入Trace、Prompt或普通日志

# 建议目录

```text
rust/crates/identity-runtime
rust/crates/credential-issuer
rust/crates/revocation-cache
java/enterprise-control-api/identity
schemas/identity
conformance-tests/identity
docs/security/identity
```

# 必须实现的公共接口

```text
IdentityVerifier.verify(request)->VerifiedIdentityContext
CredentialIssuer.issue(CredentialRequest)->CredentialHandle
CredentialValidator.validate(handle, audience, action_hash)->CredentialClaims
RevocationService.revoke(subject|task|credential, reason)
TrustBundleProvider.current()->TrustBundleSnapshot
UsageCounter.consume(credential_id, operation_hash)->remaining_uses
```

# 第1步：身份模型与信任层级
- 定义HumanSubject、ServiceSubject、AgentDefinition、AgentInstance、TaskIdentity、StepIdentity
- 区分认证强度、部署环境、模型/Agent版本与owner chain
- 把租户和组织归属从可信映射解析，不接受客户端自报tenant

# 第2步：认证入口
- 实现OIDC JWT/JWKS验证、mTLS工作负载身份接口
- 校验issuer、audience、nonce/azp、not-before、expiry和算法白名单
- JWKS轮换期间保留有限旧Key，但不得无限缓存
- 开发Verifier只能由编译feature与显式环境同时开启

# 第3步：任务身份派生
- 从已认证用户/服务与Task创建签名TaskIdentity
- StepIdentity必须引用task_id、step_id、action_hash和policy decision
- 禁止Agent自行声明更高trust_level或owner_subject

# 第4步：短期凭证签发
- CredentialRequest必须包含resource、operations、tool、action_hash、ttl、max_uses
- 由PEP obligations和Approval共同收窄scope
- 默认TTL以分钟计；高风险工业写入采用更短TTL和单次使用
- 只返回CredentialHandle；原始Secret尽可能由Proxy持有

# 第5步：吊销和生命周期
- 支持按credential、task、agent instance和tenant吊销
- Pause冻结新签发；Cancel/Kill立即吊销并推送到Gateway/Proxy/Sandbox
- 任务完成后销毁临时密钥材料
- 处理时钟漂移并限制容忍窗口

# 第6步：密钥和Secret管理
- 生产Key来自KMS/Vault/HSM或受管KeyProvider
- 实现轮换、kid、信任包版本和应急撤销
- Secret使用zeroize或等效生命周期控制，Debug/Display禁止输出内容

# 第7步：审计事件
- 记录IdentityVerified、CredentialIssued、CredentialConsumed、CredentialRevoked
- 仅记录credential_id、scope hash、issuer和结果，不记录Token值

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 伪造issuer/audience/tenant被拒绝
- 过期、未生效、错误算法和未知kid被拒绝
- 同Token越权访问其他Resource或Tool被拒绝
- max_uses=1第二次消费失败且并发无竞态
- Kill后缓存节点也拒绝旧凭证
- JWKS轮换、网络中断和时钟偏差故障注入
- 日志与Trace扫描确认无Secret

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- 生产IdentityVerifier和测试Verifier
- CredentialIssuer/Validator/Revocation接口与实现
- 数据库迁移和信任包Schema
- OIDC/mTLS集成测试
- 密钥轮换与应急吊销Runbook
- 身份威胁模型和Evidence样例

# 完成Gate
- production无真实信任根时启动失败
- 跨租户与跨Task冒用测试全部失败
- 撤销传播满足设定SLO并有测量证据
- 短期Token不含未批准权限
- 所有Secret泄漏扫描通过
- Batch 02/06/08/17可消费稳定接口

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Batch 04只管理Agent/Workload Identity、认证上下文和运行Token，不保存Git、数据库、云或工业目标系统凭证；后者完全属于Batch 08。

    ## 依赖分类

    - **contract dependencies**：Batch 01
- **implementation dependencies**：Batch 01
- **runtime integrations**：Batch 02, Batch 08, Batch 29, Batch 30
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 每个Agent运行实例、Task和Step使用独立Subject与短期Token。
- Token绑定audience、tenant、task、step、revocation_epoch和最大使用次数。
- Pause、Cancel、Kill或Owner撤销时能够立即失效。

    ## 新增或强化的模型

    - AgentPrincipal
- WorkloadIdentity
- AuthContext
- CredentialLeaseRef
- RevocationEpoch
- TokenUseCounter

    ## 必须落盘的接口

    - WorkloadTokenIssuer
- WorkloadTokenVerifier
- RevocationService
- IdentityFederationPort
- AgentOwnershipResolver

    ## 新增负向测试与故障注入

    - 共享Token、错误audience、跨租户、过期、重放、时钟偏差和撤销并发。
- Token和claims不得进入Prompt、普通Trace、异常堆栈。
- 生产环境测试签名器、匿名身份或默认共享密钥导致启动失败。

    ## v2.0完成Gate

    - 身份与目标Credential职责无重叠。
- 吊销延迟、签发SLO、密钥轮换和故障模式有测试。
- Agent Owner/Sponsor和生命周期可由Batch 30发现与治理。

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
7. **Next integration**：Batch 08 Tool/Credential Proxy、Batch 17 Approval、Batch 19 Evidence。
