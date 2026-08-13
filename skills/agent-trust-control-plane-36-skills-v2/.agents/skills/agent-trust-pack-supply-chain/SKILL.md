---
name: agent-trust-pack-supply-chain
description: 实现Skill、Tool、Protocol Adapter和Domain Pack的Manifest、签名、SBOM、权限声明、版本、安装审批、升级、回滚和撤销。用于 Batch 20，防止恶意或被篡改扩展进入可信执行链。
compatibility: 需要Batch 05 Registry、Batch 07 Sandbox、Batch 11 Adapter SDK、Batch 19 Evidence，可接Sigstore/Cosign或企业PKI。
metadata:
  project: agent-trust-control-plane
  batch: "20"
  version: "2.0.0"
---
# Batch 20：平台供应链与Domain Pack SDK Foundation
# 任务
把所有可扩展代码和规则视为软件供应链资产，只有来源可验证、权限已审查、测试通过并被批准的版本才能在限定环境启用。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 20
- 签名Skill/Tool/Adapter/Domain Pack
- 建设插件市场或私有Registry
- 处理SBOM、升级、撤销和权限扩大

# 非目标
- 不因有签名就认为内容安全
- 不允许安装自动获得生产权限
- 不允许mutable latest标签作为生产唯一标识
- 不把漏洞扫描替代行为测试

# 前置依赖
- Batch 05 Registry
- Batch 07 Sandbox
- Batch 10/19 Evidence
- Batch 11 Adapter Manifest

# 强制安全原则
1. 生产引用immutable digest和version
2. 签名身份、授权发布者和内容digest同时验证
3. Manifest声明Tools、Policy、network、data、secrets、executors和compatibility
4. 权限扩大触发重新审批
5. 撤销阻断新任务并评估运行中任务
6. Pack代码在受限Sandbox验证

# 建议目录

```text
schemas/domain-pack
rust/crates/pack-verifier
java/compliance-service/pack-registry
conformance-tests/packs
threat-scenarios/supply-chain
docs/supply-chain
```

# 必须实现的公共接口

```text
PackRegistry.publish/approve/activate/revoke
PackVerifier.verify
PermissionDiff.compute
PackInstaller.install
CompatibilityChecker.check
SupplyChainEvidence.build
```

# 第1步：Pack格式
- Manifest、Tool definitions、Policies、Evaluators、Compensations、Mappings、Threat scenarios、tests、SBOM
- 明确必需和可选文件，规范hash顺序

# 第2步：签名与发布
- publisher identity、keyless/PKI签名、时间戳可选
- 验证来源仓库、构建provenance和artifact digest

# 第3步：权限审查
- 比较新旧版本的Tool、network、data、secret、executor和approval范围
- 新增高风险能力必须人工审批

# 第4步：安装验证
- 静态Schema、依赖、漏洞、许可证、恶意模式
- 在Sandbox运行Conformance和Threat Tests

# 第5步：激活与灰度
- 按tenant/environment启用
- 不可用latest漂移
- 保留上一版本回滚

# 第6步：撤销
- publisher compromise、漏洞或行为异常时撤销
- 运行中任务根据风险Pause/Kill
- 生成影响范围

# 第7步：证据
- 发布、审批、安装、测试、激活、升级和撤销全部进入Evidence

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 篡改文件或Manifest签名失败
- 同版本不同digest拒绝
- 权限扩大未审批不能激活
- 恶意Pack访问未声明网络被阻断
- 撤销后新任务失败且运行中按策略处理
- 回滚与兼容性测试

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Pack Schema和Verifier
- Registry/Installer
- Permission Diff
- 签名与SBOM流水线
- Supply-chain threat corpus
- 升级撤销Runbook

# 完成Gate
- 生产无mutable未签名Pack
- 签名、权限和行为三类验证齐全
- 权限扩大可见且需审批
- 撤销有效
- 每个Pack有Evaluator和Threat Tests
- Marketplace与公共内核权限隔离

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Batch 20从单一Pack签名扩展为全平台供应链安全，并前移Domain Pack SDK Foundation；Batch 23—27必须用该SDK开发，Batch 28只负责Marketplace。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 05, Batch 10, Batch 19
- **implementation dependencies**：Batch 05, Batch 10, Batch 19
- **runtime integrations**：Batch 23, Batch 24, Batch 25, Batch 26, Batch 27, Batch 28, Batch 32, Batch 33, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 覆盖Rust crate、Python/Maven/npm依赖、镜像、Adapter、Policy bundle、Prompt、Evaluator、模型Manifest和Domain Pack。
- 构建产物有SBOM、Provenance、签名、Digest、兼容范围和撤销。
- Pack SDK定义Manifest、Tool/Policy/Evaluator/Compensation/Threat Scenario插件接口。

    ## 新增或强化的模型

    - ArtifactManifest
- SbomRef
- BuildProvenance
- SignatureEnvelope
- RevocationEntry
- DomainPackManifest
- PackPermissionDeclaration

    ## 必须落盘的接口

    - ArtifactVerifier
- SupplyChainGate
- PackSdk
- PackValidator
- RevocationService
- CompatibilityResolver

    ## 新增负向测试与故障注入

    - 依赖替换、签名重放、镜像tag漂移、Policy bundle篡改、Pack权限扩大、撤销传播。
- 未签名或高危漏洞产物不能进入production。
- Pack SDK示例包通过一致性与安全测试。

    ## v2.0完成Gate

    - 23—27不自定义第二套Pack结构。
- 所有可执行/策略/Prompt/Evaluator产物可追溯。
- Marketplace安装与生命周期留给Batch28。

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
7. **Next integration**：Batch 28 Domain Pack SDK/Marketplace。
