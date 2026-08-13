---
name: agent-trust-coding-risk-pack
description: 实现Coding Agent领域Risk Pack。用于 Batch 23，提供代码仓库、分支、文件、构建、测试、依赖、CI/CD、Git凭证和部署的Tool、Policy、Threat Scenarios、Compensation和Completion Evaluator。必须复用公共Control Plane，不得另建安全链路。
compatibility: 需要Batch 01—22公共能力中的适用模块、Git测试服务、至少一个Java/Spring示例仓库和Linux Sandbox。
metadata:
  project: agent-trust-control-plane
  batch: "23"
  version: "2.0.0"
---
# Batch 23：Coding Agent Risk Pack
# 任务
把Coding Agent限制在明确仓库、分支、路径、命令和网络范围内，安全地产生可编译、测试通过、证据完整、可回滚的代码修改。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 23
- 接入Codex/Claude Code等Coding Agent
- 建设软件现代化或代码转换平台安全Pack
- 实现Git/Build/Test/PR Evaluator

# 非目标
- 不提供任意Shell
- 不允许默认写main/master
- 不允许读取Secrets和CI凭证
- 不因测试通过就自动部署生产

# 前置依赖
- 公共Tool/PEP/Sandbox/Proxy/Ledger/Evidence/Approval
- Batch 20 Pack签名

# 强制安全原则
1. 工作区每Task隔离并固定baseline SHA
2. 只允许预注册仓库、分支模式和路径
3. 构建命令来自Tool模板而非Agent自由Shell
4. 网络默认关闭或仅依赖镜像源
5. 所有修改有diff、测试和rollback evidence
6. 受保护分支和部署需要独立审批

# 建议目录

```text
domain-packs/coding
policies/coding
threat-scenarios/coding
python/evaluator-runtime/coding
conformance-tests/domain/coding
examples/coding-demo
```

# 必须实现的公共接口

```text
coding.repo_read/search
coding.workspace_patch
coding.build_run
coding.tests_run
coding.api_compatibility
coding.branch_push
coding.pull_request_create
CodingEvaluator.evaluate
```

# 第1步：资产和权限模型
- 组织、仓库、branch、path、file class、CI/CD、environment
- 识别.env、pem、workflow、infra和generated文件

# 第2步：Tool定义
- 高层Git、Patch、Build、Test、Scan、PR工具
- 每个Tool严格Schema、EffectClass、timeout和compensation

# 第3步：Sandbox Profiles
- 按Java/Node/Python/Rust构建镜像
- 非root、只读工具链、临时workspace、依赖缓存只读/租户隔离

# 第4步：Policy
- 禁止protected branch、Secret路径、大规模删除、未批准网络
- 限制changed files/deleted lines/command templates

# 第5步：供应链
- 依赖锁文件、镜像digest、SBOM、恶意构建脚本和postinstall
- 新增依赖触发风险和审批

# 第6步：补偿
- workspace reset、delete task branch、revert commit、close PR、rollback test deployment

# 第7步：Evaluator
- 编译、单测/集成测试、API兼容、静态安全、diff范围、需求覆盖和Evidence
- 测试缺失不能用LLM声称完成

# 第8步：攻击场景
- Prompt injection in repo、malicious test、symlink/path traversal、Git hook、credential exfiltration、fork PR

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 无法读取.env/SSH/Docker socket
- 任意Shell和受保护分支写入拒绝
- 恶意构建脚本外连被阻断
- 重复push/PR幂等
- 编译失败但Agent声称成功时Evaluator FAIL
- 回滚恢复baseline并验证

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Coding Pack Manifest
- Tool/Policy/Compensation
- Sandbox Profiles
- Threat corpus
- Coding Evaluator
- Spring示例端到端Evidence

# 完成Gate
- 端到端Demo真实编译测试
- 无公共安全逻辑复制
- 所有写动作有幂等与rollback
- 仓库内Prompt Injection不能越权
- Evidence包含baseline/diff/build/test
- 通过Batch 22 Domain Gate

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Coding Pack聚焦代码仓库、构建、测试、依赖与部署副作用，不复制公共Gateway、Identity、PEP、Sandbox、Ledger或Evidence。

    ## 依赖分类

    - **contract dependencies**：Batch 20
- **implementation dependencies**：Batch 05, Batch 06, Batch 07, Batch 08, Batch 09, Batch 10, Batch 20, Batch 29
- **runtime integrations**：Batch 21, Batch 22, Batch 28, Batch 33, Batch 36
- **optional integrations**：Batch 12, Batch 15

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 所有Shell被高层Tool和Executor模板封装。
- 仓库、分支、路径、Secret、CI/CD和依赖风险显式建模。
- 完成标准基于编译、测试、API兼容、安全扫描和Diff范围证据。

    ## 新增或强化的模型

    - RepositoryResource
- BranchPolicy
- PatchPlan
- BuildEvidence
- TestEvidence
- ApiCompatibilityFinding
- SupplyChainFinding

    ## 必须落盘的接口

    - CodingToolProvider
- GitProxyAdapter
- BuildExecutorProfile
- CodingPolicyPack
- CodingEvaluator

    ## 新增负向测试与故障注入

    - 路径穿越、受保护分支、恶意构建脚本、依赖投毒、Secret读取、PR重复创建、部署回滚。
- 同一任务只创建一次分支/PR。
- 无测试或证据不足不得PASS。

    ## v2.0完成Gate

    - 使用Batch20 Pack SDK。
- 公开示例仓库完成端到端迁移证据。
- Sandbox/网络/Secret策略不可由Pack放宽。

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
7. **Next integration**：软件现代化、语言转换和Coding Agent产品集成。
