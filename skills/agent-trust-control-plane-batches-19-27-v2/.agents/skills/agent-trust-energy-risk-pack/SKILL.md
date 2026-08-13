---
name: agent-trust-energy-risk-pack
description: 实现微电网、储能、光伏、数据中心电力和需求响应的Energy Agent Risk Pack。用于 Batch 25，把SOC、电压、频率、功率、热约束、爬坡率、预测置信度和回退控制纳入Tool Policy、仿真、审批和Evaluator。
compatibility: 需要Batch 24工业基础、Python优化/RL/CBF环境、MATPOWER或等效仿真、时序数据。生产控制从Shadow和安全监督模式开始。
metadata:
  project: agent-trust-control-plane
  batch: "25"
  version: "2.0.0"
---
# Batch 25：Energy Agent Risk Pack
# 任务
确保能源Agent的经济优化始终服从物理安全和运行约束，在模型失效、数据延迟或通信中断时能切回确定性安全控制。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。 本Domain Pack必须复用公共身份、PEP、审批、Sandbox、Proxy、Ledger、Trace、Kill Switch和Evidence，不复制、不旁路公共安全内核。
# 触发条件
- 实现Batch 25
- 微电网/储能/数据中心电力Agent
- 需求响应与电价优化
- 部署RL/MPC/CBF控制建议

# 非目标
- 不让RL直接绕过保护逻辑
- 不把模拟收益当生产收益
- 不允许经济目标覆盖安全约束
- 不在无回退控制时开放自治写入

# 前置依赖
- Batch 24 Industrial Pack
- Batch 15模型治理可选
- 公共Approval/Ledger/Evidence

# 强制安全原则
1. 安全约束硬编码于PEP/安全控制，不仅在奖励函数
2. 数据时间戳、质量和预测置信度进入Policy
3. 动作有功率/电流/温度/SOC/ramp限制
4. 通信断开和OOD触发safe fallback
5. 仿真、Shadow、受限控制逐级认证
6. Evaluator同时报告安全、稳定、经济和舒适/业务约束

# 建议目录

```text
domain-packs/energy
policies/energy
python/energy-agent
simulators/energy
threat-scenarios/energy
conformance-tests/domain/energy
```

# 必须实现的公共接口

```text
energy.telemetry_read
energy.forecast_run
energy.optimize_plan
energy.dispatch_prepare/commit
energy.fallback_activate
EnergyEvaluator.evaluate
```

# 第1步：资产与约束
- 电池、逆变器、负荷、光伏、并网点、数据中心设施
- SOC、电压、频率、热、功率和合同边界

# 第2步：算法封装
- Python MPC/RL/CBF只输出候选计划和置信度
- Rust/Policy验证每个动作和trajectory
- 模型版本、训练数据摘要和solver状态进入Evidence

# 第3步：仿真与场景
- 正常、峰价、设备故障、预测误差、通信延迟、极端天气/负荷
- Monte Carlo/OOD场景

# 第4步：执行
- prepare获取最新状态→可行性检查→审批/自动低风险→commit→闭环监控
- 调度序列使用幂等与版本

# 第5步：回退控制
- 规则/MPC安全控制、last-known-safe或人工接管
- 回退本身定期测试

# 第6步：Evaluator
- 硬约束违规为FAIL
- 成本、峰值、SOC寿命、稳定性、舒适度分项
- 与baseline对比并给置信区间

# 第7步：Shadow到生产
- 建议与实际操作对比
- 风险预算、逐步放量、自动回退

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- RL输出越界被PEP拒绝
- 数据延迟/坏质量导致降级
- OOD与预测错误触发fallback
- 重复dispatch幂等
- 成本下降但安全约束违规Evaluator FAIL
- 回退控制故障注入

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Energy Pack
- 资产/约束Policy
- 算法接口
- 仿真场景
- Fallback Controller
- Energy Evaluator与Shadow报告

# 完成Gate
- 安全约束独立于学习模型
- 所有生产动作可被确定性Guard阻断
- Fallback有定期演练证据
- Shadow达到预设安全和效果标准
- 结果报告含不确定性
- 未经阶段认证不开放自治

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Energy Pack把经济优化置于电压、频率、SOC、功率和设备安全约束之下，支持仿真、影子和受限闭环控制。

    ## 依赖分类

    - **contract dependencies**：Batch 20
- **implementation dependencies**：Batch 05, Batch 06, Batch 07, Batch 08, Batch 09, Batch 10, Batch 16, Batch 20, Batch 29
- **runtime integrations**：Batch 21, Batch 22, Batch 28, Batch 33, Batch 34, Batch 36
- **optional integrations**：Batch 24

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 安全约束硬于成本目标；预测或RL失败时回退到确定性安全控制。
- 模型、预测、优化解和控制动作版本可追溯。
- 控制域、调度权限和通信延迟进入Policy。

    ## 新增或强化的模型

    - EnergyAsset
- OperationalConstraint
- ForecastSnapshot
- DispatchPlan
- FallbackControllerRef
- EnergyOutcome

    ## 必须落盘的接口

    - EnergyToolProvider
- ConstraintPolicyPack
- OptimizationAdapter
- FallbackController
- EnergyEvaluator

    ## 新增负向测试与故障注入

    - SOC越界、频率/电压异常、预测漂移、通信延迟、求解器无解、RL OOD、重复调度。
- 回退控制可在模型不可用时独立运行。
- 安全约束违反永不因经济收益而PASS。

    ## v2.0完成Gate

    - 使用Batch20 Pack SDK和Batch16边缘接口。
- 仿真与Shadow证据完整。
- 优化算法与执行安全边界分离。

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
7. **Next integration**：能源Pilot和行业认证扩展。
