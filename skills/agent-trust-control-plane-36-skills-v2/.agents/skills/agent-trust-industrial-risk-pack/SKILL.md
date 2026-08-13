---
name: agent-trust-industrial-risk-pack
description: 实现工业Agent领域Risk Pack。用于 Batch 24，提供设备、Node/Topic/Register、值域、变化速率、联锁、报警、维护窗口、两阶段写入、Safe Stop、补偿和物理结果Evaluator。首阶段必须使用Simulator/Digital Twin，再进入真实只读和Shadow。
compatibility: 需要Batch 16 Edge Gateway、工业模拟器/数字孪生、时序存储和公共Control Plane。真实写入需独立安全评审。
metadata:
  project: agent-trust-control-plane
  batch: "24"
  version: "2.0.0"
---
# Batch 24：Industrial Agent Risk Pack
# 任务
将工业Agent的每个动作绑定到资产、实时状态和物理约束，确保不越权、不超范围、不覆盖他人操作，并以遥测结果而非命令ACK判定完成。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。 本Domain Pack必须复用公共身份、PEP、审批、Sandbox、Proxy、Ledger、Trace、Kill Switch和Evidence，不复制、不旁路公共安全内核。
# 触发条件
- 实现Batch 24
- 工业Agent、数字孪生、预测维护或受限控制
- OPC UA/MQTT/Modbus领域策略
- 工业动作Evaluator

# 非目标
- 不直接控制SIS
- 不在第一阶段连接真实生产写权限
- 不把网络ACK当物理成功
- 不声称所有过程可自动回滚

# 前置依赖
- Batch 16工业Gateway
- Batch 17审批
- Batch 21异常检测
- 公共Ledger/Evidence

# 强制安全原则
1. 阶段顺序Simulator→Twin→Read-only→Shadow→Limited Write
2. 资产状态必须新鲜且质量良好
3. 写入范围、变化率、模式、联锁、报警和维护窗全部满足
4. 审批绑定before/target/resource version
5. Safe Stop优先于盲目restore
6. 遥测收敛和稳定期决定结果

# 建议目录

```text
domain-packs/industrial
policies/industrial
threat-scenarios/industrial
python/evaluator-runtime/industrial
simulators/industrial
conformance-tests/domain/industrial
```

# 必须实现的公共接口

```text
industrial.telemetry_read
industrial.alarm_read
industrial.simulation_run
industrial.setpoint_prepare/commit
industrial.operation_stop
industrial.state_restore
IndustrialEvaluator.evaluate
```

# 第1步：资产/风险模型
- site-line-asset-tag层级、criticality、engineering unit、safe range、rate limit
- 定义安全联锁和禁止Agent控制清单

# 第2步：Tool与Policy
- 读、仿真、prepare、commit、stop、restore
- 按环境和阶段控制Tool availability

# 第3步：两阶段执行
- prepare采集状态/报警/联锁/版本→仿真→审批→commit CAS→verify
- 审批期间状态变化则重新开始

# 第4步：补偿和Safe Stop
- 可逆设定值条件恢复
- 不可逆/过程滞后时停止、隔离、人工恢复
- 防止restore覆盖后续合法操作

# 第5步：Evaluator
- 目标区间、收敛时间、稳定时间、超调、振荡、新报警、联锁、能耗等
- 数据质量差时NEEDS_HUMAN

# 第6步：异常检测
- 频繁setpoint、跨资产枚举、控制振荡、状态欺骗、时间戳回退
- 边缘与中央信号关联

# 第7步：阶段认证
- 每阶段独立Gate和证据
- Limited Write仅开放低风险白名单

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 未注册资产/tag与超范围/速率拒绝
- 严重报警/联锁异常禁止commit
- 审批后current value变化拒绝
- 重复写入只一次副作用
- ACK成功但遥测未收敛Evaluator失败
- 网络中断触发Safe State而非继续写

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Industrial Pack
- 资产Schema与策略
- Simulator/Twin场景
- 两阶段Tool
- 补偿/Safe Stop
- 工业Evaluator和阶段证书

# 完成Gate
- 先完成Simulator闭环
- 真实OT写默认关闭
- 所有动作有前置与后置证据
- 物理结果不由Agent自述
- 阶段升级需Release Certificate
- 安全联锁永不由普通Agent修改

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Industrial Pack提供行业资产、动作风险、联锁、补偿和物理Evaluator，建立在Batch16通用Gateway之上。

    ## 依赖分类

    - **contract dependencies**：Batch 20
- **implementation dependencies**：Batch 05, Batch 06, Batch 07, Batch 08, Batch 09, Batch 10, Batch 16, Batch 20, Batch 29
- **runtime integrations**：Batch 21, Batch 22, Batch 28, Batch 33, Batch 34, Batch 36
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 设备/产线/Node/Tag/Register、工程单位、值域、变化率和状态新鲜度。
- 真实写入按Simulator→Twin→Read-only→Shadow→Limited Write分阶段。
- 命令ACK不等于物理成功；必须观察遥测收敛、报警和稳定期。

    ## 新增或强化的模型

    - IndustrialAssetModel
- SetpointPolicy
- InterlockState
- PhysicalCompensation
- TelemetryOutcome
- IndustrialRiskCase

    ## 必须落盘的接口

    - IndustrialAssetRegistry
- IndustrialPolicyPack
- SetpointToolProvider
- PhysicalEvaluator
- SafeRecoveryPlanner

    ## 新增负向测试与故障注入

    - 过期状态、值域/变化率、联锁、报警、振荡、超调、通信丢包、第三方状态改变。
- 补偿不可安全执行时进入Manual Recovery。
- Emergency Stop优先级与证据后补。

    ## v2.0完成Gate

    - 不与Batch16形成依赖环。
- 至少Simulator和Shadow场景通过。
- 每个写动作有前置条件、两阶段提交和结果Evaluator。

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
7. **Next integration**：Batch 25 Energy Pack及工业产品Pilot。
