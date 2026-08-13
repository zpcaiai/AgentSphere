---
name: agent-trust-industrial-protocol-gateway
description: 实现OPC UA、MQTT、Modbus等工业协议的受控Edge Gateway。用于 Batch 16，把设备身份、Node/Topic/Register和遥测转换为工业IR，执行本地安全Policy、断线缓存、条件写入和云边Trace。不要让中央Agent直接访问PLC或安全仪表系统。
compatibility: 需要Rust、Linux工业网关或模拟环境、OPC UA/MQTT/Modbus测试服务、Batch 06/08/10/11。真实生产接入必须从只读和Shadow Mode开始。
metadata:
  project: agent-trust-control-plane
  batch: "16"
  version: "2.0.0"
---
# Batch 16：工业协议Adapter与Edge Gateway
# 任务
在OT边界建立独立、最小权限、失败安全的协议代理，使所有工业读写具有设备身份、当前状态、值域、变化速率、联锁、审批和执行后遥测验证。
完成本Skill时必须在当前仓库实现真实代码、测试、配置、迁移和文档；不得只输出架构建议、伪代码、空接口或待办清单。先检查现有仓库并增量集成，禁止平行创建第二套同类基础设施。
# 触发条件
- 实现Batch 16
- 接入OPC UA/MQTT/Modbus
- 建设工业边缘Agent Gateway
- 实现设备只读、Shadow或受限写

# 非目标
- 不直接控制SIS/紧急联锁
- 不承诺替代PLC工程软件
- 不在断网时自动扩大权限
- 不将互联网Agent直接放入OT网

# 前置依赖
- Batch 06 PEP
- Batch 08 Tool Proxy
- Batch 10 Evidence
- Batch 11 Adapter SDK
- Batch 24 Industrial Pack

# 强制安全原则
1. 中央Control Plane无PLC直连凭证
2. 设备和节点使用预注册映射
3. 写操作默认禁用并按阶段开启
4. 边缘Policy只能等于或严于中央Policy
5. 断网时高风险写入失败关闭
6. 每次写入有before/after状态与遥测验证

# 建议目录

```text
rust/crates/industrial-edge-core
rust/crates/adapter-opcua
rust/crates/adapter-mqtt
rust/crates/adapter-modbus
schemas/industrial-ir
conformance-tests/industrial-protocols
deploy/edge-gateway
```

# 必须实现的公共接口

```text
IndustrialAdapter.read/prepare_write/commit/verify
AssetRegistry.resolve
LocalPolicy.evaluate
TelemetryBuffer.append/flush
EdgeAuthorization.verify
SafeStop.request
```

# 第1步：资产模型
- 定义site/area/line/asset/channel/node/topic/register
- 记录工程单位、范围、精度、read/write、criticality和freshness

# 第2步：协议适配
- OPC UA安全模式和证书验证
- MQTT topic ACL与QoS语义
- Modbus地址映射、字节序和写功能码限制

# 第3步：边缘身份与授权
- mTLS工作负载身份
- 验证中央签发EdgeAuthorization和ttl
- 本地设备凭证不离开网关

# 第4步：读取和遥测
- 时间戳、质量码、采样率、去重和断线缓存
- 过期/坏质量数据不得作为写入前置状态

# 第5步：两阶段写入
- prepare读取最新状态和联锁→审批/授权→commit compare-and-set→verify
- 值域、变化速率和维护窗口由Pack规则验证

# 第6步：断线与Safe State
- 网络中断停止新高风险动作
- 本地允许明确的安全停止而非任意自治
- 缓存有界并有丢弃策略

# 第7步：部署与加固
- 只读根文件系统、最小端口、证书轮换、时间同步、Watchdog
- 工业PC/ARM资源约束测试

# 数据、错误与可观测要求
- 所有跨服务对象必须带`schema_version`，关键配置和决策带不可变版本或digest。
- 错误使用稳定机器码、trace_id和安全摘要；不得回显Secret、完整输入、内部堆栈或其他租户资源存在性。
- 所有安全关键决策、拒绝、状态转换和人工动作写入Batch 10/19证据链。
- 所有队列、缓存、连接池和后台任务必须有界；超载时拒绝或降级，不无限堆积。
- 生产配置必须失败关闭；任何dev bypass都要求显式profile、醒目标记且CI验证无法进入production构建。

# 必须实现的测试与故障注入
- 未注册设备/Node/Topic/Register拒绝
- 证书无效和协议降级攻击拒绝
- 断网期间写入失败关闭
- 审批后状态变化导致commit拒绝
- Modbus越界/错误字节序/重复写测试
- 边缘Policy配置为更宽松时启动失败

同时至少包含：单元测试、契约测试、并发测试、权限负向测试、重启恢复测试和一条端到端Evidence。对只在Linux/真实协议环境成立的安全性质，必须在Linux CI或专用测试环境验证，不得用Mock结论代替。

# 必须提交的交付物
- Edge Gateway core
- OPC UA/MQTT/Modbus适配器或模拟实现
- Industrial IR/Asset Registry
- 两阶段写入
- 断线缓存和Safe Stop
- 部署加固与Runbook

# 完成Gate
- 真实生产默认只读
- 中央无直连设备凭证
- 所有写入可追踪到Authorization/Approval
- 状态新鲜度和质量受控
- 断线行为有测试证据
- 进入Limited Write前通过Batch 24 Gate

以下情况一律不得标记完成：核心执行路径仍为TODO；只提交接口无实现；关键安全测试被skip；使用Mock声称真实隔离或真实协议通过；无法提供实际运行命令与结果；存在已知高危旁路而未失败关闭。

# v2.0修订与闭环补强

    ## 修订定位

    Batch 16实现协议无关的工业边缘安全Gateway和模拟器，不依赖Batch 24；Batch 24后续注入行业Risk Pack、资产模型和Evaluator。

    ## 依赖分类

    - **contract dependencies**：Batch 01, Batch 03, Batch 05, Batch 06, Batch 11
- **implementation dependencies**：Batch 02, Batch 05, Batch 06, Batch 07, Batch 08, Batch 10, Batch 11
- **runtime integrations**：Batch 18, Batch 21, Batch 24, Batch 29, Batch 34
- **optional integrations**：无

只有`contracts`与`implementation`参与构建拓扑检查；`runtime`和`optional`不得被误写成编译前置条件。

    ## 权威边界与状态所有权

    - 所有真实写操作经过Gateway、PEP、两阶段prepare/commit和状态新鲜度检查。
- 工程单位、质量码、时间戳和资源版本是一等字段。
- 断网时中央Policy租约过期后默认禁止危险写入；Emergency Stop走本地安全规则。

    ## 新增或强化的模型

    - IndustrialResourceRef
- TelemetrySample
- QualityCode
- PreparedIndustrialAction
- EdgePolicyLease
- SafeStopRecord
- ProtocolMapping

    ## 必须落盘的接口

    - IndustrialGateway
- OpcUaAdapter
- MqttAdapter
- ModbusAdapter
- StateFreshnessChecker
- LocalSafetyController

    ## 新增负向测试与故障注入

    - 陈旧状态、单位错配、Node/Register越权、断网、时钟漂移、重复写、边缘策略宽于中央。
- Simulator、真实只读、Shadow和Limited Write阶段逐级Gate。
- 工业Gateway无法直接把ACK当业务完成。

    ## v2.0完成Gate

    - Batch 16独立可用Simulator跑通，不需要Batch 24。
- 真实PLC不暴露给Control Plane。
- 本地安全动作与中央Evidence最终一致。

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
7. **Next integration**：Batch 24 Industrial Risk Pack、Batch 25 Energy Pack。
