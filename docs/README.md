# Vanora Relay 文档中心

[← 返回仓库主页](../README.md) · **简体中文** | [English](en/README.md)

欢迎查阅 **Vanora Relay** 官方文档。本目录按**使用角色**与**技术主题**组织，帮助你快速完成节点自建、客户端集成、协议对接与安全评估。

---

## 按场景快速进入

- **我想自己搭一个免账号公网中转节点** → 直接阅读 [服务端部署与运维指南 §3 自建节点](deployment.md#3-自建节点relay_channelself免登录账号)
- **我想把远程互联嵌入桌面客户端，或用一台电脑控另一台电脑** → 阅读 [桌面适配器指南](desktop.md)
- **我在开发 Android / iOS 原生 App** → 阅读 [移动端 SDK 接入指南](mobile.md)
- **我需要用非 Go 语言实现客户端，或调试底层信令 / DataChannel** → 阅读 [协议与自定义客户端参考](protocol.md)
- **我想评估信任边界、安全防护机制，或跑一遍安全回归与靶场** → 阅读 [安全模型与验证指南](security.md)

---

## 核心文档一览

| 文档 | 适用对象 | 主要内容 |
| :--- | :--- | :--- |
| **[服务端部署与运维](deployment.md)** | 运维 / 自建部署者 | 四通道模型对比、完整环境变量矩阵、免账号自建节点（systemd / Caddy / Nginx）、CN/GLOBAL 官方单站隔离、限流与权益校验接口 |
| **[桌面适配器指南](desktop.md)** | 桌面用户 / 宿主集成者 | `vanora-desktop` CLI、Sidecar 双站分槽热切换与 JSONL 指令集、电脑互控（`remote.*` & `ctl`）、完整 `desktop.json` ACL 与审批守卫配置 |
| **[移动端 SDK 接入](mobile.md)** | Android / iOS 开发者 | Android AAR & iOS XCFramework 构建、四通道构造器与安全存储槽位、配对网多电脑并发、Kotlin / iOS 示例与事件游标恢复 |
| **[协议与自定义客户端](protocol.md)** | 协议实现 / 非 Go 开发者 | 官方与自建接入时序图、16 位手输码加密规范、PairNet 成员同步、Ed25519 签名、DataChannel 二进制分片帧与业务 RPC / 错误码 |
| **[安全模型与验证](security.md)** | 安全审计 / 架构评估 | 零信任中转边界、密码学原语、信令与 TURN 纵深防护、严格安全测试（`VANORA_SECURITY_STRICT`）、模糊测试与 Linux 隔离靶场 |

---

## 架构设计与底层模块规范

| 文档 | 语言 | 说明 |
| :--- | :---: | :--- |
| **[架构设计与验收场景](../DESIGN.md)** | 中文 | 整体信任关系、连接切换、断线恢复、撤权行为与端到端联调验收矩阵 |
| **[外部身份签发与验签规范](../internal/identity/README.md)** | English | `vanc1` 设备证书、`vanl1` 活性租约格式，以及外部身份后端 `/v1/identity/*` HTTP 契约 |
| **[STUN / TURN 内核与流量统计](../internal/ice/README.md)** | English | `internal/ice` Grant 生命周期、每连接去重字节计量、对端 IP 过滤规则与全量 `TURN_*` 配置 |
| **[安全测试套件说明](../test/security/README.md)** | 中文 | `test/security/` 目录分布、严格/高负载开关、模糊测试与 WSL2 网络命名空间靶场运行方式 |
