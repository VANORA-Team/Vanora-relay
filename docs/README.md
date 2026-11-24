# 文档目录

[← 返回仓库主页](../README.md)

本目录按使用角色与主题拆分 Vanora Relay 的详细文档：

| 文档 | 适用对象 | 主要内容 |
| --- | --- | --- |
| [服务端部署与权益校验](deployment.md) | 运维 / 自建部署者 | CN / GLOBAL 单站隔离部署、`RELAY_ALLOWED_ISSUER`、单站 TURN 权益接口、以及零外部依赖的免账号自建节点（`RELAY_CHANNEL=self`）部署步骤 |
| [桌面适配器指南](desktop.md) | 桌面端用户 / 宿主集成者 | `vanora-desktop` 双站分槽凭据管理、Sidecar 渠道热切换（`cn` / `global` / `self` + 并发 `lan`）、自建配对指令与 `desktop.json`（含 `lan_access` / `self_access`）配置 |
| [移动端 SDK 接入指南](mobile.md) | Android / iOS 开发者 | Android AAR 与 iOS XCFramework 构建、CN / GLOBAL 独立槽位接入、免账号自建配对（`NewSelfRelayClient`）、令牌刷新与单消费者事件循环约定 |
| [协议与自定义客户端参考](protocol.md) | 协议实现 / 非 Go 客户端开发者 | 官方渠道端点接入时序、自建免账号配对与 HMAC 证明协议、Ed25519 签名规范、DataChannel 分片帧格式、业务 RPC 与错误码 |

## 延伸参考

- [架构设计与验收场景](../DESIGN.md)
- [外部身份签发协议与验签规范](../internal/identity/README.md)
- [STUN / TURN 详细配置与流量统计](../internal/ice/README.md)
