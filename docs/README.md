# 文档目录

[← 返回仓库主页](../README.md)

本目录按使用角色与主题拆分 Vanora Relay 的详细文档：

| 文档 | 适用对象 | 主要内容 |
| --- | --- | --- |
| [服务端部署与权益校验](deployment.md) | 运维 / 自建部署者 | 构建与密钥生成、`relay-identity`（OIDC）配置、`relay`（信令与 STUN/TURN）启动、端口与探针说明、TURN 权益校验 HTTP 接口规范 |
| [桌面适配器指南](desktop.md) | 桌面端用户 / 宿主集成者 | `vanora-desktop` 登录与账号管理、Sidecar 内嵌协议、`desktop.json` 会话/工作区/权限/远程审批配置、服务运行与热更新 |
| [移动端 SDK 接入指南](mobile.md) | Android / iOS 开发者 | Android AAR 与 iOS XCFramework 构建、原生代码接入示例、持久化与单消费者事件循环约定 |
| [协议与自定义客户端参考](protocol.md) | 协议实现 / 非 Go 客户端开发者 | 端点接入时序、Ed25519 签名规范、DataChannel 分片帧格式、业务 RPC、流式事件与错误码 |

## 延伸参考

- [架构设计与验收场景](../DESIGN.md)
- [独立身份服务协议与全部环境变量](../internal/identity/README.md)
- [STUN / TURN 详细配置与流量统计](../internal/ice/README.md)
