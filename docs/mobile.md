# 移动端 SDK 接入指南

[← 文档目录](README.md) · [返回主页](../README.md)

`mobile` 与 `native` 目录提供基于 `gomobile` 的移动端原生绑定（Android AAR / iOS XCFramework），封装了基于宿主客户端令牌的设备注册、签名信令、WebRTC 传输、事件游标恢复与远程交互审批。

## 连接方式

- **局域网，免账号。** 用独立的安全存储创建 `NewLANClient(store)`，扫描或粘贴桌面邀请后调用 `ConnectLAN(link, deviceName)`。连接成功后保存 `LANAddress()` 返回的地址，重新启动时可用它连接同一台桌面。SDK 移除邀请密钥，并在后续连接中核验已配对的桌面公钥。`connection.state` 的路径为 `lan`。收到 `access.state` / `pairing_required` 时，提示用户重新配对。
- **官方中继，使用 Vanora 账号。** 用 `NewClient(identityURL, signalURL, pinnedPublicKeyHex, store)` 并传入宿主账号令牌。SDK 继续使用签名信令和 WebRTC，由访问者的权益决定是否可用 TURN。

两种客户端共用会话和事件接口。局域网客户端使用独立于官方账号的安全存储槽。宿主退出官方账号后可保留局域网客户端与其配对记录。

### 中转渠道选择（cn / global / 自建）

SDK 不提供渠道枚举：一个渠道由 `identityURL` + `signalURL` + 固定的身份公钥确定，宿主按用户选择传入 `NewClient`：

| 渠道 | `identityURL` | `signalURL` | TURN 权益 |
| --- | --- | --- | --- |
| `cn` | CN 站身份后端 | CN 站官方中转 | 按账号登录站校验 |
| `global` | GLOBAL 站身份后端 | GLOBAL 站官方中转 | 按账号登录站校验 |
| 自建 | 用户接入的身份后端 | 用户自建 `relay`（`RELAY_CHANNEL=self`） | 不校验 |

- **跨站账号**：CN 站账号可以使用 GLOBAL 官方中转，反之亦然。节点并行查询已配置站点的权益服务，账号只在其登录站存在，因此实际按登录站放行；只有登录站没有有效权益时才降级为仅直连，`connectionState()` 的路径显示为 `direct` 而非 `relay`。
- **切换渠道**：用目标渠道的地址和公钥创建新的 `Client`，并为每个渠道使用独立的 `Store` 槽位（Android `AndroidAccountStore(context, "<channel>")`，iOS `VanoraAccountStore(profile:)`）。设备状态绑定身份后端公钥；身份根不同却复用同一槽位时，`NewClient` 会返回 `account: stored state belongs to another authority`。`reset()` 只会在原身份根下重置，不能把槽位改绑到另一个身份根，因此不要共用槽位。
- **令牌来源一致**：`enroll(hostAccessToken)` / `updateToken` 传入的必须是该渠道对应站点的登录令牌，身份后端才会为该渠道签发设备证书。
- **自建渠道**：用户需自行部署 `relay` 并提供 `wss://<host>/v1/signal`、身份后端地址及其公钥；节点不校验会员权益，但仍要求有效的设备证书。

## Android

**环境依赖**：JDK、Go、Python 3、Android SDK（设置 `ANDROID_HOME`）及 NDK（可选设置 `ANDROID_NDK_HOME`）。

在仓库根目录执行构建：

```sh
python native/android/build.py
```

输出 `dist/vanora-mobile.aar`（最低 API 23，包含 `arm64-v8a` 与 `x86_64`）：

1. 将 AAR 放入应用模块的 `libs/`，在 Gradle 中添加 `implementation(files("libs/vanora-mobile.aar"))`。
2. 在 `AndroidManifest.xml` 中声明 `android.permission.INTERNET`。
3. 所有阻塞式 SDK 方法须在工作线程中调用。

```kotlin
go.Seq.setContext(applicationContext)
val store = org.vanora.relay.AndroidAccountStore(applicationContext, "primary")
val client = mobile.Mobile.newClient(identityUrl, signalUrl, pinnedPublicKeyHex, store)

// 1. 直接复用宿主手机 App 已有的认证令牌完成设备注册
client.enroll(hostAccessToken)

// 宿主刷新登录令牌后通知 SDK 无感续期设备证书
client.updateToken(refreshedHostAccessToken)

// 2. 获取已验证的设备目录并连接目标桌面端
val directory = client.devices() // JSON 包含已验证的 device_id、owner、name
client.connect(selectedDeviceID, selectedOwnerID)
val connState = client.connectionState() // state + direct/relay path

// 3. 列出工作区/会话，按需新建会话并拉取快照
val workspaces = client.listWorkspaces()
val created = client.createSession(selectedWorkspaceID, mobile.Mobile.newRequestID(), "新对话")
val sessions = client.listSessions()
val snapshot = client.openSession(selectedSessionID)

// 4. 响应远程工具审批或 ask 提问弹窗
client.respondUI(selectedSessionID, runID, uiID, """{"confirmed":true}""")
```

## iOS

在已安装 Xcode 的 macOS 上执行：

```sh
go install golang.org/x/mobile/cmd/gobind
export PATH="$(go env GOPATH)/bin:$PATH"
mkdir -p dist
go tool gomobile bind -target=ios,iossimulator -o dist/Mobile.xcframework ./mobile
```

1. 将 `dist/Mobile.xcframework` 以及 [VanoraAccountStore.h](../native/ios/VanoraAccountStore.h)、[VanoraAccountStore.m](../native/ios/VanoraAccountStore.m) 加入 App Target。
2. 启用 ARC，并链接 `Security.framework`。
3. 以 `VanoraAccountStore` 作为 `MobileNewClient` 的 `store`，调用 `enroll:` 传入宿主客户端当前认证令牌，并在宿主刷新令牌后调用 `updateToken:`。

## 客户端持久化与事件循环约定

- **幂等提交提示词**：调用 `startRun(sessionID, requestID, text)` 前，先持久化 `Mobile.newRequestID()` 与提示词正文；网络中断后重试必须复用两者。
- **单消费者事件循环**：`nextEvent(timeoutMillis)` 仅允许一个消费者读取；除业务 `event`（带 `seq`）外，还会推送 `connection.state`（`connecting`/`connected`/`reconnecting`/`disconnected` 与 `direct`/`relay` 路径）、`auth.state`（`login_required`）和 `subscription.error`。每应用一条带 `seq` 的业务事件并保存本地快照后，调用 `acknowledge(sessionID, seq)` 更新游标。
- **令牌刷新与恢复**：收到 `auth.state`（`login_required`）或宿主 App 刷新了用户令牌时，调用 `updateToken(newToken)` 即可触发设备证书续期与后台重连；切换账号或注销时调用 `reset()` 安全重置本地设备密钥。
- **网络切换**：切网或从后台恢复时可调用 `reconnect()` 主动重连并续订游标。
- **进程重启恢复**：使用本地保存的 `device_id` 与 `owner` 重新 `connect`，再调用 `resume(sessionID, lastAppliedSeq)` 续读事件。
- **快照重建**：收到 `snapshot_required` 时，调用 `openSession(sessionID)` 重新拉取完整快照。
- **退出清理**：切换或退出账号配置档时，务必关闭 `client`。
