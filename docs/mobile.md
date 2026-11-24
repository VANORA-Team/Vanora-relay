# 移动端 SDK 接入指南

[← 文档目录](README.md) · [返回主页](../README.md)

`mobile` 与 `native` 目录提供基于 `gomobile` 的移动端原生绑定（Android AAR / iOS XCFramework），封装了官方分站中转、免账号自建配对中转、局域网免账号配对、WebRTC 传输、事件游标恢复与远程交互审批。

## 连接方式与通道隔离

三种客户端共用同一套会话、运行与事件循环接口，各自使用**独立的安全存储槽位**，互不干扰：

| 通道 | 构造器 | 登录要求 | 存储槽位示例 | 连接方式 |
| --- | --- | --- | --- | --- |
| **CN 官方中转** | `NewClient(cnIdentityURL, cnSignalURL, cnPublicKeyHex, cnStore)` | 必须登录 CN 站 | `"cn"` | `Enroll(cnToken)` -> `Devices()` -> `Connect(deviceID, ownerID)` |
| **GLOBAL 官方中转** | `NewClient(globalIdentityURL, globalSignalURL, globalPublicKeyHex, globalStore)` | 必须登录 GLOBAL 站 | `"global"` | `Enroll(globalToken)` -> `Devices()` -> `Connect(deviceID, ownerID)` |
| **自建中转（`self`）** | `NewSelfRelayClient(selfStore)` | **免登录账号** | `"self"` | `ConnectSelfRelay(link, deviceName)`（或 `ConnectSelfRelayWithToken`） |
| **局域网直连（`lan`）** | `NewLANClient(lanStore)` | **免登录账号** | `"lan"` | `ConnectLAN(link, deviceName)` |

### 关键约束

- **官方双站严格隔离**：CN 站与 GLOBAL 站使用独立的身份公钥与信令节点，且中继权益互不共享。宿主 App 只有在用户已登录 CN 站时才允许初始化并连接 CN `Client`，只有在已登录 GLOBAL 站时才允许连接 GLOBAL `Client`。用户同时登录两站时，可各自持有独立 `Store` 槽位按需切换，切勿共用同一存储槽（否则不同身份公钥会返回 `account: stored state belongs to another authority`）。
- **自建中转仅通过配对使用（免账号）**：使用 `NewSelfRelayClient(store)`，不调用 `Enroll`/`UpdateToken`/`Devices`。扫描或粘贴桌面端生成的自建配对链接后调用 `ConnectSelfRelay(link, deviceName)`（若配对链接未内嵌节点令牌，改用 `ConnectSelfRelayWithToken(link, relayToken, deviceName)`）。连接成功后持久化 `SelfRelayTarget()` 返回的脱敏链接（已移除一次性 `pair` 令牌）用于下次自动复连。被桌面撤权或未配对时收到 `access.state` / `pairing_required`，节点令牌失效时收到 `access.state` / `relay_token_invalid`。
- **局域网配对**：使用 `NewLANClient(store)` 与 `ConnectLAN(link, deviceName)`，成功后保存 `LANAddress()`。`connection.state` 的路径为 `lan`，撤权时收到 `access.state` / `pairing_required`。退出官方账号后可继续保留自建与局域网客户端及其配对记录。

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

// --- 方式 A：官方分站（以 CN / GLOBAL 独立槽位为例）---
val cnStore = org.vanora.relay.AndroidAccountStore(applicationContext, "cn")
val cnClient = mobile.Mobile.newClient(cnIdentityUrl, cnSignalUrl, cnPinnedPublicKeyHex, cnStore)
cnClient.enroll(cnHostAccessToken) // 仅传入 CN 站登录令牌
cnClient.updateToken(refreshedCnAccessToken)

val directory = cnClient.devices() // JSON 包含已验证的 device_id、owner、name
cnClient.connect(selectedDeviceID, selectedOwnerID)
val connState = cnClient.connectionState() // state + direct/relay path

// --- 方式 B：自建中转（免登录账号，仅配对使用）---
val selfStore = org.vanora.relay.AndroidAccountStore(applicationContext, "self")
val selfClient = mobile.Mobile.newSelfRelayClient(selfStore)
selfClient.connectSelfRelay(scannedPairingLink, "Pixel 9")
val savedReconnectTarget = selfClient.selfRelayTarget() // 已去除一次性 pair 令牌

// --- 通用会话与远程审批接口（官方 / 自建 / 局域网一致）---
val workspaces = selfClient.listWorkspaces()
val created = selfClient.createSession(selectedWorkspaceID, mobile.Mobile.newRequestID(), "新对话")
val sessions = selfClient.listSessions()
val snapshot = selfClient.openSession(selectedSessionID)
selfClient.respondUI(selectedSessionID, runID, uiID, """{"confirmed":true}""")
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
3. 官方分站按站点创建独立 `VanoraAccountStore(profile: "cn")` / `VanoraAccountStore(profile: "global")` 传入 `MobileNewClient`；自建中转使用独立 `VanoraAccountStore(profile: "self")` 传入 `MobileNewSelfRelayClient`，通过 `connectSelfRelay:clientName:error:` 完成扫码配对并持久化 `selfRelayTarget`。

## 客户端持久化与事件循环约定

- **幂等提交提示词**：调用 `startRun(sessionID, requestID, text)` 前，先持久化 `Mobile.newRequestID()` 与提示词正文；网络中断后重试必须复用两者。
- **单消费者事件循环**：`nextEvent(timeoutMillis)` 仅允许一个消费者读取；除业务 `event`（带 `seq`）外，还会推送 `connection.state`（`connecting`/`connected`/`reconnecting`/`disconnected` 与 `direct`/`relay`/`lan` 路径）、`auth.state`（`login_required`，官方渠道）、`access.state`（`pairing_required` 或 `relay_token_invalid`，局域网与自建渠道）和 `subscription.error`。每应用一条带 `seq` 的业务事件并保存本地快照后，调用 `acknowledge(sessionID, seq)` 更新游标。
- **令牌刷新与恢复（官方渠道）**：收到 `auth.state`（`login_required`）或宿主 App 刷新了对应站点的用户令牌时，调用该站客户端的 `updateToken(newToken)` 即可触发设备证书续期与后台重连；切换同站账号或注销时调用 `reset()` 安全重置本地设备密钥。
- **网络切换**：切网或从后台恢复时可调用 `reconnect()` 主动重连并续订游标。
- **进程重启恢复**：官方渠道使用本地保存的 `device_id` 与 `owner` 重新 `connect`；自建渠道用 `SelfRelayTarget()` 重新 `ConnectSelfRelay`；局域网用 `LANAddress()` 重新 `ConnectLAN`；随后调用 `resume(sessionID, lastAppliedSeq)` 续读事件。
- **快照重建**：收到 `snapshot_required` 时，调用 `openSession(sessionID)` 重新拉取完整快照。
- **退出清理**：切换或退出账号配置档时，务必关闭 `client`。
