# 移动端 SDK 接入指南

[← 文档目录](README.md) · [返回主页](../README.md)

`mobile` 与 `native` 目录提供基于 `gomobile` 的移动端原生绑定（Android AAR / iOS XCFramework），封装了 OIDC 登录、签名信令、WebRTC 传输、事件游标恢复与远程交互审批。

## Android

**环境依赖**：JDK、Go、Python 3、Android SDK（设置 `ANDROID_HOME`）及 NDK（可选设置 `ANDROID_NDK_HOME`）。

在仓库根目录执行构建：

```sh
python native/android/build.py
```

输出 `dist/vanora-mobile.aar`（最低 API 23，包含 `arm64-v8a` 与 `x86_64`）：

1. 将 AAR 放入应用模块的 `libs/`，在 Gradle 中添加 `implementation(files("libs/vanora-mobile.aar"))`。
2. 在 `AndroidManifest.xml` 中声明 `android.permission.INTERNET`，并注册与 OIDC 提供方一致的回调 URI。
3. 所有阻塞式 SDK 方法须在工作线程中调用。

```kotlin
go.Seq.setContext(applicationContext)
val store = org.vanora.relay.AndroidAccountStore(applicationContext, "primary")
val client = mobile.Mobile.newClient(identityUrl, signalUrl, pinnedPublicKeyHex, store)

// 1. 在系统浏览器打开登录地址，回调中提取 code 与 state
val loginUrl = client.beginLoginWithRedirect("com.vanora.app:/oauth/callback")
client.finishLogin(code, state)

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
3. 以 `VanoraAccountStore` 作为 `MobileNewClient` 的 `store`，通过系统浏览器会话回调传入 `code` 与 `state`。

## 客户端持久化与事件循环约定

- **幂等提交提示词**：调用 `startRun(sessionID, requestID, text)` 前，先持久化 `Mobile.newRequestID()` 与提示词正文；网络中断后重试必须复用两者。
- **单消费者事件循环**：`nextEvent(timeoutMillis)` 仅允许一个消费者读取；除业务 `event`（带 `seq`）外，还会推送 `connection.state`（`connecting`/`connected`/`reconnecting`/`disconnected` 与 `direct`/`relay` 路径）、`auth.state`（`login_required`）和 `subscription.error`。每应用一条带 `seq` 的业务事件并保存本地快照后，调用 `acknowledge(sessionID, seq)` 更新游标。
- **网络切换与账号重置**：切网或从后台恢复时可调用 `reconnect()` 主动重连并续订游标；切换账号或注销时调用 `reset()` 安全重置本地设备密钥。
- **进程重启恢复**：使用本地保存的 `device_id` 与 `owner` 重新 `connect`，再调用 `resume(sessionID, lastAppliedSeq)` 续读事件。
- **快照重建**：收到 `snapshot_required` 时，调用 `openSession(sessionID)` 重新拉取完整快照。
- **退出清理**：切换或退出账号配置档时，务必关闭 `client`。
