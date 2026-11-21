# Vanora Relay

原生手机 App 通过 WebRTC 连接电脑上的 Vanora。`relay` 提供设备发现、签名信令、STUN 和按会员权益授权的 TURN。`relay-identity` 独立运行，消费外部 OpenID Connect 服务，为端点公钥签发短期证书。模型 API Key 无需进入这两个进程。

## 启动

需要 Go 1.25 或更高版本。两个命令可分别部署。首次生成密钥时，把私钥保存到独立身份服务主机，只分发公钥给 relay 和端点。以下为 Bash 示例。

```sh
go build ./cmd/...
go run ./cmd/relay-identity keygen -out identity-signing-key -public-out identity-signing-key.pub
```

Vanora 的独立 OAuth 系统使用 Keycloak。将 `VANORA_IDENTITY_OIDC_ISSUER` 设为会员后端 `VANORA_OIDC_ISSUER` 使用的完整 realm URL。在同一 realm 单独注册原生应用 client，启用 Standard Flow 和 PKCE S256，登记精确回调地址，并允许 `openid offline_access`。端点在系统浏览器里登录。电脑无人值守续期要求 refresh grant 返回可验证的 ID token。

```sh
export VANORA_IDENTITY_SIGNING_KEY_FILE=identity-signing-key
export VANORA_IDENTITY_OIDC_ISSUER=https://auth.example.com/realms/vanora
export VANORA_IDENTITY_OIDC_CLIENT_ID=vanora-native
export VANORA_IDENTITY_OIDC_REDIRECT_URI=com.vanora.app:/oauth/callback
go run ./cmd/relay-identity serve
```

在信令主机提供 `RELAY_MEMBERSHIP_TOKEN`，与 Vanora_web 后端的 `RELAY_SERVICE_TOKEN` 使用同一个随机服务密钥（至少 32 字节）。`RELAY_MEMBERSHIP_URL` 需指向能访问内部权益路由的 HTTPS 后端，也支持本机回环 HTTP。Vanora_web 默认云网关只代理公共路径，跨主机部署时需为该内部路由配置私有 HTTPS 入口。`TURN_PUBLIC_IP` 填本机或 NAT 对外公布的可达 IPv4。开发时可用 `127.0.0.1`。

```sh
export RELAY_IDENTITY_PUBLIC_KEY="$(cat identity-signing-key.pub)"
export RELAY_MEMBERSHIP_URL=https://membership.internal.example.com
export TURN_PUBLIC_IP=127.0.0.1
go run ./cmd/relay
```

| 服务 | 默认监听 | 部署要求 |
| --- | --- | --- |
| 信令 | `127.0.0.1:8787` | 代理 HTTPS 和 WebSocket 升级到 `/v1/signal`，或设置 `RELAY_ADDR`、`RELAY_TLS_CERT`、`RELAY_TLS_KEY` 直接监听 TLS。`GET /healthz` 为进程探针 |
| 身份 | `127.0.0.1:8090` | 使用独立发布权限与 TLS。`GET /readyz` 检查外部 IdP discovery 和 JWKS 可用性。客户端通过 HTTPS 调用 `/v1/identity/*` |
| STUN / TURN | `0.0.0.0:3478` UDP、TCP | 开放 `TURN_PORT` 对应的控制端口与 `TURN_RELAY_MIN_PORT` 至 `TURN_RELAY_MAX_PORT` 的 UDP 转发端口，默认 `49152–65535`。NAT 须保持公告端口映射。可分别设置 `TURN_BIND_IP` 和 `TURN_RELAY_BIND_IP` |

首版单实例、单区域。重启信令或 TURN 后端点重新上线并协商。访问者中继字节数随 grant 结束写入服务日志，部署时收集日志以保留历史。中继权益到期或撤权会关闭活跃 relay socket。公网部署默认过滤私网和回环目标。TURN 支持 UDP、TCP 控制传输和 UDP relay；只放行 HTTPS 的网络仍可能连不上。

## 接入 Vanora_web

配套后端提供 `POST /internal/v1/relay/entitlement`。在 **Vanora_web API** 配置 `RELAY_SERVICE_TOKEN`。启用会员站的第一方 OIDC 配置后，权益查询按该 Keycloak realm 已有的 `(issuer, subject)` 账号绑定查找会员。缺少绑定或本地账号停用时拒绝中继。手机和会员站应收到同一账号的相同 `sub`，部署时用同一测试账号验证两个 client 的声明。其他身份提供者可通过 `RELAY_ISSUER_PROVIDERS` 把精确 issuer 映射到已绑定账号的 OAuth provider 名称或 slug。会员管理员需要在目标套餐上启用 `relay_allowed`，旧套餐迁移时默认关闭。

信令使用服务 bearer 和 `{ "issuer": "…", "subject": "…" }` 查询**发起访问的手机账号**。返回 `data.relay_allowed` 和 `data.valid_until`（Unix 秒）。只有有效权益才发 TURN 凭证，接口超时、拒绝或无绑定都降级为 STUN。单个连接的 TURN 授权还受端点证书有效期约束。会员系统没有端点签名私钥。

## 原生端点接入顺序

1. 在系统密钥存储生成并保留 Ed25519 端点密钥。按身份协议走 `/challenges`、`/enroll`，取得证书；用 `/lease` 取得最长 60 秒的签名租约。无人值守续期走 `/renew`，原子替换返回的刷新句柄。端点内置独立发布的身份公钥。[身份协议与配置](internal/identity/README.md)
2. 打开 `wss://<relay>/v1/signal`。收到 `auth.challenge` 后用 `endpoint.OpenCredentials`、`Credentials.Login` 签名响应。收到 `auth.ok` 后，电脑调用 `Credentials.Online(name, guests)` 发布签名设备卡及本机允许访问的远程账号列表。收到 `device.registered` 即上线。权限变更马上更新本机 ACL 并重新发布完整列表。
3. 手机发 `{"type":"devices.list"}`。`data` 为签名设备卡数组。用 `endpoint.VerifyDevice` 验证名称、设备 ID 和所属账号，展示可辨认的所有者。手机应按预期所有者选机，复连时使用已保存的设备 ID 与 owner。对初次邀请，主人账号须来自已验证的邀请或用户独立选择的身份；任意信令目录都能隐藏条目或展示攻击者自己的真实设备。
4. 手机以 `Credentials.Request(deviceID, owner)` 请求连接。电脑用 `Credentials.Accept` 核验签名并再次检查本机 ACL。手机用 `Session.Accepted` 校验设备与新鲜连接随机数。任何一方被撤权或失联时，信令回送 `connect.closed`。错误事件为 `error`，其 `data` 为错误码。
5. `ice.config.data` 是标准 `RTCIceServer[]`。两端同时收集服务器允许的候选，使用常规 ICE 优先级优先直连。有权限时允许中继先连通。移动网络切换时可以 ICE restart，保留业务会话 ID。实际切换时机由端点 WebRTC 栈决定。手机可发送 `ice.refresh` 加 `connection_id` 重新核验套餐与更新 grant，两次至少间隔 10 秒；建议每 30 秒及证书更新后刷新。
6. 手机发 `rtc.offer`，电脑回 `rtc.answer`，双方可发 `rtc.candidate`。将 SDP 描述或 candidate JSON 交给 `Session.Seal`，接收方用 `Session.Open` 取得已验证的原文，之后才能调用 WebRTC 的远端描述或候选 API。连接 ID、端点身份、轮次、序号和电脑随机数共同绑定协商。单个连接的信令回调须串行处理。WebRTC DataChannel 使用可靠有序模式。[可运行的两端示例](internal/signal/integration_test.go)
7. 在证书和租约到期前，向信令发 `auth.lease`，`data` 包含 `lease`，更新证书时同传 `certificate`。两端另在已验证的 DataChannel 内交换 `endpoint.LeaseProof`，通过 `Session.Access().Update` 验证自己直接取得的租约及对端租约。第一份证明核验完成前禁止业务消息。电脑检测到身份服务失联，立即调用 `AuthorityLost()`；新会话或带工具的访问使用 `Allows(now, true, resourceGranted)`，既有只读访问使用 `Allows(now, false, resourceGranted)`。每次调用、输出投递及授权截止时都执行检查。手机失联期间暂停交付远程输出，电脑按本地任务授权继续处理，重连后重新核验。

非 Go 客户端按 `protocol/wire.go` 实现 Ed25519 签名。签名输入为 UTF-8 的八个字段，以 LF 连接，无尾换行：`vanora-relay/v1`、`type`、`connection_id`、`from`、`to`、十进制 `round`、十进制 `seq`、无填充 base64url 的 `body`。缺省数字写 `0`。`proof` 为无填充 base64url 的 Ed25519 签名。证书和签名设备卡的具体解析规则见 [端点代码](endpoint/session.go) 和 [设备发现](endpoint/discovery.go)。

## 电脑端业务边界

AI 正文在 DataChannel 和本机 Vanora 之间流转。`vanora-desktop` 启动本机 Vanora RPC 进程，按对话过滤请求和事件。手机断线时，已启动的任务继续运行。重新连接后，手机可以按事件序号续读，重发同一请求键也能取得原来的运行编号。桌面机上删除访客权限会取消该访客受影响的运行。[产品设计和验收场景](DESIGN.md)

DataChannel 标签为 `vanora`。首帧是 `{ "certificate", "lease" }` 证明，续租时重复该帧。业务层使用 UTF-8 JSON。传输层直接发送不超过 16 KiB 的消息，更大的消息通过有序二进制分片传送，每个分片包含 `00 56 4e 46`、三个大端 uint32（消息编号、从零开始的分片索引、总片数）和有效载荷。单条业务消息上限为 64 MiB。手机请求携带 `type`、`request_id` 和该操作的字段。电脑响应携带相同的 `request_id`，`type` 为 `result` 或 `error`，分别返回 `data` 或 `code`。访问者身份取自已验证的连接。

| 请求 | 请求字段 | 成功返回的 `data` |
| --- | --- | --- |
| `session.list` | 无 | `sessions` 数组，每项含 `session_id`、`title`、访问者能否提交提示词的 `can_run_tools`、会话是否启用本地工具的 `tools_enabled` |
| `session.open` | `session_id` | 当前可见的 `messages` 快照与 `last_seq`，两者对应同一时点 |
| `run.start` | `session_id`、`text` | `run_id`。在请求历史保留期内，重发相同 `request_id` 和正文返回原运行编号，正文不同则返回 `request_conflict`。每个会话默认保留最近 4096 条请求 |
| `run.cancel` | `session_id`、`run_id` | `run_id`、`status`。验证运行属于指定会话，且访问者有取消权限 |
| `events.resume` | `session_id`、`after_seq` | `session_id`、`after_seq`。随后发送 `seq > after_seq` 的事件并接续实时流。游标超出保留范围时返回 `snapshot_required`，手机重新 `session.open` |

例如，手机发送 `{"type":"run.start","request_id":"q7","session_id":"s2","text":"解释这次修改"}`，电脑返回 `{"type":"result","request_id":"q7","data":{"run_id":"r5"}}`。流式输出示例为 `{"type":"event","session_id":"s2","run_id":"r5","seq":18,"kind":"text.delta","data":{"text":"修改了"}}`。`seq` 是会话级递增整数，手机记录最后已应用的序号。`run.completed`、`run.cancelled` 或 `run.failed` 标志运行结束。不可见资源和未知资源统一返回 `unavailable`，工具权限不足返回 `tool_denied`。

## 运行桌面适配器

```sh
go build -o vanora-desktop ./cmd/vanora-desktop
./vanora-desktop login -identity https://identity.example.com -ca identity-signing-key.pub
./vanora-desktop serve -identity https://identity.example.com -ca identity-signing-key.pub -signal wss://relay.example.com/v1/signal -config desktop.json -name Office
```

Windows 可将输出名设为 `vanora-desktop.exe`。`login` 用系统浏览器打开独立 OAuth 服务，完成后输出 `user_id` 和 `device_id`。使用已注册的回环 HTTP 回调时，程序自动接收 `code` 和 `state`。使用自定义 URI 时，桌面命令可读取用户粘贴的完整回调地址。`-state-dir` 指定配置档目录，默认使用当前用户配置目录下的 `Vanora/relay`。身份密钥由系统凭据库保护。`serve` 需要以能访问该凭据库和项目的同一桌面用户身份运行。

在本地 Vanora 中先创建会话。将下面示例中的路径替换为实际绝对路径，`owner` 填登录输出的 `user_id`，`working_dir` 与会话 JSONL 首行中的 `cwd` 一致。使用本机 Vanora 可执行文件时，可直接填入 `executable` 并省略 `launcher_args`。

```json
{
  "executable": "node",
  "launcher_args": ["C:/apps/vanora/packages/coding-agent/dist/cli.js"],
  "sessions": [{
    "id": "project", "title": "项目对话",
    "working_dir": "C:/work/project",
    "session_file": "C:/work/sessions/project.jsonl",
    "owner": "本机登录输出的 user_id",
    "tools": [],
    "users": [{"user_id": "访客手机登录后的 user_id", "read": true, "tools": false}]
  }]
}
```

同账号手机使用主人权限。`users` 中只读访客可看历史和输出，`tools: true` 允许该访客提交提示词。会话级 `tools` 列表决定本机 Vanora 实际启用的工具，空数组运行纯文本对话。`serve` 每秒检查一次配置变更，配置解析失败时关闭服务。请原子替换配置文件。模型凭据沿用桌面用户的 Vanora 配置。

## 接入手机应用

Android 使用 JDK、Go、Python 3 及 Android SDK/NDK，在仓库根目录运行 `python native/android/build.py`。通过 `ANDROID_HOME` 指定 SDK，可通过 `ANDROID_NDK_HOME` 选择 NDK。将生成的 `dist/vanora-mobile.aar` 放入应用的 `libs/` 并添加 `implementation(files("libs/vanora-mobile.aar"))`。最低 API 23，包含 arm64-v8a 和 x86_64。宿主在 manifest 声明 `android.permission.INTERNET`，注册与 IdP 配置一致的回调，并在工作线程执行阻塞的 SDK 方法。

```kotlin
go.Seq.setContext(applicationContext)
val store = org.vanora.relay.AndroidAccountStore(applicationContext, "primary")
val client = mobile.Mobile.newClient(identityUrl, signalUrl, pinnedPublicKeyHex, store)
val loginUrl = client.beginLogin() // 在系统浏览器打开
// 回调处理程序提取 code 与 state
client.finishLogin(code, state)
val directory = client.devices() // JSON 中包含已验证的 device_id、owner、name
client.connect(selectedDeviceID, selectedOwnerID)
val sessions = client.listSessions()
val snapshot = client.openSession(selectedSessionID)
```

iOS 可在安装 Xcode 的 macOS 上运行 `go install golang.org/x/mobile/cmd/gobind`，把 `$(go env GOPATH)/bin` 加入 `PATH`，再运行 `mkdir -p dist && go tool gomobile bind -target=ios,iossimulator -o dist/Mobile.xcframework ./mobile`。将 framework 和 `native/ios/VanoraAccountStore.h`、`.m` 加入 App target，启用 ARC，链接 Security.framework。用 `VanoraAccountStore` 作为 `MobileNewClient` 的 store，通过系统浏览器会话传回 `code` 和 `state`。

发送前将 `Mobile.newRequestID()` 与提示词持久化，再调用 `startRun(sessionID, requestID, text)`。网络中断后重试同一条提示词须复用这两项。`nextEvent(timeoutMillis)` 只使用一个消费者；每次应用事件并保存快照后调用 `acknowledge(sessionID, seq)`。进程重启后用保存的设备与主人 ID 重新连接，调用 `resume(sessionID, lastAppliedSeq)`。收到 `snapshot_required` 后用 `openSession` 重建快照。退出账号配置档时关闭 `client`。

## 验证

```sh
go test ./...
```

信令集成测试让两个 WebRTC 端点经过真实 WebSocket 完成设备发现、访客授权与签名协商。两个场景分别强制使用会员 TURN 和免费直连，检查最终选中的候选对，在加密 DataChannel 上验证双方租约、发送手机请求和电脑回复，并覆盖签名篡改、重放与撤权。身份测试用测试 IdP 覆盖注册与续期。TURN 测试创建真实 allocation，检查流量和终止时机。公网 NAT 兼容性需要部署到可达节点后用实际手机及家庭网络验收。

`go test ./mobile` 覆盖两个适配器之间的 WebSocket、WebRTC 和会话权限。将 `VANORA_TEST_CLI` 设置为已构建的 Vanora `packages/coding-agent/dist/cli.js` 绝对路径，再运行 `go test ./mobile -run TestUpstreamVanoraRunAfterNetworkLoss -count=1`，可验证真实 CLI 在手机断线后继续处理提示词、补发事件以及重复请求去重。测试的模型响应来自本机 HTTP 测试服务。
