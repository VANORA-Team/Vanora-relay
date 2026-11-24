# 协议与自定义客户端参考

[← 文档目录](README.md) · [返回主页](../README.md)

Go 项目可直接复用本仓库的 `endpoint` 与 `adapter/transport` 包；编写其他语言客户端时请参照下方规范。可运行的端到端参考实现见 [internal/signal/integration_test.go](../internal/signal/integration_test.go)，完整架构设计见 [DESIGN.md](../DESIGN.md)。

## 1. 官方渠道端点接入顺序（`cn` / `global`）

官方 `cn` 与 `global` 站点各自使用独立的外部身份后端与 Ed25519 信任根（可选叠加 `RELAY_ALLOWED_ISSUER` 校验），跨站证书会在 `auth.login` 阶段被直接拒绝。

1. **密钥与凭证**：在系统密钥存储按站点分槽生成并保留 Ed25519 私钥，内置对应站点的外部身份后端公钥。按 [外部身份协议](../internal/identity/README.md) 使用宿主客户端对应站点的认证令牌调用 `/challenges`、`/enroll` 取得短期证书，调用 `/lease` 取得最长 60 秒的签名租约；续期调用 `/renew`（支持直接携带宿主实时令牌或可选刷新句柄）。
2. **信令认证与电脑上线**：连接 `wss://<relay>/v1/signal`。收到 `auth.challenge` 后以 `endpoint.OpenCredentials` 与 `Credentials.Login` 签名响应；收到 `auth.ok` 后，电脑调用 `Credentials.Online(name, guests)` 发布签名设备卡及允许访问的远程账号列表，收到 `device.registered` 即上线。权限变更时须立即更新本机 ACL 并重新发布完整列表。
3. **设备发现与可信选机**：手机发送 `{"type":"devices.list"}` 取得签名设备卡数组，通过 `endpoint.VerifyDevice` 校验名称、设备 ID 与所属账号并展示可辨认的所有者。复连时须使用已保存的 `device_id` 与 `owner`；初次接受分享时，主人账号须来自可信邀请或用户独立选择（任意信令目录都可能隐藏条目或展示攻击者自己的真实设备）。
4. **发起与接受连接**：手机以 `Credentials.Request(deviceID, owner)` 请求连接；电脑以 `Credentials.Accept` 验签并再次核查本机 ACL；手机以 `Session.Accepted` 校验对端设备与新鲜连接随机数。任一方被撤权或失联时信令回送 `connect.closed`；协议错误事件为 `error`，`data` 为错误码。
5. **ICE 选路与刷新**：`ice.config.data` 为标准 `RTCIceServer[]`。两端并行收集候选并按常规 ICE 优先级优先直连，有本站点中继权益时允许中继先行连通。移动网络切换可触发 ICE restart 并保留业务会话 ID（切换时机由端点 WebRTC 栈决定）。手机可发送 `ice.refresh`（附 `connection_id`）重新核验权益并刷新 grant，两次至少间隔 **10 秒**，建议每 **30 秒**及证书更新后刷新。
6. **签名 WebRTC 协商**：手机发送 `rtc.offer`，电脑回复 `rtc.answer`，双方互发 `rtc.candidate`。发送前须经 `Session.Seal` 签名，接收方须经 `Session.Open` 验签取得原文后再交给 WebRTC API。连接 ID、端点身份、轮次、序号与电脑随机数共同绑定本次协商。**单个连接的信令回调须串行处理**。DataChannel 使用可靠有序模式。
7. **租约续期与访问控制**：
   - 证书或租约到期前向信令发送 `auth.lease`（`data` 含 `lease`，换证时同传 `certificate`）。
   - 两端在已验证的 DataChannel 内交换 `endpoint.LeaseProof`，通过 `Session.Access().Update` 同时验证本端直取租约与对端租约；**首份证明核验完成前禁止业务消息**。
   - 电脑检测到身份服务失联立即调用 `AuthorityLost()`；新会话或带工具访问检查 `Allows(now, true, resourceGranted)`，既有只读访问检查 `Allows(now, false, resourceGranted)`；每次调用、输出投递及授权截止时均须校验。
   - 手机失联期间暂停远程输出交付，电脑按本地授权继续执行任务，待手机重连后重新核验再恢复。

## 2. 自建免账号渠道接入与配对协议（`RELAY_CHANNEL=self`）

自建中转不使用 `vanc1`/`vanl1` 证书、不调用外部身份后端与权益接口，仅允许通过一次性配对授权使用（参考 Go 实现 `adapter/selfrelay`）：

1. **设备标识派生**：桌面端与手机端各自在本机安全存储生成 32 字节 Ed25519 私钥，派生设备 ID：`sdev_` + `lowercase(base32_nopad(sha256("vanora/self-device/v1\x00" || raw_pubkey)[:16]))`。
2. **节点门禁与公钥 PoP 登录**：
   - WebSocket 升级请求携带 `Authorization: Bearer <RELAY_SELF_TOKEN>`（缺省或错误返回 HTTP `401`）。
   - 收到 `auth.challenge` 后发送签名的 `auth.login`（`certificate` 必须为空、`from` 为 `sdev_...`、`to` 为 `"signal"`，`body` 为 `{"role":"desktop"|"mobile","public_key":"<base64url 32B pubkey>"}`）。
   - 节点校验 `from == SelfDeviceID(public_key)` 与 Ed25519 签名后回复 `auth.ok`（`{"device_id":"sdev_...","mode":"self"}`）。自建节点禁用 `devices.list`（返回 `directory_unavailable`）与 `auth.lease`（返回 `lease_unsupported`）。
3. **电脑上线与生成配对链接**：
   - 电脑发送 `device.online`（`card` 为 `type:"device.card"`、`from:sdev_...`、`to:"self"`、由电脑私钥签署的设备名称，`certificate` 与 `guests` 为空）。
   - 桌面生成 5 分钟一次性配对链接（所有敏感参数置于 `#fragment`）：
     `https://<relay-host>/v1/signal#mode=self&pin=<base64url(desktop_pub)>&pair=<base64url(32B_pair_token)>&token=<optional_relay_self_token>`
4. **一次性配对与复连握手**：
   - 手机向目标电脑 `SelfDeviceID(desktop_pub)` 发送签名的 `connect.request`（`seq: 1`，`body` 为 `{"public_key":"<mobile_pub>","name":"<device_name>","pair_proof":"<optional_base64url_hmac>"}`）。
   - 首次配对时，手机不直接发送 `pair`，而是计算 `HMAC-SHA256(raw_pair_token, "vanora-self-pair-v1\n" + connection_id + "\n" + base64url(mobile_pub) + "\n" + base64url(desktop_pub))` 作为 `pair_proof`。
   - 电脑查本地 `self.enc` 白名单；未配对时以恒定时间比对所有未过期邀请的 HMAC，验证通过即消耗该一次性邀请并持久化手机公钥与权限（`read`/`control`）。未获授权时电脑立即签发 `connect.close`，节点关闭连接并向手机下发 `connect.closed`（`"access_denied"`）。
   - 授权通过后电脑签发 `connect.accept`（`seq: 1`，`body` 为 `{"nonce":"<32-hex>","public_key":"<desktop_pub>"}`），手机核验 `public_key` 与固定 `pin` 一致且签名有效。
5. **TURN 滑动续期与端到端加密**：
   - 节点收到 `connect.accept` 后为双方下发 STUN + 10 分钟短期 TURN 凭证（无需外部权益服务），手机按每 30 秒发送 `ice.refresh` 滑动续期；撤权或断连触发 `connect.close` 时节点立即撤销 TURN grant。
   - 后续 `rtc.offer`、`rtc.answer`、`rtc.candidate` 使用与官方模式相同的签名协商信封（由双方本机 Ed25519 私钥签名验签），DataChannel 建立后直接承载业务帧（无需发送 `LeaseProof`）。

## 3. 非 Go 客户端签名规范

参照 [protocol/wire.go](../protocol/wire.go)，Ed25519 签名输入由以下 8 个 UTF-8 字段以 LF（`\n`）连接而成，**末尾无换行**：

```text
vanora-relay/v1
<type>
<connection_id>
<from>
<to>
<round>
<seq>
<body_base64url>
```

- `round`、`seq` 为十进制整数，缺省写 `0`。
- `body` 与签名结果 `proof` 均使用**无填充 base64url** 编码。
- 证书与签名设备卡的解析和校验规则见 [endpoint/session.go](../endpoint/session.go) 与 [endpoint/discovery.go](../endpoint/discovery.go)。

## 4. DataChannel 帧格式与电脑端业务协议

AI 正文只在加密 DataChannel 与本机 Vanora 之间流转。`vanora-desktop` 启动本机 Vanora RPC 进程并按会话隔离请求与事件：手机断线时已启动的任务继续运行，重连后可按事件序号 `seq` 续读、重发相同 `request_id` 取回原 `run_id`；桌面端撤回访客权限会取消该访客受影响的运行。

### 传输层与分片格式

- **DataChannel 标签**：`vanora`（可靠有序）。
- **首帧证明**：通道建立后的首帧必须是 `{ "certificate": "...", "lease": "..." }`，续租时重复发送。
- **消息分片**：业务层使用 UTF-8 JSON，单条业务消息上限 **64 MiB**。
  - `<= 16 KiB`：直接发送原始消息。
  - `> 16 KiB`：按序拆分发送二进制分片，分片格式如下：

```text
+---------------+-----------------+-----------------+-----------------+-----------+
| Magic (4 B)   | MsgID (uint32)  | Index (uint32)  | Total (uint32)  | Payload   |
| 00 56 4E 46   | 大端消息编号     | 大端索引(0起)    | 大端总片数       | 分片字节   |
+---------------+-----------------+-----------------+-----------------+-----------+
```

### 业务请求与响应

手机请求携带 `type`、`request_id` 及对应操作字段；电脑响应携带相同 `request_id`，`type` 为 `result`（返回 `data`）或 `error`（返回 `code`）。访问者身份取自已验证的连接。

| `type` | 请求字段 | 成功返回 `data` | 说明 |
| --- | --- | --- | --- |
| `workspace.list` | 无 | `workspaces[]` | 返回当前账号可远程新建会话的白名单工作区列表 |
| `session.create` | `workspace_id`、`title`（可选） | 新会话摘要 | 在指定白名单工作区创建 Vanora 原生 v3 JSONL 会话（按 `request_id` 幂等） |
| `session.list` | 无 | `sessions[]` | 每项含 `session_id`、`title`、`can_run_tools`、`tools_enabled` 及可见性/审批能力标识 |
| `session.open` | `session_id` | `messages`、`last_seq`、`pending_ui`（可选） | 按查看者权限返回可见消息快照、最新序号及当前待审批弹窗列表 |
| `run.start` | `session_id`、`text` | `run_id` | 保留期内同 `request_id` + 同正文返回原 `run_id`，正文不同返回 `request_conflict`（每会话默认保留最近 4096 条） |
| `run.cancel` | `session_id`、`run_id` | `run_id`、`status` | 校验运行归属该会话且访问者有取消权限 |
| `ui.respond` | `session_id`、`run_id`、`ui_id`、`confirmed`/`value`/`answers`/`cancelled` | `ui_id`、`status` | 响应远程工具审批（`confirm`/`select`）或 `ask`/`input`/`editor` 弹窗 |
| `events.resume` | `session_id`、`after_seq` | `session_id`、`after_seq` | 随后补发 `seq > after_seq` 的事件并接续实时流；游标超出保留窗口返回 `snapshot_required` |

### 交互示例与错误码

```json
// 1. 手机发起运行
{"type":"run.start","request_id":"q7","session_id":"s2","text":"解释这次修改"}

// 2. 电脑返回运行编号
{"type":"result","request_id":"q7","data":{"run_id":"r5"}}

// 3. 电脑推送流式事件（seq 为会话级递增整数）
{"type":"event","session_id":"s2","run_id":"r5","seq":18,"kind":"text.delta","data":{"text":"修改了"}}
```

- **流式与交互事件 `kind`**：
  - 文本与思考：`text.delta`、`thinking.delta`（需具备思考可见权限）
  - 工具调用：`tool.call`、`tool.start`、`tool.update`、`tool.end`（需具备工具可见权限）
  - 远程审批与提问：`ui.request`、`ui.resolved`（需开启 `approval_policy: "remote"` 且具备审批权限）
  - 权限占位：`sync`（混合权限会话中用于保持未授权查看者序号连续，不携带任何正文）
  - 运行终止：`run.completed`、`run.cancelled` 或 `run.failed`
- **常见错误码**：
  - `unavailable`：资源不可见、不存在或当前不可用（统一返回）。
  - `tool_denied`：缺少提示词 / 工具执行权限（或触发被禁用的斜杠命令）。
  - `request_conflict`：复用了已有 `request_id` 但正文不一致。
  - `snapshot_required`：`events.resume` 游标超出保留范围，需重新 `session.open`。
  - `snapshot_too_large`：会话快照体积超过上限。
  - `invalid_request`：请求格式或参数无效。

## 相关文档

- [身份签发协议与配置](../internal/identity/README.md)
- [STUN / TURN 配置与限制](../internal/ice/README.md)
- [架构设计与验收场景](../DESIGN.md)
