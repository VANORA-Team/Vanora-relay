# 桌面适配器指南（`vanora-desktop`）

[← 服务端部署](deployment.md) · [文档中心](README.md) · [移动端 SDK →](mobile.md) · **简体中文** | [English](en/desktop.md)

`vanora-desktop` 运行在你的电脑上，同时具备双重身份：

- **被控宿主（Host）**：托管本机 Vanora RPC 进程，执行工作区/会话白名单与工具访问控制（ACL），并向手机或其他电脑暴露受控 AI 能力。
- **远程控制端（Controller）**：内置多端控机能力（Sidecar `remote.*` JSONL 指令与独立 `ctl` 命令行），可通过加密 WebRTC DataChannel（官方 / 自建中转）或 mTLS WebSocket（局域网）并发控制同一配对网内的其他电脑。

---

## 1. 构建与独立 CLI 使用

```sh
# Linux / macOS
go build -o vanora-desktop ./cmd/vanora-desktop

# Windows
go build -o vanora-desktop.exe ./cmd/vanora-desktop
```

### 子命令一览

| 子命令 | 用途 |
| :--- | :--- |
| `login` | 为官方渠道（`cn` / `global`）注册设备密钥并换取短期设备证书（`self` 免账号不支持） |
| `serve` | 启动被控宿主服务（支持独立模式与 `-sidecar` 嵌入模式，同时开放控机指令） |
| `ctl` | 独立命令行远程控机工具（`pair` / `peers` / `workspaces` / `sessions` / `create` / `open` / `run` / `cancel`） |
| `whoami` / `status` | 查看指定站点或全部官方槽位的注册状态、`user_id` 与 `device_id` |
| `logout` | 重置指定官方渠道的本地设备密钥并登出，不影响其他渠道 |

### 快速启动示例

```sh
# 1. 官方渠道按站注册（推荐通过 stdin 传入宿主客户端令牌，绝不落盘或打印）
printf '%s\n' "$CN_CLIENT_TOKEN" | ./vanora-desktop login \
  -channel cn \
  -cn-identity https://cn-identity.example.com \
  -cn-ca cn-identity-signing-key.pub \
  -token-stdin

# 2. 启动官方 CN 渠道服务
./vanora-desktop serve \
  -channel cn \
  -cn-identity https://cn-identity.example.com \
  -cn-ca cn-identity-signing-key.pub \
  -cn-signal wss://cn-relay.example.com/v1/signal \
  -config desktop.json \
  -name Office

# 3. 启动免账号自建渠道服务（无需身份后端或登录令牌）
./vanora-desktop serve \
  -channel self \
  -self-signal wss://relay.example.com/v1/signal \
  -self-token "$RELAY_SELF_TOKEN" \
  -config desktop.json \
  -name HomePC
```

> [!NOTE]
> 官方令牌可通过 `-token-stdin`（推荐）、环境变量 `VANORA_CLIENT_TOKEN` 或 `-token` 传入。独立运行也兼容旧单渠道参数 `-identity` / `-ca` / `-ca-hex` / `-signal`（未指定 `-channel` 且未传 `-cn-*`/`-global-*` 时沿用旧 `account.enc` 槽位）。

### 分槽安全存储布局

默认状态目录 `-state-dir` 为 `<UserConfigDir>/Vanora/relay`（加密密钥保存在系统密钥库，服务名 `Vanora Desktop Relay`），各渠道物理隔离、互不覆盖：

| 文件 / 目录 | 说明 |
| :--- | :--- |
| `account-cn.enc` | CN 站端点 Ed25519 私钥、证书、刷新句柄与配对网状态 |
| `account-global.enc` | GLOBAL 站端点 Ed25519 私钥、证书、刷新句柄与配对网状态 |
| `self.enc` | 自建中转本机设备密钥、已配对设备白名单与配对网状态 |
| `lan.enc` | 局域网 mTLS 服务端密钥、已配对设备白名单与配对网状态 |
| `sessions/` | 会话持久化事件与运行记录（`state.json`） |
| `profile.lock` | 进程排他锁，防止多个进程并发写坏加密凭据库 |

<details>
<summary>展开查看 vanora-desktop 全量 CLI 环境变量映射</summary>

| 环境变量 | 对应参数 | 说明 |
| :--- | :--- | :--- |
| `VANORA_RELAY_CHANNEL` | `-channel` | 默认渠道：`cn` / `global` / `self`（`ctl` 额外支持 `lan`） |
| `VANORA_CLIENT_TOKEN` | `-token` | 官方宿主客户端认证令牌 |
| `VANORA_RELAY_CN_IDENTITY_URL` | `-cn-identity` | CN 站身份后端地址 |
| `VANORA_RELAY_CN_CA_PUBLIC_KEY` | `-cn-ca-hex` | CN 站固定公钥（hex / base64） |
| `VANORA_RELAY_CN_SIGNAL_URL` | `-cn-signal` | CN 站信令 WebSocket 地址 |
| `VANORA_RELAY_GLOBAL_IDENTITY_URL` | `-global-identity` | GLOBAL 站身份后端地址 |
| `VANORA_RELAY_GLOBAL_CA_PUBLIC_KEY` | `-global-ca-hex` | GLOBAL 站固定公钥（hex / base64） |
| `VANORA_RELAY_GLOBAL_SIGNAL_URL` | `-global-signal` | GLOBAL 站信令 WebSocket 地址 |
| `VANORA_RELAY_SELF_SIGNAL_URL` | `-self-signal` | 自建中转信令地址（`ctl pair` 裸局域网码时可填 `IP:PORT`） |
| `VANORA_RELAY_SELF_TOKEN` | `-self-token` | 自建中转访问令牌（别名 `-signal-token` / `VANORA_RELAY_SIGNAL_TOKEN`） |
| `VANORA_RELAY_IDENTITY_URL` / `CA_PUBLIC_KEY` / `SIGNAL_URL` | `-identity` / `-ca-hex` / `-signal` | 兼容旧单渠道参数 |

</details>

---

## 2. Sidecar 内嵌模式（双站分槽与热切换）

当将 `vanora-desktop` 作为子进程嵌入桌面端宿主程序时，使用 `serve -sidecar` 即可通过标准输入输出（JSONL）进行全生命周期控制：

### 编译期注入官方双站默认配置

通过 `-ldflags` 注入 CN 与 GLOBAL 两套公开入口配置（仅含公钥与地址，**不含任何私钥**；运行时仍可通过对应参数或环境变量覆盖）：

```sh
go build -ldflags "\
  -X main.defaultCNIdentityURL=... -X main.defaultCNSignalURL=... -X main.defaultCNCAHex=... \
  -X main.defaultGlobalIdentityURL=... -X main.defaultGlobalSignalURL=... -X main.defaultGlobalCAHex=..." \
  -o vanora-desktop ./cmd/vanora-desktop
```

### 运行机制与通道隔离

- **单活跃广域网热切换 + 并发局域网**：同一 Sidecar 进程内，广域网通道在 `cn` / `global` / `self` 中至多启用 1 条（也可关闭），同时可与 `lan` 局域网服务并发运行。发送 `access.relay.set` 热切换渠道时**无需重启 Sidecar**，不中断本地运行中的 Vanora 任务与局域网连接，也不会清除另一站已注册的设备密钥。
- **结构化事件与优雅退出**：`stdout` 持续输出 JSONL 事件（`ready`、`online`、`offline`、`auth.ok`、`auth.error`、`auth.required`、`auth.logout.ok`、`access.status`、`peer.connected`、`session.created`、`ui.request`、`config.reloaded`、`shutdown` 等），父进程关闭 `stdin`（EOF）时自动优雅退出。

| 渠道 | 登录要求 | 鉴权与信任根 | TURN 权益 | 桌面资源暴露规则 |
| :--- | :--- | :--- | :--- | :--- |
| `cn` | 必须登录 CN 站 | CN 身份后端 + CN 公钥 | 仅查 CN 站权益 | 归属当前 CN 账号（`"owner": "local"` 或指定 `user_id`）及 `users` 访客 |
| `global` | 必须登录 GLOBAL 站 | GLOBAL 身份后端 + GLOBAL 公钥 | 仅查 GLOBAL 站权益 | 归属当前 GLOBAL 账号（`"owner": "local"` 或指定 `user_id`）及 `users` 访客 |
| `self` | **免登录官方账号** | `RELAY_SELF_TOKEN` + 本机公钥 PoP + 一次性配对 | 不查外部权益 | **仅配对可用**：仅暴露显式开启 `"self_access": true` 的资源 |
| `lan` | **免登录官方账号** | 局域网私有 IP + 双向 mTLS + 一次性配对 | 直连（无需 TURN） | **仅配对可用**：仅暴露显式开启 `"lan_access": true` 的资源 |

---

## 3. Sidecar `stdin` 控制指令集

所有指令均为单行 JSON（JSONL），支持附带 `request_id` 并在响应中原样回传；`access.status` 不会回显任何邀请令牌或节点令牌。

### 通道、身份与系统控制

| `type` | 请求字段 | 行为与返回 |
| :--- | :--- | :--- |
| `access.status` | `request_id?` | 返回 `active_channel`、`channels`（`cn`/`global`/`self` 详细状态）与 `lan` 状态 |
| `auth.token` | `channel: "cn" \| "global"`, `token` | 注入或更新对应站点宿主令牌；若该站为活跃渠道则立即注册或续期（绝不跨站复用） |
| `auth.logout` | `channel: "cn" \| "global"`, `request_id?` | 仅登出并重置该站点凭据，不影响另一站、自建通道或局域网；返回 `auth.logout.ok` |
| `access.relay.set` | `enabled`, `channel?: "cn" \| "global" \| "self"`, `signal_url?`, `signal_token?` | 启停或热切换广域网中转；`cn`/`global` 校验对应站令牌，`self` 校验 `signal_url` 与 `signal_token` |
| `access.lan.set` | `enabled`, `address?` | 启停局域网/Tailnet 监听（支持 RFC1918/RFC4193 私网及 `100.64.0.0/10` Tailnet 地址） |
| `access.activity.set` | `enabled` | 运行时动态启停向当前中转节点发布零信任脱敏运行态势 |
| `session.guest.respond` | `session_id`, `guest_request_id`, `action` (`approve`\|`dismiss`) | 本机宿主直接批准或忽略只读访客提交的 `guest.request` 提问 |
| `reload` / `status` / `shutdown` | — | 热重载 `desktop.json`、查询简要状态、优雅退出 |

### 配对邀请与配对网管理

通道在线后发送 `access.relay.invite.create`（广域网）或 `access.invite.create`（局域网），响应中同步返回 `qr_code`（可直接渲染的 PNG data URL）、`pairing_code`（4 组 16 位手输码）、`link`（扫码链接）以及 `invitation.expires_at`（5 分钟有效）：

| `type` | 请求字段 | 行为与返回 |
| :--- | :--- | :--- |
| `access.relay.invite.create` | `channel?`，自建可加 `access?: "read" \| "control"`、`include_token?: bool` | 为当前在线广域网渠道创建一次性邀请（自建默认 `read` 且默认携带节点令牌） |
| `access.relay.invite.revoke` | `id`, `channel?` | 同时作废指定邀请的二维码与手输码 |
| `access.relay.client.revoke` / `clients.revoke` | `id?`, `channel?` | 撤销广域网渠道中指定或全部已配对设备并即时断开连接 |
| `access.self.invite.create` / `revoke` | `access?`, `include_token?` / `id` | 自建渠道专用兼容指令，返回结构与 `access.relay.invite.*` 一致 |
| `access.self.client.revoke` / `clients.revoke` | `id?` | 撤销自建渠道中指定或全部设备，即时断开连接、切断 TURN 并取消其运行中任务 |
| `access.invite.create` / `revoke` | `access?: "read" \| "control"` / `id` | 创建或撤销局域网一次性配对链接（手输码后附私有 `IP:端口`） |
| `access.client.revoke` / `clients.revoke` | `id?` | 撤销指定或全部已配对局域网设备并取消运行中任务 |
| `access.network.list` | `channel?` (`lan` / `self` / `cn` / `global`) | 返回 `access.network`，含配对网内全部手机与电脑 `members[]` 及本机 `self_id` |
| `access.network.remove` | `channel?`, `id` | 移除指定成员，切断本机与其双向连接并将撤销同步给在线成员 |
| `access.client.access.set` | `channel: "lan" \| "self"`, `id`, `access: "read" \| "control"`, `signal_url?` | 动态切换局域网/自建配对网成员（在线或离线）的 `read` / `control` 权限，无需重新配对；会断开其当前入站连接以立即生效 |

> [!TIP]
> **配对网提示**：配对网内成员均可管理名单，两个已有配对网在发生跨网配对时会自动合并。请在 UI 展示扫码/手输入口时向用户提示这一点；每台电脑始终独立执行各自本机的工作区与会话 ACL。

```jsonl
{"type":"access.relay.invite.create","request_id":"inv-1"}
{"type":"access.network.list","channel":"lan","request_id":"list-1"}
{"type":"access.client.access.set","channel":"lan","id":"<成员 ID>","access":"control","request_id":"acl-1"}
{"type":"access.network.remove","channel":"lan","id":"<成员 ID>","request_id":"rm-1"}
```

---

## 4. 电脑与电脑双向互控

同一台电脑在托管本地 Vanora 的同时，可并发向多台远程电脑发起加密出站控制，覆盖 `cn`、`global`、`self`、`lan` 全部 4 条渠道：

- **默认安全（Fail-Safe）反向权限**：在 `lan` / `self` 渠道下，经配对网反向互认或经手机传递发现的另一台电脑默认仅获 **`read`** 权限。需要远程执行任务时，可在配对时传 `grant_access: "control"`，或事后在被控端发送 `access.client.access.set` 动态授权。
- **官方渠道权限边界**：`cn` / `global` 不设 `grant_access` 覆盖，严格由被控端 `desktop.json` ACL 判定，且 TURN 权益始终按**发起控制的一方（Caller）**核验。

### 方式 A：Sidecar `remote.*` 异步控制指令

`remote.*` 在独立协程中执行，不阻塞本地宿主服务，并复用本机分槽密钥与配对网：

| `type` | 关键请求字段 | 响应事件 / 说明 |
| :--- | :--- | :--- |
| `remote.peers.list` | `channel?` | 返回 `remote.peers`（含 `peer_id`、`channel`、`name`、`address`、`online`、`state`、`path`） |
| `remote.pair` | `input`, `channel?`, `signal_url?`, `signal_token?`, `grant_access?` | 接受二维码链接或 16 位手输码完成配对、同步配对网并建连；返回 `remote.paired` |
| `remote.connect` / `disconnect` / `reconnect` / `wakeup` | `peer_id`, `channel?`, `long_resume?` | 连接已知电脑 / 断开 / 强制重连 / **先探活再重连**（并行检测静默半开死连接） |
| `remote.route.add` / `remove` | `peer_id`, `address`, `channel?: "lan"` | 为已配对电脑注册或移除备用局域网 / Tailnet（`100.64.0.0/10`）路由，后台自动向高优路由回切 |
| `remote.workspace.list` | `peer_id`, `channel?` | 查询远程电脑白名单工作区；返回 `remote.result` |
| `remote.session.create` / `list` / `open` | `peer_id`, `workspace_id` 或 `session_id`, `title?`, `namespace?`, `link_origin?`, `mode_limit?` | 远程创建会话（支持幂等命名空间、`link_origin` 围栏与 `mode_limit` 单调收窄）/ 列出会话 / 拉取快照 |
| `remote.events.resume` / `ack` | `peer_id`, `session_id`, `after_seq` 或 `seq`, `channel?` | 补发断点事件 / 确认已消费序号以支持断线自动恢复 |
| `remote.run.start` / `cancel` | `peer_id`, `session_id`, `text` 或 `run_id`, `namespace?`, `link_origin?`, `mode_limit?` | 发起幂等对话/工具运行 / 取消指定运行（受控子进程内自动阻止 `A -> B -> C` 二次跳跃转发） |
| `remote.guest.request` / `respond` | `peer_id`, `session_id`, `text` 或 `guest_request_id`+`action` | 只读提交待主人确认的提问 / 会话主人远程批准或忽略提问 |
| `remote.ui.respond` | `peer_id`, `session_id`, `run_id`, `ui_id`, `confirmed`/`value`/`answers`/`cancelled` | 响应远程审批或提问弹窗 |

异步推送事件包括：`remote.connection.state`、`remote.event`（流式文本/思考/工具/审批/运行终态）、`remote.network.updated`、`remote.access.state`、`remote.auth.state`、`remote.subscription.error` 与 `remote.error`。

```jsonl
{"type":"remote.pair","request_id":"p1","channel":"lan","input":"ABCD-EFGH-JKLM-NPQR@192.168.1.42:3773","grant_access":"control"}
{"type":"remote.session.list","request_id":"l1","channel":"lan","peer_id":"<peer_id>"}
{"type":"remote.run.start","request_id":"r1","channel":"lan","peer_id":"<peer_id>","session_id":"existing","text":"运行单元测试并汇总结果"}
```

### 方式 B：独立命令行 `vanora-desktop ctl`

适合在终端或自动化脚本中直接操作远程电脑（追加 `-json` 可输出结构化 JSONL）：

```sh
# 1. 局域网配对（-grant-access control 可一步开放双向控制）
./vanora-desktop ctl pair -channel lan \
  -input "ABCD-EFGH-JKLM-NPQR@192.168.1.42:3773" \
  -grant-access control

# 2. 自建中转配对
./vanora-desktop ctl pair -channel self \
  -self-signal wss://relay.example.com/v1/signal \
  -self-token "$RELAY_SELF_TOKEN" \
  -input "ABCD-EFGH-JKLM-NPQR" \
  -grant-access control

# 3. 查看已配对或同配对网的远程电脑
./vanora-desktop ctl peers

# 4. 列出目标电脑的工作区与会话，并实时流式执行任务
./vanora-desktop ctl workspaces -peer <peer_id>
./vanora-desktop ctl sessions -peer <peer_id>
./vanora-desktop ctl run -peer <peer_id> -session <session_id> -text "检查当前 git 状态"
```

> [!TIP]
> `ctl` 会对 `-state-dir` 加排他锁（`profile.lock`）。如果本机已有 `vanora-desktop serve` 正在运行并占用默认目录，请改用 Sidecar 的 `remote.*` 指令，或为纯控制端 `ctl` 指定独立的 `-state-dir`。

---

## 5. 会话与工作区配置（`desktop.json`）

`desktop.json` 是本机唯一授权白名单，远程协议无法越过该配置新增会话、选择任意目录或篡改启动参数。允许以 `0` 个预置会话启动（仅配置 `workspaces` 供远端新建会话）。所有路径须为本机真实**绝对路径**（Windows 可使用正斜杠 `/`）：

```json
{
  "executable": "node",
  "launcher_args": ["/abs/path/to/vanora/packages/coding-agent/dist/cli.js"],
  "allow_slash_commands": false,
  "max_text_bytes": 65536,
  "max_snapshot_bytes": 16777216,
  "retention": {
    "max_events": 4096,
    "max_bytes": 4194304,
    "max_requests": 4096
  },
  "workspaces": [
    {
      "id": "project",
      "title": "项目工作区",
      "working_dir": "/abs/path/to/project",
      "owner": "local",
      "lan_access": true,
      "self_access": true,
      "tools": ["read", "edit", "write", "bash", "ask"],
      "show_thinking": true,
      "show_tools": true,
      "approval_policy": "remote"
    }
  ],
  "sessions": [
    {
      "id": "existing",
      "title": "已有对话",
      "working_dir": "/abs/path/to/project",
      "session_file": "/abs/path/to/sessions/project.jsonl",
      "owner": "local",
      "lan_access": true,
      "self_access": false,
      "tools": ["read", "bash"],
      "show_thinking": true,
      "show_tools": true,
      "approval_policy": "remote",
      "users": [
        {
          "user_id": "访客账号注册后的 usr_...",
          "read": true,
          "tools": false,
          "show_thinking": false,
          "show_tools": false,
          "approve": false
        }
      ]
    }
  ]
}
```

### 字段与权限详解

#### 顶层配置

| 字段 | 默认值 / 限制 | 说明 |
| :--- | :--- | :--- |
| `executable` | *(必填)* | 本机 Vanora 可执行文件路径；经 Node 启动时填 `node` 并配合 `launcher_args` |
| `launcher_args` | 可选 | 仅当 `executable` 为 `node` 时生效，填写 1 个指向 `.js`/`.mjs` 入口的绝对路径 |
| `arguments` | 可选 | 传递给 Vanora RPC 的固定参数（如指定模型或供应商；禁止篡改会话、工具或运行模式） |
| `approval_extension` | 内置守卫脚本 | 可选自定义 `.js`/`.mjs` 审批守卫扩展绝对路径 |
| `allow_slash_commands` | `false` | 是否允许远程提交 `/` 开头的斜杠命令（默认禁用以防调用未授权模板/工具） |
| `max_text_bytes` | `64 KiB`（上限 `1 MiB`） | 单条远程提示词最大字节数 |
| `max_snapshot_bytes` | `16 MiB`（上限 `48 MiB`） | `session.open` 快照体积上限，超出返回 `snapshot_too_large` |
| `publish_activity` | `false` | 是否向当前在线中转节点自动发布零信任脱敏会话态势（供手机 `PollActivity` 与可选 `RELAY_PUSH_WEBHOOK_URL` 消费） |
| `retention` | `4096` 条 / `4 MiB` / `4096` 请求 | 单会话事件回放窗口与 `request_id` 幂等去重保留上限 |

#### 工作区与会话权限

| 字段 | 说明 |
| :--- | :--- |
| `working_dir` / `session_file` | 均为绝对路径，且 `working_dir` 必须与会话 JSONL 首行记录的 `cwd` 一致 |
| `session_dir` *(仅 `workspaces`)* | 覆盖新会话落盘目录；默认写入 Vanora 原生目录 `<agent_dir>/sessions/--<path>--/`（支持环境变量 `VANORA_SESSION_DIR` / `VANORA_AGENT_DIR`，与终端 `vanora --resume` 互通） |
| `owner` | `"local"` 自动归属当前活跃官方渠道登录账号，或填固定 `usr_...` |
| `lan_access` / `self_access` | 两个**彼此完全独立**的开关（默认均 `false`），防止仅限局域网的资源在开启公网自建中转后被意外暴露 |
| `tools` | 本机实际启用的工具白名单；空数组 `[]` 表示纯文本对话（自动传 `--no-tools`） |
| `show_thinking` / `show_tools` | 是否向主人与 `control` 配对端展示思考过程和工具详情（默认关闭；未授权查看者仅收到无信息泄露的 `sync` 占位序号） |
| `approval_policy` | `"none"`（默认，本地自动取消交互弹窗）或 `"remote"`（加载审批守卫拦截写入/破坏性/开放世界工具并推送远端确认，同时支持 `ask` 提问；审批超时可通过环境变量 `VANORA_RELAY_APPROVAL_TIMEOUT_MS` 调整，默认与上限 `300000` ms） |
| `fence_peer_sessions` | 开启后，非主人对端仅可在自身新建的受围栏会话（`link_origin`）中执行/取消任务，禁止改动宿主既有会话或其他对端会话，且自动向子进程注入 `VANORA_LINK_ORIGIN` 阻断跨机传递跳跃 |
| `allow_guest_requests` | 开启后，只读访客可通过 `guest.request` 提交待主人确认的提示词请求（不赋予直接 `run.start` 权限） |
| `users` | 官方渠道显式访客列表（同时支持 `sessions` 与 `workspaces`）。`read` 控制读取，`tools` 控制提交提示词，思考/工具/审批可见性须分别显式开启 |

> [!WARNING]
> **热重载 Fail-Closed 保护**：`serve` 每秒检查一次 `desktop.json` 以实时生效 ACL 变更；若配置解析失败，服务会**立即撤销授权并退出**以防权限漂移。更新配置时请务必使用原子替换（先写入临时文件，再 `rename` 覆盖）。
