# 桌面适配器指南（`vanora-desktop`）

[← 文档目录](README.md) · [返回主页](../README.md)

`vanora-desktop` 运行在本机电脑上，负责托管本机 Vanora RPC 进程、执行本地会话与工具访问控制（ACL），并通过加密 WebRTC DataChannel（官方 / 自建中转）或 mTLS WebSocket（局域网）与移动端通信。

## 1. 构建与独立 CLI 使用

```sh
go build -o vanora-desktop ./cmd/vanora-desktop

# 官方渠道按站注册设备（复用宿主客户端对应站点的认证令牌，推荐通过 stdin 传入）
printf '%s\n' "$CN_CLIENT_TOKEN" | ./vanora-desktop login \
  -channel cn \
  -cn-identity https://cn-identity.example.com \
  -cn-ca cn-identity-signing-key.pub \
  -token-stdin

printf '%s\n' "$GLOBAL_CLIENT_TOKEN" | ./vanora-desktop login \
  -channel global \
  -global-identity https://global-identity.example.com \
  -global-ca global-identity-signing-key.pub \
  -token-stdin
```

- **Windows**：可将产物名设为 `vanora-desktop.exe`。
- **令牌传入方式**：支持 `-token-stdin`（推荐）、环境变量 `VANORA_CLIENT_TOKEN` 或 `-token`。`vanora-desktop` 仅将宿主令牌用于向对应站点的外部身份后端交换短期设备证书，**不会**持久化或打印宿主令牌。
- **账号管理子命令**：支持 `whoami` / `status` 与 `logout`（双站同时配置时通过 `-channel cn|global` 指定目标站；`self` 自建渠道免账号，不支持 `login` / `logout`）。
- **单渠道兼容参数**：独立运行时仍兼容旧参数 `-identity` / `-ca` / `-ca-hex` / `-signal`（未指定 `-channel` 且未传 `-cn-*`/`-global-*` 时兼容沿用旧 `account.enc` 槽位）。
- **分槽安全存储**：同一 `-state-dir`（默认 `<UserConfigDir>/Vanora/relay`）内按渠道物理隔离存储，互不覆盖：
  - `account-cn.enc`：CN 站端点密钥、证书与刷新句柄
  - `account-global.enc`：GLOBAL 站端点密钥、证书与刷新句柄
  - `self.enc`：自建中转本机设备密钥与已配对手机白名单
  - `lan.enc`：局域网服务端密钥与已配对局域网设备白名单

## 2. Sidecar 内嵌模式（双站分槽 + 热切换）

将 `vanora-desktop` 作为子进程嵌入宿主程序（如 Vanora 桌面端或 CLI）时：

- **编译期注入双站默认服务配置**：可通过 `-ldflags` 同时注入 CN 与 GLOBAL 两套官方配置（均为公钥与入口地址，无私钥；运行时也可用对应 `-cn-*` / `-global-*` 参数或 `VANORA_RELAY_CN_*` / `VANORA_RELAY_GLOBAL_*` 环境变量覆盖）：

  ```sh
  go build -ldflags "\
    -X main.defaultCNIdentityURL=... -X main.defaultCNSignalURL=... -X main.defaultCNCAHex=... \
    -X main.defaultGlobalIdentityURL=... -X main.defaultGlobalSignalURL=... -X main.defaultGlobalCAHex=..." \
    -o vanora-desktop ./cmd/vanora-desktop
  ```

- **单活跃广域网热切换 + 并发局域网**：
  - 同一个 Sidecar 进程内，广域网中转同一时刻在 `cn`、`global`、`self` 中至多启用 1 条（也可关闭），同时可与 `lan` 局域网服务并发运行。
  - 通过 `stdin` 发送 `access.relay.set` 切换渠道时**无需重启 Sidecar**，不中断正在运行的本机 Vanora 任务与局域网连接，也不会丢失另一站已经注册好的设备密钥与 `device_id`。
- **模型与中转交叉使用**：
  - 宿主在供应商侧可同时登录 CN 站与 GLOBAL 站，并按需在电脑本机调用任一站的模型；
  - 手机互联通道独立按站门控：启用 `cn` 必须已注入 CN 站令牌，启用 `global` 必须已注入 GLOBAL 站令牌（两站令牌与权益绝不互通），启用 `self` 无需任何官方登录态。
- **结构化状态事件与生命周期**：`serve -sidecar` 向 `stdout` 输出 JSONL 事件（`ready`、`online`、`offline`、`auth.ok`、`auth.error`、`auth.required`、`auth.logout.ok`、`access.status`、`peer.connected`、`session.created`、`ui.request`、`shutdown` 等，其中认证与在线事件携带 `"channel": "cn"|"global"|"self"`），并在父进程关闭 `stdin`（EOF）时自动干净退出。

### 中转渠道选择（`cn` / `global` / `self`）

| 渠道 | 登录要求 | 鉴权与信任根 | TURN 权益 | 桌面资源暴露规则 |
| --- | --- | --- | --- | --- |
| `cn` | 必须登录 CN 站 | CN 身份后端 + CN 公钥 | 仅查 CN 站权益 | 归属当前 CN 账号（`"owner": "local"` 或指定 `user_id`）及 `users` 访客 |
| `global` | 必须登录 GLOBAL 站 | GLOBAL 身份后端 + GLOBAL 公钥 | 仅查 GLOBAL 站权益 | 归属当前 GLOBAL 账号（`"owner": "local"` 或指定 `user_id`）及 `users` 访客 |
| `self` | **免登录任何官方账号** | `RELAY_SELF_TOKEN` + 本机 Ed25519 公钥 + 一次性配对 | 不查外部权益 | **仅配对可用**：仅暴露显式开启 `"self_access": true` 的工作区与会话 |

### Sidecar `stdin` 控制指令

| `type` | 请求字段 | 行为与结果 |
| --- | --- | --- |
| `access.status` | `request_id?` | 返回 `active_channel`、`channels`（`cn`、`global`、`self` 各自配置/在线/配对明细）与 `lan` 状态 |
| `auth.token` | `channel: "cn" \| "global"`, `token` | 更新指定站点的宿主令牌；若该站为当前活跃渠道则立即注册或续期；绝不跨站复用 |
| `auth.logout` | `channel: "cn" \| "global"`, `request_id?` | 仅重置并断开对应站点，不影响另一站凭据、自建通道或局域网；返回 `auth.logout.ok` |
| `access.relay.set` | `enabled`, `channel?: "cn" \| "global" \| "self"`, `signal_url?`, `signal_token?` | 启停或热切换广域网中转：`cn`/`global` 校验对应站令牌，`self` 校验 `signal_url` 与 `signal_token`（免登录） |
| `access.self.invite.create` | `access?: "read" \| "control"`, `include_token?: bool` | 生成自建中转 5 分钟一次性配对链接与邀请（默认 `include_token: true` 将节点令牌写入 `#fragment` 方便扫码） |
| `access.self.invite.revoke` | `id` | 撤销待用的自建配对链接 |
| `access.self.client.revoke` / `access.self.clients.revoke` | `id?` | 撤销指定或全部已配对的自建手机，立即断开连接、切断 TURN 并取消其运行中任务 |
| `access.lan.set` | `enabled`, `address?` | 启停局域网监听（启用时传私有 IP 与端口，如 `192.168.1.42:3773`） |
| `access.invite.create` / `revoke` | `access?`, `id?` | 创建或撤销局域网一次性配对链接（参考 T3 Code [配对授权](https://github.com/pingdotgg/t3code/blob/11224f63d2a3d444ca1fd1f67cd3ff21c1f5f8a1/apps/server/src/auth/PairingGrantStore.ts)与[客户端会话](https://github.com/pingdotgg/t3code/blob/11224f63d2a3d444ca1fd1f67cd3ff21c1f5f8a1/apps/server/src/auth/SessionStore.ts)） |
| `access.client.revoke` / `access.clients.revoke` | `id?` | 撤销指定或全部已配对局域网设备并取消运行中任务 |
| `reload` / `status` / `shutdown` | — | 热重载配置、查询简要状态、优雅退出 |

> [!NOTE]
> 所有命令可携带 `request_id`，响应原样回传。`access.status` 不会回显邀请令牌或节点令牌。需要变更已配对设备的 `read`/`control` 权限时，先撤销该设备，再重新生成目标权限的配对链接。

## 3. 会话与工作区配置（`desktop.json`）

`sessions` 与 `workspaces` 均可按需配置（允许 `0` 个预置会话启动，配合 `workspaces` 由手机远程新建会话）。所有路径须为本机真实**绝对路径**（Windows 可使用正斜杠 `/`）：

```json
{
  "executable": "node",
  "launcher_args": ["/abs/path/to/vanora/packages/coding-agent/dist/cli.js"],
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
        { "user_id": "访客手机注册后的 user_id", "read": true, "tools": false }
      ]
    }
  ]
}
```

### 字段与权限说明

- **`executable` / `launcher_args`**：直接运行本机 Vanora 可执行文件时，仅填 `executable` 并省略 `launcher_args`；通过 Node 启动 `dist/cli.js` 时按上方示例配置。
- **`workspaces`**：远程新建会话的白名单工作目录。手机端只能选择已授权的 `workspace_id`，无法传入任意本机路径；默认按 Vanora 原生目录 `~/.vanora/agent/sessions/--<path>--/` 写入 v3 JSONL 会话文件（与终端 `vanora --resume` 直接互通），也可通过 `session_dir` 覆盖。
- **`working_dir` / `session_file`**：均须为绝对路径，且 `working_dir` 必须与会话 JSONL 首行记录的 `cwd` 一致。
- **`owner`**：设为 `"local"` 时自动归属当前活跃官方渠道（CN 或 GLOBAL）已登录账号；也可填入指定官方账号的 `user_id` 固定绑定。
- **`lan_access` / `self_access`**：彼此完全独立的布尔开关（均默认 `false`）。`lan_access: true` 仅对已配对的局域网设备开放；`self_access: true` 仅对已配对的自建中转设备开放，避免仅限局域网的资源在开启公网自建中转后被意外暴露。两者均支持按配对邀请区分 `read` 与 `control` 权限。
- **`users`**：官方渠道的显式访客授权列表。`read: true` 允许读取文本消息；`tools: true` 允许提交提示词（需同时开启 `read`）；访客默认**不**可见思考过程、工具调用详情与审批弹窗，除非显式设置 `show_thinking` / `show_tools` / `approve`。
- **`tools`**：决定本机 Vanora 实际启用的本地工具白名单；空数组 `[]` 表示运行纯文本对话。
- **`show_thinking` / `show_tools`**：是否向主人及 `control` 配对设备展示模型思考过程及工具调用/执行输出（默认关闭，开启后仅对具备对应权限的查看者下发，未授权访客收到无信息泄露的 `sync` 占位序号）。
- **`approval_policy`**：`"none"`（默认，本地自动取消所有交互弹窗）或 `"remote"`（自动通过 `--no-extensions -e <guard>` 加载内置审批守卫扩展，仅拦截写入/破坏性/开放世界工具并通过加密通道推送给手机确认，同时支持 Vanora 内置 `ask` 提问弹窗；超时或租约失联自动拒绝）。可通过顶层 `approval_extension` 指定自定义 `.mjs`/`.js` 守卫脚本。
- **模型凭据**：沿用当前桌面用户本机的 Vanora 配置（与当前中转渠道无关）。

## 4. 独立启动服务示例

```sh
# 1. 官方 CN 渠道
./vanora-desktop serve \
  -channel cn \
  -cn-identity https://cn-identity.example.com \
  -cn-ca cn-identity-signing-key.pub \
  -cn-signal wss://cn-relay.example.com/v1/signal \
  -config desktop.json \
  -name Office

# 2. 自建免账号渠道（无需任何身份后端参数或登录令牌）
./vanora-desktop serve \
  -channel self \
  -self-signal wss://relay.example.com/v1/signal \
  -self-token "$RELAY_SELF_TOKEN" \
  -config desktop.json \
  -name HomePC
```

> [!WARNING]
> `serve` 每秒检查一次配置文件以热更新本地 ACL；若配置解析失败，服务会**立即退出**以防止权限漂移。更新配置时请使用原子替换（先写入临时文件再重命名）。
