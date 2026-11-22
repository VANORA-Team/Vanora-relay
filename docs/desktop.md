# 桌面适配器指南（`vanora-desktop`）

[← 文档目录](README.md) · [返回主页](../README.md)

`vanora-desktop` 运行在本机电脑上，负责托管本机 Vanora RPC 进程、执行本地会话与工具访问控制（ACL），并通过加密 WebRTC DataChannel 与移动端通信。

## 1. 构建与设备注册（复用宿主客户端令牌）

```sh
go build -o vanora-desktop ./cmd/vanora-desktop

# 推荐通过 stdin 传入宿主 AI 客户端已有的认证令牌（避免令牌出现在进程命令行中）
printf '%s\n' "$CLIENT_AUTH_TOKEN" | ./vanora-desktop login \
  -identity https://identity.example.com \
  -ca identity-signing-key.pub \
  -token-stdin
```

- **Windows**：可将产物名设为 `vanora-desktop.exe`。
- **令牌传入方式**：支持 `-token-stdin`（推荐）、环境变量 `VANORA_CLIENT_TOKEN` 或 `-token`。`vanora-desktop` 仅将宿主令牌用于向外部身份后端交换短期设备证书，**不会**持久化或打印宿主令牌。
- **账号管理子命令**：支持 `whoami` / `status`（查看当前 `enrolled`、`user_id`、`device_id`）与 `logout`（安全重置本地设备密钥与绑定）。
- **凭据与状态目录**：可通过 `-state-dir` 指定配置档目录，默认位于当前用户配置目录下的 `Vanora/relay`。端点私钥保存在系统凭据库中，运行 `serve` 时须使用同一桌面用户身份。

## 2. Sidecar 内嵌模式

将 `vanora-desktop` 作为子进程嵌入宿主程序（如 Vanora 桌面端或 CLI）时：

- **编译期注入默认服务配置**：可通过 `-ldflags` 注入默认值（运行时仍可用 `-identity` / `-signal` / `-ca` / `-ca-hex` 或环境变量覆盖）：

  ```sh
  go build -ldflags "-X main.defaultIdentityURL=... -X main.defaultSignalURL=... -X main.defaultCAHex=..." \
    -o vanora-desktop ./cmd/vanora-desktop
  ```

- **自动注册与热更新令牌**：启动 `serve -sidecar` 时可通过环境变量 `VANORA_CLIENT_TOKEN` 传入当前宿主令牌（未注册设备会自动完成注册，已注册设备会更新内存令牌）；宿主刷新令牌后通过 `stdin` 发送 `{"type":"auth.token","token":"..."}` 即可无感续期（收到 `{"type":"auth.required",...}` 时亦可推送新令牌恢复）。
- **结构化状态事件**：以 `serve -sidecar` 启动后会向 `stdout` 输出 JSON-lines 状态事件（`ready`、`online`、`offline`、`auth.ok`、`auth.required`、`peer.connected`、`session.created`、`ui.request`、`shutdown` 等）。
- **生命周期控制**：支持通过 `stdin` 发送 `{"type":"auth.token"|"reload"|"status"|"shutdown"}`，并在父进程退出（`stdin` EOF）时自动干净退出。

### 共享与访问

一次性邀请与客户端撤权流程参考 T3 Code 的 [配对授权](https://github.com/pingdotgg/t3code/blob/11224f63d2a3d444ca1fd1f67cd3ff21c1f5f8a1/apps/server/src/auth/PairingGrantStore.ts)和[客户端会话](https://github.com/pingdotgg/t3code/blob/11224f63d2a3d444ca1fd1f67cd3ff21c1f5f8a1/apps/server/src/auth/SessionStore.ts)。

宿主可以在用户未登录时启动 Sidecar，并通过 `-lan-listen 192.168.1.42:3773` 或 `access.lan.set` 启用局域网。地址必须指定本机私有 IP 与端口。`127.0.0.1` 也可用于本机调试。局域网入口默认关闭，手机使用桌面生成的链接配对。桌面验证手机设备私钥，并将配对授权保存在与账号凭据独立的系统凭据库中。

同一个 Sidecar 可同时服务已配对的局域网设备和登录 Vanora 的官方中继客户端。Sidecar 要求宿主提供当前登录令牌才会连接官方中继。使用 `-relay=false` 可把官方中继初始设为关闭。宿主退出账号或切换账号时发送 `auth.logout`，等待 `auth.logout.ok` 后再发送新账号的 `auth.token`。退出只关闭官方路径，局域网授权继续有效。

| `stdin` 命令的 `type` | 字段与结果 |
| --- | --- |
| `access.status` | 返回 `lan.enabled`、监听地址、已授权客户端和待用邀请，以及官方中继的配置、开关、认证和在线状态 |
| `access.lan.set` | 用 `enabled` 启用或关闭局域网。启用时传 `address`，如 `192.168.1.42:3773` |
| `access.relay.set` | 用 `enabled` 启用或关闭官方中继。开启需要已签入 Vanora |
| `access.invite.create` | 可传 `access: "read"`（默认）或 `"control"`。`access.invite.created` 返回一次性 `link` 和 `invitation`，五分钟内有效。宿主可以把 `link` 编为二维码 |
| `access.invite.revoke` | 用邀请 `id` 取消待用链接 |
| `access.client.revoke` / `access.clients.revoke` | 按客户端 `id` 撤权，或撤销全部局域网客户端和待用邀请。会关闭对应连接并取消该设备的运行中任务 |

命令可带 `request_id`，响应回传该值。`access.status` 不显示邀请密钥。宿主可在收到 `peer.connected` 或 `peer.disconnected` 后刷新列表。更改已有设备的权限时，先撤销该设备，再生成对应权限的配对链接。

为允许局域网访问，在指定会话或工作区配置 `lan_access: true`。仅开启监听不会分享任何资源。`read` 客户端可以读已分享会话。`control` 也可以在允许的工作区创建会话、提交提示词，并按会话的工具与审批设置工作。使用 `"owner": "local"` 时，桌面登录后的官方账号可接续本地会话。也可在 `owner` 填入指定账号的官方 `user_id`，将所有者权限绑定到该账号。

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
      "owner": "本机注册输出的 user_id",
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
      "owner": "本机注册输出的 user_id",
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
- **`owner`**：填写 `login` 输出的 `user_id`；同账号手机自动享有主人权限。
- **`users`**：显式授权的访客列表。`read: true` 允许读取文本消息；`tools: true` 允许提交提示词（需同时开启 `read`）；访客默认**不**可见思考过程、工具调用详情与审批弹窗，除非显式设置 `show_thinking` / `show_tools` / `approve`。
- **`tools`**：决定本机 Vanora 实际启用的本地工具白名单；空数组 `[]` 表示运行纯文本对话。
- **`show_thinking` / `show_tools`**：是否向主人展示模型思考过程及工具调用/执行输出（默认关闭，开启后仅对具备对应权限的查看者下发，未授权访客收到无信息泄露的 `sync` 占位序号）。
- **`approval_policy`**：`"none"`（默认，本地自动取消所有交互弹窗）或 `"remote"`（自动通过 `--no-extensions -e <guard>` 加载内置审批守卫扩展，仅拦截写入/破坏性/开放世界工具并通过加密通道推送给手机确认，同时支持 Vanora 内置 `ask` 提问弹窗；超时或租约失联自动拒绝）。可通过顶层 `approval_extension` 指定自定义 `.mjs`/`.js` 守卫脚本。
- **模型凭据**：沿用当前桌面用户本机的 Vanora 配置。

## 4. 启动服务

```sh
./vanora-desktop serve \
  -identity https://identity.example.com \
  -ca identity-signing-key.pub \
  -signal wss://relay.example.com/v1/signal \
  -config desktop.json \
  -name Office
```

> [!WARNING]
> `serve` 每秒检查一次配置文件以热更新本地 ACL；若配置解析失败，服务会**立即退出**以防止权限漂移。更新配置时请使用原子替换（先写入临时文件再重命名）。
