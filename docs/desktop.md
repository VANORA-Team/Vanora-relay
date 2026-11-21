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
