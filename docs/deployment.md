# 服务端部署与权益校验

[← 文档目录](README.md) · [返回主页](../README.md)

需要 **Go 1.25** 或更高版本。`relay-identity` 与 `relay` 可独立部署，以下均为 Bash 示例。

## 1. 构建并生成身份签名密钥

```sh
go build ./cmd/...
go run ./cmd/relay-identity keygen -out identity-signing-key -public-out identity-signing-key.pub
```

> [!IMPORTANT]
> 私钥（`identity-signing-key`）只保存在独立部署的 `relay-identity` 主机上（权限 `0600`），不要分发给信令、权益后端或客户端；仅将公钥（`identity-signing-key.pub`）分发给 `relay` 与各端点。

## 2. 配置 OIDC 并启动 `relay-identity`

`relay-identity` 支持任意符合标准 Discovery / JWKS 规范的 OIDC 提供方（如 Keycloak），配置需满足：

- 单独注册一个原生应用 Client：启用 **Authorization Code（Standard Flow）** 与 **PKCE S256**，登记精确回调地址，并允许 `openid offline_access`。
- 若配合外部权益服务校验中继权限，`VANORA_IDENTITY_OIDC_ISSUER` 须与权益服务使用的完整 issuer URL（例如 Keycloak 的完整 realm URL）一致，且同一账号在两个端应返回相同的 `sub`。
- 端点在系统浏览器中完成登录；电脑端无人值守自动续期要求 OIDC 的 refresh grant 返回可验证的 ID token（如提供方不支持，可设置 `VANORA_IDENTITY_DISABLE_REFRESH=1`，证书过期后需重新登录）。

```sh
export VANORA_IDENTITY_SIGNING_KEY_FILE=identity-signing-key
export VANORA_IDENTITY_OIDC_ISSUER=https://auth.example.com/realms/vanora
export VANORA_IDENTITY_OIDC_CLIENT_ID=vanora-native
export VANORA_IDENTITY_OIDC_REDIRECT_URI=com.vanora.app:/oauth/callback
export VANORA_IDENTITY_OIDC_REDIRECT_URIS=http://127.0.0.1/oauth/callback

go run ./cmd/relay-identity serve
```

> [!TIP]
> 同时配置 `VANORA_IDENTITY_OIDC_REDIRECT_URI`（手机自定义 Scheme）与 `VANORA_IDENTITY_OIDC_REDIRECT_URIS`（如 `http://127.0.0.1/oauth/callback`，不写端口即按 RFC 8252 自动匹配桌面临时回环端口），即可让手机和电脑 Sidecar 都自动完成浏览器回调登录，无需手动复制回调链接。

全部环境变量（监听地址、TLS、证书 / 挑战 / 租约 TTL 等）见 [internal/identity/README.md](../internal/identity/README.md)。

## 3. 启动 `relay`（信令 + STUN / TURN）

| 环境变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `RELAY_IDENTITY_PUBLIC_KEY` | 是 | — | `relay-identity keygen` 生成的 Ed25519 公钥（hex） |
| `RELAY_MEMBERSHIP_URL` | 是 | — | 权益校验后端地址（生产须 HTTPS，本地开发允许回环 HTTP） |
| `RELAY_MEMBERSHIP_TOKEN` | 是 | — | 调用权益接口的随机服务密钥（至少 32 字节，不可含空白字符） |
| `TURN_PUBLIC_IP` | 是 | — | 本机或 NAT 对外公布的可达 IPv4（本地开发可用 `127.0.0.1`） |
| `RELAY_ADDR` | 否 | `127.0.0.1:8787` | 信令监听地址；非回环监听须配置 TLS |
| `RELAY_TLS_CERT` / `RELAY_TLS_KEY` | 否 | — | 信令直接启用 TLS 时的证书与私钥（成对设置） |

> [!NOTE]
> `RELAY_MEMBERSHIP_URL` 指向的权益路由属于内部服务接口，跨主机部署时建议通过私有网络与 HTTPS 入口暴露。完整 `TURN_*` 配置（端口范围、绑定网卡、并发上限等）见 [internal/ice/README.md](../internal/ice/README.md)。

```sh
export RELAY_IDENTITY_PUBLIC_KEY="$(cat identity-signing-key.pub)"
export RELAY_MEMBERSHIP_URL=https://entitlement.internal.example.com
export RELAY_MEMBERSHIP_TOKEN="<至少32字节的随机服务密钥>"
export TURN_PUBLIC_IP=127.0.0.1

go run ./cmd/relay
```

## 4. 端口、探针与运维说明

| 服务 | 默认监听 | 健康探针 | 部署与防火墙要求 |
| --- | --- | --- | --- |
| 信令（`relay`） | `127.0.0.1:8787` | `GET /healthz` | 经反代暴露 HTTPS 并支持 `/v1/signal` WebSocket 升级，或设置 `RELAY_ADDR`、`RELAY_TLS_CERT`、`RELAY_TLS_KEY` 直接监听 TLS |
| 身份（`relay-identity`） | `127.0.0.1:8090` | `GET /readyz` | 独立发布权限与 TLS；`/readyz` 检查外部 IdP discovery 与 JWKS 可达性；客户端经 HTTPS 调用 `/v1/identity/*` |
| STUN / TURN（`relay`） | `0.0.0.0:3478`（UDP / TCP） | — | 放行 `TURN_PORT`（UDP + TCP）及 `TURN_RELAY_MIN_PORT`–`TURN_RELAY_MAX_PORT` UDP 端口（默认 `49152–65535`）；NAT 需保持公告端口映射；可按需设置 `TURN_BIND_IP`、`TURN_RELAY_BIND_IP` |

**运行时行为与限制：**

- **单实例、单区域**：首版不跨节点同步状态；重启信令或 TURN 后，端点会自动重新上线并重新协商连接。
- **流量统计日志**：访问者的中继字节数在 grant 结束时输出到服务日志，如需留存历史账单请在部署侧收集日志。
- **实时断流**：中继权益到期或被撤权时，服务端会立即关闭对应活跃的 relay socket。
- **目标地址过滤**：公网部署默认拒绝私网、回环、保留段等非公网单播目标 IP。
- **受限网络说明**：TURN 支持 UDP / TCP 控制传输与 UDP relay；仅放行 HTTPS 的网络环境仍可能无法连通。

## 5. 权益校验接口（TURN 授权）

`relay` 不内置订阅数据库，而是通过一个简单的 HTTP 内部接口向外部权益服务（可对接自建后端或会员系统）查询**发起访问的手机账号**是否允许使用 TURN 中继。

```http
POST /internal/v1/relay/entitlement
Authorization: Bearer <RELAY_MEMBERSHIP_TOKEN>
Content-Type: application/json
```

> 若 `RELAY_MEMBERSHIP_URL` 未以 `/internal/v1/relay/entitlement` 结尾，客户端会自动拼接该路径；请求不跟随 HTTP 重定向。

**请求体：**

```json
{
  "issuer": "https://auth.example.com/realms/vanora",
  "subject": "<OIDC sub>"
}
```

**响应体：**

```json
{
  "success": true,
  "data": {
    "relay_allowed": true,
    "valid_until": 1767225600
  }
}
```

`valid_until` 为权益截止的 Unix 秒级时间戳。实现与对接时须遵循以下约定：

- **按访问者判权**：查询身份始终是发起连接的手机账号，电脑主人的中继权益不能替访客解锁 TURN。
- **身份一致性**：权益后端按 `(issuer, subject)` 定位已绑定账号；请使用同一测试账号验证原生端与账户系统拿到的 `sub` 一致。
- **显式授权**：建议由套餐或订阅状态显式控制 `relay_allowed`（默认关闭）。
- **失败降级（Fail-Closed）**：只有返回 `success: true`、`relay_allowed: true` 且 `valid_until` 在未来时才会下发 TURN 凭证；账号未绑定、已停用、请求超时或接口报错均自动降级为仅 STUN。
- **有效期叠加**：单次连接的 TURN 授权同时受端点证书有效期约束；权益服务不持有端点签名私钥。
