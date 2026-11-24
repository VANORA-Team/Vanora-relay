# 服务端部署与权益校验

[← 文档目录](README.md) · [返回主页](../README.md)

需要 **Go 1.25** 或更高版本。设备证书签发服务由外部身份后端独立部署；本仓库构建并提供 `relay`（信令 + STUN / TURN）与 `vanora-desktop`。

## 1. 对接外部身份签发后端

端点证书与活性租约的签发逻辑不包含在本开源仓库中。部署 `relay` 前，需在你的私有身份后端实现 [外部身份签发协议](../internal/identity/README.md)：

- 持有独立的 Ed25519 签发私钥，仅向 `relay`、桌面端与移动端分发对应的 32 字节 **公钥**（hex 或 base64）。
- 暴露 `POST /v1/identity/challenges`、`POST /v1/identity/enroll`、`POST /v1/identity/lease` 与 `POST /v1/identity/renew`，在签发前校验宿主客户端现有认证令牌与端点 Ed25519 私钥持有证明（PoP）。
- 若同时对接外部权益服务校验中继权限，证书中的 `iss` 与 `sub` 须与权益服务识别的 `(issuer, subject)` 保持一致。

## 2. 构建并启动 `relay`（信令 + STUN / TURN）

```sh
go build ./cmd/relay
```

| 环境变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `RELAY_CHANNEL` | 否 | `cn` | 中转渠道：`cn`、`global` 或 `self`（用户自建）。见下文「渠道与权益校验」 |
| `RELAY_IDENTITY_PUBLIC_KEY` | 是 | — | 外部身份后端对应的 Ed25519 公钥（hex 或 base64） |
| `RELAY_MEMBERSHIP_URL` | 官方渠道必填 | — | 权益校验后端地址（生产须 HTTPS，本地开发允许回环 HTTP）。`self` 渠道不需要 |
| `RELAY_MEMBERSHIP_TOKEN` | 官方渠道必填 | — | 调用权益接口的随机服务密钥（至少 32 字节，不可含空白字符）。`self` 渠道不需要 |
| `TURN_PUBLIC_IP` | 是 | — | 本机或 NAT 对外公布的可达 IPv4（本地开发可用 `127.0.0.1`） |
| `STUN_URLS` | 否 | 小米和哔哩哔哩公共 STUN | 逗号分隔的 `stun:host[:port]`，可混用国内外服务。设为 `local` 时使用 `relay` 内置 STUN |
| `RELAY_ADDR` | 否 | `127.0.0.1:8787` | 信令监听地址；非回环监听须配置 TLS |
| `RELAY_TLS_CERT` / `RELAY_TLS_KEY` | 否 | — | 信令直接启用 TLS 时的证书与私钥（成对设置） |

> [!NOTE]
> `RELAY_MEMBERSHIP_URL` 指向的权益路由属于内部服务接口，跨主机部署时建议通过私有网络与 HTTPS 入口暴露。完整 `TURN_*` 配置（端口范围、绑定网卡、并发上限等）见 [internal/ice/README.md](../internal/ice/README.md)。

### 渠道与权益校验

每个 `relay` 节点只服务一个渠道，客户端按渠道选择对应的信令地址：

| `RELAY_CHANNEL` | 面向用户 | 权益校验 |
| --- | --- | --- |
| `cn`（默认） | 在 CN 站登录的账号 | 用 `RELAY_MEMBERSHIP_URL` 指向的 **CN 站**权益服务校验 `(issuer, subject)` |
| `global` | 在 GLOBAL 站登录的账号 | 用 `RELAY_MEMBERSHIP_URL` 指向的 **GLOBAL 站**权益服务校验 `(issuer, subject)` |
| `self` | 用户自建节点 | **不校验**中转资格；认证通过的连接直接获得 TURN 授权 |

`cn` / `global` 节点的权益服务需与对应站点同源部署，证书中的 `iss` 必须是该站点的登录 issuer，`sub` 是站点账号标识。校验失败或超时一律降级为仅 STUN 直连，不会中断信令。

`self` 节点不查询会员系统，TURN 授权有效期随两端设备证书到期而结束（客户端会周期刷新）。因此自建节点仍必须接入有效的身份签发后端，不能匿名转发。

`relay` 通过 `ice.config` 把 STUN 列表发给手机和电脑，由两端直接向这些地址收集直连候选。下面的 `STUN_URLS` 配置将默认列表替换为小米和 Cloudflare。

```sh
export STUN_URLS='stun:stun.miwifi.com:3478,stun:stun.cloudflare.com:3478'
```

本地开发可使用以下配置启用内置 STUN。

```sh
export RELAY_CHANNEL=cn
export RELAY_IDENTITY_PUBLIC_KEY="<外部身份后端导出的 Ed25519 公钥>"
export RELAY_MEMBERSHIP_URL=https://entitlement.internal.example.com
export RELAY_MEMBERSHIP_TOKEN="<至少32字节的随机服务密钥>"
export TURN_PUBLIC_IP=127.0.0.1
export STUN_URLS=local

go run ./cmd/relay
```

用户自建节点把渠道设为 `self`，此时无需 `RELAY_MEMBERSHIP_*`：

```sh
export RELAY_CHANNEL=self
export RELAY_IDENTITY_PUBLIC_KEY="<外部身份后端导出的 Ed25519 公钥>"
export TURN_PUBLIC_IP=127.0.0.1
export STUN_URLS=local

go run ./cmd/relay
```

## 3. 端口、探针与运维说明

| 服务 | 默认监听 | 健康探针 | 部署与防火墙要求 |
| --- | --- | --- | --- |
| 信令（`relay`） | `127.0.0.1:8787` | `GET /healthz` | 经反代暴露 HTTPS 并支持 `/v1/signal` WebSocket 升级，或设置 `RELAY_ADDR`、`RELAY_TLS_CERT`、`RELAY_TLS_KEY` 直接监听 TLS |
| 外部身份签发后端 | 部署方自定义 | 部署方自定义 | 独立发布权限与 HTTPS；客户端调用 `/v1/identity/*` |
| STUN / TURN（`relay`） | `0.0.0.0:3478`（UDP / TCP） | — | 放行 `TURN_PORT`（UDP + TCP）及 `TURN_RELAY_MIN_PORT`–`TURN_RELAY_MAX_PORT` UDP 端口（默认 `49152–65535`）；NAT 需保持公告端口映射；可按需设置 `TURN_BIND_IP`、`TURN_RELAY_BIND_IP` |

**运行时行为与限制：**

- **单实例、单区域**：首版不跨节点同步状态；重启信令或 TURN 后，端点会自动重新上线并重新协商连接。
- **流量统计日志**：访问者的中继字节数在 grant 结束时输出到服务日志，如需留存历史账单请在部署侧收集日志。
- **实时断流**：中继权益到期或被撤权时，服务端会立即关闭对应活跃的 relay socket。
- **目标地址过滤**：公网部署默认拒绝私网、回环、保留段等非公网单播目标 IP。
- **受限网络说明**：TURN 支持 UDP / TCP 控制传输与 UDP relay；仅放行 HTTPS 的网络环境仍可能无法连通。

## 4. 权益校验接口（TURN 授权，仅 CN / GLOBAL 渠道）

`relay` 不内置订阅数据库。`cn` 与 `global` 渠道的节点通过一个简单的 HTTP 内部接口向对应站点的权益服务查询**发起访问的手机账号**是否允许使用 TURN 中继；`self` 渠道不调用该接口。

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
  "subject": "<account subject>"
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
