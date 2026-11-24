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
| `RELAY_CHANNEL` | 否 | `cn` | 中转渠道：`cn`、`global` 或 `self`（用户自建）。决定是否校验权益，见下文「渠道与权益校验」 |
| `RELAY_IDENTITY_PUBLIC_KEY` | 是 | — | 外部身份后端对应的 Ed25519 公钥（hex 或 base64） |
| `RELAY_CN_MEMBERSHIP_URL` | 官方渠道配置 CN 站时 | — | CN 站权益校验后端地址（生产须 HTTPS，本地开发允许回环 HTTP） |
| `RELAY_CN_MEMBERSHIP_TOKEN` | 同上 | — | 调用 CN 站权益接口的随机服务密钥（至少 32 字节，不可含空白字符） |
| `RELAY_GLOBAL_MEMBERSHIP_URL` | 官方渠道配置 GLOBAL 站时 | — | GLOBAL 站权益校验后端地址 |
| `RELAY_GLOBAL_MEMBERSHIP_TOKEN` | 同上 | — | 调用 GLOBAL 站权益接口的随机服务密钥（至少 32 字节，不可含空白字符） |
| `RELAY_MEMBERSHIP_URL` | 否 | — | 兼容变量：节点所属站点的两个专用变量都为空时，作为该站点的权益地址 |
| `RELAY_MEMBERSHIP_TOKEN` | 否 | — | 兼容变量，与 `RELAY_MEMBERSHIP_URL` 成对使用；`self` 渠道不需要任何权益变量 |
| `TURN_PUBLIC_IP` | 是 | — | 本机或 NAT 对外公布的可达 IPv4（本地开发可用 `127.0.0.1`） |
| `STUN_URLS` | 否 | 小米和哔哩哔哩公共 STUN | 逗号分隔的 `stun:host[:port]`，可混用国内外服务。设为 `local` 时使用 `relay` 内置 STUN |
| `RELAY_ADDR` | 否 | `127.0.0.1:8787` | 信令监听地址；非回环监听须配置 TLS |
| `RELAY_TLS_CERT` / `RELAY_TLS_KEY` | 否 | — | 信令直接启用 TLS 时的证书与私钥（成对设置） |

> [!NOTE]
> `RELAY_MEMBERSHIP_URL` 指向的权益路由属于内部服务接口，跨主机部署时建议通过私有网络与 HTTPS 入口暴露。完整 `TURN_*` 配置（端口范围、绑定网卡、并发上限等）见 [internal/ice/README.md](../internal/ice/README.md)。

### 渠道与权益校验

`RELAY_CHANNEL` 决定节点是否校验中转资格，以及兼容变量 `RELAY_MEMBERSHIP_*` 归属哪个站点；客户端按渠道选择信令地址：

| `RELAY_CHANNEL` | 节点 | 权益校验 |
| --- | --- | --- |
| `cn`（默认） | CN 区域官方节点 | 校验；`RELAY_MEMBERSHIP_*` 归属 CN 站 |
| `global` | GLOBAL 区域官方节点 | 校验；`RELAY_MEMBERSHIP_*` 归属 GLOBAL 站 |
| `self` | 用户自建节点 | **不校验**中转资格；认证通过的连接直接获得 TURN 授权 |

跨站账号（CN 站账号使用 GLOBAL 节点，或反之）是正常场景，因此官方节点应同时配置两个站点的权益服务，至少配置一个：

| 变量对 | 说明 |
| --- | --- |
| `RELAY_CN_MEMBERSHIP_URL` / `RELAY_CN_MEMBERSHIP_TOKEN` | CN 站权益服务 |
| `RELAY_GLOBAL_MEMBERSHIP_URL` / `RELAY_GLOBAL_MEMBERSHIP_TOKEN` | GLOBAL 站权益服务 |
| `RELAY_MEMBERSHIP_URL` / `RELAY_MEMBERSHIP_TOKEN` | 兼容变量，仅当节点所属站点的两个专用变量都未设置时作为该站点的服务地址 |

节点并行查询所有已配置站点的 `/internal/v1/relay/entitlement`，任一站点放行即授予 TURN 并取最晚的有效期。账号只存在于其登录站点，其余站点会明确返回未授权，所以实际生效的仍是登录站点的订阅。全部站点拒绝时降级为仅 STUN；无站点放行且至少一个站点报错时同样按拒绝处理（错误写入服务日志）。证书中的 `iss` 必须是登录站点的 issuer，`sub` 是站点账号标识。

`self` 节点不查询会员系统，TURN 授权有效期随两端设备证书到期而结束（客户端会周期刷新）。因此自建节点仍必须接入有效的身份签发后端，不能匿名转发。

`relay` 通过 `ice.config` 把 STUN 列表发给手机和电脑，由两端直接向这些地址收集直连候选。下面的 `STUN_URLS` 配置将默认列表替换为小米和 Cloudflare。

```sh
export STUN_URLS='stun:stun.miwifi.com:3478,stun:stun.cloudflare.com:3478'
```

本地开发可使用以下配置启用内置 STUN。

```sh
export RELAY_CHANNEL=cn
export RELAY_IDENTITY_PUBLIC_KEY="<外部身份后端导出的 Ed25519 公钥>"
export RELAY_CN_MEMBERSHIP_URL=https://cn-entitlement.internal.example.com
export RELAY_CN_MEMBERSHIP_TOKEN="<至少32字节的随机服务密钥>"
export RELAY_GLOBAL_MEMBERSHIP_URL=https://global-entitlement.internal.example.com
export RELAY_GLOBAL_MEMBERSHIP_TOKEN="<至少32字节的随机服务密钥>"
export TURN_PUBLIC_IP=127.0.0.1
export STUN_URLS=local

go run ./cmd/relay
```

只配置一个站点也能启动，但该节点只会放行该站点的账号；另一个站点的账号连接时因查不到订阅而退化为仅直连。

用户自建节点把渠道设为 `self`，此时无需任何 `*_MEMBERSHIP_*` 变量：

```sh
export RELAY_CHANNEL=self
export RELAY_IDENTITY_PUBLIC_KEY="<外部身份后端导出的 Ed25519 公钥>"
export TURN_PUBLIC_IP=127.0.0.1
export STUN_URLS=local

go run ./cmd/relay
```

### 自建节点的身份与鉴权

`relay` 不校验账号密码，也不接触宿主令牌；它只验签设备证书（`vanc1` / `vanl1`）。因此自建中转的鉴权完全取决于节点固定的身份公钥，而不是中转 URL 本身：

- **复用现有身份后端（推荐，用户只需填写中转 URL）**：客户端仍登录原站点、向原身份后端取得短期证书，只把信令地址换成 `wss://<你的服务器>/v1/signal`。节点设置 `RELAY_CHANNEL=self`，`RELAY_IDENTITY_PUBLIC_KEY` 填该身份后端的公钥，即手机/桌面客户端已经固定的同一把公钥。登录、续期、吊销流程全部不变，自建节点只跳过 TURN 权益校验。
- **自建身份后端（需要自定义客户端接入）**：按 [外部身份签发协议](../internal/identity/README.md) 实现四个 `/v1/identity/*` 接口与宿主令牌校验，由签发服务生成并保管 Ed25519 私钥、导出公钥。此时客户端不能只填中转 URL，还必须同时配置该后端的地址、公钥，并能提供该后端接受的登录令牌；三者缺一不可。

公钥来源：由实际签发证书的身份后端生成并导出（hex、base64 或 32 字节文件），本仓库不含签发端，也不提供在线 JWKS / 公钥发现。复用官方身份后端时，向该站点的运营方获取其公钥（官方客户端构建已内置同一把）。以下三处必须一致：

| 位置 | 配置 |
| --- | --- |
| `relay` | `RELAY_IDENTITY_PUBLIC_KEY` |
| 桌面端 | `-ca <文件>` 或 `-ca-hex` / `VANORA_RELAY_CA_PUBLIC_KEY` |
| 移动端 | `NewClient(identityURL, signalURL, publicKeyHex, store)` 的 `publicKeyHex` |

更换公钥等于更换信任根：已注册设备必须清理状态后重新登录，否则会返回 `account: stored state belongs to another authority`；没有在线轮换机制，新公钥需要重新分发。

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

## 4. 权益校验接口（TURN 授权，仅官方渠道）

`relay` 不内置订阅数据库。`cn` 与 `global` 节点通过一个简单的 HTTP 内部接口，向**所有已配置站点**的权益服务查询**发起访问的手机账号**是否允许使用 TURN 中继；`self` 渠道不调用该接口。每个站点使用自己的 `RELAY_CN_MEMBERSHIP_*` 或 `RELAY_GLOBAL_MEMBERSHIP_*`（未配置时回退到 `RELAY_MEMBERSHIP_*`）。

```http
POST /internal/v1/relay/entitlement
Authorization: Bearer <RELAY_MEMBERSHIP_TOKEN>
Content-Type: application/json
```

> 若站点的 URL 未以 `/internal/v1/relay/entitlement` 结尾，客户端会自动拼接该路径；请求不跟随 HTTP 重定向。

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
