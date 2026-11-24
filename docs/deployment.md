# 服务端部署与权益校验

[← 文档目录](README.md) · [返回主页](../README.md)

模块最低要求为 **Go 1.25**，仓库首选构建工具链为 **Go 1.27.4**。本仓库构建并提供 `relay`（信令 + STUN / TURN）与 `vanora-desktop`。官方渠道（`cn` / `global`）对接各自站点的外部身份后端与权益服务；自建渠道（`self`）免登录账号、不依赖任何外部身份或权益服务。

## 1. 渠道模型与身份边界

`RELAY_CHANNEL` 决定节点运行模式与安全边界：

| `RELAY_CHANNEL` | 身份认证方式 | 权益校验 | 说明 |
| --- | --- | --- | --- |
| `cn`（默认） | CN 站独立身份后端的 Ed25519 公钥（可选叠加 `RELAY_ALLOWED_ISSUER`） | 仅查 CN 站权益服务 | 仅登录 CN 站的用户可接入，不支持 GLOBAL 站证书或权益 |
| `global` | GLOBAL 站独立身份后端的 Ed25519 公钥（可选叠加 `RELAY_ALLOWED_ISSUER`） | 仅查 GLOBAL 站权益服务 | 仅登录 GLOBAL 站的用户可接入，不支持 CN 站证书或权益 |
| `self` | `RELAY_SELF_TOKEN` 节点门禁 + 端点本机 Ed25519 公钥 PoP + 桌面一次性配对 | **不校验** | 免登录任何官方账号，零外部身份后端依赖 |

## 2. 构建并启动 `relay`（信令 + STUN / TURN）

```sh
go build ./cmd/relay
```

### 环境变量矩阵

| 环境变量 | `cn` | `global` | `self` | 说明 |
| --- | --- | --- | --- | --- |
| `RELAY_CHANNEL` | 默认 / `cn` | `global` | `self` | 决定节点模式与隔离边界 |
| `RELAY_IDENTITY_PUBLIC_KEY` | **必填**（CN 公钥） | **必填**（GLOBAL 公钥） | **禁止设置** | 官方站点外部身份后端导出的 Ed25519 公钥（hex 或 base64），两站各自独立 |
| `RELAY_ALLOWED_ISSUER` | 可选（CN `iss`） | 可选（GLOBAL `iss`） | **禁止设置** | 可选纵深防御：固定允许的证书 `iss` origin（生产须 HTTPS，本地开发允许回环 HTTP） |
| `RELAY_CN_MEMBERSHIP_URL` / `TOKEN` | **必填**（为空时回退 `RELAY_MEMBERSHIP_*`） | **禁止设置** | **禁止设置** | CN 站权益校验后端地址与随机服务密钥（>= 32 字节无空白） |
| `RELAY_GLOBAL_MEMBERSHIP_URL` / `TOKEN` | **禁止设置** | **必填**（为空时回退 `RELAY_MEMBERSHIP_*`） | **禁止设置** | GLOBAL 站权益校验后端地址与随机服务密钥（>= 32 字节无空白） |
| `RELAY_MEMBERSHIP_URL` / `TOKEN` | 兼容回退变量 | 兼容回退变量 | **禁止设置** | 仅当当前官方站点的专用变量都为空时作为该站点的回退配置 |
| `RELAY_SELF_TOKEN` | **禁止设置** | **禁止设置** | **必填** | 自建节点共享访问令牌（32–512 字节无空白），客户端升级 WebSocket 时通过 `Authorization: Bearer` 提交 |
| `TURN_PUBLIC_IP` | **必填** | **必填** | **必填** | 本机或 NAT 对外公布的可达 IPv4（本地开发可用 `127.0.0.1`） |
| `STUN_URLS` | 可选 | 可选 | 可选 | 逗号分隔的 `stun:host[:port]`，默认小米与哔哩哔哩公共 STUN；设为 `local` 使用内置 STUN |
| `RELAY_ADDR` | 可选 | 可选 | 可选 | 信令监听地址，默认 `127.0.0.1:8787`；非回环监听须配置 TLS |
| `RELAY_TLS_CERT` / `RELAY_TLS_KEY` | 可选 | 可选 | 可选 | 信令直接启用 TLS 时的证书与私钥（成对设置） |

> [!NOTE]
> 完整 `TURN_*` 配置（端口范围、绑定网卡、并发上限等）见 [internal/ice/README.md](../internal/ice/README.md)。

### 官方渠道启动示例（CN / GLOBAL 严格隔离）

官方节点**只对接本站点**的外部身份公钥与权益服务；若在 CN 节点误配 `RELAY_GLOBAL_MEMBERSHIP_*`（或在 GLOBAL 节点误配 `RELAY_CN_MEMBERSHIP_*`），进程会在启动阶段直接失败（fail-fast）：

- CN 站与 GLOBAL 站必须各自使用独立的外部身份签发私钥与公钥（协议见 [internal/identity/README.md](../internal/identity/README.md)），跨站证书在 WebSocket `auth.login` 阶段即被直接拒绝，无法上线或发现设备。
- 建议同时配置 `RELAY_ALLOWED_ISSUER`，在验签之上叠加一层 `iss` 白名单校验。
- 权益互不共享：若用户同时登录了 CN 站与 GLOBAL 站，需要用 CN 中转就须具备 CN 站中继权益，需要用 GLOBAL 中转就须具备 GLOBAL 站中继权益；但电脑本机调用哪一站的模型完全不受中转渠道限制。

```sh
# CN 官方节点示例
export RELAY_CHANNEL=cn
export RELAY_IDENTITY_PUBLIC_KEY="<CN 身份后端导出的 Ed25519 公钥>"
export RELAY_ALLOWED_ISSUER="https://cn-auth.example.com/realms/vanora"
export RELAY_CN_MEMBERSHIP_URL="https://cn-entitlement.internal.example.com"
export RELAY_CN_MEMBERSHIP_TOKEN="<至少32字节的随机服务密钥>"
export TURN_PUBLIC_IP="127.0.0.1"
export STUN_URLS="local"

go run ./cmd/relay
```

```sh
# GLOBAL 官方节点示例
export RELAY_CHANNEL=global
export RELAY_IDENTITY_PUBLIC_KEY="<GLOBAL 身份后端导出的 Ed25519 公钥>"
export RELAY_ALLOWED_ISSUER="https://global-auth.example.com/realms/vanora"
export RELAY_GLOBAL_MEMBERSHIP_URL="https://global-entitlement.internal.example.com"
export RELAY_GLOBAL_MEMBERSHIP_TOKEN="<至少32字节的随机服务密钥>"
export TURN_PUBLIC_IP="127.0.0.1"
export STUN_URLS="local"

go run ./cmd/relay
```

---

## 3. 自建节点（`RELAY_CHANNEL=self`，免登录账号）

自建节点**完全由用户自行管理鉴权**：不需要登录任何 Vanora 官方账号，不需要部署外部身份后端，也不配置 `RELAY_IDENTITY_PUBLIC_KEY` 或任何 `*_MEMBERSHIP_*` 变量。

两层防护机制：
1. **节点门禁（`RELAY_SELF_TOKEN`）**：防止公网 URL 泄露后被陌生人占用信令与 TURN；WebSocket 升级请求缺少或提供错误 `Authorization: Bearer <RELAY_SELF_TOKEN>` 时直接返回 `401`。
2. **端点一次性配对（Pairing-Only）**：电脑与手机各自在本机生成 Ed25519 密钥对，直接通过公钥持有证明（PoP）上线；手机必须通过电脑生成的一次性配对链接/二维码完成绑定，才能建立 WebRTC 连接并访问电脑上显式开启 `self_access: true` 的工作区与会话。未配对或被撤销的手机会被电脑实时拒绝并切断 TURN。

### 单机自建步骤

以下示例假设域名 `relay.example.com`、服务用户 `vanora`、二进制安装在 `/usr/local/bin/relay`。

1. **构建并安装**

```sh
go build -o relay ./cmd/relay
sudo install -m 0755 relay /usr/local/bin/relay
```

2. **写配置**（`/etc/vanora-relay.env`，权限 `0600`）

```sh
RELAY_CHANNEL=self
RELAY_SELF_TOKEN=<openssl rand -base64 32>
TURN_PUBLIC_IP=<服务器公网 IPv4>
RELAY_ADDR=127.0.0.1:8787
STUN_URLS=local
TURN_RELAY_MIN_PORT=49160
TURN_RELAY_MAX_PORT=49200
```

3. **交给 systemd 托管**（`/etc/systemd/system/vanora-relay.service`）

```ini
[Unit]
Description=Vanora self-hosted relay (signaling + STUN/TURN)
After=network-online.target
Wants=network-online.target

[Service]
User=vanora
EnvironmentFile=/etc/vanora-relay.env
ExecStart=/usr/local/bin/relay
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now vanora-relay
```

4. **终止 TLS 并反代信令**

   把 `RELAY_ADDR` 保持在回环地址，由反向代理对外提供 HTTPS 与 WebSocket。Caddy 最小配置：

```caddyfile
relay.example.com {
	reverse_proxy 127.0.0.1:8787
}
```

   使用 Nginx 时显式转发升级头与 `Authorization` 并关闭缓冲：

```nginx
location /v1/signal {
	proxy_pass http://127.0.0.1:8787;
	proxy_http_version 1.1;
	proxy_set_header Upgrade $http_upgrade;
	proxy_set_header Connection "upgrade";
	proxy_set_header Authorization $http_authorization;
	proxy_buffering off;
	proxy_read_timeout 3600s;
}
```

5. **放行防火墙 / NAT**

   - TCP `8787` 只对反向代理开放，不需要对公网开放；
   - UDP + TCP `3478`（STUN/TURN 控制）；
   - UDP `TURN_RELAY_MIN_PORT`–`TURN_RELAY_MAX_PORT`（上例 `49160–49200`）；
   - 有 NAT 时把 `TURN_PUBLIC_IP` 设为公网地址，并保持上述端口映射不变。

6. **验证并配对客户端**

```sh
curl -fsS https://relay.example.com/healthz
```

   桌面端无需登录任何官方账号，直接以 `-channel self` 启动或通过 Sidecar 的 `access.relay.set`（`channel: "self"`）接入后，使用 `access.self.invite.create` 生成一次性配对链接/二维码，手机端调用 `NewSelfRelayClient(store)` + `ConnectSelfRelay(link, deviceName)` 即可完成配对与外网连接。轮换 `RELAY_SELF_TOKEN` 时同时更新节点配置与客户端令牌即可。

---

## 4. 端口、探针与运维说明

| 服务 | 默认监听 | 健康探针 | 部署与防火墙要求 |
| --- | --- | --- | --- |
| 信令（`relay`） | `127.0.0.1:8787` | `GET /healthz` | 经反代暴露 HTTPS 并支持 `/v1/signal` WebSocket 升级，或设置 `RELAY_ADDR`、`RELAY_TLS_CERT`、`RELAY_TLS_KEY` 直接监听 TLS |
| 外部身份签发后端（仅官方渠道） | 部署方自定义 | 部署方自定义 | CN 与 GLOBAL 独立部署、独立私钥与 HTTPS；客户端调用 `/v1/identity/*` |
| STUN / TURN（`relay`） | `0.0.0.0:3478`（UDP / TCP） | — | 放行 `TURN_PORT`（UDP + TCP）及 `TURN_RELAY_MIN_PORT`–`TURN_RELAY_MAX_PORT` UDP 端口（默认 `49152–65535`）；NAT 需保持公告端口映射；可按需设置 `TURN_BIND_IP`、`TURN_RELAY_BIND_IP` |

**运行时行为与限制：**

- **单实例、单区域**：首版不跨节点同步状态；重启信令或 TURN 后，端点会自动重新上线并重新协商连接。
- **流量统计日志**：访问者的中继字节数在 grant 结束时输出到服务日志，如需留存历史账单请在部署侧收集日志。
- **实时断流**：官方渠道权益到期或撤权、自建渠道桌面撤权或断连时，服务端会立即关闭对应活跃的 relay socket。
- **目标地址过滤**：公网部署默认拒绝私网、回环、保留段等非公网单播目标 IP。
- **受限网络说明**：TURN 支持 UDP / TCP 控制传输与 UDP relay；仅放行 HTTPS 的网络环境仍可能无法连通。

---

## 5. 权益校验接口（TURN 授权，仅官方渠道）

`relay` 不内置订阅数据库。`cn` 节点只查询 CN 站权益服务，`global` 节点只查询 GLOBAL 站权益服务；`self` 渠道不调用该接口。

```http
POST /internal/v1/relay/entitlement
Authorization: Bearer <RELAY_CN_MEMBERSHIP_TOKEN | RELAY_GLOBAL_MEMBERSHIP_TOKEN>
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

- **按站点严格隔离**：CN 节点仅信任 CN 站点的账号与权益，GLOBAL 节点仅信任 GLOBAL 站点的账号与权益，彼此不互通。
- **按访问者判权**：查询身份始终是发起连接的手机账号，电脑主人的中继权益不能替访客解锁 TURN。
- **身份一致性**：权益后端按 `(issuer, subject)` 定位已绑定账号；请使用同一测试账号验证原生端与账户系统拿到的 `sub` 一致。
- **显式授权**：建议由套餐或订阅状态显式控制 `relay_allowed`（默认关闭）。
- **失败降级（Fail-Closed）**：只有返回 `success: true`、`relay_allowed: true` 且 `valid_until` 在未来时才会下发 TURN 凭证；账号未绑定、已停用、请求超时或接口报错均自动降级为仅 STUN。
- **有效期叠加**：单次连接的 TURN 授权同时受端点证书有效期约束；权益服务不持有端点签名私钥。
