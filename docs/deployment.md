# 服务端部署与运维指南

[← 文档中心](README.md) · [返回主页](../README.md) · [桌面适配器指南 →](desktop.md) · **简体中文** | [English](en/deployment.md)

本文面向运维工程师与个人自建部署者，涵盖 `relay`（信令 + STUN/TURN 统一服务端）的渠道模式选择、完整环境变量配置、生产级反向代理与防火墙策略，以及官方渠道的权益校验接口约定。

> **环境要求**：最低要求 **Go 1.26+**（仓库默认工具链为 `go1.27.4`）。

---

## 1. 选择运行模式（`RELAY_CHANNEL`）

`relay` 通过单个环境变量 `RELAY_CHANNEL` 决定节点身份体系与安全边界。各模式严格隔离，混配不属于当前模式的环境变量会在启动阶段直接报错（Fail-Fast）：

| 模式 | `RELAY_CHANNEL` | 身份认证方式 | TURN 权益校验 | 外部依赖 |
| :--- | :---: | :--- | :---: | :--- |
| **自建免账号** | `self` | `RELAY_SELF_TOKEN` 节点门禁 + 端点 Ed25519 公钥 PoP + 桌面一次性配对 | 不校验（10 分钟滑动续期） | **零外部依赖** |
| **CN 官方站** | `cn` *(默认)* | CN 站独立 Ed25519 公钥（可选 `RELAY_ALLOWED_ISSUER`） | 仅查 CN 站权益服务 | CN 身份后端 + CN 权益服务 |
| **GLOBAL 官方站** | `global` | GLOBAL 站独立 Ed25519 公钥（可选 `RELAY_ALLOWED_ISSUER`） | 仅查 GLOBAL 站权益服务 | GLOBAL 身份后端 + GLOBAL 权益服务 |

---

## 2. 环境变量参考

### 信令与渠道配置

| 环境变量 | `self` | `cn` | `global` | 说明 |
| :--- | :---: | :---: | :---: | :--- |
| `RELAY_CHANNEL` | `self` | 默认 / `cn` | `global` | 节点运行模式与隔离边界 |
| `RELAY_SELF_TOKEN` | **必填** | 禁止设置 | 禁止设置 | 自建节点共享访问令牌（32–512 字节，无空白字符）；客户端通过 `Authorization: Bearer` 提交 |
| `RELAY_IDENTITY_PUBLIC_KEY` | 禁止设置 | **必填** | **必填** | 对应官方站点外部身份后端导出的 Ed25519 公钥（hex 或 base64），双站独立 |
| `RELAY_ALLOWED_ISSUER` | 禁止设置 | 可选 | 可选 | 纵深防御：固定允许的证书 `iss` origin（生产须 HTTPS，本地开发允许回环 HTTP） |
| `RELAY_CN_MEMBERSHIP_URL` / `TOKEN` | 禁止设置 | **必填*** | 禁止设置 | CN 站权益服务地址与随机服务密钥（`>= 32` 字节无空白） |
| `RELAY_GLOBAL_MEMBERSHIP_URL` / `TOKEN` | 禁止设置 | 禁止设置 | **必填*** | GLOBAL 站权益服务地址与随机服务密钥（`>= 32` 字节无空白） |
| `RELAY_MEMBERSHIP_URL` / `TOKEN` | 禁止设置 | 兼容回退 | 兼容回退 | 仅当当前官方站点的专用变量均未设置时作为回退 |
| `RELAY_ADDR` | 可选 | 可选 | 可选 | 信令监听地址，默认 `127.0.0.1:8787`；非回环监听必须配置 TLS |
| `RELAY_TLS_CERT` / `RELAY_TLS_KEY` | 可选 | 可选 | 可选 | 信令直接终止 TLS 时的证书与私钥路径（须成对设置） |

### STUN / TURN 核心配置

| 环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `TURN_PUBLIC_IP` | *(必填)* | 对外公告的公网 IPv4 地址（本地测试可用 `127.0.0.1`） |
| `STUN_URLS` | 小米 + B 站公共 STUN | 逗号分隔的 `stun:host[:port]`；设为 `local` 使用内置 STUN；海外可配 Cloudflare / Google STUN |
| `TURN_PORT` | `3478` | STUN/TURN 控制监听端口（同时启用 UDP 与 TCP） |
| `TURN_BIND_IP` / `TURN_RELAY_BIND_IP` | `0.0.0.0` | 控制面与中继套接字绑定的本机 IPv4 |
| `TURN_RELAY_MIN_PORT` / `TURN_RELAY_MAX_PORT` | `49152` / `65535` | UDP 媒体中继端口范围（需在防火墙放行） |
| `TURN_MAX_GRANTS` | `4096` | 全局最大并发 TURN Grant 数（范围 `1..1,000,000`） |
| `TURN_MAX_GRANTS_PER_VISITOR` | `min(32, max(1, MAX/2))` | 单访客最大活跃 Grant 数（默认 `32`），防止单访客耗尽全局名额 |
| `TURN_MAX_ALLOCATIONS_PER_GRANT` | `8` | 单个 Grant 最大并发 Allocation 数（范围 `1..1024`） |
| `TURN_LOG_LEVEL` | `error` | 可选 `disabled` / `error` / `warn` / `info` / `debug` / `trace` |

> [!NOTE]
> `TURN_UDP`、`TURN_TCP`、`TURN_REALM` 等完整参数及字节计量原理见 [internal/ice/README.md](../internal/ice/README.md)。

---

## 3. 自建节点（`RELAY_CHANNEL=self`，免登录账号）

自建节点完全由部署者自行管理访问边界，**无需登录官方账号，也无需部署外部身份或权益服务**。安全由两道防线共同保障：

1. **节点门禁（`RELAY_SELF_TOKEN`）**：防止公网域名暴露后被陌生人滥用信令与 TURN；缺少或错误提供 `Authorization: Bearer` 直接返回 HTTP `401`。
2. **端点一次性配对（Pairing-Only）**：两端在本机生成 Ed25519 密钥对，经电脑签发的一次性二维码/手输码完成 HMAC 证明互认；电脑仅开放显式设置 `"self_access": true` 的工作区与会话，并支持随时撤权并即时切断 TURN。

### 生产部署步骤（Linux + systemd + TLS 反代）

以下示例假设域名为 `relay.example.com`，运行用户为 `vanora`。

#### 第一步：构建并安装二进制

```sh
go build -o relay ./cmd/relay
sudo install -m 0755 relay /usr/local/bin/relay
```

#### 第二步：创建配置文件

新建 `/etc/vanora-relay.env` 并限制权限为 `0600`（`sudo chmod 600 /etc/vanora-relay.env`）：

```sh
RELAY_CHANNEL=self
RELAY_SELF_TOKEN=<执行 openssl rand -base64 32 生成>
TURN_PUBLIC_IP=<服务器公网 IPv4>
RELAY_ADDR=127.0.0.1:8787
STUN_URLS=local
TURN_RELAY_MIN_PORT=49160
TURN_RELAY_MAX_PORT=49200
```

#### 第三步：配置 systemd 托管服务

创建 `/etc/systemd/system/vanora-relay.service`：

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

启用并启动服务：

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now vanora-relay
```

#### 第四步：配置 TLS 反向代理

推荐将 `RELAY_ADDR` 保持在回环地址 `127.0.0.1:8787`，由反向代理统一终止 HTTPS / WSS。

> [!IMPORTANT]
> `/v1/signal` 同时承担三类请求：**WebSocket 升级**、桌面登记配对码的 **HTTP `POST`**，以及客户端解析手输码的 **HTTP `GET ?pairing=...`**。反向代理必须将三者路由至同一 `relay` 进程，保留 `Authorization` 与 `Vanora-Desktop` 请求头，且禁止缓存查询响应。

**Caddy 配置（最简推荐）：**

```caddyfile
relay.example.com {
	reverse_proxy 127.0.0.1:8787
}
```

**Nginx 配置（同时兼容 WebSocket 升级与普通 HTTP 配对请求）：**

```nginx
# 放在 http {} 块中
map $http_upgrade $connection_upgrade {
	default upgrade;
	''      close;
}

# 放在对应 server {} 块中
location /v1/signal {
	proxy_pass http://127.0.0.1:8787;
	proxy_http_version 1.1;
	proxy_set_header Upgrade $http_upgrade;
	proxy_set_header Connection $connection_upgrade;
	proxy_set_header Host $host;
	proxy_set_header Authorization $http_authorization;
	proxy_buffering off;
	proxy_cache off;
	proxy_read_timeout 3600s;
}

location = /healthz {
	proxy_pass http://127.0.0.1:8787;
}
```

#### 第五步：放行防火墙与 NAT 映射

| 端口 / 协议 | 方向 | 暴露范围 | 用途 |
| :--- | :---: | :--- | :--- |
| `TCP 443` | 入站 | 公网 | 反向代理 HTTPS / WSS 信令入口 |
| `TCP 8787` | 仅本机 | `127.0.0.1` | `relay` 内部信令端口（**无需对公网开放**） |
| `UDP + TCP 3478` | 入站 | 公网 | STUN / TURN 控制面（对应 `TURN_PORT`） |
| `UDP 49160–49200` | 入站 | 公网 | TURN 媒体中继端口段（对应 `TURN_RELAY_MIN/MAX_PORT`） |

#### 第六步：健康检查与客户端接入

```sh
curl -fsS https://relay.example.com/healthz
# 预期输出: ok
```

随后在桌面端以 `-channel self` 启动（或通过 Sidecar 发送 `access.relay.set`），执行 `access.relay.invite.create` 生成一次性二维码与 16 位配对码即可供手机或另一台电脑接入。轮换 `RELAY_SELF_TOKEN` 时，请同步更新服务端环境变量与客户端令牌。

---

## 4. 官方渠道部署（CN / GLOBAL 单站严格隔离）

官方节点**只对接本站点**的外部身份签发公钥与权益服务，两站账号、密钥与中继权益完全独立、互不共享：

- **独立信任根**：CN 与 GLOBAL 必须各自使用独立的外部身份后端与 Ed25519 私钥（协议详见 [internal/identity/README.md](../internal/identity/README.md)），跨站证书在 `auth.login` 阶段会被直接拒绝。
- **纵深防误配**：在 `cn` 节点误配 `RELAY_GLOBAL_MEMBERSHIP_*`（或在 `global` 节点误配 `RELAY_CN_MEMBERSHIP_*`）会触发启动期 fail-fast；建议同时配置 `RELAY_ALLOWED_ISSUER` 固定允许的证书签发者 origin。

<details>
<summary>展开查看 CN / GLOBAL 官方节点启动示例</summary>

```sh
# CN 官方节点
export RELAY_CHANNEL=cn
export RELAY_IDENTITY_PUBLIC_KEY="<CN 身份后端导出的 Ed25519 公钥>"
export RELAY_ALLOWED_ISSUER="https://cn-auth.example.com/realms/vanora"
export RELAY_CN_MEMBERSHIP_URL="https://cn-entitlement.internal.example.com"
export RELAY_CN_MEMBERSHIP_TOKEN="<至少32字节随机服务密钥>"
export TURN_PUBLIC_IP="<公网 IPv4>"
export STUN_URLS="local"

./relay
```

```sh
# GLOBAL 官方节点
export RELAY_CHANNEL=global
export RELAY_IDENTITY_PUBLIC_KEY="<GLOBAL 身份后端导出的 Ed25519 公钥>"
export RELAY_ALLOWED_ISSUER="https://global-auth.example.com/realms/vanora"
export RELAY_GLOBAL_MEMBERSHIP_URL="https://global-entitlement.internal.example.com"
export RELAY_GLOBAL_MEMBERSHIP_TOKEN="<至少32字节随机服务密钥>"
export TURN_PUBLIC_IP="<公网 IPv4>"
export STUN_URLS="local"

./relay
```

</details>

### 权益校验接口约定（仅官方渠道）

`relay` 不内置订阅数据库，仅在官方渠道建立连接或 `ice.refresh` 时向本站点权益服务发起查询（不跟随 HTTP 重定向；URL 未以 `/internal/v1/relay/entitlement` 结尾时自动拼接）：

```http
POST /internal/v1/relay/entitlement
Authorization: Bearer <RELAY_CN_MEMBERSHIP_TOKEN | RELAY_GLOBAL_MEMBERSHIP_TOKEN>
Content-Type: application/json
```

```json
// 请求体
{
  "issuer": "https://auth.example.com/realms/vanora",
  "subject": "<account subject>"
}

// 响应体（valid_until 为 Unix 秒级时间戳）
{
  "success": true,
  "data": {
    "relay_allowed": true,
    "valid_until": 1767225600
  }
}
```

对接须满足以下安全约束：

- **按发起者判权**：查询身份始终是发起连接的访客（手机或主控电脑），被控电脑主人的权益不能替访客解锁 TURN。
- **失败降级（Fail-Closed）**：仅当 `success: true`、`relay_allowed: true` 且 `valid_until` 在未来时下发 TURN 凭证；超时、报错、未绑定或过期一律自动降级为仅 STUN 直连。
- **有效期叠加**：TURN Grant 有效期同时受端点证书有效期上限约束；到期或撤权时立即关闭活跃 relay socket。

---

## 5. 运维须知、限流与运行时行为

| 特性 | 行为说明与运维建议 |
| :--- | :--- |
| **单实例架构** | 首版为单区域单实例部署，不跨节点同步内存态。重启 `relay` 后，在线端点会自动重连并重新协商会话。 |
| **升级兼容性** | 部署配对网功能时，请同步升级中转节点、桌面适配器与移动端 SDK。 |
| **预认证限流与反代** | 为防空连接耗尽资源，未认证连接进入独立槽位池（全局 `256`、单来源 IP `16`，超限返回 HTTP `429`）；认证成功后转入在线槽位池（`1024`）。为防伪造头绕过，来源 IP 直接取自 `r.RemoteAddr`（**不信任 `X-Forwarded-For`**）。当全部流量经本机反代（`127.0.0.1`）转发时，全站瞬时并发握手上限为 `16`（正常握手仅需数十毫秒），单桌面同时挂起的未接受 `connect.request` 上限为 `16`。 |
| **本机 IP 过滤与动态网卡** | `ice.Server` 在启动时采集宿主机 `net.InterfaceAddrs()`，自动拦截除同连接 `TURN_PUBLIC_IP` hairpin 外的全部本机网卡地址及私网/回环/保留段。若宿主机运行期间动态挂载新公网弹性 IP，需重启 `relay` 生效。 |
| **流量计量日志** | 访问者的中继有效载荷字节数在 Grant 结束时通过 `slog.Info` 输出（去重计量、不含协议开销与直连流量）；如需计费或留档请在部署侧采集结构化日志。 |
| **极端受限网络** | TURN 控制支持 UDP / TCP，媒体中继使用 UDP；仅允许出站 HTTPS (`443/tcp`) 的严格企业防火墙环境仍可能无法连通。 |
