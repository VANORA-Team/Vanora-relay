# 安全模型与验证指南

[← 协议参考](protocol.md) · [文档中心](README.md) · [架构设计 →](../DESIGN.md) · **简体中文** | [English](en/security.md)

**Vanora Relay** 按照**零信任中转（Zero-Trust Relay）**原则设计：中转服务器仅承担连接撮合与密文转发职责，即使信令节点、网络运营商或外部会员站被入侵，也无法解密 AI 对话正文、提取本机模型密钥、伪造已绑定的电脑身份，或绕过本机 ACL 执行本地工具。

---

## 1. 四层安全边界总览

| 安全层级 | 防护目标 | 核心实现机制 |
| :--- | :--- | :--- |
| **1. 身份与配对层** | 防止伪造设备身份、跨站越权与邀请重放 | 官方渠道固定单站 Ed25519 公钥（可选 `RELAY_ALLOWED_ISSUER`）验证短期 `vanc1` 证书与 `<= 60s` `vanl1` 租约；自建与局域网采用本机 Ed25519 密钥 + 一次性 HMAC 配对证明 |
| **2. 信令与路由层** | 防止未认证资源耗尽、链路占满与协商篡改 | 预认证/已认证槽位分离限流；每桌面已接受与挂起链路独立限额；所有 `rtc.offer` / `answer` / `candidate` 绑定连接 ID、轮次、序号与随机数并由端点签名 |
| **3. 传输与 TURN 层** | 防止密文窃听、内网穿透（SSRF）与中继滥用 | WebRTC DTLS 指纹经端点私钥签名核验；TURN 强制公网单播白名单 + 宿主机本机网卡地址屏蔽 + 每访客 Grant 配额 + 并发 Allocation 原子配额 |
| **4. 桌面 ACL 与执行层** | 防止越权读取、跨访客审批泄露与静默提权 | 本机 `desktop.json` 唯一白名单 + `lan_access` / `self_access` 独立隔离；审批事件与历史运行严格按所有者/发起人隔离；配置解析失败立即撤权退出 |

---

## 2. 关键密码学与隔离保障

### 模型密钥与对话正文零托管
- 模型供应商 API Key 与登录态仅保存于桌面端本地 Vanora 配置中，**绝不进入中转节点、配对二维码或外部身份服务**。
- 所有 AI 提示词、思维链、工具参数与文件片段均通过端到端加密的 WebRTC DataChannel（或局域网双向 mTLS WebSocket）传输；中转节点仅在需要 TURN 时转发无法解密的 DTLS 密文。

### 防中间人篡改与防跨连接重放
- 双方在 WebRTC 握手阶段对包含 **DTLS 指纹**、双方设备身份、目标电脑、连接随机数与协商轮次的信封进行 Ed25519 签名。即使恶意的信令节点替换 SDP、伪造指纹或重放旧连接签名，端点在建立 DataChannel 业务通信前即会直接拒绝。
- 16 位加密手输码采用 `AES-256-GCM` 在发送端加密邀请链接后寄存于信令节点，中转节点仅看到哈希定位器 `locator` 与密文 `box`，无法读取其中的一次性配对密钥或节点令牌。

### 双站严格隔离与租约实时熔断
- **CN / GLOBAL 完全隔离**：两站分别部署独立的外部身份签发私钥与权益服务；节点配置校验采用 Fail-Fast，跨站证书在登录阶段即拒绝，权益绝不跨站共享。
- **活性租约与失联熔断**：官方渠道两端须在 DataChannel 内交换 `<= 60s` 签发期活性租约；一旦桌面检测到身份服务失联，立即禁止新会话与工具执行，既有只读访问最长持续 60 秒后强制断开。
- **默认最小权限与不可提权**：在 `lan` / `self` 渠道下，经配对网反向互认的新电脑默认仅获 `read` 权限；已配对的只读设备再次提交高权限一次性邀请时，既不会提权也不会消耗该邀请。

---

## 3. 中转层与 TURN 纵深防护参数

| 防护项 | 默认上限 / 行为 | 说明 |
| :--- | :--- | :--- |
| **预认证连接槽位** | 全局 `256` / 单 IP `16`（超限返 HTTP `429`） | 与已认证在线槽位池（`1024`）物理分离，防止空连接占满在线容量 |
| **单帧大小与消息速率** | 帧上限 `200 KiB` / 限流 `120 msg/s` | 防止超大信令帧或高频消息洪泛 |
| **自建主机链路保护** | 已接受 `32` / 挂起 `32` / 单 `(caller, host)` `2` / 单 `(IP, host)` `16` | 防止持有 `RELAY_SELF_TOKEN` 的异常客户端通过挂起请求阻塞合法设备 |
| **重放 `connection_id` 保护** | 桌面端保留最近 `4096` 条已见连接 ID | 恶意中继重放旧 `connect.request` 时静默丢弃，不覆盖活跃链路 |
| **TURN 对端过滤** | 仅允许公网单播 IPv4 + 屏蔽宿主机全部本机网卡 IP | 阻断经 TURN 探测内网、云元数据地址（`169.254.169.254`）与宿主机次级公网 IP |
| **TURN 配额控制** | `TURN_MAX_GRANTS=4096` / `TURN_MAX_GRANTS_PER_VISITOR=32` / `TURN_MAX_ALLOCATIONS_PER_GRANT=8` | 原子预占配额消除并发 Allocate 竞态，防止单访客耗尽全局中继资源 |

---

## 4. 可复现安全测试与验证

本仓库内置完整、可重复执行的隔离安全测试套件（详细说明见 [test/security/README.md](../test/security/README.md)），覆盖信令鉴权、WebRTC/TURN 安全边界、桌面端多访客 ACL 隔离、协议模糊测试以及无外网转发的 Linux 网络命名空间靶场。

### 1. 常规与严格安全回归门禁

```sh
# 常规单元与集成测试
go vet ./...
go test ./... -count=1

# 严格 + 高压力安全回归门禁（含 1024 槽位耗尽与全部安全基线断言）
VANORA_SECURITY_STRICT=1 VANORA_SECURITY_HEAVY=1 go test ./... -count=1
```

### 2. Go 原生模糊测试（Fuzzing）

覆盖协议线格式解码验签、证书与租约验签、公钥与自建证明解析、自建/局域网链接解析 4 个模糊目标：

```sh
go test ./test/security -run '^$' -fuzz '^FuzzProtocolDecodeAndVerify$' -fuzztime 60s
go test ./test/security -run '^$' -fuzz '^FuzzIdentityVerifyCertificateAndLease$' -fuzztime 60s
go test ./test/security -run '^$' -fuzz '^FuzzIdentityParsePublicKeyAndSelfProof$' -fuzztime 60s
go test ./test/security -run '^$' -fuzz '^FuzzSelfRelayAndLANTargetParse$' -fuzztime 60s
```

### 3. 依赖漏洞扫描

```sh
go run golang.org/x/vuln/cmd/govulncheck@latest -show verbose ./...
```

### 4. Linux / WSL2 网络命名空间隔离靶场

在无外网转发（`ip_forward=0`）的独立网络命名空间中端到端验证：内网/云元数据段过滤、宿主机主/次级 IP 拦截、16 并发 TCP TURN Allocate 配额、实时撤权断流，以及 UDP/TCP TURN 与无权益降级路径：

```sh
# 1. 构建 Linux amd64 测试二进制（在 Windows 可设置 GOOS=linux GOARCH=amd64）
GOOS=linux GOARCH=amd64 go build -o /tmp/vanora-lab/relay ./cmd/relay
GOOS=linux GOARCH=amd64 go build -o /tmp/vanora-lab/seclab ./test/security/lab
GOOS=linux GOARCH=amd64 go build -o /tmp/vanora-lab/relaye2e ./test/relaye2e

# 2. 在 Linux / WSL2 root 环境下运行靶场
VANORA_SECURITY_STRICT=1 bash test/security/lab/run.sh /tmp/vanora-lab
bash test/relaye2e/run.sh /tmp/vanora-lab
```

---

## 5. 已知边界与部署建议

- **真实公网 NAT 验收**：仓库内隔离靶场基于本机回环与 Linux 网络命名空间，上线公网节点后仍建议使用真实蜂窝网络与家庭宽带完成双向 NAT 穿透验收。
- **反代源 IP 限流特性**：默认信令不信任 `X-Forwarded-For` 以防伪造头绕过；若所有公网流量经本机反代转发，请知悉预认证并发上限（`16`）与挂起请求上限（`16`）的特性（详见 [部署指南 §5](deployment.md#5-运维须知限流与运行时行为)）。
- **TURN 带宽限速**：`internal/ice` 当前提供精确的去重字节计量日志，不含每连接带宽限速；面向公网开放大流量官方节点时，建议结合宿主机 `tc` 或云安全组策略控制单实例出口带宽。
- **Windows 本地凭据目录**：加密凭据文件在 Windows 上依赖当前系统用户的目录 ACL 与 Windows Credential Manager 保护，请勿将 `-state-dir` 置于共享目录中。
