# Vanora Relay 安全测试、修复与复测交接文档

**日期**：2026-11-24  
**基线提交**：`0e78e50`（所有改动当前保留在工作区，尚未执行 `git commit`）  
**工具链**：`go 1.26.0`（构建与验证使用 `go1.27.4`）

---

## 1. 交接概览

本轮在隔离环境完成了对 `Vanora-relay` 的全栈安全测试（代码审计、静态与依赖漏洞扫描、进程内协议/权限攻击测试、60 秒模糊测试、WSL2 Linux 网络命名空间无外网转发靶场），并将确认的 **7 项高/中/低危漏洞（`VR-SEC-01` ~ `VR-SEC-07`）**、**1 项信息泄露（`VR-SEC-10`）** 以及 **`govulncheck` 报告的全部依赖漏洞** 全部修复并完成回归复测。

当前状态：

- **可重复安全测试套件已落库**：`test/security/`（含 WSL2/Linux 网络命名空间隔离靶场 `test/security/lab/`）、`adapter/desktop/security_test.go`、`adapter/selfrelay/security_test.go`。
- **全量回归与严格安全门禁通过**：
  - `VANORA_SECURITY_STRICT=1 VANORA_SECURITY_HEAVY=1 go test ./... -count=1`（全部 17 个包通过）
  - `go vet ./...`、`go build ./cmd/...`、`gofmt -l`（均无告警/未格式化项）
  - `govulncheck -show verbose ./...`（`No vulnerabilities found.`）
  - WSL2 隔离安全靶场 `VANORA_SECURITY_STRICT=1 test/security/lab/run.sh`（`SECLAB_ALL_PASS`）
  - 原有生产路径隔离靶场 `test/relaye2e/run.sh`（`ALL_SCENARIOS_PASS`）

---

## 2. 已修复漏洞与改动明细

| 编号 | 严重度 | 组件与改动文件 | 原问题简述 | 修复机制 | 复测状态 |
| --- | --- | --- | --- | --- | --- |
| `VR-SEC-01` | **高危** | `adapter/desktop/state.go`<br>`adapter/desktop/adapter.go`<br>`adapter/desktop/protocol.go` | 多控制访客共享会话时，`events.resume` 重放历史事件未校验审批归属，访客 B 可读取访客 A 的 `ui.request` / `ui.resolved` 审批内容（含工具名及参数） | `storedEvent` 新增持久化字段 `approval_user`；`appendEventVisibleLocked` 写入归属者；`handleEventsResume` 与 `deliver` 对 `visApproval` 严格校验所有者或发起者（缺失字段时回退查询 `sr.ps.Runs[run_id].UserID`，仍为空则对非所有者 fail-closed 下发 `sync` 占位） | `TestSecurityEventsResumeDoesNotLeakOtherGuestApproval` **PASS**（严格模式） |
| `VR-SEC-02` | **中危** | `internal/signal/hub.go`<br>`internal/signal/socket.go` | 官方渠道升级 WebSocket 前无来源限制，单源打开 1024 个未应答 `auth.challenge` 连接即可占满全局槽位，导致正常用户收到 HTTP `503` | 分离预认证槽位池（`maxPreAuthSlots = 256`、单 IP `maxPreAuthPerIP = 16`，超限返回 HTTP `429`）与已认证在线槽位池（`maxAuthenticatedSlots = 1024`）；认证通过后立即释放预认证槽位 | `TestSignalPreAuthSlotExhaustion` **PASS**（`HEAVY=1`, `STRICT=1`，单 IP 限流在 `16/1024`，异源 `127.0.0.2` 正常 `auth.ok`） |
| `VR-SEC-03` | **中危** | `internal/signal/hub.go` | 自建模式中继不校验配对状态，持有 `RELAY_SELF_TOKEN` 的攻击者派生 4 个手机密钥即可用 32 条挂起 `connect.request` 打满桌面 `hostCount >= 32`，阻断已配对手机 | 拆分已接受活跃链路（`maxHostAcceptedLinks = 32`）与挂起请求（`maxHostPendingLinks = 32`）；增加单 `(phone, host)` 挂起上限 `2` 与单 `(IP, host)` 挂起上限 `16`，并在 `connect.accept` 时复检活跃上限 | `TestSignalSelfHostLinkSlotPressure` **PASS**（严格模式，合法手机正常路由至桌面） |
| `VR-SEC-04` | **中危** | `internal/ice/peers.go`<br>`internal/ice/relay.go`<br>`internal/ice/env.go`<br>`internal/ice/ice.go` | TURN 对端过滤仅放行全局单播并对 `TURN_PUBLIC_IP` 做单点拦截，宿主机次级公网 IP（如靶场 `8.8.8.1:19998` 或多网卡次级公网地址）可被 TURN 穿透访问 | `ice.Server` 启动时采集 `net.InterfaceAddrs()` 存入 `localAddrs`；`peerAllowed` 与 `relayConn.WriteTo` 双重拦截除 `TURN_PUBLIC_IP` 外的全部宿主机本机接口地址（同连接 `TURN_PUBLIC_IP` hairpin 保持不受影响） | WSL2 靶场 `official_turn_security` 输出 **`PASS SECONDARY_IP_BLOCKED`** |
| `VR-SEC-05` | **低危** | `internal/ice/ice.go`<br>`internal/ice/relay.go` | `quota()` 检查 `len(g.allocations) < maxAllocationsPerGrant` 与 `allocationCreated()` 登记之间存在 TOCTOU 竞态，TCP 控制通道 16 并发 `Allocate` 实测突破至 `9/8` | `grant` 增加带 5 秒自动过期清理的 `pendingAllocs`，`quota()` 持 `s.mu` 原子预占配额，`allocationCreated()` 核销预占并二次校验上限 | WSL2 靶场 16 并发 TCP Allocate 输出 **`PASS ALLOC_QUOTA_ENFORCED succeeded=8`** |
| `VR-SEC-06` | **低危** | `internal/ice/ice.go`<br>`internal/ice/env.go` | TURN 仅限制全局 `TURN_MAX_GRANTS`（默认 4096），单访客可占满全局名额导致其他访客 `ice_unavailable` | 新增每访客活跃 Grant 上限 `TURN_MAX_GRANTS_PER_VISITOR`（默认 `min(32, max(1, TURN_MAX_GRANTS/2))`）及错误 `ice.ErrVisitorGrantLimit` | `TestICEPerVisitorGrantCap` **PASS**（严格模式） |
| `VR-SEC-07` | **低危** | `adapter/selfrelay/server.go` | 自建模式桌面端收到异常中继重放的已签名 `connect.request`（同 `connection_id`）时，直接覆盖 `s.links[connID]` 导致原活跃链路失联 | `runningConn` 新增 `seenConns` 去重表（上限 4096 时保留活跃条目并清理陈旧记录）；`handleConnectRequest` 在鉴权前与写入 `s.links` 前双重校验重复 `connID` 并直接静默丢弃 | `TestSelfRelayConnectRequestReplayDoesNotBreakLiveLink` **PASS**（严格模式） |
| `VR-SEC-10` | **信息** | `adapter/desktop/protocol.go` | 已结束任务从活跃表移除后，同会话任意可读访客调用 `run.cancel` 可获知该 `run_id` 的终态 | `handleRunCancel` 查询持久化 `sr.ps.Runs[req.RunID]` 前增加 `rec.UserID != user && !sr.cfg.owns(user)` 校验，非所有者/非发起者统一返回 `unavailable` | `TestSecurityCrossGuestRunCancelAndUIRespondRejected` **PASS**（严格模式） |
| 依赖漏洞 | **中/低危** | `go.mod`<br>`go.sum` | `govulncheck` 检出可达漏洞 `GO-2026-6163`（`pion/stun/v3@v3.0.1`）、`GO-2026-5942`（`x/net@v0.50.0`）、包级 `GO-2026-5024`（`x/sys@v0.41.0`）及 32 项间接模块漏洞 | 升级 `github.com/pion/stun/v3@v3.1.5`、`github.com/pion/transport/v4@v4.0.2`、`golang.org/x/net@v0.63.0`、`golang.org/x/crypto@v0.59.0`、`golang.org/x/sys@v0.50.0`（`go 1.26.0`） | `govulncheck -show verbose ./...` 输出 **`No vulnerabilities found.`** |

---

## 3. 新增配置项与行为变更（接手必看）

1. **新增环境变量 `TURN_MAX_GRANTS_PER_VISITOR`**：
   - 取值范围：`1` ~ `TURN_MAX_GRANTS`。
   - 默认值：`min(32, max(1, TURN_MAX_GRANTS/2))`（默认 `TURN_MAX_GRANTS=4096` 时为 `32`）。
   - 超限时 `ice.Server.Config` 返回 `ice.ErrVisitorGrantLimit`，信令层统一映射为 `ice_unavailable`。
2. **信令预认证限流与反代部署注意事项**：
   - 未认证连接进入独立的 `preAuthSlots`（全局 `256`，单来源 IP `16`，超限返回 HTTP `429`）；认证成功后释放预认证槽位并占用 `slots`（`1024`）。
   - 为避免客户端伪造请求头绕过限流，来源 IP 直接取自 `r.RemoteAddr`（**不信任** `X-Forwarded-For`）。若线上通过本机反向代理（Caddy / Nginx 转发至 `127.0.0.1:8787`），所有客户端的 `r.RemoteAddr` 均为 `127.0.0.1`，此时全站并发的“正在握手但尚未完成 `auth.login`”的连接上限为 `16`，单桌面同时挂起未接受的 `connect.request` 上限为 `16`（正常客户端握手通常在几十毫秒内完成，一般不受影响；如官方高并发场景出现突发重连抖动，后续可增加显式受信任反代 CIDR 白名单后再解析代理头）。
3. **TURN 宿主机接口地址采样时机**：
   - `ice.Server` 在启动初始化阶段读取一次 `net.InterfaceAddrs()` 构造禁访表；若宿主机运行期间动态挂载新公网网卡/弹性 IP，需重启 `relay` 进程生效。
4. **桌面端 `state.json` 兼容性**：
   - `storedEvent` 新增 `approval_user` 为 `omitempty` 可选字段，完全向后兼容既有 `state.json`。对升级前已落盘且无 `approval_user` 的历史审批事件，自动按 `run_id` 回查 `runs` 记录的 `user_id`；若仍缺失则仅允许会话所有者读取。

---

## 4. 新增安全测试套件与复跑方式

### 文件清单

- `test/security/README.md`：套件运行说明与约定。
- `test/security/internal/sectest/sectest.go`：`VANORA_SECURITY_STRICT` / `VANORA_SECURITY_HEAVY` 开关与 `Finding` 辅助函数。
- `test/security/signal_test.go`：自建 Bearer 门禁、PoP 错绑、挑战重放、跨站/过期/错误签发者/未来时间证书与租约校验、重复 `device_id` 与半开重连窗口、跨链路签名注入、序号/轮次重放、帧大小（200 KiB）与 `120 msg/s` 限流、预认证槽位占满（`HEAVY=1`）、自建链路槽位压力、输出队列溢出压力测试。
- `test/security/ice_test.go`：每访客 TURN Grant 上限隔离测试。
- `test/security/lan_test.go`：已配对 `read` 局域网设备提交新 `control` 邀请不可提权且不消耗邀请测试。
- `test/security/fuzz_test.go`：4 个模糊测试目标（协议线格式解码验签、证书与租约验签、公钥解析与自建配对证明、自建/局域网链接解析）。
- `test/security/lab/main.go` & `test/security/lab/run.sh`：Linux 网络命名空间隔离靶场（支持 `VANORA_SECURITY_STRICT=1`）。
- `adapter/desktop/security_test.go`：审批历史重放隔离、跨访客 `run.cancel` / `ui.respond` 及历史任务状态隔离测试。
- `adapter/selfrelay/security_test.go`：自建配对 HMAC 证明换绑拒绝、恶意中继重放 `connect.request` 防覆盖测试。

### 常用复测命令

```powershell
# 1. 默认回归测试（适合常规 CI）
go vet ./...
go test ./... -count=1

# 2. 严格 + 高压力安全门禁（全量安全回归，所有 VR-SEC-* 均须 PASS）
$env:VANORA_SECURITY_STRICT='1'
$env:VANORA_SECURITY_HEAVY='1'
go test ./... -count=1

# 3. 依赖漏洞扫描
go run golang.org/x/vuln/cmd/govulncheck@latest -show verbose ./...

# 4. 模糊测试（已验证 4 个目标各跑 60s，累计 >510 万次执行，0 崩溃）
go test ./test/security -run '^$' -fuzz '^FuzzProtocolDecodeAndVerify$' -fuzztime 60s -parallel 4
go test ./test/security -run '^$' -fuzz '^FuzzIdentityVerifyCertificateAndLease$' -fuzztime 60s -parallel 4
go test ./test/security -run '^$' -fuzz '^FuzzIdentityParsePublicKeyAndSelfProof$' -fuzztime 60s -parallel 4
go test ./test/security -run '^$' -fuzz '^FuzzSelfRelayAndLANTargetParse$' -fuzztime 60s -parallel 4
```

**WSL2 / Linux 隔离网络命名空间靶场**（先在 Windows 交叉编译 Linux 二进制，再以 Linux `root` 运行）：

```powershell
$env:GOOS='linux'; $env:GOARCH='amd64'
go build -o /tmp/seclab-bin/relay ./cmd/relay
go build -o /tmp/seclab-bin/seclab ./test/security/lab
go build -o /tmp/seclab-bin/relaye2e ./test/relaye2e
```

```sh
# 严格安全靶场（验证内网段/元数据过滤、本机主/次级 IP 拦截、16 并发 TCP Allocate 配额、撤权清理、自建 TLS/TURN）
VANORA_SECURITY_STRICT=1 bash test/security/lab/run.sh /tmp/seclab-bin

# 生产路径端到端靶场（UDP TURN、TCP TURN、无权益 fail-closed）
bash test/relaye2e/run.sh /tmp/seclab-bin
```

---

## 5. 保留的设计权衡、未覆盖范围与后续建议

### 已知设计与信息项（当前保留）

- **`VR-SEC-08`（半开连接重连窗口）**：重复 `device_id` 沿用“首连接优先”防踢号策略；客户端静默掉线（无 TCP FIN/RST）时服务端依赖 `15s` Ping + `5s` 超时释放槽位，实测重连阻塞窗口为 **`20.1s`**（`TestSignalDuplicateDeviceIDAndStaleReconnectWindow`）。如需进一步优化移动端切网恢复体验，后续可评估缩短 Ping 周期或探测旧连接存活后允许同密钥接管。
- **`VR-SEC-11`（自建模式 TURN 滑动续期）**：`RELAY_CHANNEL=self` 下 `ice.refresh` 每 ≥10s 续期 10 分钟 `selfTurnWindow`，连接存活期间可无上限续期（符合自建免权益设计）。
- **`VR-SEC-12`（自建邀请默认携带节点令牌）**：`access.self.invite.create` 默认 `include_token: true` 将 `RELAY_SELF_TOKEN` 置于 URL `#fragment`（不随 HTTP 请求发送，但经剪贴板/二维码分享时须提示用户）；需高安全隔离时可传 `include_token: false` 改为带外输入。
- **`VR-SEC-13`（Windows 文件权限）**：`state.json` 及加密文件在 Windows 上忽略 POSIX `0600`/`0700` 模式位，依赖用户配置目录 ACL 保护。

### 尚未覆盖的测试盲区与后续跟进

1. **Go Data Race 检测（`-race`）**：当前 Windows 测试环境未安装 `gcc`（`CGO_ENABLED=0`），未执行 `go test -race ./...`。建议接手后在 Linux/macOS 或装有 `gcc` 的环境执行 `VANORA_SECURITY_STRICT=1 go test -race ./... -count=1`。
2. **TURN 带宽 / 流量速率限制**：当前 `internal/ice` 仅统计并上报字节数，未实现单访客或单 Grant 带宽限速（防滥用高带宽转发），若面向公网开放官方中继建议后续在 `relayConn` 层或部署侧 `tc`/防火墙补充限速策略。
3. **真实公网 NAT 与外部闭源后端**：本轮隔离测试覆盖本机回环与单机 Linux 网络命名空间，不含真实蜂窝/家庭双层 NAT 穿透验收，亦不含外部身份签发后端与会员权益后端的接口渗透测试。
4. **文档与提交整理**：当前工作区变更尚未提交；如需合入主分支，请按需将 `TURN_MAX_GRANTS_PER_VISITOR` 及新限流行为同步补充到 `internal/ice/README.md` 与 `docs/deployment.md`，并在提交前再次确认 `git diff`。
5. **`staticcheck` 非安全风格提示**：`adapter/desktop/adapter.go:529` 的空临界区（`SA2001`，系 `close()` 中等待在途 `Send` 结束的有意同步屏障）及 8 处 `ST1013` / `ST1005` / `U1000` 风格提示未做改动，可按需后续清理。
