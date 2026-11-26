# 红队测试报告 — vanora-relay @580bc5595f9cb7d449c6fe601a96b8e3777cce85

测试范围：cmd/relay、internal/{signal,ice,routes,identity,membership}、adapter/{desktop,lan,selfrelay,transport,pairnet}、mobile、protocol。所有 PoC 位于 `red_poc/`（未跟踪目录），基线 `go test ./internal/... ./adapter/... ./cmd/...` 207 通过。除 PoC 外未修改任何受跟踪文件。WSL 复核副本 /root/vanora/vanora-relay（HEAD 580bc55 clean）。

## 战果（全部带可复现 PoC）

### VULN-A【中】未授权 HTTP 配对面绕过预认证限流并争抢单例 hub 互斥锁（可用性 DoS）
- **位置**：internal/signal/socket.go（?activity/?pairing 在 token 检查前分流）；internal/signal/activity.go:210-24、314-424、433-437；internal/signal/hub.go（servePairing 全程持有 h.mu）。
- **机制**：`/v1/signal?pairing=...` 与 `?activity=...` 为未认证可达的 HTTP 面，服务前不占 VR-SEC-02 的 preAuthSlots；处理路径与已认证 hub 路由共享同一把 `h.mu`。攻击者无需 token、无需配对码即可持续注入请求 —— 实测 15188 次洪水（32 goroutine）**零 429/503**，合法配对信令 `connect.request` 推送 p50 从基线（亚分辨率，floor 1µs）抬升至 528µs（×528），认证与 TURN 配流全部被拖慢。
- **PoC**：`red_poc/unauth_hmutex_contention_test.go`；运行：`VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedUnauthHubMutexStarvation -v`；实测输出 `red_poc/OUTPUT_mutex_starvation.txt`（含错误控制组：无 bearer 401 / 伪证明 401，证明是配对面专属的争抢）。
- **危害**：局域网/公网任意客户端可对自建/官方中继做未认证 DoS（放大系数 ~500 倍时延尖峰）；配对与设备上线吞吐整体退化。

### VULN-B【中】未限定次数的 `session.create` → state.json 64MiB 断电砖（持久 DoS）
- **位置**：adapter/desktop/protocol.go:399-547（a.state.Sessions/CreatedSessions 永久登记，仅 CreateRequests 被 trim）；adapter/desktop/state.go:388-421（saveState 无体积上限）；adapter/desktop/state.go:241-242（loadState >64<<20 硬失败）；adapter/desktop/config.go:339-352（canCreate：任意 lan_access 工作区的 LAN "control" 配对设备即可，无需逐工作区授权；official 只读+tools 且未 fence 的访客亦可）。
- **机制**：每个 create 持久化 ~925B 元数据 + 工作区 session 目录新增一个 O_EXCL 0600 JSONL；实测 2400 次 create → state.json 2.22MB、工作区目录 2400 个文件（64 秒内），**完全没有上限**。攻击者以 ~75k create（或 16 个 session × 每会 4MiB 事件保留上限 state.go:349-362）使 state.json 越过 64MiB 后，**每次桌面启动都失败**（`desktop.New` → `desktop: state.json is too large` → serve fail-closed 退出），必须手工删除 state.json（连带丢失全部事件与去重状态）才能恢复。
- **PoC**：`red_poc/session_create_state_brick_test.go`；运行：`VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedSessionCreateStateBrick -v`；实测输出 `red_poc/OUTPUT_state_brick.txt`（2400 create 全成功 → 无上限增长 → 越限后 New 复位失败）。

### VULN-C【中】self 模式活动轮询无目标级 ACL：任意 token 持有者可探测全节点任意桌面的会话/运行元数据
- **位置**：internal/signal/activity.go:342-361（self 分支只查 devID≠target + 签名）；:382（`if !h.selfHosted` 才做 owner/grants ACL）；对比 :382-394 官方分支有完整校验。桌面侧发布门禁完好（activity.go:223-245 需 desktop pairing_ticket）。
- **机制**：RELAY_CHANNEL=self 下 RELAY_SELF_TOKEN 是节点级共享凭据，且按默认配置嵌入邀请链接 URL#fragment（VR-SEC-12 已接受风险）。因此**任何拿到邀请链接/QR 的历史或被撤销成员**都能轮询节点上**任何桌面**（含未与其配对的、已将其除名的）的 ActivityState{session_id, run_id, phase(含 awaiting_approval), ui_id, method, updated_at} —— 跨配对边界的元数据外泄（监视：何时在跑什么、等待谁批准、活跃会话名/方法名）。
- **PoC**：`red_poc/self_activity_leak_test.go`；运行：`VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedSelfActivityPollWithoutPairing -v`；实测输出 `red_poc/OUTPUT_self_activity_leak.txt`（攻击者 sdev_xlytbywaksec4kfkgpl3r2hjca 与桌面 sdev_jieq3b3flxgpkydul7aoyfnogy 无任何配对关系，仍取回 phase=running/method=run.start 的完整活动记录；对照错误组：bad bearer 401、bad proof 401）。

### VULN-D【中】mobile 客户端数据竞态：ConnectLAN 与后台路由维护并发读写（生产崩溃面）
- **位置**：写者 mobile/mobile.go:454（`(*Client).ConnectLAN`），读者 mobile/wakeup.go:405（`checkBetterRoutes`，由 mobile/mobile.go:160 派生的 maintainRoutes goroutine 持续运行）。
- **机制**：`go test -race` 全仓（WSL Go 1.27.4）在 mobile 包稳定复现 TestWakeupPreservesHealthySocketAndReplacesSilentSocket 与 TestMultiRouteFailoverAndPollActivityAndGuestRequests 的同一数据竞态 —— 根因是 connect 前台路径与持续运行的路由后台循环对同一路由状态无同步。Go 内存模型下属于未定义行为，可致撕裂读 → nil 解引用崩溃或路由反复抖动。属蓝队从未运行 -race 的盲区（HANDOFF §5.2 已知"no race run"，但未修复）。
- **PoC**：`red_poc/race_mobile_full.log`（完整 race 报告）；运行：`wsl -d Debian -u root -- env -i HOME=/root PATH=/usr/local/go/bin:/usr/bin:/bin /bin/bash -c 'cd /root/vanora/vanora-relay && go test -race ./mobile -run TestWakeupPreservesHealthySocketAndReplacesSilentSocket -count=1'`（Windows 主机无 gcc 无法本地 -race）。

### VULN-E【低】self 节点 token 爆破无任何限流/锁定
- **位置**：cmd/relay/main.go:140-142（token 策略仅 32-512 字节、无空白，不拒绝弱/字典式 token）；internal/signal/socket.go:110-136（requireToken 校验在 acquirePreAuth **之前**，失败不占槽、无失败计数/退避/锁定）。
- **机制**：实测 2000 次全错字典式猜测仅 458ms（4364 req/s 本地回环，0.23ms/req），全部免费 401；正确猜测 204 与错误 401 区分清晰；猜中后不留任何失败痕迹。token 常见弱形态（产品名+后缀）在公网自建场景下可离线/在线爆破,且配对邀请 QR 将其分发给所有受邀设备持续扩大暴露面。常量时间比较（sha256+ConstantTimeCompare）排除了时序侧信道,但没有任何速率控制 —— 这与 VR-SEC-02(已修)只覆盖 WS 预认证流形成互补缺口。
- **PoC**：`red_poc/auth_guess_no_throttle_test.go`；运行：`VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedSelfTokenGuessingUnthrottled -v`；实测输出 `red_poc/OUTPUT_auth_guess.txt`。

## 观察项（静态怀疑，未 PoC/影响有限/上游依赖）

1. **活动簿快照在宿主掉线后最长 15 分钟内不失效**（internal/signal/activity.go book.grants/lastSeen 维护路径;官方模式）—— 已撤销访客在目标桌面离线 ≤15min 内仍可能轮询到缓存活动。需官方身份后端 harness 动态验证，列为观察。
2. **远端审批对话将工具参数截断至 2000 字符**（adapter/desktop/guard/approval-guard.mjs:19-30 叠加 run.go:725-729 的 512/4096 截断）：审批人可视盲区可被提示注入利用以越过人为防线（需带工具的 agent 运行时验证）。
3. **VANORA_LINK_ORIGIN 委托链路守卫仅对带 linkOrigin 的会话生效**（protocol.go:1360-1365、1932-1938；消费侧 ctl.go:101-104、remote.go:89-96）：未 fence 创建会话/配置会话/本地审批运行不含该守卫，多跳限制实际不通用（需额外本地配合条件，低危）。
4. **ReloadACL 快照竞态**（adapter.go:615-858）：创建会话落在快照后可被误判 session_removed 取消 —— 自伤性、需时序运气，Info。
5. **TURN IPv6 过渡前缀表缺口**（internal/ice/peers.go blockedPeerPrefixes 缺 64:ff9b::/96、2002::/16、ORCHIDv2 2001:20::/28）现因 pion turn v4.1.4 写死 udp4 中继 socket 而惰性化；升级 pion 或启用 IPv6 中继前须补表。
6. **ICE Refresh `channel-binding` 与 EVEN-PORT 在配额闸门前被上游处理**（pion turn.go:137 GetRandomEvenPort 每包最多 128 次 bind/close，持 s.mu/localMu）：认证小包可放大为系统调用洪水，建议上游 hook 拒绝该属性；本仓无拦截点。
7. **每 allocation 的 permission map 无上限**（grant 生命周期内）低危。
8. **adapter/transport/client.go:642-652 addLink 对同 connID 静默覆盖**：hub 侧 VR-SEC-07 去重令其当前惰性,作纵深加固记录。
9. **pairnet Group.Merge 允许已配对成员清空 roster / 踢出桌面自身 / 互相担保**：配对语义即信任,列 Info。
10. **客户端 VerifyCertificate 不 pin Issuer**（adapter/transport 侧; hub 侧仅在配置 RELAY_IDENTITY_PUBLIC_KEY 时检查）：官方部署已配置,自建不涉及 —— 纵深建议。
11. **TURN 无带宽/速率限制**（HANDOFF §5.2 已知）复确认：配额只限 allocation 数量,不限流量,公网自建滥用面仍在。
12. **扩展 fuzz（4 目标 × 300s，共 ~22.5M execs）零失败**：FuzzProtocolDecodeAndVerify 4.93M、FuzzIdentityVerifyCertificateAndLease 4.20M、FuzzIdentityParsePublicKeyAndSelfProof 6.77M、FuzzSelfRelayAndLANTargetParse 6.57M executions，无 crasher/无失败输入 —— 协议解析与身份验证面在蓝队 60s 基线之外仍未见崩点（阴性结果，供蓝队置信）。

## 被攻击但未突破的防线（负面结果，供蓝队复测置信）

- 认证/时序：sha256+ConstantTimeCompare token 比较、challenge-nonce 一次性、Ed25519 全签名域 `\n\r\x00` 拒绝 —— 无绕过。
- 信令状态机：round/seq 单调、connect.request 槽位（4 项上限）在 accept 时复查、ice.refresh 10s 节流 + entitlement 释放锁后复验身份、invite 清理双向（hub.invites+host.invites）—— 无竞态可乘。
- VR-SEC-01/03/04/05/06/07/10 修复全部经攻击复核完好。
- 配对码 80bit 空间 + locator 单向，不可枚举；AES-GCM AAD=locator 防换码。
- TURN peerAllowed：RFC1918/回环/CGNAT/保留段全拒，宿主接口地址拒绝（04 复验）—— 无新 SSRF。
- 桌面侧请求去重（requestHash 三元 namespace）、guest.request 语义、审批 canSee 审查、fence 时序、LAN 身份伪造 —— 全部未破；state.json/vault/会话路径注入无。
- 帧重组（transport/frame.go）：严格 in-order、30s 装配时限、无预分配放大 —— 无放大点。

## 附录：复现矩阵

| 编号 | PoC | 命令 |
|---|---|---|
| A | red_poc/unauth_hmutex_contention_test.go | `VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedUnauthHubMutexStarvation -v` |
| B | red_poc/session_create_state_brick_test.go | `VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedSessionCreateStateBrick -v` |
| C | red_poc/self_activity_leak_test.go | `VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedSelfActivityPollWithoutPairing -v` |
| D | red_poc/race_mobile_full.log | WSL `go test -race ./mobile -run TestWakeupPreservesHealthySocketAndReplacesSilentSocket -count=1` |
| E | red_poc/auth_guess_no_throttle_test.go | `VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedSelfTokenGuessingUnthrottled -v` |

红队报告完毕
