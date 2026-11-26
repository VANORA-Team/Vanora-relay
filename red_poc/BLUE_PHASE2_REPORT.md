# 蓝队 Phase 2 修复报告

靶场：vanora-relay（本地隔离环境，HEAD 580bc55，red_poc/ 未跟踪）
写权限：本会话独占；所有命令均在主树真实执行，输出可复跑抽查。

## 一、修复清单（根因 → 修复 → 回归测试）

**1. VULN-C / VR-B1（中）self 模式 activity.poll 无目标 ACL** — 根因：`internal/signal/activity.go` serveActivityPoll 中 `if !h.selfHosted { ...ACL... }`，self 分支跳过授权；publish 侧也只在 official 记录 owner/grants。修复：hub 的 `device.online` self 分支接受 `guests`（≤256 个 ValidSelfDeviceID，含自举配对名单）；`internal/signal/activity.go` 的 `refreshActivityGrants`（device.online 时刷新书）+ publish 对 self 也记录 owner/grants；poll 的 ACL 对两种模式统一执行（在线 host 的 grants 快照 + 15 分钟书回退，均 fail-closed 403 "unavailable"）。selfrelay 端 `adapter/selfrelay/server.go` 按配对名单（union(state.Clients, 网络成员)）发布 guests，并在每次 Invite 配对成功 / Remove / closeRemoved 后触发重发。回归：`internal/signal/self_acl_test.go`（无配对 poll → 403；配置 guests 后 poll → 200；书过期 15 分钟后 → 403）；`TestActivitySelfHostedEndToEnd` 契约更新（无配对者 → 403）。
**红方 PoC C 复跑（negation）**：`self_activity_leak_test.go:197: expected ACL to block unpaired token holder, got leak: unavailable` ← 泄露分支不可达。

**2. VULN-A / VR-B2（中）未认证 pairing/activity 面绕过预认证限流 + 争抢全局 h.mu** — 根因：socket.go 分发顺序里 `?pairing`/`?activity` 在 token 检查与 acquirePreAuth 之前，且 servePairing 全程持 hub 互斥锁。修复：`internal/signal/limit.go`（新）per-IP 令牌桶 16 rps/burst 64 + 失败计数锁定（15s 窗口 24 次起指数锁定 ≤5min）+ 8192 项 LRU 清理；所有进入 hub 互斥锁的路径前先做定型校验（43 字符 locator 形状、1..128 设备 ID）；未认证 GET/POST 超额一律 429 + Retry-After。回归：`internal/signal` 既有 `TestSelfHostedActivity*` 全绿 + limit.go 单测（见 gate 输出 4.796s）。
**红方 PoC A 复跑（negation）**：`unauth_hmutex_contention_test.go:177: flood was throttled? total=29995 404s=102 — expected zero throttling` ← 洪水分流 429，基准时延恢复（connect.request p50 ×1 量级）。

**3. VULN-B / DESK-F1（中）session.create 无配额 → state.json >64MiB 砖化** — 根因：`adapter/desktop/protocol.go` 会话集合只增不减，可创建会话的 ACL 过宽（LAN control 或 official read+tools）。修复：每 workspace 配额（`adapter/desktop/config.go` 派生，默认 16）+ 超 32 规模即拒绝新建；会话创建返回机器可读错误码 `session_limit`（`protocol.go:481` sendError）。PoC 中攻击者请求被逐条拒绝。
**红方 PoC B 复跑（negation）**：`session_create_state_brick_test.go:137: timed out waiting for adapter frame; frames: [{"code":"session_limit","request_id":"atk-64","type":"error"}]` ← 砖化路径不可达，进程存活持续应答。

**4. VULN-D（中）mobile 路由状态数据竞争（红 PoC D）** — 根因：`ConnectLAN`（c.op）与 `checkBetterRoutes`/`Routes`/`PollActivity`/`networkBinding`（c.mu）对 `lanTarget/selfTarget/officialInvite/lanName/selfName/deviceName` 无统一锁。修复：全部指针与易变字段（`lanTarget.{Token,Address}`、`selfTarget.Pair` 及指针变量）读写一律 c.mu；写侧保留 c.op→c.mu 全序（无死锁，switchToBetterLANRoute 原有序不变）：`mobile/mobile.go` ConnectLAN(449-455,460-462)、Connect(361-363)、Pair(421-425)、ConnectSelfRelayWithToken(525-531,541-544)、dialPeer(695-709,723-741)、disconnect(761-786)；`mobile/wakeup.go` dialLANPeer(326-330,337-339,377-381)、AddRoute/RemoveRoute；`mobile/network.go` networkBinding/child.deviceName(159-164)。RaceWSL 复核发现的三处残余写（wakeup.go Token 清零、mobile.go:761 disconnect 置空、network.go 跨结构写）一并闭合。
**验证**：
`wsl -d Debian -- bash .../race.sh` → `ok vanora-relay/mobile 5.517s` `RACE_EXIT=0`（`-race` 全包）。
红 PoC D 的原始日志（race_mobile_full.log：`WARNING: DATA RACE, Write ConnectLAN mobile.go:454 vs Previous read checkBetterRoutes wakeup.go:405`）的竞争对已消除。

**5. VULN-E（低）self 节点 token 猜测不受限** — 修复：与 #2 共用 limit.go；鉴权失败计入 per-IP 计数/锁定；token 正确性仍常数时间比较，401/429 可区分但穷举成本受 429 与锁定压制（400 req/s → 16 rps 区间）。
**红方 PoC E 复跑（negation）**：`auth_guess_no_throttle_test.go:63: expected every wrong guess to get a free 401, got map[401:23 429:1977]`。

**6. H1（高）TURN TCP 控制口预认证耗尽** — 修复：`internal/ice/tcp_limit.go`（新）监听器包装：全局并发连接上限（512）+ per-IP（16）+ accept 时刻首读截止（首成功 STUN 读后清除），超额 close；`env.go` 仅在启用各协议时包装。回归：`internal/ice/tcp_limit_test.go`（TestLimitedListener/TestFirstReadConn 全绿，gate 5.669s）。

**7. M3（中）TCP/UDP allocationKey 五元组碰撞** — 修复：`internal/ice/relay.go` allocationKey 加入 `dstAddr.Network()` 前缀；撤销/到期并列分配不再互相覆盖或误关。回归：`TestAllocationKey`（TCP/UDP 同五元组两键并存，gate 内绿）。

**8. obs5 TURN IPv6  transition 前缀缺项** — `internal/ice/peers.go` blockedPeerPrefixes 补 `64:ff9b::/96`、`2002::/16`、`2001:20::/28`（前向兼容，pion v4.1.4 目前强制 udp4，故为纵深防御）。

**9. LAN1（高）PairNet Merge 重聚结清空（roster 接管/持久化抹除/席位阻塞）** — 修复：`internal/pairnet/network.go` Merge 的 `rejoining` 清空路径仅当发送者为 desktop 角色时生效（`fromDesktop && incoming[g.self].Active() && incoming[g.self].Epoch > r[g.self].Epoch`）；红 PoC 的伪造重聚结（手机声明 desktop Epoch 触发 `clear(r)`）被阻断。手机成员仍可互相 vouch/更新自己条目/推进 Epoch（**保留是产品语义**：docs/desktop.md:162「配对网络内每个成员都能管理名册」，`TestPairingNetwork` 明确要求手机间互 vouch 与 epoch 驱逐传播 — 我在回归测试 `internal/pairnet/merge_test.go` 用 7 个用例同时钉死：红方路径失败 ×2（`TestMergeMobileCannotWipeRoster`、伪造重聚结），产品路径成功 ×5）。
修复过程中的一次回归是我的编辑事故（mobile/network.go 误删 `group, local = c.identity.PairingIdentity(...)` 一行导致 cn/global 传递配对失败），已根因定位并恢复——`TestDesktopToDesktopGrantControlOnPairAndTransitiveViaPhone` 四通道 8.54s 全绿。

**10. LAN2（中）selfrelay 每客户端并发连接无上限** — `adapter/selfrelay/server.go`：`maxPeerLinksPerClient = 8`（并发 + 授权后复核 + rejectRequest→connect.close 落盘），配额耗尽前资源有界。回归：`adapter/selfrelay/lan_limits_test.go` TestSelfRelayCapsConcurrentLinksPerClient（10 连接 → 拒绝出现，存活 ≤8）。

**11. LAN3（低）seenConns 4096 整段 clear 重放窗** — 环形窗口（`maxSeenConns` FIFO 淘汰替代 `clear()`）。回归：TestSelfRelaySeenConnWindowStaysBounded（churn 后窗口有界，0.66s）。

**12. obs1 / Wake-F2（低）桌面下线后 grants 快照 ≤15min 陈旧** — 与 #1 共用 refreshActivityGrants：host 重新上线即刷新书；poll 的书回退保持 15 分钟 TTL 惩罚不变。

**13. obs8 adapter addLink 重复 connID 静默覆盖** — `adapter/transport/client.go` addLink 遇重复 connID 返回错误而非覆盖（信号层 VR-SEC-07 去重之后的纵深防御）。

## 二、验证输出（真实摘录）

**全量门禁**：`VANORA_SECURITY_STRICT=1 VANORA_SECURITY_HEAVY=1 go test ./... -count=1`
```
ok  vanora-relay/adapter/account      0.242s
ok  vanora-relay/adapter/desktop      8.249s
ok  vanora-relay/adapter/lan         0.143s
ok  vanora-relay/adapter/selfrelay   4.793s
ok  vanora-relay/adapter/transport    1.436s
ok  vanora-relay/cmd/relay            0.147s
ok  vanora-relay/cmd/vanora-desktop  41.110s
ok  vanora-relay/internal/ice         5.669s
ok  vanora-relay/internal/identity    0.066s
ok  vanora-relay/internal/membership   0.158s
ok  vanora-relay/internal/pairnet     0.072s
ok  vanora-relay/internal/routes       0.129s
ok  vanora-relay/internal/signal       4.796s
ok  vanora-relay/mobile               9.851s
ok  vanora-relay/test/security       15.038s
```
（mobile 深化加锁后单独复跑 `ok vanora-relay/mobile 8.882s`；消费 mobile 的 cmd/vanora-desktop 测试复跑 `ok vanora-relay/cmd/vanora-desktop 39.851s`；red_poc 的 5 个 WIN 探测按预期失败 = 否定成功。）

**vet**：`go vet ./...` → exit 0，无输出。

**govulncheck**（govulncheck@v1.10.0, DB 2026-11-24）：
source 模式在 go1.27.4 上游不兼容（x/tools 解析器滞后新 std：`math/rand/v2/rand.go:213:18: generic method requires go1.27 or later`，@latest 与 @master 相同），故按可用模式核验二进制：
```
govulncheck -mode=binary relay_bin.exe     → No vulnerabilities found.
govulncheck -mode=binary desktop_bin.exe   → No vulnerabilities found.
```
（两个 exe 为修复后主树当日重建。）

**红方 PoC 否定复跑**（`VANORA_SECURITY_STRICT=1 go test ./red_poc -run <X> -v`，A/B/C/E 真实输出见上文各条；D 见 WSL -race）——5/5 WIN 条件均不可达。

**模糊测试加固回归**（`VANORA_SECURITY_STRICT=1 go test ./test/security -run '^$' -fuzz <T> -fuzztime 180s -parallel 4`）：
```
FuzzProtocolDecodeAndVerify        4,997,461 execs (18,258/sec)  PASS
FuzzIdentityVerifyCertificateAndLease 4,580,197 execs (27,439/sec) PASS
FuzzIdentityParsePublicKeyAndSelfProof 5,543,786 execs (31,163/sec) PASS
FuzzSelfRelayAndLANTargetParse     5,993,294 execs (31,147/sec) PASS
```
4 目标 × 180s ≈ 2111 万次执行，0 崩溃 0 挂起。

**竞态门禁**：`wsl -d Debian -- go test -race ./mobile -count=1` → `ok vanora-relay/mobile 5.352s`、`RACE_EXIT=0`（最终树，含 9 号修复）。

## 二·五、驳回回归修复（数据面拨号韧性）

监督方驳回点复现机理与修复（m02191 两例 + 我的 15 连通过对照）：
- **根因**：Windows 环回临时端口段（49152-65535）同时供应 `Listen(:0)` 与出站 connect 源端口选择；测试环境（尤其冷启动后端口分配游标贴近段底）中监听器先占 49152…相邻位、随后第一条出站 connect 的游标恰落到目标端口，`connectex` 以 WSAEADDRINUSE（10048，"Only one usage of each socket address"）硬失败；监督方 `/lan try2 "phone pair Beta: dial tcp 127.0.0.1:49154"` 即此类。Go 的 `syscall.EADDRINUSE` 在 Windows 是合成值（Errno(536870914)），与 winsock 10048 不相等——用 errors.Is(syscall.EADDRINUSE) 探测必然漏判（已用最小程序 addrcheck 实证：errors.As 得 Errno=10048=true、errors.Is(syscall.EADDRINUSE)=false）。该类失败在生产同样成立：客户端首连/重连遇 10048 即对用户硬报错。
- **修复（产品侧，零测试改动）**：新增 `internal/dialretry`（`AddressInUse` 同时识别 syscall.EADDRINUSE/EADDRNOTAVAIL 与 winsock 10048/10049；`Dial(ctx, fn)` 对该类瞬时失败退避重试，maxAttempts=5、25ms 指数退避 cap 200ms，最坏额外 ~375ms；其他错误（连接拒绝/TLS pin 不符等）原样返回不掩盖）。接线三处会话建立拨号 + 一处探测：`adapter/lan/client.go`（WS 拨号与 ProbeTarget）、`adapter/selfrelay/peer.go` dialSignalFor、`adapter/transport/client.go` dial()。回归测试 `internal/dialretry/dialretry_test.go`（6 例：瞬时至成功/超限返最后错误/退避时序/永久错误立即返回且不再调/ctx 取消返回挂起错误/errno 识别矩阵）。
- **真实输出**：`VANORA_SECURITY_STRICT=1 VANORA_SECURITY_HEAVY=1 go test ./cmd/vanora-desktop -count=1 -run TestDesktopToDesktopGrantControlOnPairAndTransitiveViaPhone -v` → lan/self/cn/global 四通道 `--- PASS (8.18s)` `ok 9.208s`；随后连续 3 次 `ok 8.108s / 7.953s / 8.247s`；包级 `ok vanora-relay/cmd/vanora-desktop 35.761s`（strict+heavy）；全量 gate 全绿（尾部见上）；5 红 PoC 否定不回退（A/B/C/E 仍各自死于 WIN 断言、D 的 -race 0 报告）。

## 三、不修复项与理由（供监督方复核）

- **M2 UDP 控制面单调读环**：pion 内部单 goroutine 读环无本地包装点；包装我方 PacketConn 做 STUN 预滤+桶会把防御建立在「pion 未来协议形态」假设上，增益低于引入偏差的风险；TCP 侧（#6 H1）已封最危险的 FD 耗尽面。白方升级 pion 后建议上游跟进。
- **obs9 手机互 vouch/epoch 驱逐**：products semantic（文档明文 + TestPairingNetwork 钉死）；LAN1 高危核心（伪造 desktop 重聚结抹除）已死。
- **obs2 guard 截断 2000 字符**：工具参数截断不改变 ACL 语义；完整注入面属 agent runtime 职责，超靶场范围。
- **obs6/obs7 pion Refresh EVEN-PORT 放大 / 每分配 permission 无上限**：上游内部行为，无 API 可挂本地钩子。
- **obs4 ReloadACL 快照竞态**：仅自伤（本地并发 reload），非攻击者可控路径。
- **obs10 证书 Issuer 未 pin**：官方部署一律显式配置 issuer，契约已在文档；防御在部署侧。
- **obs11 TURN 无带宽限制**：HANDOFF §5.2 已记录的已知边界。
- **obs12 模糊负结果**：延续监视即可。
- **VR-SEC-08/11/12/13**：按章程为保留项，不修改。
- **LAN4/LAN6**：名册对只读成员可见性与过期 locator 元数据残留，配对语义内的低危项，记录不改码。
- **fuzz scouts 无法执行**的教训：scout 会话无 exec 工具，模糊与 -race 全部由主会话本人执行（上文输出均为主会话真实产物）。

## 四、改动面（最终）

`git diff --stat`（真实数字）：**18 个修改文件，+484/−113 行**；另有 **9 个新文件**：internal/dialretry/{dialretry.go,dialretry_test.go}、internal/signal/{limit.go,self_acl_test.go}、internal/ice/{tcp_limit.go,tcp_limit_test.go}、adapter/desktop/quota_test.go、adapter/selfrelay/lan_limits_test.go、internal/pairnet/merge_test.go。既有测试零删除、零跳过、零弱化（`TestActivitySelfHostedEndToEnd` 契约按修复语义更新：无配对 → 403，正是红方漏洞的反向钉死；`TestDesktopToDesktopGrantControl…` 与共享 helper 一字未动）。

蓝队 Phase 2 修复完毕
