# Vanora Relay Security Test Suite

可重复执行的隔离安全测试套件，覆盖信令鉴权、WebRTC/TURN 安全边界、桌面端访问控制、自建与局域网配对、协议模糊测试以及 Linux 网络命名空间隔离靶场。

## 目录与测试分布

- `test/security/internal/sectest/`：通用断言约定（`Finding`、`Strict`、`Heavy`）。
- `test/security/signal_test.go`：基于内存态 `httptest` 与真实 loopback `ice.Server` 的信令安全测试（Bearer Token、PoP、重放、证书/租约校验、跨连接注入、速率/帧大小限制、空占槽位与链路槽位耗尽、输出队列压力测试、陈旧连接重连窗口）。
- `test/security/ice_test.go`：STUN/TURN 授权策略与每访客配额上限校验。
- `test/security/lan_test.go`：局域网配对权限不可提权与一次性邀请不消耗校验。
- `test/security/fuzz_test.go`：协议线格式、证书、租约、公钥、自建/局域网链接解析的 Go 原生模糊测试。
- `test/security/lab/{main.go,run.sh}`：基于 WSL2 Debian + `unshare` + `ip netns` 的无外网转发隔离靶场（验证内网段/元数据过滤、非公开绑定 IP 探测、撤权后凭据失效、并发 Allocation 竞态、自建模式 TURN 续期）。
- `adapter/desktop/security_test.go`：桌面端会话/审批隔离测试（需要访问同包内测桩如 `newTestEnv`、`fakePeer`；同样遵循 `FINDING` / `VANORA_SECURITY_STRICT` 约定）。
- `adapter/selfrelay/security_test.go`：自建中转配对绑定与连接标识覆盖测试（需要访问同包内 `Server` 内部链接表；同样遵循 `FINDING` / `VANORA_SECURITY_STRICT` 约定）。

## 运行约定

1. **默认模式（CI 安全门禁不阻塞未修复的已知弱点）**
   - 所有测试均按**应有安全行为**编写断言。
   - 对已知尚未修复的弱点，复现后调用 `Finding(t, "VR-SEC-NN", ...)`，默认记录 `FINDING VR-SEC-NN: ...` 并 `t.Skipf`，使常规 `go test ./...` 保持通过。
   ```sh
   go test ./... -count=1
   ```

2. **严格模式（回归验证）**
   - 设置 `VANORA_SECURITY_STRICT=1` 后，所有已知 `VR-SEC-*` 弱点均改为 `t.Fatalf`，修复任意一项后即可作为回归测试强制守护：
   ```sh
   VANORA_SECURITY_STRICT=1 go test ./test/security/... ./adapter/... -count=1
   ```

3. **高资源消耗测试**
   - 涉及大批量 WebSocket 建连（如 1024 预认证槽位占满）的测试默认跳过，设置 `VANORA_SECURITY_HEAVY=1` 启用（单次上限 <=1100 sockets、<=30s）：
   ```sh
   VANORA_SECURITY_HEAVY=1 VANORA_SECURITY_STRICT=1 go test ./test/security -run TestSignalPreAuthSlotExhaustion -v -count=1
   ```

4. **模糊测试**
   ```sh
   go test ./test/security -run '^$' -fuzz '^Fuzz' -fuzztime 60s
   ```

5. **WSL2 网络命名空间隔离靶场**
   在 Windows 上交叉编译 Linux amd64 二进制后，在 WSL2 Debian root 下运行隔离命名空间脚本：
   ```powershell
   $env:GOOS='linux'; $env:GOARCH='amd64'
   go build -o seclab-bin/relay ./cmd/relay
   go build -o seclab-bin/seclab ./test/security/lab
   ```
   ```sh
   # 在 WSL2 root 中（unshare + netns，不开启 ip_forward）
   bash /mnt/c/<repo>/test/security/lab/run.sh /tmp/seclab-bin
   ```
