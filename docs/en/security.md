# Security Model & Verification Guide

[← Protocol Reference](protocol.md) · [Docs Hub](README.md) · [Architecture Design →](design.md) · [简体中文](../security.md) | **English**

**Vanora Relay** is engineered around a **Zero-Trust Relay** threat model: relay nodes coordinate signaling and forward encrypted bytes only. Even if a signaling relay, network intermediary, or membership backend is compromised, an attacker cannot decrypt AI conversations, extract local model API keys, forge a paired desktop identity, or bypass local ACLs.

---

## 1. Four-Layer Security Architecture

| Layer | Threat Mitigated | Core Controls |
| :--- | :--- | :--- |
| **1. Identity & Pairing** | Endpoint impersonation, cross-site privilege crossover, invite replay | Official channels pin per-site Ed25519 keys (+ optional `RELAY_ALLOWED_ISSUER`) for short-lived `vanc1` certs and `<= 60s` `vanl1` leases; self-hosted & LAN use local Ed25519 keys + one-time HMAC proofs |
| **2. Signaling & Routing** | Pre-auth slot exhaustion, link flooding, SDP tampering | Separate pre-auth and authenticated connection pools; bounded accepted & pending links per desktop; endpoint-signed `rtc.offer` / `answer` / `candidate` bound to connection ID, round, seq, and nonce |
| **3. Transport & TURN** | Eavesdropping, internal SSRF pivoting, relay quota abuse | Signed WebRTC DTLS fingerprint verification; TURN global-unicast IPv4 allowlist + host interface IP blocking + per-visitor grant caps + atomic concurrent allocation quotas |
| **4. Desktop ACL & Execution** | Unauthorized reads, cross-guest approval leakage, silent escalation | Local `desktop.json` sole allowlist + independent `lan_access` / `self_access` gates; owner/initiator isolation on approval replay & run cancel; fail-closed exit on config parse failure |

---

## 2. Cryptographic & Isolation Guarantees

### Zero-Custody Model Keys & Conversation Content
- Provider API keys and model credentials stay exclusively inside your desktop's local Vanora configuration—they **never enter relay servers, pairing QR codes, or identity backends**.
- Prompts, model reasoning, tool parameters, and file diffs traverse end-to-end encrypted WebRTC DataChannels (or LAN mutual-TLS WebSockets) only; TURN forwards opaque DTLS ciphertext.

### MITM & Replay Resistance
- Both peers sign WebRTC negotiation envelopes containing **DTLS fingerprints**, both endpoint identities, target desktop ID, desktop nonce, and round number. Tampered SDPs, swapped fingerprints, or replayed handshakes are rejected before any DataChannel business frame is accepted.
- 16-character manual pairing codes encrypt the invitation URI end-to-end with `AES-256-GCM` before posting to the relay; the server stores only a hashed `locator` and opaque `box`.

### Site Isolation & Real-Time Authority Cutoff
- **Strict CN / GLOBAL Separation**: Each official site deploys an independent identity authority keypair and entitlement service. Cross-site certificates fail at `auth.login`, and misconfigured cross-site env vars fail fast at startup.
- **Liveness Leases**: Official peers exchange `<= 60s` leases inside the DataChannel. If the desktop loses contact with its identity authority, new sessions and tool execution stop immediately while read-only access caps at 60 seconds.
- **Least Privilege & Anti-Escalation**: Transitive PairNet peers on `lan` / `self` default to `read` only. An already-paired `read` peer submitting a `control` invitation neither escalates privileges nor consumes the invitation.

---

## 3. Defense-in-Depth Quotas & Protections

| Control | Default Limit / Behavior | Purpose |
| :--- | :--- | :--- |
| **Pre-Auth Signaling Pool** | `256` global / `16` per source IP (HTTP `429`) | Isolated from the `1024` authenticated pool so unauthenticated sockets cannot starve valid users |
| **Frame & Rate Limits** | `200 KiB` max frame / `120 msg/s` | Mitigates oversized frame and message flooding attacks |
| **Self-Hosted Host Link Caps** | `32` accepted / `32` pending / `2` per `(caller, host)` / `16` per `(IP, host)` | Prevents a client holding `RELAY_SELF_TOKEN` from blocking legitimate paired phones with pending requests |
| **Replay `connection_id` Guard** | Desktop tracks last `4096` seen connection IDs | Silently drops replayed `connect.request` frames from a rogue relay so live links are never overwritten |
| **TURN Peer Filter** | Public unicast IPv4 only + blocks all host interface IPs | Blocks TURN pivoting into RFC 1918 LANs, cloud metadata (`169.254.169.254`), and secondary host NICs |
| **TURN Quotas** | `TURN_MAX_GRANTS=4096` / `TURN_MAX_GRANTS_PER_VISITOR=32` / `TURN_MAX_ALLOCATIONS_PER_GRANT=8` | Atomic quota reservation eliminates concurrent `Allocate` races and caps single-visitor exhaustion |

---

## 4. Reproducible Security Tests & Labs

This repository ships an automated, isolated security test suite (see [test/security/README.md](../../test/security/README.md)) covering signaling auth, TURN boundaries, multi-guest desktop ACL isolation, protocol fuzzing, and Linux network-namespace labs.

### 1. Standard & Strict Regression Gate

```sh
# Standard unit & integration checks
go vet ./...
go test ./... -count=1

# Strict + heavy security gate (includes 1024-socket pre-auth pressure & all VR-SEC assertions)
VANORA_SECURITY_STRICT=1 VANORA_SECURITY_HEAVY=1 go test ./... -count=1
```

### 2. Native Go Fuzzing (4 Targets)

Covers protocol wire decoding/verification, certificate/lease verification, public key & self-proof parsing, and self-relay/LAN URI parsing:

```sh
go test ./test/security -run '^$' -fuzz '^FuzzProtocolDecodeAndVerify$' -fuzztime 60s
go test ./test/security -run '^$' -fuzz '^FuzzIdentityVerifyCertificateAndLease$' -fuzztime 60s
go test ./test/security -run '^$' -fuzz '^FuzzIdentityParsePublicKeyAndSelfProof$' -fuzztime 60s
go test ./test/security -run '^$' -fuzz '^FuzzSelfRelayAndLANTargetParse$' -fuzztime 60s
```

### 3. Dependency Vulnerability Scan

```sh
go run golang.org/x/vuln/cmd/govulncheck@latest -show verbose ./...
```

### 4. Linux / WSL2 Isolated Network-Namespace Labs

Verifies private/metadata IP rejection, primary & secondary host-IP blocking, 16-way concurrent TCP TURN `Allocate` quota enforcement, live revocation cutoffs, and E2E UDP/TCP TURN paths with `ip_forward=0`:

```sh
# 1. Cross-compile Linux amd64 binaries
GOOS=linux GOARCH=amd64 go build -o /tmp/vanora-lab/relay ./cmd/relay
GOOS=linux GOARCH=amd64 go build -o /tmp/vanora-lab/seclab ./test/security/lab
GOOS=linux GOARCH=amd64 go build -o /tmp/vanora-lab/relaye2e ./test/relaye2e

# 2. Run inside Linux / WSL2 root
VANORA_SECURITY_STRICT=1 bash test/security/lab/run.sh /tmp/vanora-lab
bash test/relaye2e/run.sh /tmp/vanora-lab
```

---

## 5. Known Boundaries & Deployment Recommendations

- **Real-World NAT Verification**: Repo labs run over loopback and Linux network namespaces; verify public deployments using real cellular and residential networks.
- **Reverse-Proxy Source IP Rate Limiting**: Signaling ignores `X-Forwarded-For` to prevent spoofing. When routing through a local reverse proxy, be aware of the shared loopback pre-auth cap (`16`) and per-host pending cap (`16`) (see [Deployment Guide §5](deployment.md#5-operations-rate-limits--runtime-behavior)).
- **TURN Bandwidth Shaping**: `internal/ice` logs accurate deduplicated byte counts without built-in per-grant bandwidth throttling; pair public high-volume deployments with host `tc` or cloud network limits.
- **Windows Vault Storage**: Encrypted vaults rely on per-user NTFS directory ACLs and Windows Credential Manager; never place `-state-dir` in a shared directory.
