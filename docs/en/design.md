# Architecture Design & Acceptance Matrix

[← Security Model](security.md) · [Docs Hub](README.md) · [Home](../../README.en.md) · [简体中文](../../DESIGN.md) | **English**

This document outlines the core design principles, component trust boundaries, connection/revocation semantics, and end-to-end acceptance matrix of **Vanora Relay**. For deployment instructions, client guides, and wire specifications, see the [Documentation Hub](README.md).

---

## 1. Four-Channel Connectivity Model

- **LAN Direct (`lan`)**: When devices share a local network, they pair via a one-time invitation. The desktop listens on a private IP over mutual-TLS WebSocket and checks peer device keys, while callers pin the desktop's public key fingerprint from the invitation. Fully independent from Vanora accounts and gated by `lan_access`.
- **CN Official (`RELAY_CHANNEL=cn`)**: Accepts only CN-issued endpoint certificates and verifies TURN entitlements solely against the CN entitlement service.
- **GLOBAL Official (`RELAY_CHANNEL=global`)**: Accepts only GLOBAL-issued endpoint certificates and verifies TURN entitlements solely against the GLOBAL entitlement service. Both sites maintain separate Ed25519 trust roots (+ optional `RELAY_ALLOWED_ISSUER`) with zero cross-site sharing.
- **Self-Hosted (`RELAY_CHANNEL=self`)**: User-managed authentication with zero official accounts or external identity/entitlement backends. Protected by `RELAY_SELF_TOKEN` plus local Ed25519 keys and one-time HMAC pairing, gated by `self_access`.

**Models and Relays Are Decoupled**: Desktops may stay logged into multiple model providers simultaneously and pair any local model with any relay channel. The desktop Sidecar hot-switches one active WAN channel (`cn` / `global` / `self`) alongside concurrent `lan` access while storing credentials in separate vaults (`account-cn.enc` / `account-global.enc` / `self.enc` / `lan.enc`).

---

## 2. Components & Trust Boundaries

| Component | Core Responsibility | Data & Privilege Boundary |
| :--- | :--- | :--- |
| **External Entitlement Service** *(official)* | Evaluates caller subscription eligibility (`relay_allowed`, `valid_until`) | Account ID, plan, expiry; **never holds endpoint signing keys** |
| **External Identity Authority** *(official)* | Validates host client tokens & endpoint PoP; mints `vanc1` certs and `<= 60s` `vanl1` leases | Independent Ed25519 signing key (deployed privately outside this repo) & account status |
| **Signaling Service (`relay`)** | Presence, pairing-code storage, signed WebRTC routing, TURN grant management | Connection/endpoint IDs and network metadata; **cannot read AI text or forge identities** |
| **Public / Built-in STUN** | Helps endpoints discover reachable public candidates | Network addresses only |
| **TURN Relay (`relay`)** | Forwards DTLS ciphertext across restrictive NATs with deduplicated byte accounting | Network addresses, short-lived allocations, payload byte counts |
| **Desktop Adapter (`vanora-desktop`)** | Supervises local Vanora RPC, enforces ACLs, persists sessions, and provides outbound PC-to-PC control (`remote.*` & `ctl`) | Device private key, ACL allowlist, PairNet roster, session logs & runs |
| **Native Mobile App (`mobile` / `native`)** | Enrolls/pairs, pins desktop keys, establishes E2EE links, and drives sessions/approvals | Device private key and caller-visible conversation state |

v1 runs `relay` as a single-region instance. A faulty or malicious relay can drop traffic, but **cannot impersonate a paired endpoint or tamper with the encrypted session**. End-to-end encryption spans the client-to-desktop hop; upstream model calls reuse the desktop's local Vanora configuration.

---

## 3. Identity Binding & v1 Contract Overview

### Official Enrollment Principles
1. **Reuse Host Sign-In**: Endpoints generate Ed25519 keys in OS secure storage and exchange existing host tokens via PoP challenges for short-lived `vanc1` certs—no separate relay passwords or secondary browser logins.
2. **Stable Remote Identity**: Owners authorize guests by immutable `remote_user_id`. Directories assist discovery only; desktops verify signatures and ACLs on every connection. Renaming, changing emails, or recycling handles never transfers permissions.
3. **Explicit Account Switching**: Switching the bound account requires calling `Reset()` to rotate the endpoint key; a new token never silently overwrites an existing binding.

### Contract Surface

`connection_id` identifies one transport link, `session_id` identifies a resumable AI conversation, and `device_id` remains stable across desktop restarts:

| Provider | Endpoint / Messages | Contract & Security Guarantees |
| :--- | :--- | :--- |
| External Identity Authority | `POST /v1/identity/{challenges,enroll,lease,renew}` | Validates host token + PoP; signs short-lived cert & lease ([spec](../../internal/identity/README.md)) |
| External Entitlement Service | `POST /internal/v1/relay/entitlement` | Queried by `relay` for caller `(issuer, subject)`; fails closed to STUN-only |
| Signaling (`relay`) | `WSS /v1/signal`, `POST/GET /v1/signal` | Presence, encrypted pairing-box lookup, pairing & reconnect routing; blocks self-connect |
| Signaling (`relay`) | `rtc.offer`, `rtc.answer`, `rtc.candidate` | Endpoint-signed and bound to `connection_id`, peers, round, and seq; rejects replays |
| Signaling / TURN | `ice.config`, `ice.refresh` | Supplies STUN and optional short-lived TURN credentials strictly by **initiating caller** |
| Desktop | DataChannel `workspace.list`, `session.{create,list,open}`, `run.{start,cancel}`, `ui.respond`, `events.resume` | Re-checks caller permissions and resource ownership on every call |

TURN payload accounting counts each relayed packet once at the peer-facing boundary (deduplicating same-server hairpin traffic and excluding direct P2P traffic).

---

## 4. Routing, Recovery & Revocation Semantics

- **Authenticated Peer Verification**: Peers sign negotiation envelopes containing WebRTC DTLS fingerprints, identities, desktop nonce, and round. No DataChannel business message is accepted until identity and local ACL checks succeed.
- **Parallel Candidate Gathering & Migration**: Entitled connections gather direct and TURN candidates in parallel, allowing TURN to connect first and migrate to direct paths when available. Grant expiry or revocation immediately closes active TURN relay sockets independently of TURN refresh lifetimes.
- **Idempotent Controlled Execution**: Runs are deduplicated by `(caller, session_id, request_id)`, returning the original `run_id` on retry. Tool allowlists and approval guards are enforced at tool invocation time.
- **Offline Continuity**: While authorization remains valid, desktops continue running tasks when callers drop. Reconnecting callers invoke `events.resume(session_id, after_seq)` to catch up seamlessly, or rebuild via `session.open` on `snapshot_required`.
- **Immediate Revocation**: Desktops update local ACLs first, cut affected links, and cancel the revoked guest's active runs (owner tasks continue unaffected; already-executed side effects cannot be rolled back).
- **Authority-Loss Cutoff**: Official desktops losing contact with their identity authority immediately block new sessions and tool execution, capping existing read-only sessions at `60` seconds after the last valid lease.

---

## 5. End-to-End Acceptance Matrix

| Scenario | Pass Criteria |
| :--- | :--- |
| **Caller-Based Entitlement** (owner entitled, guest not; then swapped) | First case grants TURN to neither side; second case allows TURN to reach the non-entitled host |
| **Direct vs. Relay-Only Networks** (cellular/home direct vs. TURN-only symmetric NAT) | Entitled calls stream in both cases; unentitled calls clearly report direct connectivity unavailable when direct fails |
| **Relay-to-Direct Handoff + Idempotent Retry** | Switching networks while retrying the same `request_id` launches exactly one run with zero duplicate events |
| **Negotiation Tampering & Replay** (swapped pubkey/DTLS fingerprint or replayed signature) | Rejected before business framing; compromising signaling or membership alone cannot forge trust |
| **Privilege Probing & Multi-Guest Isolation** (guessed `session_id`, disallowed tools, cross-guest approvals) | Only granted resources are readable; unauthorized actions return `unavailable` or `tool_denied` with strict approval isolation |
| **Mid-Run Disruptions** (caller offline, owner revocation, authority loss) | Offline runs resume cleanly; revocation stops new calls and cancels guest runs; authority loss halts execution immediately and caps read-only at 60s |
| **Plan Expiry & Account Changes** (plan expires mid-relay; handle/email change or password reset) | Active TURN sockets close at expiry; identity renames never transfer access and password resets cannot hijack an enrolled desktop |

---

## References

- [Vanora Coding Agent RPC Docs](https://github.com/VANORA-Team/vanora/blob/main/packages/coding-agent/docs/rpc.md)
- [Vanora Permissions & Containerization](https://github.com/VANORA-Team/vanora#permissions--containerization)
- [Protocol Reference](protocol.md) · [External Identity Contract](../../internal/identity/README.md) · [STUN / TURN Internals](../../internal/ice/README.md)
