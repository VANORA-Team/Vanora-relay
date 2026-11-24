# Server Deployment & Operations Guide

[← Docs Hub](README.md) · [Home](../../README.en.md) · [Desktop Adapter →](desktop.md) · [简体中文](../deployment.md) | **English**

This guide covers deploying and operating `relay` (the unified WebSocket signaling + STUN/TURN server), including channel mode selection, environment variables, production reverse-proxy & firewall configuration, and the official entitlement API contract.

> **Requirement**: **Go 1.26+** minimum (default repository toolchain: `go1.27.4`).

---

## 1. Choose a Relay Mode (`RELAY_CHANNEL`)

`RELAY_CHANNEL` determines the authentication model and isolation boundary. Misconfiguring variables that belong to another channel causes `relay` to fail fast at startup:

| Mode | `RELAY_CHANNEL` | Authentication | TURN Entitlement Check | External Dependencies |
| :--- | :---: | :--- | :---: | :--- |
| **Self-Hosted** | `self` | `RELAY_SELF_TOKEN` gate + endpoint Ed25519 PoP + one-time desktop pairing | Skipped (10-min sliding renewal) | **None** |
| **CN Official** | `cn` *(default)* | CN site Ed25519 public key (optional `RELAY_ALLOWED_ISSUER`) | CN entitlement service only | CN identity + CN entitlement |
| **GLOBAL Official** | `global` | GLOBAL site Ed25519 public key (optional `RELAY_ALLOWED_ISSUER`) | GLOBAL entitlement service only | GLOBAL identity + GLOBAL entitlement |

---

## 2. Environment Variables

### Signaling & Channel Settings

| Variable | `self` | `cn` | `global` | Description |
| :--- | :---: | :---: | :---: | :--- |
| `RELAY_CHANNEL` | `self` | default / `cn` | `global` | Selects operating mode and isolation boundary |
| `RELAY_SELF_TOKEN` | **Required** | Forbidden | Forbidden | Shared bearer token (32–512 bytes, no whitespace) sent via `Authorization: Bearer` on WebSocket upgrade |
| `RELAY_IDENTITY_PUBLIC_KEY` | Forbidden | **Required** | **Required** | Ed25519 public key (hex or base64) exported by the site's external identity authority |
| `RELAY_ALLOWED_ISSUER` | Forbidden | Optional | Optional | Defense-in-depth allowlist pinning the exact certificate `iss` origin (HTTPS in prod; loopback HTTP in dev) |
| `RELAY_CN_MEMBERSHIP_URL` / `TOKEN` | Forbidden | **Required*** | Forbidden | CN entitlement endpoint URL and secret token (`>= 32` bytes, no whitespace) |
| `RELAY_GLOBAL_MEMBERSHIP_URL` / `TOKEN` | Forbidden | Forbidden | **Required*** | GLOBAL entitlement endpoint URL and secret token (`>= 32` bytes, no whitespace) |
| `RELAY_MEMBERSHIP_URL` / `TOKEN` | Forbidden | Fallback | Fallback | Legacy fallback used only when both site-specific vars for the current official channel are unset |
| `RELAY_ADDR` | Optional | Optional | Optional | Signaling bind address, default `127.0.0.1:8787`; non-loopback listeners require TLS |
| `RELAY_TLS_CERT` / `RELAY_TLS_KEY` | Optional | Optional | Optional | Direct TLS cert & key file paths (must be configured as a pair) |

### STUN / TURN Settings

| Variable | Default | Description |
| :--- | :--- | :--- |
| `TURN_PUBLIC_IP` | *(Required)* | Public IPv4 advertised in TURN URLs and relay addresses (`127.0.0.1` for local dev) |
| `STUN_URLS` | MiWiFi + Bilibili public STUN | Comma-separated `stun:host[:port]`; use `local` for built-in STUN, or configure Cloudflare / Google STUN overseas |
| `TURN_PORT` | `3478` | STUN/TURN control port (UDP + TCP enabled by default) |
| `TURN_BIND_IP` / `TURN_RELAY_BIND_IP` | `0.0.0.0` | Local IPv4 for control listeners and relay sockets |
| `TURN_RELAY_MIN_PORT` / `TURN_RELAY_MAX_PORT` | `49152` / `65535` | Inclusive UDP port range for relayed media (open in firewall) |
| `TURN_MAX_GRANTS` | `4096` | Global concurrent TURN grant limit (`1..1,000,000`) |
| `TURN_MAX_GRANTS_PER_VISITOR` | `min(32, max(1, MAX/2))` | Active grant cap per visitor (default `32`) to prevent global quota exhaustion |
| `TURN_MAX_ALLOCATIONS_PER_GRANT` | `8` | Max concurrent TURN allocations per credential (`1..1024`) |
| `TURN_LOG_LEVEL` | `error` | `disabled` / `error` / `warn` / `info` / `debug` / `trace` |

> [!NOTE]
> See [internal/ice/README.md](../../internal/ice/README.md) for `TURN_UDP`, `TURN_TCP`, `TURN_REALM`, peer filtering, and deduplicated byte accounting details.

---

## 3. Self-Hosted Node (`RELAY_CHANNEL=self`, Account-Free)

Self-hosted nodes require **no Vanora account, no external identity server, and no entitlement service**. Two layers protect your node and computers:

1. **Node Gate (`RELAY_SELF_TOKEN`)**: Prevents strangers who learn your URL from using signaling or TURN; missing or wrong `Authorization: Bearer` receives HTTP `401`.
2. **One-Time Device Pairing (Pairing-Only)**: Endpoints generate local Ed25519 keys and prove possession on login; a caller must redeem a desktop-issued one-time QR code / pairing code (verified via HMAC) before WebRTC succeeds. Desktops only expose resources explicitly marked `"self_access": true`, and revoking a device immediately terminates active TURN sockets.

### Production Setup (Linux + systemd + TLS Reverse Proxy)

Assuming domain `relay.example.com` and service user `vanora`:

#### Step 1: Build & Install

```sh
go build -o relay ./cmd/relay
sudo install -m 0755 relay /usr/local/bin/relay
```

#### Step 2: Create Environment File

Write `/etc/vanora-relay.env` and set permissions to `0600` (`sudo chmod 600 /etc/vanora-relay.env`):

```sh
RELAY_CHANNEL=self
RELAY_SELF_TOKEN=<output of openssl rand -base64 32>
TURN_PUBLIC_IP=<server public IPv4>
RELAY_ADDR=127.0.0.1:8787
STUN_URLS=local
TURN_RELAY_MIN_PORT=49160
TURN_RELAY_MAX_PORT=49200
```

#### Step 3: Configure systemd

Create `/etc/systemd/system/vanora-relay.service`:

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

#### Step 4: Terminate TLS with a Reverse Proxy

Keep `RELAY_ADDR` on loopback (`127.0.0.1:8787`) behind Caddy or Nginx.

> [!IMPORTANT]
> `/v1/signal` serves **WebSocket upgrades**, desktop pairing registration (**HTTP `POST`**), and pairing-code lookup (**HTTP `GET ?pairing=...`**). Route all three to the same `relay` process, preserve `Authorization` and `Vanora-Desktop` headers, and disable response caching.

**Caddy (minimal recommended):**

```caddyfile
relay.example.com {
	reverse_proxy 127.0.0.1:8787
}
```

**Nginx (handles both WebSocket upgrade and plain HTTP pairing requests):**

```nginx
# Inside http {}
map $http_upgrade $connection_upgrade {
	default upgrade;
	''      close;
}

# Inside server {}
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

#### Step 5: Firewall & NAT Port Forwarding

| Port / Protocol | Direction | Exposure | Purpose |
| :--- | :---: | :--- | :--- |
| `TCP 443` | Inbound | Public | Reverse-proxy HTTPS / WSS signaling |
| `TCP 8787` | Local only | `127.0.0.1` | Internal `relay` listener (**do not expose publicly**) |
| `UDP + TCP 3478` | Inbound | Public | STUN / TURN control (`TURN_PORT`) |
| `UDP 49160–49200` | Inbound | Public | TURN media relay range (`TURN_RELAY_MIN/MAX_PORT`) |

#### Step 6: Verify & Pair Clients

```sh
curl -fsS https://relay.example.com/healthz
# Expected output: ok
```

Start your desktop with `-channel self` (or via Sidecar `access.relay.set`), send `access.relay.invite.create` to produce a one-time QR code / pairing code, and pair from mobile (`NewSelfRelayClient`) or another computer (`vanora-desktop ctl pair`). When rotating `RELAY_SELF_TOKEN`, update both the server and client configurations.

---

## 4. Official Channels (CN / GLOBAL Strict Isolation)

Official nodes trust **only their own site's** external identity public key and entitlement backend. Accounts, certificates, and TURN entitlements are never shared across CN and GLOBAL:

- **Independent Trust Roots**: CN and GLOBAL run separate external identity authorities with distinct Ed25519 keys (see [internal/identity/README.md](../../internal/identity/README.md)); cross-site certificates are rejected during `auth.login`.
- **Fail-Fast Guards**: Setting `RELAY_GLOBAL_MEMBERSHIP_*` on a `cn` node (or vice versa) aborts startup. Pinning `RELAY_ALLOWED_ISSUER` is recommended as defense in depth.

<details>
<summary>Expand CN / GLOBAL official startup examples</summary>

```sh
# CN Official Node
export RELAY_CHANNEL=cn
export RELAY_IDENTITY_PUBLIC_KEY="<CN authority Ed25519 public key>"
export RELAY_ALLOWED_ISSUER="https://cn-auth.example.com/realms/vanora"
export RELAY_CN_MEMBERSHIP_URL="https://cn-entitlement.internal.example.com"
export RELAY_CN_MEMBERSHIP_TOKEN="<random >=32-byte service token>"
export TURN_PUBLIC_IP="<public IPv4>"
export STUN_URLS="local"

./relay
```

```sh
# GLOBAL Official Node
export RELAY_CHANNEL=global
export RELAY_IDENTITY_PUBLIC_KEY="<GLOBAL authority Ed25519 public key>"
export RELAY_ALLOWED_ISSUER="https://global-auth.example.com/realms/vanora"
export RELAY_GLOBAL_MEMBERSHIP_URL="https://global-entitlement.internal.example.com"
export RELAY_GLOBAL_MEMBERSHIP_TOKEN="<random >=32-byte service token>"
export TURN_PUBLIC_IP="<public IPv4>"
export STUN_URLS="local"

./relay
```

</details>

### Entitlement Verification API (Official Channels Only)

`relay` has no built-in subscription database. On connection setup and `ice.refresh`, it queries the site's entitlement service (HTTP redirects are disabled; `/internal/v1/relay/entitlement` is appended automatically if absent):

```http
POST /internal/v1/relay/entitlement
Authorization: Bearer <RELAY_CN_MEMBERSHIP_TOKEN | RELAY_GLOBAL_MEMBERSHIP_TOKEN>
Content-Type: application/json
```

```json
// Request
{
  "issuer": "https://auth.example.com/realms/vanora",
  "subject": "<account subject>"
}

// Response (valid_until is Unix seconds)
{
  "success": true,
  "data": {
    "relay_allowed": true,
    "valid_until": 1767225600
  }
}
```

Contract rules:

- **Caller-Based Authorization**: Entitlement is always checked for the **initiating caller** (phone or controlling desktop); the target desktop owner's subscription never unlocks TURN for a guest.
- **Fail-Closed Fallback**: TURN credentials are issued only when `success: true`, `relay_allowed: true`, and `valid_until` is in the future; timeouts, errors, or expired plans automatically degrade to STUN-only direct attempts.
- **Bounded Lifetime**: Each TURN grant is also capped by the caller's certificate expiry and terminated immediately on expiry or revocation.

---

## 5. Operations, Rate Limits & Runtime Behavior

| Topic | Behavior & Operational Notes |
| :--- | :--- |
| **Single-Instance Design** | v1 runs as a single-region process with in-memory state. After a restart, endpoints automatically reconnect and renegotiate. |
| **Coordinated Upgrades** | Upgrade the relay, desktop Sidecar, and mobile SDK together when rolling out Pairing Network features. |
| **Pre-Auth Rate Limits & Reverse Proxies** | Unauthenticated WebSockets enter a dedicated pre-auth pool (`256` global, `16` per source IP, HTTP `429` when full) before graduating to the authenticated pool (`1024`). Source IP is read directly from `r.RemoteAddr` (`X-Forwarded-For` is **not trusted** to prevent header spoofing). Behind a local loopback proxy (`127.0.0.1`), all clients share one source IP, capping simultaneous mid-handshake connections at `16` and pending unaccepted `connect.request` links per desktop at `16` (normal handshakes complete in tens of milliseconds). |
| **Host Interface IP Filtering** | `ice.Server` snapshots `net.InterfaceAddrs()` at startup and blocks all local NIC IPs (except same-connection `TURN_PUBLIC_IP` hairpin) plus private/loopback/reserved ranges. Restart `relay` if new public elastic IPs are attached dynamically. |
| **Relay Byte Logs** | Deduplicated payload byte counts are logged via `slog.Info` when each grant closes (excluding TURN overhead and direct P2P traffic). Collect structured logs externally if billing history is needed. |
| **Restricted Firewalls** | TURN control supports UDP and TCP, while relayed media uses UDP; environments that allow only outbound HTTPS (`443/tcp`) may still block TURN. |
