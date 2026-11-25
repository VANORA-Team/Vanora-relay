# Desktop Adapter Guide (`vanora-desktop`)

[← Server Deployment](deployment.md) · [Docs Hub](README.md) · [Mobile SDK →](mobile.md) · [简体中文](../desktop.md) | **English**

`vanora-desktop` runs on your computer in a dual role:

- **Controlled Host**: Supervises the local Vanora RPC process, enforces workspace/session/tool ACLs, and exposes controlled AI capabilities to mobile apps or other computers.
- **Remote Controller**: Embeds outbound multi-desktop control (Sidecar `remote.*` JSONL commands and standalone `vanora-desktop ctl` CLI) over encrypted WebRTC DataChannels (`cn` / `global` / `self`) or LAN mutual-TLS WebSockets (`lan`).

---

## 1. Build & Standalone CLI

```sh
# Linux / macOS
go build -o vanora-desktop ./cmd/vanora-desktop

# Windows
go build -o vanora-desktop.exe ./cmd/vanora-desktop
```

### Subcommands

| Subcommand | Purpose |
| :--- | :--- |
| `login` | Enrolls the desktop's Ed25519 key for an official site (`cn` / `global`) using an existing host token (`self` is account-free and does not use `login`) |
| `serve` | Runs the desktop host service (standalone or `-sidecar` embedded mode; also handles outbound `remote.*` commands) |
| `ctl` | Standalone CLI for pairing and controlling remote desktops (`pair` / `peers` / `workspaces` / `sessions` / `create` / `open` / `run` / `cancel`) |
| `whoami` / `status` | Prints enrollment status, `user_id`, and `device_id` for one or both official slots |
| `logout` | Resets local keys for the targeted official site without affecting other channels |

### Quick Start Examples

```sh
# 1. Enroll an official channel (stdin recommended; host token is never persisted or logged)
printf '%s\n' "$CN_CLIENT_TOKEN" | ./vanora-desktop login \
  -channel cn \
  -cn-identity https://cn-identity.example.com \
  -cn-ca cn-identity-signing-key.pub \
  -token-stdin

# 2. Serve on the official CN channel
./vanora-desktop serve \
  -channel cn \
  -cn-identity https://cn-identity.example.com \
  -cn-ca cn-identity-signing-key.pub \
  -cn-signal wss://cn-relay.example.com/v1/signal \
  -config desktop.json \
  -name Office

# 3. Serve on an account-free self-hosted relay
./vanora-desktop serve \
  -channel self \
  -self-signal wss://relay.example.com/v1/signal \
  -self-token "$RELAY_SELF_TOKEN" \
  -config desktop.json \
  -name HomePC
```

> [!NOTE]
> Supply official host tokens via `-token-stdin` (recommended), `VANORA_CLIENT_TOKEN`, or `-token`. Standalone runs remain backward-compatible with legacy single-channel flags (`-identity`, `-ca`, `-ca-hex`, `-signal`, stored in `account.enc`).

### Channel-Isolated Vault Layout

Default `-state-dir` is `<UserConfigDir>/Vanora/relay` (encryption keys live in the OS keyring under service `"Vanora Desktop Relay"`):

| File / Dir | Contents |
| :--- | :--- |
| `account-cn.enc` | CN site Ed25519 private key, certificate, refresh handle, and PairNet roster |
| `account-global.enc` | GLOBAL site Ed25519 private key, certificate, refresh handle, and PairNet roster |
| `self.enc` | Self-hosted device key, paired device allowlist, and PairNet roster |
| `lan.enc` | LAN mTLS server key, paired LAN device allowlist, and PairNet roster |
| `sessions/` | Persisted session replay logs and run metadata (`state.json`) |
| `profile.lock` | Exclusive lock preventing concurrent processes from corrupting encrypted state |

<details>
<summary>Expand full vanora-desktop environment variable reference</summary>

| Variable | Flag | Description |
| :--- | :--- | :--- |
| `VANORA_RELAY_CHANNEL` | `-channel` | Active channel: `cn` / `global` / `self` (`ctl` also accepts `lan`) |
| `VANORA_CLIENT_TOKEN` | `-token` | Official host client auth token |
| `VANORA_RELAY_CN_IDENTITY_URL` | `-cn-identity` | CN identity authority URL |
| `VANORA_RELAY_CN_CA_PUBLIC_KEY` | `-cn-ca-hex` | CN pinned Ed25519 public key (hex or base64) |
| `VANORA_RELAY_CN_SIGNAL_URL` | `-cn-signal` | CN signaling WebSocket URL |
| `VANORA_RELAY_GLOBAL_IDENTITY_URL` | `-global-identity` | GLOBAL identity authority URL |
| `VANORA_RELAY_GLOBAL_CA_PUBLIC_KEY` | `-global-ca-hex` | GLOBAL pinned Ed25519 public key (hex or base64) |
| `VANORA_RELAY_GLOBAL_SIGNAL_URL` | `-global-signal` | GLOBAL signaling WebSocket URL |
| `VANORA_RELAY_SELF_SIGNAL_URL` | `-self-signal` | Self-hosted signaling URL (or `IP:PORT` for bare LAN codes in `ctl pair`) |
| `VANORA_RELAY_SELF_TOKEN` | `-self-token` | Self-hosted relay bearer token (alias `-signal-token` / `VANORA_RELAY_SIGNAL_TOKEN`) |
| `VANORA_RELAY_IDENTITY_URL` / `CA_PUBLIC_KEY` / `SIGNAL_URL` | `-identity` / `-ca-hex` / `-signal` | Legacy single-channel flags |

</details>

---

## 2. Sidecar Mode (Dual-Site Slots & Hot-Switching)

Embed `vanora-desktop serve -sidecar` inside a host desktop app to drive it over newline-delimited JSON (JSONL) via `stdin`/`stdout`:

### Build-Time Dual-Site Defaults

Inject both CN and GLOBAL public endpoints & pinned public keys via `-ldflags` (no private keys; overridable at runtime via flags or env vars):

```sh
go build -ldflags "\
  -X main.defaultCNIdentityURL=... -X main.defaultCNSignalURL=... -X main.defaultCNCAHex=... \
  -X main.defaultGlobalIdentityURL=... -X main.defaultGlobalSignalURL=... -X main.defaultGlobalCAHex=..." \
  -o vanora-desktop ./cmd/vanora-desktop
```

### Runtime Architecture

- **Single Active WAN + Concurrent LAN**: At most one WAN relay (`cn`, `global`, or `self`) is active at a time alongside optional concurrent `lan` hosting. Sending `access.relay.set` hot-switches the WAN channel **without restarting the Sidecar**, disrupting running local tasks, dropping `lan` clients, or erasing another site's enrolled keys.
- **Structured JSONL Events & Clean Exit**: Emits structured `stdout` events (`ready`, `online`, `offline`, `auth.ok`, `auth.error`, `auth.required`, `auth.logout.ok`, `access.status`, `peer.connected`, `session.created`, `ui.request`, `config.reloaded`, `shutdown`, etc.) and exits cleanly when the parent closes `stdin` (EOF).

| Channel | Sign-In Required | Auth & Trust Root | TURN Entitlement | Exposed Desktop Resources |
| :--- | :--- | :--- | :--- | :--- |
| `cn` | CN site sign-in | CN identity authority + CN key | CN entitlement only | Owned by current CN user (`"owner": "local"` or `user_id`) + `users` grants |
| `global` | GLOBAL site sign-in | GLOBAL identity authority + GLOBAL key | GLOBAL entitlement only | Owned by current GLOBAL user (`"owner": "local"` or `user_id`) + `users` grants |
| `self` | **Account-free** | `RELAY_SELF_TOKEN` + local key PoP + pairing | None | **Pairing-only**: resources with `"self_access": true` |
| `lan` | **Account-free** | Private IP + mutual-TLS + pairing | Direct LAN | **Pairing-only**: resources with `"lan_access": true` |

---

## 3. Sidecar `stdin` Control Commands

Every command is one JSON line and accepts an optional `request_id` echoed back in the response. `access.status` never echoes invitation secrets or relay tokens.

### Channel, Auth & Lifecycle

| `type` | Fields | Behavior |
| :--- | :--- | :--- |
| `access.status` | `request_id?` | Returns `active_channel`, per-channel state (`cn`, `global`, `self`), and `lan` status |
| `auth.token` | `channel: "cn" \| "global"`, `token` | Updates the host token for that site; immediately enrolls/renews if active (never reused across sites) |
| `auth.logout` | `channel: "cn" \| "global"`, `request_id?` | Resets and disconnects only the specified official site; returns `auth.logout.ok` |
| `access.relay.set` | `enabled`, `channel?: "cn" \| "global" \| "self"`, `signal_url?`, `signal_token?` | Starts, stops, or hot-switches the WAN channel |
| `access.lan.set` | `enabled`, `address?` | Starts or stops LAN hosting (pass private `IP:port`, e.g. `192.168.1.42:3773`) |
| `session.collaborators` | `session_id?` | Inspects active run, queued turns, online participants, and pending guest requests for one or all sessions |
| `session.guest.list` | `session_id?` | Lists pending `guest.request` entries for one or all sessions |
| `session.guest.respond` | `session_id`, `guest_request_id`, `action` (`approve`\|`dismiss`), `text?`, `mode_limit?` | Locally approves (with optional prompt edit, `mode_limit`, and automatic turn queuing) or dismisses a guest prompt request |
| `reload` / `status` / `shutdown` | — | Hot-reloads `desktop.json`, returns brief status, or exits gracefully |

### Pairing Invitations & Pairing Network Management

Creating an invitation returns `qr_code` (ready-to-render PNG data URL), `pairing_code` (16-char grouped code), `link` (scannable URI), and `invitation.expires_at` (5-minute TTL):

| `type` | Fields | Behavior |
| :--- | :--- | :--- |
| `access.relay.invite.create` | `channel?`; self adds `access?: "read" \| "control"`, `include_token?: bool` | Creates a one-time invite for the active WAN channel (self defaults to `read` + `include_token: true`) |
| `access.relay.invite.revoke` | `id`, `channel?` | Invalidates both QR link and pairing code |
| `access.relay.client.revoke` / `clients.revoke` | `id?`, `channel?` | Revokes one or all paired WAN devices and closes active connections |
| `access.self.invite.create` / `revoke` | `access?`, `include_token?` / `id` | Compatibility aliases for self-hosted invites |
| `access.self.client.revoke` / `clients.revoke` | `id?` | Revokes self-hosted peer(s), cuts TURN, and cancels their active runs |
| `access.invite.create` / `revoke` | `access?: "read" \| "control"` / `id` | Creates or revokes a LAN invite (pairing code appends `@privateIP:port`) |
| `access.client.revoke` / `clients.revoke` | `id?` | Revokes paired LAN peer(s) and cancels their active runs |
| `access.network.list` | `channel?` (`lan` / `self` / `cn` / `global`) | Returns `access.network` containing all mobile & desktop `members[]` and `self_id` |
| `access.network.remove` | `channel?`, `id` | Removes a member, closes bidirectional links, and syncs revocation to online peers |
| `access.client.access.set` | `channel: "lan" \| "self"`, `id`, `access: "read" \| "control"`, `signal_url?` | Dynamically changes `read` / `control` permission for any online or offline LAN/self member without re-pairing; disconnects active inbound link to take immediate effect |

> [!TIP]
> **PairNet Notice**: Every member in a Pairing Network can manage the roster, and pairing across two existing networks merges them. Inform users in your UI before scanning/entering a code; each desktop continues enforcing its own local ACL independently.

```jsonl
{"type":"access.relay.invite.create","request_id":"inv-1"}
{"type":"access.network.list","channel":"lan","request_id":"list-1"}
{"type":"access.client.access.set","channel":"lan","id":"<member_id>","access":"control","request_id":"acl-1"}
{"type":"access.network.remove","channel":"lan","id":"<member_id>","request_id":"rm-1"}
```

---

## 4. Bidirectional PC-to-PC Remote Control

A single desktop can serve inbound requests while concurrently controlling multiple remote desktops across all 4 channels (`cn`, `global`, `self`, `lan`):

- **Fail-Safe Reverse Access**: On `lan` / `self`, reverse-discovered desktops default to **`read`** only. Grant execution via `"grant_access": "control"` on `remote.pair` (or `-grant-access control` in `ctl pair`), or upgrade later using `access.client.access.set`.
- **Official Channel Isolation**: On `cn` / `global`, `grant_access` does not apply—the target desktop enforces its own `desktop.json` ACL, and TURN entitlement is always verified against the **initiating caller**.

### Option A: Sidecar `remote.*` Commands

Executed asynchronously in dedicated goroutines without blocking local hosting:

| `type` | Key Request Fields | Response / Behavior |
| :--- | :--- | :--- |
| `remote.peers.list` | `channel?` | Returns `remote.peers` (`peer_id`, `channel`, `name`, `address`, `online`, `state`, `path`) |
| `remote.pair` | `input`, `channel?`, `signal_url?`, `signal_token?`, `grant_access?` | Redeems a QR link or 16-char code, syncs PairNet, and connects; returns `remote.paired` |
| `remote.connect` / `disconnect` / `reconnect` | `peer_id`, `channel?` | Connects to a known PairNet desktop / disconnects & pauses retry / reconnects & resumes cursors |
| `remote.workspace.list` | `peer_id`, `channel?` | Lists allowlisted remote workspaces; returns `remote.result` |
| `remote.session.create` / `list` / `open` / `close` | `peer_id`, `workspace_id` or `session_id`, `title?`, `watch_presence?`, `channel?` | Creates session / lists sessions / opens snapshot & subscribes (optional live presence) / unsubscribes & updates presence |
| `remote.session.presence` | `peer_id`, `session_id`, `watch?`, `channel?` | Queries online collaborators on a remote session and toggles live `presence.updated` events |
| `remote.events.resume` / `ack` | `peer_id`, `session_id`, `after_seq` or `seq`, `channel?` | Replays missed events / acknowledges consumed sequence cursor |
| `remote.run.start` / `cancel` | `peer_id`, `session_id`, `text` or `run_id`, `queue_policy?` (`enqueue`\|`reject`), `channel?` | Starts or queues an idempotent remote run / cancels an active or queued run |
| `remote.guest.request` / `respond` | `peer_id`, `session_id`, `text` or `guest_request_id`+`action` (`approve`\|`dismiss`\|`cancel`), `text?`, `mode_limit?` | Submits a gated guest prompt / approves (with optional prompt edit & `mode_limit`), dismisses, or self-cancels |
| `remote.ui.respond` | `peer_id`, `session_id`, `run_id`, `ui_id`, `confirmed`/`value`/`answers`/`cancelled` | Answers a remote tool approval or prompt dialog |

Async `stdout` events: `remote.connection.state`, `remote.event`, `remote.network.updated`, `remote.access.state`, `remote.auth.state`, `remote.subscription.error`, and `remote.error`.

### Option B: Standalone `vanora-desktop ctl` CLI

Ideal for terminals and automation (add `-json` for structured JSONL output):

```sh
# 1. Pair with another desktop over LAN (-grant-access control enables reverse control)
./vanora-desktop ctl pair -channel lan \
  -input "ABCD-EFGH-JKLM-NPQR@192.168.1.42:3773" \
  -grant-access control

# 2. Pair over a self-hosted relay
./vanora-desktop ctl pair -channel self \
  -self-signal wss://relay.example.com/v1/signal \
  -self-token "$RELAY_SELF_TOKEN" \
  -input "ABCD-EFGH-JKLM-NPQR" \
  -grant-access control

# 3. List known remote desktops and run a streaming prompt
./vanora-desktop ctl peers
./vanora-desktop ctl workspaces -peer <peer_id>
./vanora-desktop ctl sessions -peer <peer_id>
./vanora-desktop ctl run -peer <peer_id> -session <session_id> -text "Summarize git status"
```

> [!TIP]
> `ctl` acquires `profile.lock` inside `-state-dir`. If `vanora-desktop serve` is already running against the default state directory, send `remote.*` commands to the running Sidecar or pass a separate `-state-dir` to `ctl`.

---

## 5. Session & Workspace Configuration (`desktop.json`)

`desktop.json` is the sole local allowlist; remote RPC cannot add sessions, pick arbitrary directories, or alter process arguments. You may start with `0` pre-configured `sessions` and rely on `workspaces` for remote session creation. All filesystem paths must be **absolute** (forward slashes `/` work on Windows):

```json
{
  "executable": "node",
  "launcher_args": ["/abs/path/to/vanora/packages/coding-agent/dist/cli.js"],
  "allow_slash_commands": false,
  "max_text_bytes": 65536,
  "max_snapshot_bytes": 16777216,
  "retention": {
    "max_events": 4096,
    "max_bytes": 4194304,
    "max_requests": 4096
  },
  "workspaces": [
    {
      "id": "project",
      "title": "Project Workspace",
      "working_dir": "/abs/path/to/project",
      "owner": "local",
      "lan_access": true,
      "self_access": true,
      "tools": ["read", "edit", "write", "bash", "ask"],
      "show_thinking": true,
      "show_tools": true,
      "approval_policy": "remote"
    }
  ],
  "sessions": [
    {
      "id": "existing",
      "title": "Existing Conversation",
      "working_dir": "/abs/path/to/project",
      "session_file": "/abs/path/to/sessions/project.jsonl",
      "owner": "local",
      "lan_access": true,
      "self_access": false,
      "tools": ["read", "bash"],
      "show_thinking": true,
      "show_tools": true,
      "approval_policy": "remote",
      "users": [
        {
          "user_id": "guest usr_...",
          "read": true,
          "tools": false,
          "show_thinking": false,
          "show_tools": false,
          "approve": false
        }
      ]
    }
  ]
}
```

### Schema Reference

#### Top-Level Fields

| Field | Default / Cap | Description |
| :--- | :--- | :--- |
| `executable` | *(Required)* | Local Vanora binary path, or `node` when paired with `launcher_args` |
| `launcher_args` | Optional | Valid only with `executable: "node"`; single absolute path to a `.js`/`.mjs` entrypoint |
| `arguments` | Optional | Fixed RPC arguments (e.g. model/provider flags; cannot alter session, tools, or mode) |
| `approval_extension` | Built-in guard | Optional absolute path to a custom `.js`/`.mjs` approval guard extension |
| `allow_slash_commands` | `false` | Allows prompts starting with `/` (disabled by default to block unapproved templates/tools) |
| `max_text_bytes` | `64 KiB` (max `1 MiB`) | Max byte size of one remote prompt |
| `max_snapshot_bytes` | `16 MiB` (max `48 MiB`) | Max `session.open` JSON payload; larger histories return `snapshot_too_large` |
| `retention` | `4096` events / `4 MiB` / `4096` reqs | Per-session replay buffer and `request_id` deduplication bounds |

#### Workspace & Session ACL Fields

| Field | Description |
| :--- | :--- |
| `working_dir` / `session_file` | Must be absolute paths, and `working_dir` must match the `cwd` recorded in the session JSONL header |
| `session_dir` *(workspaces only)* | Overrides where new sessions are written; defaults to native Vanora layout `<agent_dir>/sessions/--<encoded-path>--/` (respects `VANORA_SESSION_DIR` / `VANORA_AGENT_DIR`, interoperable with `vanora --resume`) |
| `owner` | `"local"` binds dynamically to the active official channel's user, or specify an explicit `usr_...` |
| `lan_access` / `self_access` | Independent boolean gates (both `false` by default) so LAN-only resources are never accidentally exposed when enabling a public self-hosted relay |
| `tools` | Local tool allowlist; empty `[]` passes `--no-tools` for text-only chat |
| `show_thinking` / `show_tools` | Controls reasoning and tool output visibility for owners and `control` peers (unauthorized viewers receive zero-leak `sync` sequence placeholders) |
| `approval_policy` | `"none"` (default, cancels interactive prompts locally) or `"remote"` (loads approval guard via `--no-extensions -e <guard>` to forward write/destructive tool confirmations & `ask` prompts; timeout configurable via `VANORA_RELAY_APPROVAL_TIMEOUT_MS`, default/cap `300000` ms) |
| `users` | Explicit official-channel guest grants (`read`, `tools`, `show_thinking`, `show_tools`, `approve`) on both `sessions` and `workspaces` |

> [!WARNING]
> **Fail-Closed Hot Reload**: `serve` polls `desktop.json` every second. If parsing fails, the service **immediately revokes authority and exits** to prevent ACL drift. Always update `desktop.json` via atomic write-and-rename.
