# internal/ice

Single-region STUN/TURN edge for Vanora remote connections, built on
[`github.com/pion/turn/v4`](https://github.com/pion/turn).

The package runs one in-process TURN server and one grant table. The signaling
service asks for ICE servers with `Config`, revokes them with `Revoke`, and the
server cuts relaying itself when a grant expires. There is no clustering and no
persistence: a restart drops every grant and clients must reconfigure through
signaling.

## API

```go
srv, err := ice.FromEnv()          // reads STUN_URLS and TURN_* env, starts listeners
defer srv.Close()

servers, err := srv.Config(connectionID, visitor, entitlement.ValidUntil)
// servers is []ice.ICEServer, ready to embed in a /v1/signal response.

srv.Revoke(connectionID)           // closes live allocations immediately
```

`ICEServer` is the standard WebRTC shape:

```json
{"urls": ["stun:stun.miwifi.com:3478", "stun:stun.chat.bilibili.com:3478"]}
{"urls": ["turn:203.0.113.10:3478?transport=udp", "turn:203.0.113.10:3478?transport=tcp"],
 "username": "…", "credential": "…"}
```

`FromEnv` returns an error for a missing public address, an invalid STUN URL,
an invalid port or range, or no enabled control transport. `Close` is idempotent.

## Grant lifecycle

- `Config(connectionID, visitor, until)` with a zero `until` returns STUN only:
  no TURN credential is minted and any existing grant for that connection is
  revoked.
- A non-zero `until` at or before `time.Now()` is treated as already expired:
  the grant is revoked and the caller gets STUN only, so signaling never
  returns a dead credential.
- A positive `until` mints a random TURN username/password (long-term
  credential) for that connection. Every call for the same connection returns
  the same credential, so the desktop and the phone can both configure it.
  Calling again extends the grant to the later `until`.
- A connection belongs to one visitor. Reconfiguring a live connection for a
  different visitor fails with `ErrVisitorMismatch`; the caller must revoke
  first. This keeps one connection's relay traffic attributed to one visitor.
- `Revoke` removes the credential and closes the relay socket of every live
  allocation made with it. The TURN client's allocation refresh fails
  afterwards, and peers can no longer reach the relay address.
- Expiry does the same: a timer fired at `until` closes relay sockets, so
  established relaying stops at the entitlement boundary rather than at the
  client's TURN allocation refresh lifetime (10 minutes by default). The TURN
  username TTL is a second line of defense for new allocations, not the
  mechanism that cuts existing ones.
- `TURN_MAX_GRANTS` bounds the global grant table, `TURN_MAX_GRANTS_PER_VISITOR`
  bounds active grants per visitor (failing with `ErrVisitorGrantLimit`), and
  `TURN_MAX_ALLOCATIONS_PER_GRANT` atomically bounds concurrent allocations per
  credential (reserving pending quota before allocation creation so concurrent
  `Allocate` requests cannot race past the limit).

Removal is logged with `slog.Info` (or delivered to the test hook):

```
turn relay grant removed connection_id=… visitor=… reason=revoked|expired|"not entitled"|"server closed" relay_bytes=… visitor_relay_bytes=…
```

## Byte accounting

The accounting boundary is the **peer-facing relay socket**, not the
client-facing STUN/TURN socket:

- every UDP payload the server writes from the relay socket to a peer is
  counted once (`to_peers`), except a hairpin delivery to another relay socket
  of the same grant, which is counted at the receiving socket instead (see
  below);
- every UDP payload the server reads from a peer on the relay socket is counted
  once (`from_peers`);
- the server's read-from-client and write-to-client paths are identical for
  ChannelData and Data indications; only the inner payload is counted, so
  STUN/channel framing, padding, retransmissions, and TURN control traffic are
  never billed;
- direct peer-to-peer traffic that never traverses the relay is not counted;
- a payload relayed between two allocations of the **same connection** on this
  server is counted once, at the receiving allocation. The sending relay
  socket recognises the destination as a local relay socket owned by the same
  grant and writes it without counting, so a connection whose two endpoints
  both use TURN (or a peer that relays back through the same server) is not
  billed twice. The same-server case is only possible when the host can route
  to its own advertised address (NAT hairpin/loopback); otherwise the two
  relay sockets never exchange packets and nothing is counted twice anyway.

Counters are kept per allocation and folded into the grant and the visitor when
an allocation is deleted, revoked, or expired. State is bounded: at most
`TURN_MAX_GRANTS` grants and `TURN_MAX_ALLOCATIONS_PER_GRANT` allocations per
grant exist, and every grant/allocation/relay-socket record is deleted when its
grant is removed. Visitor totals are deleted when the last grant for that
visitor is removed. The server keeps no historical per-visitor state.

The final counters are emitted on grant removal; the log's `relay_bytes` is the
connection total and `visitor_relay_bytes` is the visitor's running total for
the grants currently active. Emitting a durable usage record is the caller's
job; this package only logs and returns the removal record to the internal test
hook.

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `STUN_URLS` | Channel-specific | Comma-separated `stun:host[:port]` URLs. Use `local` to advertise the in-process STUN server. |
| `TURN_PUBLIC_IP` | *(required)* | Public IPv4 advertised in TURN URLs and relay addresses, and in the STUN URL when `STUN_URLS=local`. |
| `TURN_BIND_IP` | `0.0.0.0` | Local IPv4 for the UDP/TCP control listeners. |
| `TURN_RELAY_BIND_IP` | `TURN_BIND_IP` | Local IPv4 the relay sockets bind to. |
| `TURN_PORT` | `3478` | Control port for both UDP and TCP. `0` picks an ephemeral port (testing only). |
| `TURN_UDP` | `true` | Enable the UDP control listener. |
| `TURN_TCP` | `true` | Enable the TCP control listener. |
| `TURN_RELAY_MIN_PORT` | `49152` | First UDP relay port. |
| `TURN_RELAY_MAX_PORT` | `65535` | Last UDP relay port (inclusive). Set both relay bounds to `0` for ephemeral relay ports. |
| `TURN_REALM` | `vanora` | STUN/TURN authentication realm. |
| `TURN_MAX_GRANTS` | `4096` | Maximum concurrent grants globally (`1..1000000`). |
| `TURN_MAX_GRANTS_PER_VISITOR` | `min(32, max(1, TURN_MAX_GRANTS/2))` | Maximum concurrent active grants per visitor (`1..TURN_MAX_GRANTS`). |
| `TURN_MAX_ALLOCATIONS_PER_GRANT` | `8` | Maximum allocations per credential (desktop + phone + retries, `1..1024`). |
| `TURN_MAX_BYTES_PER_SEC` | `0` | Combined ingress and egress byte rate across a grant's relay sockets. `0` is unlimited. |
| `TURN_MAX_VISITOR_BYTES_PER_SEC` | `0` | Combined ingress and egress byte rate across all active grants for a visitor. `0` is unlimited. |
| `TURN_LOG_LEVEL` | `error` | `disabled`, `error`, `warn`, `info`, `debug`, or `trace`. Pion's `PION_LOG_*` variables may add per-package detail. |

The STUN list goes to both endpoints in `ice.config`. Clients gather candidates
from the configured servers in parallel. Without `STUN_URLS`, `RELAY_CHANNEL=cn`
and an unset channel use `stun:stun.miwifi.com:3478,stun:stun.chat.bilibili.com:3478`.
The `global` channel uses `stun:stun.cloudflare.com:3478,stun:stun.l.google.com:19302`.
The `self` channel uses the in-process STUN server.

When bandwidth limits are enabled, the server drops datagrams that exceed
either limit. Each bucket permits a burst of at least 64 KiB so it can admit
a full-size datagram.

TURN URLs advertise `TURN_PUBLIC_IP:TURN_PORT`. Deployments behind NAT must
forward the control port and relay range to this instance.

With `TURN_PORT=0` and both transports enabled, the TCP listener picks the
ephemeral port first and UDP binds the same port, retrying the pair with a new
TCP port if the port is taken (Windows reports such collisions as access-denied
errors). Tests may still prefer a single control transport to keep the port
choice simple.

## Protocol

- STUN (RFC 5389) and TURN (RFC 5766) over UDP and TCP control transports.
  TURN control over TCP is for clients that cannot send UDP; relayed media is
  always UDP because pion does not implement RFC 6062 TCP relays.
- Long-term credential authentication with a per-grant random username and
  password. The credential is valid exactly while the grant is active; after
  revocation or expiry the authentication handler rejects it and any new
  Allocate/Refresh/CreatePermission attempt fails.
- No TURN over TLS (`turns:`) and no DTLS transport in this version. ICE uses
  `turn:` URLs only.
- IPv4 only for control and relay; IPv6 peers are filtered out.
- Permissions and ChannelBind requests are filtered by peer IP. Only globally
  routable unicast peers are allowed: loopback, RFC 1918, link-local,
  multicast, unspecified, CGNAT (`100.64.0.0/10`), documentation/benchmarking
  ranges, IPv4-compatible IPv6, Teredo, ORCHID, and deprecated site-local
  ranges are rejected. The filter runs on the address the TURN client asks to
  reach, before any permission or channel is created.
- **Host interface address blocking**: At startup, `ice.Server` snapshots
  `net.InterfaceAddrs()` and rejects relay permissions and outbound packets to
  any local host interface IP (including secondary public NICs) except
  `TURN_PUBLIC_IP` itself. If a new public IP or NIC is attached at runtime,
  restart the `relay` process so the snapshot refreshes.
- `TURN_PUBLIC_IP` itself is the one exception: a permission for the server's
  own advertised address is allowed so two allocations of one connection can
  relay to each other. Permissions are per IP, so the relay socket independently
  enforces that data sent to that address is delivered only to a relay socket
  belonging to the same grant. Packets to any other service on the server's
  public IP are dropped even if the client holds a permission. Never co-locate
  other UDP services on the relay host and expect TURN permissions to protect
  them.

## Firewall

Inbound, to the relay host:

- `TURN_PORT/udp` and `TURN_PORT/tcp` from the internet (clients and the
  signaling service's health checks).
- `TURN_RELAY_MIN_PORT`–`TURN_RELAY_MAX_PORT/udp` from the internet. Peers send
  media to these ports; without the range open, relayed media from peers is
  dropped even though the allocation succeeded.

Outbound:

- UDP to arbitrary public peers on the ports they advertise (TURN relays to
  whatever address a permitted client asks for; the peer filter above keeps it
  public unicast).
- TCP replies on established control connections.

Do not expose the relay range to peers on private networks; the peer filter is
the application-level control, the firewall is the network-level control. If
the relay range is left at `0`/`0`, relay ports are ephemeral and cannot be
opened in advance; use the default range in production.

## Tests

`internal/ice/ice_test.go` runs the real pion client against the real server
over loopback:

- credential reuse across endpoints and STUN-only behavior;
- a full allocation with peer echo, byte counting, `Revoke`, and allocation
  close;
- grant expiry closing a live allocation and rejecting the expired credential;
- hairpin between two allocations of one connection counting each payload
  exactly once per direction;
- the strict peer policy allowing only same-connection relay sockets on the
  server's own address, and dropping other services there despite a permission;
- the public-peer filter.

The tests enable a package-private unsafe-peer switch because they relay over
loopback; production always uses the public-peer filter, and the strict-policy
test exercises the production path.
