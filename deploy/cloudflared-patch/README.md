# Restricted cloudflared for official desktop builds

Use upstream [cloudflared 2026.11.2](https://github.com/cloudflare/cloudflared/releases/tag/2026.11.2), commit `dc57315806d5faa8715f728fd37b5302c81c467b`, as the patch baseline. Review the same startup, update, and origin dial paths on each upstream upgrade.

## Startup pins

In `cmd/cloudflared/tunnel/cmd.go`, register `--vanora-pin-hostname` and `--vanora-pin-origin` as tunnel command flags before `run`. Accept them together in a token-authenticated Named Tunnel. Validate the hostname as one literal DNS name without a port, wildcard, terminal dot, or path. Parse the origin with `netip.ParseAddrPort` and require a canonical literal `127.0.0.1:<port>` or `[::1]:<port>` with a nonzero port. The desktop passes the allocated hostname and the exact return value of the loopback listener's `Origin()`.

Pinned mode requires `--token` or `TUNNEL_TOKEN`. The local origin is redacted in the startup settings and tunnel diagnostics.

In `prepareTunnelConfig` in `cmd/cloudflared/tunnel/configuration.go`, build local ingress from the validated pins. Bypass `ParseIngressFromConfigAndCLI` in pinned mode. Construct exactly these two rules via `ingress.ParseIngress` and a synthetic `config.Configuration`, with the default origin request configuration and `originRequest.httpHostHeader` set to the pinned hostname on the first rule.

```yaml
ingress:
  - hostname: <pinned-hostname>
    service: http://<pinned-origin>
    originRequest:
      httpHostHeader: <pinned-hostname>
  - service: http_status:404
warp-routing:
  enabled: false
```

Keep the hostname rule unrestricted by `path`. The loopback listener validates the exact upgrade path. In `StartServer`, omit `ingress.NewManagementRule` in pinned mode so internal ingress rules cannot precede the two compiled rules.

Upstream `2026.11.2` represents WARP configuration without an `Enabled` field. Pinned startup uses zero-value WARP settings and disables private dialing, virtual DNS, and ICMP in the connector.

## Remote configuration

Add an immutable hostname/origin pin to `orchestration.Config`. In `orchestration/orchestrator.go`, branch under `UpdateConfig`'s existing lock **before** decoding into `newRemoteConfig` or calling `updateIngress`. Check the raw JSON against a closed schema and reject duplicate keys. Require the two rules in the same order, exactly the pinned hostname and canonical service in the first rule, an unconditional `http_status:404` catch-all, no `path`, and disabled WARP. Allow omitted or empty `originRequest`, or the exact pinned `httpHostHeader` on the named rule. Reject any additional origin request settings, WARP settings, or rules. Treat a missing `warp-routing` object or an empty one as disabled.

For matching updates, acknowledge the version and keep the compiled ingress, transport, and private routing restrictions in service. For drift, return an error and the previous `LastAppliedVersion`. Avoid logging the raw configuration in this branch. Update `currentVersion` and the configuration version metric on accepted versions only. Apply the same checks to updates at version zero.

## Origin dial guards

- In `ingress/origin_service.go`, add a process-local pinned address to the constructed HTTP service. Assign it after local ingress parsing, before `StartOrigins`. In `newHTTPTransport`, set `Proxy` to `nil` and wrap `DialContext` for that service. Require `tcp`, `tcp4`, or `tcp6` and a `netip.ParseAddrPort(addr)` result exactly equal to the pinned loopback address and port immediately before calling `net.Dialer.DialContext`. Use the pin's canonical address string when dialing. Leave TLS and Unix-socket origin dial paths unavailable for this service.
- Guard `ingress.OriginDialerService.DialTCP` and `DialUDP` in pinned mode before the reserved-service lookup or default dialer. Both must reject private-network requests. The HTTP ingress above has its own dial path. Skip virtual DNS registration and ICMP router setup in `prepareTunnelConfig`; leave their service pointers nil. Keep the data dial guard in place if `updateIngress` updates default dialer settings.
- Leave Cloudflare edge connection dialing on the normal connector path. The restriction applies to origin dialing.

## Build and verify

[`vanora-pinned-origin.patch`](vanora-pinned-origin.patch) contains the upstream changes and tests. [`upstream.lock`](upstream.lock) records the upstream repository, tag, exact commit, and SHA-256 of the LF-normalized patch. Use Git and Go `1.27.4`, the version declared by the locked upstream `go.mod`.

[`build.ps1`](build.ps1) and [`build.sh`](build.sh) verify the lock, create a temporary detached worktree from the source repository in `dist/cloudflared-src`, and check and apply the patch there. They run the patched `ingress`, `orchestration`, and `cmd/cloudflared/tunnel` test suites on the host. They then write a CGO-disabled `cloudflared-vanora[.exe]` and its `.sha256` file to `dist/cloudflared/`. Both source and artifacts remain under ignored `dist/`.

The upstream raw ICMP echo tests require a supported native ICMP backend. On Windows, they run with CGO enabled. The pinned-mode test checks ICMP packet rejection with CGO disabled.

From the repository root on Windows PowerShell 5.1 or later:

```powershell
powershell.exe -NoProfile -File .\deploy\cloudflared-patch\build.ps1
$binary = '.\dist\cloudflared\cloudflared-vanora.exe'
$expected = (Get-Content -LiteralPath "$binary.sha256").Split(' ')[0]
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash -ine $expected) { throw 'SHA-256 mismatch' }
& $binary --version
& $binary tunnel --help
```

To target Linux amd64 from PowerShell, pass `-TargetOS linux -TargetArch amd64`. Both scripts also read `GOOS` and `GOARCH` from the environment. From a POSIX shell:

```sh
GOOS=linux GOARCH=amd64 sh deploy/cloudflared-patch/build.sh
(cd dist/cloudflared && sha256sum -c cloudflared-vanora.sha256)
go version -m dist/cloudflared/cloudflared-vanora
```

## Release checks

The patch's `TestVanoraPinnedOriginIntegration` exercises loopback QUIC and HTTP/2 edge connections, HTTP and WebSocket proxying, private TCP/UDP/DNS/ICMP restrictions, remote updates, and recompiling the ingress after a restart with a new listener port.

For an official release, run the upstream suite and repeat the integration checks with an actual Named Tunnel. Start a permitted loopback HTTP server and a second server on another port. Exercise QUIC and HTTP/2. Verify the pinned hostname reaches the first server, unmatched hosts receive 404, and private TCP/UDP/DNS/ICMP traffic is rejected. Push remote updates that change the port, redirect to a private or external address, introduce a wildcard or another rule, reorder rules, enable WARP, or supply global/per-rule origin overrides. Each must preserve the running configuration and leave the second server untouched. Confirm an identical update is acknowledged and a desktop restart uses the new local listener port.

Ship the restricted binary by pinned commit and verify the packaged artifact's digest. The launch command passes the protocol and both pins as arguments and supplies the connector token through `TUNNEL_TOKEN` in the child environment.
