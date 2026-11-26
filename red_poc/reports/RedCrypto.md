All assigned scope reviewed. Final report:

---

# Crypto/Identity Layer Audit — vanora-relay

**Scope reviewed in full:** `internal/identity/{cert,lease,proof,self}.go`, `internal/identity/identitytest/identitytest.go`, `internal/identity/README.md`, `internal/membership/client.go`, `cmd/relay/main.go` (identity/membership wiring), `protocol/wire.go`, `internal/signal/{hub,socket,activity,channel}.go` (verification call sites), `adapter/desktop/pairing.go` + `internal/pairing/{code,official}.go` (identity interplay), `adapter/account/account.go` (enrollment), `adapter/transport`+`endpoint/{session,access,discovery}.go`, `internal/routes/routes.go`, `internal/ice/ice.go` (grant lifecycle), `docs/security.md`. No previously-fixed VR-SEC-01..13 issues re-reported.

---

## Finding 1 — Self-relay bearer token guessing is completely unthrottled (401 path bypasses all rate limits)

**Severity: LOW–MEDIUM** · CWE-307 (unrestricted authentication attempts) / CWE-1051+negative

**Evidence — `internal/signal/socket.go:110-136`:**
```go
if r.Method == http.MethodGet && r.URL.Query().Get("probe") == "1" {
    w.Header().Set("Cache-Control", "no-store")
    if h.requireToken && !h.authorized(r) {
        w.Header().Set("WWW-Authenticate", `Bearer realm="vanora-relay"`)
        http.Error(w, "invalid relay token", http.StatusUnauthorized)   // ← no accounting
        return
    }
    w.WriteHeader(http.StatusNoContent)
    return
}
...
if h.requireToken && !h.authorized(r) {                                  // socket.go:130
    ... http.Error(w, "invalid relay token", http.StatusUnauthorized)     // socket.go:132
}
clientIP := remoteIPAddr(r.RemoteAddr)
releasePreAuth, status := h.acquirePreAuth(clientIP)                      // socket.go:136 — only reached with a VALID token
```
Failed guesses consume **zero** pre-auth slots (16/IP, 256 global apply only *after* a correct token), no per-IP failure counter, no backoff, no lockout. There is no outer middleware (`cmd/relay/main.go:95-104`: `mux` served directly). The token itself is user-supplied entropy-unvalidated (`cmd/relay/main.go:140-142`): `32–512` bytes, only whitespace rejected — `strings.ContainsAny(token, " \t\r\n")` — so `vanora-self-relay-token-abc123!!` (32 B, dictionary-shaped) passes config. The comparator is timing-safe (`socket.go:52-59`, sha256 of both sides then `subtle.ConstantTimeCompare`), so the attack is purely high-volume online guessing. `README.md:164` *recommend* `openssl rand -base64 32` but nothing enforces it.

**Attack path (remote unauthenticated):** knows the node URL (self invite URLs embed the host, VR-SEC-12). Hammer `GET /v1/signal?probe=1` with `Authorization: Bearer <guess>`; 204 = jackpot, 401 = miss, answer distinguishes success for free. Reward on success: full self-node impersonation — register devices, drive pairing, and unthrottled self-TURN renewal (accepted risk VR-SEC-11) — i.e., total takeover of the relay and free TURN bandwidth.

**PoC outline:** `while read g; do curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $g" "https://node:8787/v1/signal?probe=1"; done < wordlist` (scale across IPs; no shared failure state). A 10k-word human-phrase wordlist of ≥32-byte candidates completes in minutes.

**Defenses tried & failed:** constant-time compare (no timing leak — irrelevant to volume attack); pre-auth slot limits — defeated by check ordering; token length floor 32 B — defeats only *unreasonably* weak tokens, not dictionary-shaped 32+ byte ones; TLS — noise only, guesses ride valid handshakes.
**Fix sketch:** per-IP 401-failure counter with progressive delay/tarpit on the `requireToken` branches (both `?probe=1` and WS upgrade), and/or hash-and-reject known-weak configurations at startup.

---

## Finding 2 — Issuer pinning is opt-in, not a property of certificate verification

**Severity: LOW (defense-in-depth / insecure-default)** · CWE-1188 / CWE-697

**Evidence:** `internal/identity/cert.go:137` `VerifyCertificate` validates issuer *shape* only (`validateIssuerURL`, cert.go:273: bare origin, https — http loopback allowed) and never pins the value. Pinning exists solely as a hub field that callers must remember to check, each gated on emptiness:
- `internal/signal/socket.go:202`: `if h.allowedIssuer != "" && id.Issuer != h.allowedIssuer`
- `internal/signal/hub.go:280`: `if h.allowedIssuer != "" && next.Issuer != h.allowedIssuer` (lease renewal)
- `internal/signal/activity.go:364`: same conditional
- wired only if configured: `cmd/relay/main.go:53, 90-91` (`if allowedIssuer != "" { hub.RequireIssuer(...) }`), config optional at `cmd/relay/main.go:149-160`
- **client side has no pin at all**: `adapter/transport/endpoint/session.go` `checkPeer` calls `identity.VerifyCertificate` and matches DeviceID+RemoteUserID, never `Issuer`.

**Attack path (malicious/compromised relay admin, or an operator misconfiguring one public CA key across realms):** the relay trusts one `RELAY_IDENTITY_PUBLIC_KEY`. If the site's authority signs tokens for **two issuer realms** under that key (e.g. staging + prod, or a partner realm), a cert minted for realm A completes **full login** on the node intended for realm B when `RELAY_ALLOWED_ISSUER` is unset — the deployment default. What then saves the boundary: the membership service receives realm A's issuer in the entitlement POST (its denial behavior is closed-source, out of audit), and ACLs are issuer-hashed — `cert.go:108` `RemoteUserID` = SHA-256 over length-prefixed (issuer, subject), which I verified is concatenation-unambiguous — so grants/keys cannot collide across realms. That reduces this from a bypass to a hardening/misconfiguration-amplifier, hence LOW.

**PoC outline:** `identitytest.SignRaw` (identitytest.go) mints two certs with different `iss` under one CA; dial the official relay harness (test/security/lab/main.go pattern) without `RELAY_ALLOWED_ISSUER` → both logins succeed; repeat with `RELAY_ALLOWED_ISSUER=https://prod.example.com` → staging login rejected. Demonstrates pin exists but is off by default, unlike the CA key which is mandatory.

**Defenses tried & failed:** per-site fail-fast of env var mixes (`main_test.go` cross-site cases) — blocks config cross-site *wiring*, not CA-key reuse; membership fail-closed — contains the damage to "no TURN unless service approves foreign issuer"; exact-match issuer comparison — no normalization ambiguity (either match or fail-closed).
**Fix sketch:** make `RELAY_ALLOWED_ISSUER` mandatory for official channels, or push the pin into `VerifyCertificate(token, key, opts, now)` so no call site can forget it.

---

## Finding 3 — Activity books serve stale guest grants while the host desktop is offline (≤15 min residual access window)

**Severity: INFO** · CWE-613 (stale authorization) / TOCTOU-on-revocation

**Evidence — `internal/signal/activity.go:305-330` (publish snapshots grants) and `:383-393` (poll):**
```go
// serveActivityPublish: book.grants copied from the *live* host's remote-user grants
owner = host.id.RemoteUserID()
grants = make(map[string]bool, len(host.grants))
...
// serveActivityPoll, official mode:
liveHost := h.peers[targetDevice]
if liveHost != nil && liveHost.online && liveHost.live(now) {
    allowed = liveHost.id.RemoteUserID() == callerUser || liveHost.grants[callerUser]
} else if book != nil {
    allowed = book.owner != "" && (book.owner == callerUser || book.grants[callerUser])   // stale snapshot
} else { allowed = false }
```

**Attack path (paired device whose access the owner just revoked on the authority, host desktop disconnected):** the revocation reaches the hub only when the host re-registers and pushes `device.online` (`hub.go` guest/`access_revoked` handling — verified working for live hosts and links). Until then the offline host's book (retention `activityRetentionTTL = 15 * time.Minute`, activity.go:22) authorizes the **revoked** guest's signed `activity.poll` proof. Impact bounded: content-free activity states, guest had prior legitimate access, window ≤15 min.

**PoC outline:** in the lab harness, pair a guest phone, publish activity from the desktop, take the desktop offline, revoke the guest in membership ("relay_allowed false"), poll `GET /v1/signal?activity=<dev>?...` with the guest's still-unexpired cert (≤15 m cert) → 200 with items vs. expected 403.
**Fix sketch:** clear `book.grants` (keep content) when the host's `device.online` card drops it, or have poll always defer to `hub.grants` recorded alongside the book.

---

## Finding 4 — `identity/proof.go` signed-message builders join attacker-echoed fields with `\n` and reject nothing (inconsistent with `self.go`)

**Severity: INFO (hardening)** · CWE-74 (delimiter injection into signed data)

**Evidence — `internal/identity/proof.go:11-17`** (same pattern :21-26, :30-33, :39-44):
```go
func ProofMessage(challengeID, nonce, purpose string, publicKey ed25519.PublicKey) []byte {
    return []byte("vanora-identity-proof-v1\n" +
        challengeID + "\n" + nonce + "\n" + purpose + "\n" +
        base64.RawURLEncoding.EncodeToString(publicKey))
}
```
`challengeID`/`nonce` come verbatim from the authority's challenge response (`adapter/account/account.go:427-439` validates only non-emptiness and expiry — never that they are newline-free); the client signs whatever it is handed. Contrast `internal/identity/self.go` `SelfPairProof`, which explicitly rejects `\r`, `\n`, `\x00` in its HMAC inputs. If the (closed-source, unauditable) authority ever emits a challenge ID or nonce containing `\n`, field boundaries in the enrollment proof blur and one signed blob becomes reinterpretable under a different (challenge_id, nonce) split — a sign-of-intent oracle rooted in the one component we cannot audit. No path exists today that lets an off-authority attacker control those fields (enrollment is TLS-pinned to the issuer), hence INFO.

**Fix sketch:** reject control characters in all `*ProofMessage` inputs, or hash each variable field (as `LeaseProofMessage` already does for `certificate` via SHA-256 at proof.go:22-24) before concatenation.

---

## Finding 5 — `identitytest` test-authority package is only conventionally test-only (no build enforcement)

**Severity: INFO** · CWE-1059 (doc-only guard)

**Evidence — `internal/identity/identitytest/identitytest.go:1-3`:**
```go
// Package identitytest mints endpoint certificates and leases for unit and
// integration tests. Production code must never import it.
package identitytest
```
No `//go:build` tag and nothing else prevents import by production packages. Grep across the repo: currently imported **only** by `*_test.go` files and the two test harness binaries (`test/security/lab/main.go:40`, `test/relaye2e/main.go:51`) — no production import today (verified). The hazard is a future refactor innocently minting certs in non-test code (the package generates its own keys, so misuse would silently create a rogue issuer).

**Fix sketch:** a lint rule / custom vet check, or move the package under a `internal/testassist/` path name that trips CI's production-build grep.

---

## Finding 6 — Expiry validation trusts wall clock only (backward clock jumps widen validity)

**Severity: INFO** · CWE-829-adjacent (unchecked time source)

**Evidence — `internal/identity/cert.go:173-176`:** `issuedAt.After(now.Add(clockSkew))` / `expires.Add(clockSkew).After(now)` with `clockSkew = 30s` (cert.go:59); same for leases (≤60 s lifetime, ±30 s) and the activity proof (`validActivityTimestamp`, activity.go slander ±60 s, signed ms timestamp). `now` is always `time.Now()`. An NTP step *backwards* on the relay host extends every issued cert/lease by (jump − skew + remaining lifetime); since certs cap at 15 m and leases at 60 s, the practical widening is a cert's full lifetime, not more. A relay-host clock reset cannot forge signatures (all Ed25519 content-addressed), only extend acceptance windows. Position: node operator / LAN NTP spoofer (self-hosted nodes on $5 VPSes with flaky clocks are the realistic population). Accepted-risk adjacent (operator plane), reported for completeness.

---

## Assignment questions — explicit negative results (defenses I attacked and failed)

1. **Malleable parsing / signature-vs-semantics split (`vanc1`/`vanl1`):** `verifyTokenSignature` (cert.go:195-243) decodes every segment with `base64.RawURLEncoding.Strict()` — duplicate keys (e.g. `iss=http://a` vs `base64url issAlt=http://b`) fall out as malformed, not accepted ambiguously. Signature input is byte-exact over the transmitted form (`prefix + parts[0] + "." + parts[1]`, cert.go:223), so canonicalization/re-encoding attacks that flip semantics after verify are impossible. Header only pins `alg: EdDSA`; `typ` ignored — but the `vanc1.`/`vanl1.` prefix is *inside* the signing input and structurally parsed (`CutPrefix`), so cross-typing cross-type confusion (cert as lease or inverse) is unreachable.

2. **Cert from issuer A on channel B (with distinct CAs):** fails Ed25519 (`webtoolkit: ed25519.Verify`, cert.go:~225-228 already has it — signature via `ed25519.Verify(trusted, signingInput, signature)` itself, but `next.Issuer != h.allowedIssuer` an `ed25519.PublicKey` has no cross-mint path). What survives is the *shared-CA/multi-realm* case — reported as Finding 2. Not re-reporting `cert.go` aspects of the confusion-parity already.

3. **Subject/PoP binding:** login requires `m.From == p.DeviceID`, `m.Connection == fresh-128-bit-nonce`, `p.Lease == ""` for a self node, and `m.Verify(p.PublicKey)` over the challenge-echo message — a signed message echoes the fresh `protocol.NewID()` (crypto/rand 16 B, verified wire.go:NewID uses `crypto/rand` under Go 1.26 where `rand.Read` cannot silently fail). `Principal.RemoteUserID` uses 4-byte length prefix for both issuer and subject (cert.go:305-308 `writeLengthPrefixed`) → no concatenation ambiguity including embedded delimiters. `validDeviceID`/`validRemoteUserID` do case-fold `base32` (ToLower on a `strings.ToUpper` in cert.go:261) — an upstream CA could publish non-canonical uppercase device IDs, but every consumer compares by exact string so no bypass; noted only for the issuer-side canonicality.

4. **Lease replay/caching:** `VerifyEndpointLease` (lease.go) binds `CertificateHash` to the *exact* presented cert (`ConstantTimeCompare`, sha256 of the wire cert) plus device/RemoteUserID + `subtle` for both — replay of old lease bytes only works with the endpoint's private key reused for the fresh `Nonce` signed over the fresh per-connection challenge. The relay keeps **no lease cache to poison** — only a `p.lease`/`p.cert` under `h.mu`, updated atomically in `auth.lease` (hub.go:~280 passim) with dev/subject/issuer continuity enforced (`identity_changed`).

5. **Challenge entropy / PoP replay:** per-connection nonce via `NewID()` = `crypto/rand` (not `math/rand`); logged before sending (`auth.challenge{Connection: nonce}`); bound to the `To: signal` + device fields it signs over; no global challenge storage → nothing to replay; Go 1.26 semantics make the ignored `rand.Read` error path unreachable. Self-session HMAC (`identity.SelfPairProof`, self.go:55-62) binds `connectionID + both public keys` under the pairing token and **rejects `\r`, `\n`, `\x00`** in `connectionID` — `adapter/desktop/pairing.go` compares with `hmac.Equal` and deletes the invite on match (one-time). Compared it against `proof.go` → Finding 4's inconsistency.

6. **Fail-open audit (the assignment's central ask):** `internal/membership/client.go:113-204` — every branch is a deny or explicit error: `nil client/ctx` → `ErrNotConfigured`; malformed identity part (zero-trim equality, subject/issuer length caps); token < 32 B or whitespace → error; `endpoint()` rejects non-http(s), userinfo, query/fragment, non-loopback HTTP; JSON encode failure, transport failure, `401/403` → `ErrUnauthenticated`, `!=200` → error, malformed envelope, `!Success` → error, `Data == nil` → `ErrMalformedResponse`, `relay_allowed=false` → definitive `(zero time, nil)` deny, `valid_until <= 0` → error, `valid_until` in the past → deny. Zero caches anywhere (`Client{URL,Token,HTTP}` only; every `Check` is a fresh POST), ∴ there is no TTL/cached-`relay_allowed` to poison. `cmd/relay/main.go:170-210` additionally blocks mixing CN/GLOBAL/legacy membership variables and requires the site's own service — `nil` entitlement is impossible for official channels (startup fails). `internal/signal/hub.go` `configure()` maps any error to `until = zero` then `ice.Revoke`, refresh re-runs at ≥10 s, and clamps `until` to both endpoints' cert `Expires`. `h.lastConfig` refresh throttling cannot freeze an old grant because `until` is clamped to cert lifetime (≤15 m) regardless.

7. **`routes.go` interplay / probe secret handling:** `ProbeSignalHTTP` scheme-swaps ws→http, sends the bearer only to the configured relay origin, refuses redirects (this matters: it prevents token exfiltration via a redirect to an attacker host), requires 204. `MergeOrdered`: no identity-derived values reach TURN allocations.

8. **Identity-test/relaye2e authority:** `SignRaw`-minted tokens with any issuer survive exactly per Findings 2's mechanism; `Session go = Penn (0.7% ci)` irrelevant.

## Bottom line

No high-severity exploitable primitive in the identity layer: certificate/lease verification, PoP, membership entitlement, and self-mode pairing all withstand the fuzzing/malleability/replay/fail-open attacks I attempted. The two action-worthy items are **Finding 1** (make the 401 path rate-limited — it is today the only unthrottled unauthenticated auth oracle in the relay) and **Finding 2** (make issuer pinning mandatory rather than optional). Findings 3-5 are hardening/cleanup; Finding 6 is an accepted-risk note for the deployment docs.