# Vanora identity authority

`internal/identity` is Vanora's independent endpoint certificate authority, and
`cmd/relay-identity` is its server process. It verifies an external OIDC login,
binds the verified owner to an Ed25519 endpoint key, and issues short-lived
certificates and liveness leases. The relay and desktop verify those tokens
with the authority's public key; they never hold its signing key.

```
native client                 identity authority              external IdP
     |                                |                             |
     |-- POST /challenges ----------->|                             |
     |   (endpoint public key)        |                             |
     |<-- challenge, nonce, state ----|                             |
     |   auth URL + PKCE challenge    |                             |
     |------------------------------------------------------------->|
     |<--------------- authorization code (browser + PKCE) --------|
     |-- POST /enroll (code,state,sig)-->|                         |
     |                                |-- code + server verifier -->|
     |                                |<-- ID token ----------------|
     |                                | verify sig/iss/aud/exp/nonce|
     |<-- certificate ----------------|                             |
     |-- POST /lease (cert, nonce,sig)-->|                         |
     |                                | readiness + replay check    |
     |<-- lease ----------------------|                             |
     |                                |                             |
     |   later, unattended:           |                             |
     |-- POST /renew (handle, PoP) ---->|-- refresh_token grant ----->|
     |<-- new cert + new handle -------|<-- id_token (iss/sub/exp) --|
```

Only this service holds the Ed25519 signing private key. Clients and the relay
hold only the public verifying key.

## Running

```sh
go run ./cmd/relay-identity keygen -out identity-signing-key -public-out identity-signing-key.pub
VANORA_IDENTITY_SIGNING_KEY_FILE=identity-signing-key \
VANORA_IDENTITY_OIDC_ISSUER=https://id.example.com \
VANORA_IDENTITY_OIDC_CLIENT_ID=vanora-native \
VANORA_IDENTITY_OIDC_REDIRECT_URI=com.vanora.app:/oauth/callback \
go run ./cmd/relay-identity serve
```

`keygen` writes a 32-byte hex Ed25519 seed (mode 0600) and the public key. The
private key file must stay on the authority host, readable only by the service
account. The process refuses to overwrite existing files.

### Environment

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `VANORA_IDENTITY_ADDR` | no | `127.0.0.1:8090` | listen address (`host:port`) |
| `VANORA_IDENTITY_SIGNING_KEY_FILE` | yes | – | private key: 32-byte seed or 64-byte key, in hex or base64 |
| `VANORA_IDENTITY_OIDC_ISSUER` | yes | – | exact issuer URL; must be https except loopback development |
| `VANORA_IDENTITY_OIDC_CLIENT_ID` | yes | – | native public client id |
| `VANORA_IDENTITY_OIDC_CLIENT_SECRET` | no | – | only for a confidential client; sent with the token request |
| `VANORA_IDENTITY_OIDC_REDIRECT_URI` | yes* | – | default registered callback: https, loopback http, or a custom app scheme (`*` required unless `VANORA_IDENTITY_OIDC_REDIRECT_URIS` is set) |
| `VANORA_IDENTITY_OIDC_REDIRECT_URIS` | no | – | comma/space list of additional allowed callbacks (e.g. `http://127.0.0.1/oauth/callback` alongside a mobile scheme; an `http` loopback entry without a port allows any ephemeral loopback port per RFC 8252) |
| `VANORA_IDENTITY_OIDC_SCOPES` | no | `openid, offline_access` | comma/space list; `openid` is always added |
| `VANORA_IDENTITY_DISABLE_REFRESH` | no | off | do not request `offline_access` and refuse renewal; unattended clients must sign in again when certificates expire |
| `VANORA_IDENTITY_CERT_TTL` | no | `10m` | certificate lifetime, `0 < ttl <= 15m` |
| `VANORA_IDENTITY_CHALLENGE_TTL` | no | `5m` | challenge lifetime, `0 < ttl <= 10m` |
| `VANORA_IDENTITY_LEASE_TTL` | no | `45s` | lease lifetime, `0 < ttl <= 60s` |
| `VANORA_IDENTITY_TLS_CERT` / `_TLS_KEY` | no | – | serve TLS directly; set both or neither |
| `VANORA_IDENTITY_ALLOW_PLAINTEXT` | no | off | allow plaintext on a non-loopback address (trusted proxy only) |

The server exposes `GET /healthz` (process only) and `GET /readyz` (discovery
document and JWKS reachable, cached for at most 5s). Leases are issued only
while readiness holds.

## OIDC assumptions

- Discovery is `{issuer}/.well-known/openid-configuration`; the discovery
  issuer must exactly match the configured issuer.
- Authorization code flow with PKCE S256. The native client opens
  `authorization_url` in the system browser. The authority generates the PKCE
  verifier, `state`, and OIDC `nonce`; the client never chooses them.
- The ID token must be signed by a key in the issuer's JWKS and must carry the
  configured client id as audience, a valid `exp`, a non-empty `sub` of at most
  255 characters, and the challenge nonce. Signature, `iss`, `aud`, and `exp`
  are verified by `github.com/coreos/go-oidc/v3`; the nonce is compared in
  constant time by this package.
- The endpoint key is proven separately: the client signs the proof message
  with the Ed25519 key whose public half was sent with the challenge request.
  An OIDC login alone cannot enroll a key.
- Unattended renewal needs a provider refresh token. `offline_access` is
  requested by default. If the provider rejects that scope, set
  `VANORA_IDENTITY_OIDC_SCOPES` to exactly the supported scopes (without
  `offline_access`) or `VANORA_IDENTITY_DISABLE_REFRESH=1`; enrollment then
  returns `"renewable": false`, no refresh handle, and the desktop will need a
  human sign-in before each 15-minute certificate expires. A provider that
  returns a refresh token but no `id_token` on the refresh grant is treated as
  unavailable for renewal, because the authority refuses to extend a
  certificate without rechecking the issuer and subject.

**Refresh token handling:** the provider refresh token is never sent to the
client. It is sealed with AES-256-GCM under a key derived from the authority
signing seed and returned as an opaque handle `vanr1.<nonce>.<ciphertext>`
bound to the issuer, subject, device id, and endpoint public key. The handle
lives at most 90 days (`MaxRefreshHandleLifetime`); the provider may expire
the token sooner. A provider that rotates the refresh token invalidates the
previous handle.

**Recovery restriction:** an IdP account-recovery flow that can be completed by
an attacker yields a normal OIDC login and therefore cannot be distinguished
here. Enrollment is only as resistant to takeover as the IdP's recovery
policy. Vanora account recovery must not be a rebinding path, and deployments
must configure the IdP to disallow uncontrolled recovery (or expose trusted
recovery state to a future version). This service deliberately does not
implement passwords, login UI, OAuth provider behavior, or recovery.

## Protocol

All requests and responses are JSON over HTTPS. Request bodies are limited to
16 KiB, are rejected with `DisallowUnknownFields`, and responses carry
`Cache-Control: no-store`.

Both identifiers use the exact UTF-8 bytes of the issuer and subject. Encode each
as its 4-byte big-endian byte length followed by its bytes. Concatenate the two
fields in issuer, subject order to form `account`.

- `remote_user_id` hashes `"vanora/remote-user/v1\x00" || account` with SHA-256.
- `device_id` authenticates `"vanora/device/v1\x00" || account || raw_endpoint_public_key` with HMAC-SHA-256 under the device key derived from the signing seed.

Take the first 16 **bytes** of the digest, encode them with lowercase unpadded
RFC 4648 base32, then prepend `usr_` or `dev_` respectively.

`device_id` is stable for the same owner and endpoint key: reinstalling with
the same key keeps it, while a new key yields a new device. A client can
compare the `device_id`, `remote_user_id`, certificate issuer, and subject
returned by enrollment with the values it expects.

### 1. Create a challenge

`POST /v1/identity/challenges`

```json
{"purpose": "enroll", "public_key": "<base64url 32-byte Ed25519 public key>", "redirect_uri": "http://127.0.0.1:45678/oauth/callback"}
```

`purpose` is `enroll` or `renew` (default `enroll`). `redirect_uri` is optional; when omitted, `VANORA_IDENTITY_OIDC_REDIRECT_URI` (or the first entry of `VANORA_IDENTITY_OIDC_REDIRECT_URIS`) is used. When provided, it must match the configured allowlist (or an ephemeral port on a portless `http` loopback entry). Success (`200`):

```json
{
  "challenge_id": "...",
  "nonce": "...",
  "state": "...",
  "code_challenge": "...",
  "code_challenge_method": "S256",
  "authorization_url": "https://id.example.com/authorize?...",
  "expires_at": 1700000000
}
```

Open `authorization_url`; the IdP returns `code` and `state` to
`VANORA_IDENTITY_OIDC_REDIRECT_URI`. A challenge is single use and expires
after `VANORA_IDENTITY_CHALLENGE_TTL`.

Proof message to sign with the endpoint key (all parts except the key are the
base64url strings from the challenge; the key is raw base64url):

```
vanora-identity-proof-v1
<challenge_id>
<nonce>
<purpose>
<public_key>
```

### 2. Enroll

`POST /v1/identity/enroll`

```json
{"challenge_id": "...", "code": "...", "state": "...", "signature": "<base64url 64-byte signature>"}
```

The authority checks the proof first and then consumes the challenge
atomically, so a forged request cannot burn another client's challenge and a
successful request cannot be replayed. It then redeems the code with the
server-held PKCE verifier and verifies the ID token nonce. Success (`200`):

```json
{
  "certificate": "vanc1....",
  "device_id": "dev_...",
  "remote_user_id": "usr_...",
  "expires_at": 1700000600
}
```

When the provider returns a refresh token, the response also carries:

```json
{
  "refresh_handle": "vanr1....",
  "renewable": true
}
```

`renewable` is `false` and `refresh_handle` is omitted when the provider did
not return a refresh token or refresh support is disabled. The client stores
the handle with the endpoint private key; losing either loses renewal.

Certificate format: `vanc1.<header>.<claims>.<sig>`, Ed25519 over the ASCII
`vanc1.<header>.<claims>`. Claims: `v`, `iss`, `sub`, `dev`, `pk` (raw
base64url public key), `aud` (`vanora-relay`), `iat`, `exp`. The service is
the only holder of the signing key; verifiers call
`identity.VerifyCertificate(token, trustedPublicKey, now)` and receive a
`Principal{Issuer, Subject, DeviceID, PublicKey, Expires}`.

### 3. Lease

A certificate proves enrollment but not liveness. Endpoints prove possession
of the key on each connection with a fresh random nonce (`16..64` base64url
bytes) and receive a short lease bound to the exact certificate:

`POST /v1/identity/lease`

```json
{"certificate": "vanc1....", "nonce": "...", "signature": "<base64url 64-byte signature>"}
```

Lease proof message (the certificate is hashed as raw base64url SHA-256):

```
vanora-identity-lease-v1
<nonce>
<base64url(sha256(certificate))>
```

Success (`200`):

```json
{"lease": "vanl1....", "device_id": "dev_...", "remote_user_id": "usr_...", "issued_at": 1700000000, "expires_at": 1700000045}
```

Lease claims bind `aud`, `uid` (`remote_user_id`), `dev`, `ch`
(certificate hash), `n` (nonce), `iat`, `exp`. The relay calls
`identity.VerifyEndpointLease(lease, trustedPublicKey, now, certificate,
principal)`; a lease is valid only for the same remote user, device, and exact
certificate, and never past the certificate expiry. Leases are capped at 60
seconds and the authority only issues them while its readiness probe succeeds.

### 4. Renew without a browser

`POST /v1/identity/renew`

```json
{"refresh_handle": "vanr1....", "nonce": "...", "signature": "<base64url 64-byte signature>"}
```

`nonce` is fresh client randomness (`16..64` base64url bytes). The client signs
with the endpoint key bound by the handle:

```
vanora-identity-renew-v1
<nonce>
<base64url(sha256(refresh_handle))>
```

The authority decrypts the handle, proves possession of the bound key, refuses
a replayed nonce, and redeems the refresh token with the provider. The
provider rejects disabled or revoked accounts; the returned ID token must pass
normal signature/issuer/audience/expiry checks and its subject must equal the
subject inside the handle. The device id is recomputed from issuer, subject,
and key and must match the handle. The response is:

```json
{"certificate": "vanc1....", "refresh_handle": "vanr1....", "device_id": "dev_...", "remote_user_id": "usr_...", "expires_at": 1700000600}
```

Always replace the stored handle with the returned one: the provider may have
rotated the refresh token, in which case the old handle fails with
`401 refresh_rejected`. Clients should renew shortly before `expires_at`; a
certificate is at most 15 minutes, so checking every few minutes is enough.
Refresh failures are `401 refresh_rejected` (provider refused the token),
`401 identity_verification_failed` (issuer/subject/device no longer match),
`400 invalid_refresh_handle`, `401 proof_invalid`, `409 nonce_reused`, or
`503 provider_unavailable`.

### Errors and limits

Errors are `{"error":"code"}` with a status code: `400` invalid request,
challenge, proof, or certificate; `401` rejected OIDC code or ID token; `409`
replayed lease nonce; `503` provider unavailable; `500` internal. The service
keeps at most 4096 outstanding challenges (oldest evicted), remembers used
lease and renewal nonces for at least a lease lifetime plus clock skew (8192
entries each),
rejects certificates and leases beyond their maximum lifetime, allows 30s of
clock skew, and exposes no revocation list: revocation is bounded by the
maximum certificate lifetime (15 minutes).

## Tests

```sh
go test ./internal/identity/...
```

The tests use real Ed25519 signatures, a real in-process OIDC provider, and
assert replay, expiry, audience, issuer, device-binding, and readiness
behavior. `internal/identity/identitytest` is a test-only helper for minting
certificates; production code must not import it.
