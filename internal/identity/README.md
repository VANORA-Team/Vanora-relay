# Vanora Identity Verification & External Authority Contract

`internal/identity` implements **verification and client proof-of-possession (PoP) helpers only**. Device certificate signing, account authentication, and key management are intentionally NOT shipped in this open-source repository—they run inside each official site's external identity backend (`cn` and `global` deploy independent signing keys and issuers), which is the sole holder of its Ed25519 signing private key.

The official-channel relay (`cmd/relay` with `RELAY_CHANNEL=cn|global`), desktop adapter (`cmd/vanora-desktop`), and mobile SDK (`mobile`) pin only the target site's 32-byte Ed25519 public key and verify certificates (`vanc1`) and liveness leases (`vanl1`) offline.

> **Self-hosted nodes (`RELAY_CHANNEL=self`) do not use this external authority protocol.** They run account-free with `RELAY_SELF_TOKEN` and locally generated Ed25519 keys, using only `SelfDeviceID` (`sdev_<26-char-base32>`) and `SelfPairProof` (HMAC-SHA256 over `"vanora-self-pair-v1\n<connection_id>\n<mobile_pub>\n<desktop_pub>"`) from this package.

```text
native client (with host auth token)      external identity authority (private)
      |                                                |
      |-- POST /v1/identity/challenges --------------->|
      |   {purpose:"enroll", public_key}               |
      |<-- {challenge_id, nonce, expires_at} ----------|
      |                                                |
      |-- POST /v1/identity/enroll ------------------->|
      |   {challenge_id, token, PoP signature}         |  verify PoP + validate host token
      |<-- {certificate, device_id, remote_user_id, ---|  sign short-lived vanc1 cert
      |     expires_at, renewable, refresh_handle?}    |
      |                                                |
      |-- POST /v1/identity/lease -------------------->|
      |   {certificate, nonce, PoP signature}          |  verify cert + PoP + replay + user active
      |<-- {lease, device_id, remote_user_id, ...} ----|  sign <=60s vanl1 lease
      |                                                |
      |   later (certificate approaching expiry):      |
      |-- POST /v1/identity/renew -------------------->|  either direct {token, public_key, nonce, sig}
      |<-- {certificate, refresh_handle?, ...} --------|  or sealed {refresh_handle, nonce, sig}
```

## Identifier Derivation

Both identifiers derive from the exact UTF-8 bytes of `issuer` and `subject`. Encode each as a 4-byte big-endian length prefix followed by its UTF-8 bytes, concatenated in `(issuer, subject)` order as `account`:

- `remote_user_id`: `"usr_" + lowercase(base32_nopad(sha256("vanora/remote-user/v1\x00" || account)[:16]))`
- `device_id`: `"dev_" + lowercase(base32_nopad(tag[:16]))` (26 lowercase RFC 4648 base32 characters after `dev_`), stably derived by the authority from `(issuer, subject, raw_endpoint_public_key)` under an authority-held secret key so reinstalling with the same key keeps the same `device_id` while a new key produces a new `device_id`.

## Wire Token Formats

All segments after the prefix use **canonical unpadded base64url** (strict decoding; non-zero trailing bits are rejected). Ed25519 signatures cover the exact ASCII bytes `<prefix><header_b64>.<claims_b64>`.

### Device Certificate (`vanc1`)

`vanc1.<header>.<claims>.<sig>` (max 4096 bytes):

- Header: `{"alg":"EdDSA","typ":"vanc+v1","kid":"<key-id>"}`
- Claims:
  - `v`: `1`
  - `iss`: HTTPS issuer URL (or loopback `http://` for local dev), no query/fragment/userinfo
  - `sub`: stable non-empty account subject
  - `dev`: `dev_<26-char-base32>`
  - `pk`: unpadded base64url 32-byte Ed25519 endpoint public key
  - `aud`: `"vanora-relay"`
  - `iat`, `exp`: Unix seconds; `0 < exp - iat <= 900` (15 minutes max; 10 minutes recommended)

### Liveness Lease (`vanl1`)

`vanl1.<header>.<claims>.<sig>` (max 2048 bytes):

- Header: `{"alg":"EdDSA","typ":"vanl+v1","kid":"<key-id>"}`
- Claims:
  - `v`: `1`
  - `aud`: `"vanora-relay"`
  - `uid`: `remote_user_id` (`usr_<26-char-base32>`)
  - `dev`: `device_id` (`dev_<26-char-base32>`)
  - `ch`: unpadded base64url `sha256(exact_certificate_string)`
  - `n`: client nonce (base64url encoding of 16..64 random bytes)
  - `iat`, `exp`: Unix seconds; `0 < exp - iat <= 60` and `exp <= certificate.exp`

## External Authority HTTP API

All requests and responses are JSON over HTTPS (loopback HTTP allowed for local development only), with `Cache-Control: no-store`. Clients reject HTTP redirects. Error responses are `{"error":"<code>"}`.

### 1. `POST /v1/identity/challenges`

Request:

```json
{"purpose": "enroll", "public_key": "<base64url 32-byte Ed25519 public key>"}
```

Response (`200`):

```json
{"challenge_id": "...", "nonce": "...", "expires_at": 1700000300}
```

### 2. `POST /v1/identity/enroll`

Client signs `identity.ProofMessage(challenge_id, nonce, "enroll", public_key)`:

```text
vanora-identity-proof-v1
<challenge_id>
<nonce>
enroll
<base64url(public_key)>
```

Request:

```json
{"challenge_id": "...", "token": "<host client auth token>", "signature": "<base64url 64-byte Ed25519 sig>"}
```

Response (`200`):

```json
{
  "certificate": "vanc1....",
  "device_id": "dev_...",
  "remote_user_id": "usr_...",
  "expires_at": 1700000600,
  "renewable": false
}
```

When unattended renewal via opaque handle is supported, the authority may also return `"renewable": true` and `"refresh_handle": "..."`.

### 3. `POST /v1/identity/lease`

Client signs `identity.LeaseProofMessage(nonce, certificate)`:

```text
vanora-identity-lease-v1
<nonce>
<base64url(sha256(certificate))>
```

Request:

```json
{"certificate": "vanc1....", "nonce": "...", "signature": "<base64url 64-byte Ed25519 sig>"}
```

Response (`200`):

```json
{
  "lease": "vanl1....",
  "device_id": "dev_...",
  "remote_user_id": "usr_...",
  "issued_at": 1700000000,
  "expires_at": 1700000045
}
```

### 4. `POST /v1/identity/renew`

Two mutually exclusive modes are supported:

1. **Direct live-token renewal** (preferred whenever the host client has a current auth token):
   - Client signs `identity.DirectRenewProofMessage(nonce, token, public_key)`:
     ```text
     vanora-identity-renew-token-v1
     <nonce>
     <base64url(sha256(token))>
     <base64url(public_key)>
     ```
   - Request: `{"token": "...", "public_key": "...", "nonce": "...", "signature": "..."}`
2. **Opaque refresh-handle renewal** (optional, for unattended renewal when the authority issued a handle):
   - Client signs `identity.RenewProofMessage(nonce, refresh_handle)`:
     ```text
     vanora-identity-renew-v1
     <nonce>
     <base64url(sha256(refresh_handle))>
     ```
   - Request: `{"refresh_handle": "...", "nonce": "...", "signature": "..."}`

Response (`200`):

```json
{
  "certificate": "vanc1....",
  "refresh_handle": "...",
  "device_id": "dev_...",
  "remote_user_id": "usr_...",
  "expires_at": 1700000600
}
```

`refresh_handle` is optional on direct-token renewal and required on handle-based renewal. Definitive `401` denial codes recognized by `adapter/account` are `token_rejected`, `refresh_rejected`, and `identity_verification_failed`.

## Tests

```sh
go test ./internal/identity/...
```

`internal/identity/identitytest` provides a test-only `Authority` for minting certificates and leases in unit and integration tests; production code must never import it.
