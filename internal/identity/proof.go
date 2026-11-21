package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
)

// ProofMessage returns the exact bytes an endpoint signs with its Ed25519 key
// to prove possession of the key registered in POST /v1/identity/challenges.
func ProofMessage(challengeID, nonce, purpose string, publicKey ed25519.PublicKey) []byte {
	return []byte("vanora-identity-proof-v1\n" +
		challengeID + "\n" +
		nonce + "\n" +
		purpose + "\n" +
		base64.RawURLEncoding.EncodeToString(publicKey))
}

// LeaseProofMessage returns the exact bytes an endpoint signs with its
// certificate key to request a short-lived liveness lease.
func LeaseProofMessage(nonce, certificate string) []byte {
	sum := sha256.Sum256([]byte(certificate))
	return []byte("vanora-identity-lease-v1\n" +
		nonce + "\n" +
		base64.RawURLEncoding.EncodeToString(sum[:]))
}

// RenewProofMessage returns the exact bytes an endpoint signs with its enrolled
// key to renew a certificate using an opaque refresh handle.
func RenewProofMessage(nonce, handle string) []byte {
	sum := sha256.Sum256([]byte(handle))
	return []byte("vanora-identity-renew-v1\n" +
		nonce + "\n" +
		base64.RawURLEncoding.EncodeToString(sum[:]))
}

// DirectRenewProofMessage returns the exact bytes an endpoint signs with its
// enrolled key to renew a certificate directly using a live client auth token.
func DirectRenewProofMessage(nonce, token string, publicKey ed25519.PublicKey) []byte {
	sum := sha256.Sum256([]byte(token))
	return []byte("vanora-identity-renew-token-v1\n" +
		nonce + "\n" +
		base64.RawURLEncoding.EncodeToString(sum[:]) + "\n" +
		base64.RawURLEncoding.EncodeToString(publicKey))
}
