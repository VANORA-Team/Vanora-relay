package cftunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/internal/membership"
)

type MembershipLookup interface {
	Lookup(context.Context, string, string) (membership.Entitlement, error)
}

const errMembershipUnavailable ErrorCode = "membership_unavailable"

func (s *Service) lookupMembership(ctx context.Context, principal identity.Principal) (membership.Entitlement, error) {
	if s.membership == nil || principal.Issuer != s.scope.AllowedIssuer || principal.Subject == "" {
		return membership.Entitlement{}, errMembershipUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ent, err := s.membership.Lookup(ctx, principal.Issuer, principal.Subject)
	if err != nil {
		return membership.Entitlement{}, errMembershipUnavailable
	}
	return ent, nil
}

func HTTPProofPayload(channel Channel, controlOrigin, canonicalPath, actorDeviceID, challenge, rawBodySHA256Hex, idempotencyKey, credentialHashHex string) []byte {
	return frameFields("vanora/tunnel-http/v1", string(channel), controlOrigin, http.MethodPost, canonicalPath,
		actorDeviceID, challenge, rawBodySHA256Hex, idempotencyKey, credentialHashHex)
}

func SignHTTPProof(key ed25519.PrivateKey, channel Channel, controlOrigin, canonicalPath, actorDeviceID, challenge, rawBodySHA256Hex, idempotencyKey, credentialHashHex string) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, HTTPProofPayload(channel, controlOrigin, canonicalPath,
		actorDeviceID, challenge, rawBodySHA256Hex, idempotencyKey, credentialHashHex)))
}

var authHeaders = []string{
	"Authorization", "Vanora-Certificate", "Vanora-Lease", "Vanora-Public-Key",
	"Vanora-Challenge", "Vanora-Proof", "Idempotency-Key",
}

func validAuthHeaders(headers http.Header, self bool) bool {
	for _, header := range authHeaders {
		if len(headers.Values(header)) > 1 {
			return false
		}
	}
	if self {
		return len(headers.Values("Vanora-Certificate")) == 0 && len(headers.Values("Vanora-Lease")) == 0
	}
	return len(headers.Values("Authorization")) == 0 && len(headers.Values("Vanora-Public-Key")) == 0
}

func (h *httpHandler) validBearer(header string) bool {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	presented := sha256.Sum256([]byte(header[len(prefix):]))
	return h.hasToken && subtle.ConstantTimeCompare(h.selfToken[:], presented[:]) == 1
}

func (h *httpHandler) authenticate(r *http.Request, action, bodyHash string, now time.Time) (identity.Principal, ProofUse, error) {
	var principal identity.Principal
	var credentialHash string
	if h.s.cfg.Channel.IsSelfHosted() {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(r.Header.Get("Vanora-Public-Key"))
		key := ed25519.PublicKey(raw)
		device, keyErr := identity.SelfDeviceID(key)
		if err != nil || keyErr != nil {
			return principal, ProofUse{}, ErrInvalidProof
		}
		principal = identity.Principal{DeviceID: device, Subject: device, PublicKey: key}
		credentialHash = hashHex(key)
	} else {
		cert, lease := r.Header.Get("Vanora-Certificate"), r.Header.Get("Vanora-Lease")
		var err error
		principal, err = identity.VerifyCertificate(cert, h.caKey, now)
		if err != nil || principal.Issuer != h.s.scope.AllowedIssuer || !principal.Expires.After(now) {
			return principal, ProofUse{}, ErrInvalidProof
		}
		expires, err := identity.VerifyEndpointLease(lease, h.caKey, now, cert, principal)
		if err != nil || !expires.After(now) {
			return principal, ProofUse{}, ErrInvalidProof
		}
		credentialHash = hashHex([]byte(cert + "\x00" + lease))
	}
	challenge := r.Header.Get("Vanora-Challenge")
	proof, err := h.s.crypto.VerifyChallenge(challenge, h.s.scope.ID, action, principal.DeviceID, now)
	if err != nil {
		return principal, ProofUse{}, err
	}
	payload := HTTPProofPayload(h.s.cfg.Channel, h.s.scope.ControlOrigin, r.URL.Path, principal.DeviceID, challenge,
		bodyHash, r.Header.Get("Idempotency-Key"), credentialHash)
	signature, err := base64.RawURLEncoding.Strict().DecodeString(r.Header.Get("Vanora-Proof"))
	if err != nil || !ed25519.Verify(principal.PublicKey, payload, signature) {
		return principal, ProofUse{}, ErrInvalidProof
	}
	return principal, proof, nil
}

func (s *Service) ownerPolicy(ctx context.Context, principal identity.Principal, now time.Time) (ClaimPolicy, error) {
	var quota OwnerQuotaDecision
	if s.cfg.Channel.IsSelfHosted() {
		_, allowlisted := s.cfg.SelfDevices[principal.DeviceID]
		quota = EvaluateSelfOwnerPolicy(allowlisted, 1, now, nil)
	} else {
		ent, err := s.lookupMembership(ctx, principal)
		if err != nil {
			return ClaimPolicy{}, err
		}
		quota = EvaluateOwnerPolicy(ent, s.now(), s.cfg.FreeSlots, s.cfg.PaidDefaultSlots, nil)
	}
	if !quota.Allowed {
		return ClaimPolicy{}, ErrEntitlementDenied
	}
	return ClaimPolicy{OwnerSlots: quota.MaxTunnels}, nil
}
