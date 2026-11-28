// Package cftunnel authenticates and encrypts peer connections carried over
// Cloudflare Named Tunnels.
package cftunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
)

const (
	Subprotocol      = "vanora-tunnel.v1"
	tunnelPath       = "/v1/tunnel/ws"
	innerALPN        = "vanora-cf/1"
	exporterLabel    = "EXPORTER-vanora-cf-tunnel-v1"
	handshakeTimeout = 10 * time.Second
)

// ConnectionContext binds an authenticated tunnel to one signed permit.
type ConnectionContext struct {
	Channel         string
	Scope           string
	ConnectionID    string
	Hostname        string
	Generation      int64
	Incarnation     int64
	RuntimeID       string
	JTI             string
	HostDeviceID    string
	HostKeyHash     string
	VisitorDeviceID string
	VisitorKeyHash  string
	VisitorRole     string
}

type leaseProvider func(context.Context) (endpoint.LeaseProof, error)

func (binding ConnectionContext) official() bool { return binding.Channel != "self" }

// KeyHash encodes a device key as the SHA-256 hex digest used in tunnel signaling.
func KeyHash(key ed25519.PublicKey) string {
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:])
}

func validHostname(host string) bool {
	if len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func (binding ConnectionContext) validate(host, visitor ed25519.PublicKey) error {
	if (binding.Channel != "self" && binding.Channel != "cn" && binding.Channel != "global") ||
		(binding.VisitorRole != "mobile" && binding.VisitorRole != "desktop") ||
		!validHostname(binding.Hostname) || binding.Generation <= 0 || binding.Incarnation <= 0 ||
		binding.HostDeviceID == binding.VisitorDeviceID || len(host) != ed25519.PublicKeySize ||
		len(visitor) != ed25519.PublicKeySize || binding.HostKeyHash != KeyHash(host) ||
		binding.VisitorKeyHash != KeyHash(visitor) {
		return errors.New("cftunnel: invalid connection binding")
	}
	for _, value := range []string{binding.Scope, binding.ConnectionID, binding.RuntimeID, binding.JTI, binding.HostDeviceID, binding.VisitorDeviceID} {
		if len(value) == 0 || len(value) > 128 || strings.ContainsFunc(value, func(char rune) bool {
			return char <= ' ' || char >= 127 || char == ','
		}) {
			return errors.New("cftunnel: invalid connection identifier")
		}
	}
	return nil
}

func frameFields(fields ...string) []byte {
	var payload []byte
	for _, field := range fields {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(field)))
		payload = append(payload, field...)
	}
	return payload
}

func (binding ConnectionContext) hash() [sha256.Size]byte {
	return sha256.Sum256(frameFields(innerALPN, binding.Channel, binding.Scope, binding.ConnectionID,
		binding.Hostname, strconv.FormatInt(binding.Generation, 10), strconv.FormatInt(binding.Incarnation, 10),
		binding.RuntimeID, binding.JTI, binding.HostDeviceID, binding.HostKeyHash, binding.VisitorDeviceID,
		binding.VisitorKeyHash, binding.VisitorRole))
}

func validPrivateKey(key ed25519.PrivateKey) bool {
	return len(key) == ed25519.PrivateKeySize && key.Equal(ed25519.NewKeyFromSeed(key.Seed()))
}

type certCacheKey struct {
	keyHash [sha256.Size]byte
	usage   x509.ExtKeyUsage
}

type cachedCert struct {
	cert    tls.Certificate
	renewAt time.Time
}

var innerCertCache struct {
	mu      sync.Mutex
	entries map[certCacheKey]cachedCert
}

func makeCertificate(key ed25519.PrivateKey, usage x509.ExtKeyUsage, now time.Time) (tls.Certificate, error) {
	pub, _ := key.Public().(ed25519.PublicKey)
	cacheKey := certCacheKey{keyHash: sha256.Sum256(pub), usage: usage}
	innerCertCache.mu.Lock()
	if cached, ok := innerCertCache.entries[cacheKey]; ok && now.Before(cached.renewAt) {
		innerCertCache.mu.Unlock()
		return cached.cert, nil
	}
	innerCertCache.mu.Unlock()

	template := &x509.Certificate{
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	innerCertCache.mu.Lock()
	if innerCertCache.entries == nil {
		innerCertCache.entries = make(map[certCacheKey]cachedCert)
	}
	if len(innerCertCache.entries) >= 64 {
		for k, v := range innerCertCache.entries {
			if !now.Before(v.renewAt) {
				delete(innerCertCache.entries, k)
			}
		}
		if len(innerCertCache.entries) >= 64 {
			clear(innerCertCache.entries)
		}
	}
	innerCertCache.entries[cacheKey] = cachedCert{cert: cert, renewAt: now.Add(12 * time.Hour)}
	innerCertCache.mu.Unlock()
	return cert, nil
}

func tlsConfig(key ed25519.PrivateKey, pin ed25519.PublicKey, server bool) (*tls.Config, error) {
	localUsage, remoteUsage := x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth
	if server {
		localUsage, remoteUsage = remoteUsage, localUsage
	}
	cert, err := makeCertificate(key, localUsage, time.Now())
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             []string{innerALPN},
		CurvePreferences:       []tls.CurveID{tls.X25519},
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{cert},
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != innerALPN ||
				state.DidResume || len(state.PeerCertificates) != 1 {
				return errors.New("cftunnel: invalid inner TLS session")
			}
			leaf := state.PeerCertificates[0]
			peerKey, ok := leaf.PublicKey.(ed25519.PublicKey)
			now := time.Now()
			if !ok || !pin.Equal(peerKey) || leaf.IsCA || len(leaf.UnhandledCriticalExtensions) != 0 ||
				now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
				leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
				len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != remoteUsage ||
				!bytes.Equal(leaf.RawIssuer, leaf.RawSubject) ||
				leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
				return errors.New("cftunnel: invalid inner TLS peer certificate")
			}
			return nil
		},
	}
	if server {
		cfg.ClientAuth = tls.RequireAnyClientCert
	} else {
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

func leaseAccess(binding ConnectionContext, server bool, ca ed25519.PublicKey, local, remote identity.Principal, provider leaseProvider) (*endpoint.Access, error) {
	if !binding.official() {
		return nil, nil
	}
	localID, remoteID := binding.VisitorDeviceID, binding.HostDeviceID
	localHash, remoteHash := binding.VisitorKeyHash, binding.HostKeyHash
	if server {
		localID, remoteID = remoteID, localID
		localHash, remoteHash = remoteHash, localHash
	}
	if provider == nil || local.DeviceID != localID || remote.DeviceID != remoteID ||
		KeyHash(local.PublicKey) != localHash || KeyHash(remote.PublicKey) != remoteHash {
		return nil, errors.New("cftunnel: official leases require matching pinned identities and a local proof provider")
	}
	return endpoint.NewPeerAccess(ca, local, remote)
}

func innerHandshake(ctx, lifetime context.Context, ws *websocket.Conn, cfg *tls.Config, binding ConnectionContext, server bool, access *endpoint.Access, provider leaseProvider) (*tls.Conn, error) {
	stream := websocket.NetConn(lifetime, ws, websocket.MessageBinary)
	ws.SetReadLimit(64 << 10)
	conn := tls.Client(stream, cfg)
	if server {
		conn = tls.Server(stream, cfg)
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = ws.CloseNow() })
	defer stop()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := exchangeProof(ctx, conn, binding, server, access, provider); err != nil {
		return nil, err
	}
	if !stop() || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

type proofRecord struct {
	MAC   string          `json:"mac"`
	Lease json.RawMessage `json:"lease_proof,omitempty"`
}

func exchangeProof(ctx context.Context, conn *tls.Conn, binding ConnectionContext, server bool, access *endpoint.Access, provider leaseProvider) error {
	state := conn.ConnectionState()
	hash := binding.hash()
	key, err := state.ExportKeyingMaterial(exporterLabel, hash[:], sha256.Size)
	if err != nil {
		return err
	}
	clientMAC := proofMAC(key, "client-proof")
	serverMAC := proofMAC(key, "server-proof")
	localMAC, remoteMAC := clientMAC, serverMAC
	if server {
		localMAC, remoteMAC = serverMAC, clientMAC
	}
	record := proofRecord{MAC: base64.RawURLEncoding.EncodeToString(localMAC)}
	if access != nil {
		proof, err := provider(ctx)
		if err != nil {
			return errors.New("cftunnel: local lease unavailable")
		}
		if err := access.Update(true, proof, time.Now()); err != nil {
			return errors.New("cftunnel: invalid local lease proof")
		}
		record.Lease = protocol.Encode(proof)
	}
	// Exchange proofs full-duplex so handshake saves one network RTT.
	writeErr := make(chan error, 1)
	go func() {
		writeErr <- writeRecord(conn, frameProof, protocol.Encode(record))
	}()
	readErr := readProof(conn, remoteMAC, access)
	if err := <-writeErr; err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	if access != nil && !access.Allows(time.Now(), true, true) {
		return transport.ErrUnauthorized
	}
	return nil
}

func proofMAC(key []byte, direction string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(direction))
	return mac.Sum(nil)
}

func readProof(conn *tls.Conn, expectedMAC []byte, access *endpoint.Access) error {
	kind, payload, err := readRecord(conn)
	if err != nil {
		return err
	}
	var record proofRecord
	if kind != frameProof || strictjson.Decode(payload, &record) != nil {
		return errors.New("cftunnel: invalid first proof record")
	}
	mac, err := base64.RawURLEncoding.Strict().DecodeString(record.MAC)
	if err != nil || !hmac.Equal(mac, expectedMAC) {
		return errors.New("cftunnel: TLS proof context mismatch")
	}
	if access == nil {
		if record.Lease != nil {
			return errors.New("cftunnel: unexpected lease on self channel")
		}
		return nil
	}
	var proof endpoint.LeaseProof
	if strictjson.Decode(record.Lease, &proof) != nil || access.Update(false, proof, time.Now()) != nil {
		return errors.New("cftunnel: invalid remote lease proof")
	}
	return nil
}
