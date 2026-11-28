package lan

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/netip"
	"strings"
	"sync"
	"time"

	"vanora-relay/internal/routes"
)

type cachedLANCert struct {
	cert     tls.Certificate
	pin      string
	notAfter time.Time
}

var (
	lanCertMu    sync.RWMutex
	lanCertCache = make(map[string]cachedLANCert)
)

const (
	Read    = "read"
	Control = "control"
	path    = "/v1/lan"
)

type Store interface {
	Load() (string, error)
	Save(string) error
}

func newKey() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(seed), nil
}

func LoadClientKey(store Store) (string, error) {
	if store == nil {
		return "", errors.New("LAN: secure storage required")
	}
	key, err := store.Load()
	if err != nil {
		return "", err
	}
	if key == "" {
		key, err = newKey()
		if err != nil {
			return "", err
		}
		if err := store.Save(key); err != nil {
			return "", err
		}
	}
	if !validToken(key) {
		return "", errors.New("LAN: invalid stored device key")
	}
	return key, nil
}

func makeCertificate(seed string) (tls.Certificate, string, error) {
	now := time.Now()
	lanCertMu.RLock()
	if cached, ok := lanCertCache[seed]; ok && now.Add(24*time.Hour).Before(cached.notAfter) {
		lanCertMu.RUnlock()
		return cached.cert, cached.pin, nil
	}
	lanCertMu.RUnlock()

	raw, err := base64.RawURLEncoding.Strict().DecodeString(seed)
	if err != nil || len(raw) != ed25519.SeedSize {
		return tls.Certificate{}, "", errors.New("LAN: invalid device key")
	}
	key := ed25519.NewKeyFromSeed(raw)
	publicKey := key.Public().(ed25519.PublicKey)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	notAfter := now.AddDate(10, 0, 0)
	template := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pin := fingerprint(publicKey)
	lanCertMu.Lock()
	if len(lanCertCache) >= 16 {
		clear(lanCertCache)
	}
	lanCertCache[seed] = cachedLANCert{cert: cert, pin: pin, notAfter: notAfter}
	lanCertMu.Unlock()
	return cert, pin, nil
}

func fingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ClientID(seed string) string {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(seed)
	if err != nil || len(raw) != ed25519.SeedSize {
		return ""
	}
	return fingerprint(ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey))
}

func peerFingerprint(state tls.ConnectionState) string {
	if len(state.PeerCertificates) != 1 {
		return ""
	}
	key, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return fingerprint(key)
}

func validToken(value string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == sha256.Size
}

// IsTailnetAddress reports whether address is in RFC 6598 100.64.0.0/10
// shared address space (Tailscale / Headscale / WireGuard tailnets).
func IsTailnetAddress(address netip.Addr) bool {
	return routes.IsTailnetAddr(address)
}

func localAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsPrivate() || address.IsLoopback() || IsTailnetAddress(address)
}

func pathForAddress(address netip.Addr) string {
	if IsTailnetAddress(address) {
		return "tailnet"
	}
	return "lan"
}

func parseLocalAddress(raw string) (netip.AddrPort, error) {
	address, err := netip.ParseAddrPort(raw)
	if err != nil || !localAddress(address.Addr()) || address.Addr().Zone() != "" {
		return netip.AddrPort{}, errors.New("LAN: address must specify a private or tailnet IP and port")
	}
	return address, nil
}

func Access(userID string) string {
	prefix, suffix, _ := strings.Cut(userID, ":")
	level, id, _ := strings.Cut(suffix, ":")
	if prefix == "lan" && (level == Read || level == Control) && validToken(id) {
		return level
	}
	return ""
}

func userID(client ClientInfo) string {
	return "lan:" + client.Access + ":" + client.ID
}
