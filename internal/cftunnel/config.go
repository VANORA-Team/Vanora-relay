package cftunnel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"vanora-relay/internal/identity"
)

type Channel string
type Mode string
type Process string
type StoreKind string
type EdgeGate string
type ReaperMode string

const (
	ChannelCN     Channel = "cn"
	ChannelGlobal Channel = "global"
	ChannelSelf   Channel = "self"

	ModeOff     Mode = "off"
	ModeManaged Mode = "managed"
	ModeDrain   Mode = "drain"

	ProcessAll     Process = "all"
	ProcessControl Process = "control"

	StoreSQLite   StoreKind = "sqlite"
	StorePostgres StoreKind = "postgres"

	EdgeWorkerHMAC  EdgeGate = "worker_hmac"
	EdgeWAFHMAC     EdgeGate = "waf_hmac"
	EdgeDesktopOnly EdgeGate = "desktop_only"

	ReaperOff    ReaperMode = "off"
	ReaperDryRun ReaperMode = "dry-run"
	ReaperActive ReaperMode = "active"
)

func ParseChannel(value string) (Channel, error) {
	switch channel := Channel(strings.ToLower(strings.TrimSpace(value))); channel {
	case "":
		return ChannelCN, nil
	case ChannelCN, ChannelGlobal, ChannelSelf:
		return channel, nil
	default:
		return "", errors.New("RELAY_CHANNEL must be cn, global or self")
	}
}

func (c Channel) ChecksEntitlement() bool { return c == ChannelCN || c == ChannelGlobal }
func (c Channel) IsSelfHosted() bool      { return c == ChannelSelf }

// Config holds validated tunnel startup settings. ModeOff leaves storage and
// Cloudflare settings unused. Secret values must never be logged.
type Config struct {
	Channel          Channel
	Mode             Mode
	Process          Process
	Store            StoreKind
	SQLitePath       string
	PostgresDSN      string
	ControlOrigin    string
	AccountID        string
	ZoneID           string
	BaseDomain       string
	Namespace        string
	TunnelToken      string
	DNSToken         string
	MasterKey        []byte
	EdgeGate         EdgeGate
	EdgeKey          []byte
	EdgePrevKey      []byte
	EdgeCanaryHost   string
	SiteManifest     *SiteManifest
	TrustedProxies   []netip.Prefix
	SelfDevices      map[string]struct{}
	FreeSlots        int
	PaidDefaultSlots int
	AccountCap       int
	PurchasedCap     int
	Reaper           ReaperConfig
	CloudflareRate   RateConfig
}

type ReaperConfig struct {
	Mode          ReaperMode
	PendingGrace  time.Duration
	DownGrace     time.Duration
	LegacyGrace   time.Duration
	InactiveGrace time.Duration
	OrphanGrace   time.Duration
	Interval      time.Duration
	Budget        time.Duration
	Concurrency   int
}

type RateConfig struct {
	PerSecond   int
	Burst       int
	Concurrency int
}

// SiteManifest pins the independent identity and Cloudflare coordinates of an
// official site. The file is loaded only when tunnels are enabled.
type SiteManifest struct {
	Channel           Channel `json:"channel"`
	CAPublicKeySHA256 string  `json:"ca_public_key_sha256"`
	AllowedIssuer     string  `json:"allowed_issuer"`
	MembershipOrigin  string  `json:"membership_origin"`
	ControlOrigin     string  `json:"control_origin"`
	AccountID         string  `json:"cf_account_id"`
	ZoneID            string  `json:"cf_zone_id"`
	BaseDomain        string  `json:"cf_base_domain"`
	Namespace         string  `json:"cf_namespace"`
}

var (
	cfIDPattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	namespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,15}$`)
	dnsLabelPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ConfigFromEnv validates the selected configuration without opening a DB or
// connecting to Cloudflare. lookupEnv normally receives os.Getenv.
func ConfigFromEnv(channel Channel, lookupEnv func(string) string) (Config, error) {
	if lookupEnv == nil {
		lookupEnv = os.Getenv
	}
	env := envValues{lookup: lookupEnv}
	cfg := Config{
		Channel: channel,
		Mode:    Mode(env.value("RELAY_TUNNEL_MODE", string(ModeOff))),
		Process: Process(env.value("RELAY_TUNNEL_PROCESS", string(ProcessAll))),
	}
	if !channel.ChecksEntitlement() && !channel.IsSelfHosted() {
		return Config{}, errors.New("unknown RELAY_CHANNEL")
	}
	manifest := lookupEnv("RELAY_TUNNEL_SITE_MANIFEST")
	selfDevices := lookupEnv("RELAY_TUNNEL_SELF_ALLOWED_DEVICES")
	if channel.IsSelfHosted() && manifest != "" {
		return Config{}, errors.New("RELAY_TUNNEL_SITE_MANIFEST is only allowed on official channels")
	}
	if channel.ChecksEntitlement() && selfDevices != "" {
		return Config{}, errors.New("RELAY_TUNNEL_SELF_ALLOWED_DEVICES is only allowed with RELAY_CHANNEL=self")
	}
	if channel.ChecksEntitlement() && lookupEnv("RELAY_TUNNEL_EDGE_GATE") == string(EdgeDesktopOnly) {
		return Config{}, errors.New("RELAY_TUNNEL_EDGE_GATE=desktop_only requires RELAY_CHANNEL=self")
	}
	if cfg.Process != ProcessAll && cfg.Process != ProcessControl {
		return Config{}, errors.New("RELAY_TUNNEL_PROCESS must be all or control")
	}
	if cfg.Mode == ModeOff {
		if cfg.Process == ProcessControl {
			return Config{}, errors.New("RELAY_TUNNEL_PROCESS=control requires enabled tunnels")
		}
		return cfg, nil
	}
	if cfg.Mode != ModeManaged && cfg.Mode != ModeDrain {
		return Config{}, errors.New("RELAY_TUNNEL_MODE must be off, managed or drain")
	}
	if err := cfg.loadStorage(env); err != nil {
		return Config{}, err
	}
	control, err := checkedOrigin(lookupEnv("RELAY_TUNNEL_CONTROL_ORIGIN"), false)
	if err != nil {
		return Config{}, fmt.Errorf("RELAY_TUNNEL_CONTROL_ORIGIN: %w", err)
	}
	cfg.ControlOrigin = control
	if err := cfg.loadCloudflare(env); err != nil {
		return Config{}, err
	}
	if channel.IsSelfHosted() {
		cfg.SelfDevices = make(map[string]struct{})
		for device := range strings.SplitSeq(selfDevices, ",") {
			device = strings.TrimSpace(device)
			if !identity.ValidSelfDeviceID(device) || !tunnelLabelPattern.MatchString(strings.TrimPrefix(device, identity.SelfDeviceIDPrefix)) {
				return Config{}, errors.New("RELAY_TUNNEL_SELF_ALLOWED_DEVICES requires valid sdev_ IDs")
			}
			cfg.SelfDevices[device] = struct{}{}
		}
	} else if err := cfg.loadManifest(env, manifest); err != nil {
		return Config{}, err
	}
	if cfg.TrustedProxies, err = trustedProxies(lookupEnv("RELAY_TRUSTED_PROXY_CIDRS")); err != nil {
		return Config{}, err
	}
	if err := cfg.loadLimits(&env); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (cfg *Config) loadStorage(env envValues) error {
	cfg.Store = StoreKind(env.value("RELAY_TUNNEL_STORE", string(StoreSQLite)))
	if cfg.Process == ProcessControl && cfg.Store != StorePostgres {
		return errors.New("RELAY_TUNNEL_PROCESS=control requires postgres")
	}
	switch cfg.Store {
	case StoreSQLite:
		cfg.SQLitePath = env.lookup("RELAY_TUNNEL_SQLITE_PATH")
		if err := ValidateSQLitePath(cfg.SQLitePath); err != nil {
			return fmt.Errorf("RELAY_TUNNEL_SQLITE_PATH: %w", err)
		}
	case StorePostgres:
		cfg.PostgresDSN = env.lookup("RELAY_TUNNEL_PG_DSN")
		if _, err := ParsePostgresDSN(cfg.PostgresDSN); err != nil {
			return fmt.Errorf("RELAY_TUNNEL_PG_DSN: %w", err)
		}
	default:
		return errors.New("RELAY_TUNNEL_STORE must be sqlite or postgres")
	}
	return nil
}

// ValidateSQLitePath accepts a filesystem path suitable for a sidecar lock.
func ValidateSQLitePath(path string) error {
	clean := strings.ToLower(filepath.Base(filepath.Clean(path)))
	if path == "" || strings.TrimSpace(path) != path || clean == "." || clean == ".." ||
		clean == ":memory:" || strings.HasPrefix(strings.ToLower(path), "file:") || strings.ContainsAny(path, "?#\x00\r\n") {
		return errors.New("a persistent SQLite filesystem path is required")
	}
	return nil
}

// ParsePostgresDSN applies remote verify-full to every effective pgx target,
// including fallback hosts. The error deliberately omits the input DSN.
func ParsePostgresDSN(dsn string) (*pgx.ConnConfig, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("a PostgreSQL DSN is required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL DSN")
	}
	if !loopback(cfg.Host) && (cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify || !strings.EqualFold(cfg.TLSConfig.ServerName, cfg.Host)) {
		return nil, errors.New("remote PostgreSQL requires sslmode=verify-full")
	}
	for _, fallback := range cfg.Fallbacks {
		if !loopback(fallback.Host) && (fallback.TLSConfig == nil || fallback.TLSConfig.InsecureSkipVerify || !strings.EqualFold(fallback.TLSConfig.ServerName, fallback.Host)) {
			return nil, errors.New("remote PostgreSQL fallback requires sslmode=verify-full")
		}
	}
	return cfg, nil
}

func (cfg *Config) loadCloudflare(env envValues) error {
	cfg.AccountID = strings.ToLower(env.lookup("RELAY_CF_ACCOUNT_ID"))
	cfg.ZoneID = strings.ToLower(env.lookup("RELAY_CF_ZONE_ID"))
	if !cfIDPattern.MatchString(cfg.AccountID) || !cfIDPattern.MatchString(cfg.ZoneID) {
		return errors.New("RELAY_CF_ACCOUNT_ID and RELAY_CF_ZONE_ID require 32 hexadecimal digits")
	}
	cfg.BaseDomain = normalizeDomain(env.lookup("RELAY_CF_BASE_DOMAIN"))
	if cfg.BaseDomain == "" || len(cfg.BaseDomain) > 253-27 {
		return errors.New("invalid RELAY_CF_BASE_DOMAIN")
	}
	cfg.Namespace = env.lookup("RELAY_CF_NAMESPACE")
	if !namespacePattern.MatchString(cfg.Namespace) {
		return errors.New("invalid RELAY_CF_NAMESPACE")
	}
	cfg.TunnelToken = env.lookup("RELAY_CF_TUNNEL_TOKEN")
	cfg.DNSToken = env.lookup("RELAY_CF_DNS_TOKEN")
	if token := env.lookup("RELAY_CF_API_TOKEN"); token != "" {
		if cfg.TunnelToken != "" || cfg.DNSToken != "" {
			return errors.New("configure a combined RELAY_CF_API_TOKEN or both split tokens")
		}
		cfg.TunnelToken, cfg.DNSToken = token, token
	}
	if !validToken(cfg.TunnelToken) || !validToken(cfg.DNSToken) {
		return errors.New("Cloudflare API tokens require at least 32 bytes without whitespace or control characters")
	}
	var err error
	cfg.MasterKey, err = decodeKey(env.lookup("RELAY_TUNNEL_MASTER_KEY"))
	if err != nil {
		return fmt.Errorf("RELAY_TUNNEL_MASTER_KEY: %w", err)
	}
	cfg.EdgeGate = EdgeGate(env.value("RELAY_TUNNEL_EDGE_GATE", string(EdgeWorkerHMAC)))
	switch cfg.EdgeGate {
	case EdgeDesktopOnly:
		if !cfg.Channel.IsSelfHosted() {
			return errors.New("RELAY_TUNNEL_EDGE_GATE=desktop_only requires RELAY_CHANNEL=self")
		}
	case EdgeWorkerHMAC, EdgeWAFHMAC:
		if key := env.lookup("RELAY_CF_EDGE_KEY"); validEdgeKey(key) {
			cfg.EdgeKey = []byte(key)
		} else {
			return errors.New("RELAY_CF_EDGE_KEY requires at least 32 visible ASCII bytes")
		}
		if prev := env.lookup("RELAY_CF_EDGE_PREV_KEY"); prev != "" {
			if !validEdgeKey(prev) {
				return errors.New("RELAY_CF_EDGE_PREV_KEY requires at least 32 visible ASCII bytes")
			}
			cfg.EdgePrevKey = []byte(prev)
		}
		if cfg.Mode == ModeManaged && env.lookup("RELAY_TUNNEL_EDGE_CANARY_HOST") == "" {
			return errors.New("RELAY_TUNNEL_EDGE_CANARY_HOST is required in managed HMAC mode")
		}
	default:
		return errors.New("invalid RELAY_TUNNEL_EDGE_GATE")
	}
	if raw := env.lookup("RELAY_TUNNEL_EDGE_CANARY_HOST"); raw != "" {
		cfg.EdgeCanaryHost = normalizeDomain(raw)
		if !strings.HasSuffix(cfg.EdgeCanaryHost, "."+cfg.BaseDomain) {
			return errors.New("RELAY_TUNNEL_EDGE_CANARY_HOST must be a subdomain of RELAY_CF_BASE_DOMAIN")
		}
	}
	return nil
}

func (cfg *Config) loadManifest(env envValues, path string) error {
	if path == "" {
		return errors.New("RELAY_TUNNEL_SITE_MANIFEST is required on official channels")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open RELAY_TUNNEL_SITE_MANIFEST: %w", err)
	}
	defer file.Close()
	const maxSize = 16 << 10
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSize {
		return errors.New("RELAY_TUNNEL_SITE_MANIFEST must be a regular JSON file of at most 16 KiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxSize+1))
	decoder.DisallowUnknownFields()
	var manifest SiteManifest
	var extra json.RawMessage
	if decoder.Decode(&manifest) != nil || decoder.Decode(&extra) != io.EOF || decoder.InputOffset() > maxSize {
		return errors.New("invalid RELAY_TUNNEL_SITE_MANIFEST JSON")
	}
	if err := manifest.validateCloudflare(*cfg); err != nil {
		return err
	}
	caDigest, err := hex.DecodeString(manifest.CAPublicKeySHA256)
	if err != nil || len(caDigest) != sha256.Size || manifest.CAPublicKeySHA256 != strings.ToLower(manifest.CAPublicKeySHA256) {
		return errors.New("invalid ca_public_key_sha256 in RELAY_TUNNEL_SITE_MANIFEST")
	}
	issuer := strings.TrimSpace(env.lookup("RELAY_ALLOWED_ISSUER"))
	siteVar := "RELAY_" + strings.ToUpper(string(cfg.Channel)) + "_MEMBERSHIP_URL"
	memberURL := env.value(siteVar, env.lookup("RELAY_MEMBERSHIP_URL"))
	if err := manifest.validateIdentity(issuer, memberURL); err != nil {
		return err
	}
	cfg.SiteManifest = &manifest
	caKey, err := identity.ParsePublicKey([]byte(strings.TrimSpace(env.lookup("RELAY_IDENTITY_PUBLIC_KEY"))))
	if err != nil {
		return errors.New("RELAY_IDENTITY_PUBLIC_KEY must contain the official Ed25519 public key")
	}
	return cfg.ValidateSiteIdentity(caKey, issuer, memberURL)
}

// ValidateSiteIdentity checks the actual key, issuer and membership URL used
// by relay startup. Call it with the resolved startup values before serving.
func (cfg Config) ValidateSiteIdentity(caKey ed25519.PublicKey, allowedIssuer, membershipURL string) error {
	if cfg.Mode == ModeOff || cfg.Channel.IsSelfHosted() {
		return nil
	}
	if cfg.SiteManifest == nil || len(caKey) != ed25519.PublicKeySize {
		return errors.New("official tunnel identity manifest and Ed25519 public key are required")
	}
	hash := sha256.Sum256(caKey)
	if cfg.SiteManifest.CAPublicKeySHA256 != hex.EncodeToString(hash[:]) {
		return errors.New("RELAY_TUNNEL_SITE_MANIFEST ca_public_key_sha256 does not match the configured CA")
	}
	return cfg.SiteManifest.validateIdentity(allowedIssuer, membershipURL)
}

func (cfg Config) BuildScope(caKey ed25519.PublicKey, allowedIssuer, membershipURL string) (Scope, error) {
	if cfg.Mode != ModeManaged && cfg.Mode != ModeDrain || len(cfg.MasterKey) < 32 ||
		!cfIDPattern.MatchString(cfg.AccountID) || !cfIDPattern.MatchString(cfg.ZoneID) ||
		cfg.BaseDomain == "" || normalizeDomain(cfg.BaseDomain) != cfg.BaseDomain || !namespacePattern.MatchString(cfg.Namespace) {
		return Scope{}, ErrScopeMismatch
	}
	controlOrigin, err := checkedOrigin(cfg.ControlOrigin, false)
	if err != nil {
		return Scope{}, ErrScopeMismatch
	}
	scope := Scope{
		Channel: string(cfg.Channel), ControlOrigin: controlOrigin, AccountID: cfg.AccountID, ZoneID: cfg.ZoneID,
		BaseDomain: cfg.BaseDomain, Namespace: cfg.Namespace, MasterKeySHA256: hashHex(cfg.MasterKey),
	}
	switch {
	case cfg.Channel.ChecksEntitlement():
		if err := cfg.ValidateSiteIdentity(caKey, allowedIssuer, membershipURL); err != nil {
			return Scope{}, err
		}
		if err := cfg.SiteManifest.validateCloudflare(cfg); err != nil {
			return Scope{}, err
		}
		scope.CAPublicKeySHA256 = hashHex(caKey)
		scope.AllowedIssuer = allowedIssuer
		scope.MembershipOrigin, _ = checkedOrigin(membershipURL, true)
	case cfg.Channel.IsSelfHosted():
		if len(caKey) != 0 || allowedIssuer != "" || membershipURL != "" || cfg.SiteManifest != nil {
			return Scope{}, ErrScopeMismatch
		}
	default:
		return Scope{}, ErrScopeMismatch
	}
	scope.ID = hashHex(frameFields("vanora/tunnel-scope/v1", scope.Channel, scope.CAPublicKeySHA256,
		scope.AllowedIssuer, scope.MembershipOrigin, scope.ControlOrigin, scope.AccountID, scope.ZoneID,
		scope.BaseDomain, scope.Namespace, scope.MasterKeySHA256))
	return scope, nil
}

func (m SiteManifest) validateCloudflare(cfg Config) error {
	if m.Channel != cfg.Channel || m.ControlOrigin != cfg.ControlOrigin || m.AccountID != cfg.AccountID ||
		m.ZoneID != cfg.ZoneID || m.BaseDomain != cfg.BaseDomain || m.Namespace != cfg.Namespace {
		return errors.New("RELAY_TUNNEL_SITE_MANIFEST does not match channel, control origin or Cloudflare settings")
	}
	return nil
}

func (m SiteManifest) validateIdentity(issuer, memberURL string) error {
	if identity.ValidateIssuerURL(issuer) != nil || strings.ContainsAny(issuer, "?#") || m.AllowedIssuer != issuer {
		return errors.New("RELAY_TUNNEL_SITE_MANIFEST allowed_issuer does not match a valid RELAY_ALLOWED_ISSUER")
	}
	origin, err := checkedOrigin(memberURL, true)
	if err != nil || m.MembershipOrigin != origin {
		return errors.New("RELAY_TUNNEL_SITE_MANIFEST membership_origin does not match the configured membership URL")
	}
	return nil
}

func checkedOrigin(raw string, allowPath bool) (string, error) {
	if identity.ValidateIssuerURL(raw) != nil || strings.ContainsAny(raw, "?#") {
		return "", errors.New("expected HTTPS or loopback HTTP without userinfo, query or fragment")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || !allowPath && parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		return "", errors.New("invalid endpoint origin")
	}
	if port := parsed.Port(); port != "" {
		if value, err := strconv.Atoi(port); err != nil || value < 1 || value > 65535 {
			return "", errors.New("invalid endpoint port")
		}
	}
	return parsed.Scheme + "://" + strings.ToLower(parsed.Host), nil
}

func normalizeDomain(raw string) string {
	domain := strings.ToLower(strings.TrimSuffix(raw, "."))
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return ""
	}
	for label := range strings.SplitSeq(domain, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return ""
		}
	}
	return domain
}

func decodeKey(raw string) ([]byte, error) {
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	if strings.ContainsFunc(raw, unicode.IsSpace) {
		return nil, errors.New("key must contain no whitespace")
	}
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if decoded, err := encoding.Strict().DecodeString(raw); err == nil && len(decoded) >= 32 {
			return decoded, nil
		}
	}
	return nil, errors.New("key must be hex or base64 encoding of at least 32 bytes")
}

func validToken(token string) bool {
	return len(token) >= 32 && !strings.ContainsFunc(token, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

func validEdgeKey(key string) bool {
	return len(key) >= 32 && !strings.ContainsFunc(key, func(r rune) bool { return r < '!' || r > '~' })
}

func loopback(host string) bool {
	address, err := netip.ParseAddr(host)
	return strings.EqualFold(host, "localhost") || err == nil && address.Unmap().IsLoopback()
}

func trustedProxies(raw string) ([]netip.Prefix, error) {
	if raw == "" {
		return nil, nil
	}
	var prefixes []netip.Prefix
	for value := range strings.SplitSeq(raw, ",") {
		value = strings.TrimSpace(value)
		if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
		} else if prefix, err := netip.ParsePrefix(value); err == nil && prefix == prefix.Masked() {
			prefixes = append(prefixes, prefix)
		} else {
			return nil, errors.New("invalid IP or CIDR in RELAY_TRUSTED_PROXY_CIDRS")
		}
	}
	return prefixes, nil
}

type envValues struct {
	lookup func(string) string
	err    error
}

func (e envValues) value(name, fallback string) string {
	if raw := e.lookup(name); raw != "" {
		return raw
	}
	return fallback
}

func (e *envValues) integer(name string, fallback, lower, upper int) int {
	value, err := strconv.Atoi(e.value(name, strconv.Itoa(fallback)))
	if e.err == nil {
		if err != nil {
			e.err = fmt.Errorf("%s must be an integer", name)
		} else {
			e.err = validateLimit(name, value, lower, upper)
		}
	}
	return value
}

func (e *envValues) duration(name string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(e.value(name, fallback.String()))
	if e.err == nil && (err != nil || value <= 0) {
		e.err = fmt.Errorf("%s must be a positive duration", name)
	}
	return value
}

func (cfg *Config) loadLimits(env *envValues) error {
	cfg.FreeSlots = env.integer("RELAY_TUNNEL_FREE_SLOTS", 1, 0, 10000)
	cfg.PaidDefaultSlots = env.integer("RELAY_TUNNEL_PAID_DEFAULT_SLOTS", 3, cfg.FreeSlots, 10000)
	accountDefault := 900
	if cfg.Channel.IsSelfHosted() {
		accountDefault = 16
	}
	cfg.AccountCap = env.integer("RELAY_TUNNEL_ACCOUNT_CAP", accountDefault, 1, 1000000)
	cfg.PurchasedCap = env.integer("RELAY_TUNNEL_PURCHASED_CAP", 0, 0, 1000000)
	cfg.Reaper = ReaperConfig{
		Mode:          ReaperMode(env.value("RELAY_TUNNEL_REAPER", string(ReaperDryRun))),
		DownGrace:     env.duration("RELAY_TUNNEL_REAP_DOWN", 5*time.Minute),
		LegacyGrace:   env.duration("RELAY_TUNNEL_REAP_LEGACY", 168*time.Hour),
		InactiveGrace: env.duration("RELAY_TUNNEL_REAP_INACTIVE", time.Hour),
		PendingGrace:  env.duration("RELAY_TUNNEL_REAP_PENDING", 15*time.Minute),
		OrphanGrace:   env.duration("RELAY_TUNNEL_REAP_ORPHAN", 24*time.Hour),
		Interval:      env.duration("RELAY_TUNNEL_REAPER_INTERVAL", time.Minute),
		Budget:        env.duration("RELAY_TUNNEL_REAPER_BUDGET", 30*time.Second),
		Concurrency:   env.integer("RELAY_TUNNEL_REAPER_CONCURRENCY", 2, 1, 10000),
	}
	cfg.CloudflareRate = RateConfig{
		PerSecond:   env.integer("RELAY_CF_API_RPS", 3, 1, 10000),
		Burst:       env.integer("RELAY_CF_API_BURST", 4, 1, 10000),
		Concurrency: env.integer("RELAY_CF_API_CONCURRENCY", 4, 1, 10000),
	}
	if env.err != nil {
		return env.err
	}
	if cfg.AccountCap > 1000 && cfg.PurchasedCap < cfg.AccountCap {
		return errors.New("RELAY_TUNNEL_ACCOUNT_CAP above 1000 requires matching RELAY_TUNNEL_PURCHASED_CAP")
	}
	switch cfg.Reaper.Mode {
	case ReaperOff, ReaperDryRun, ReaperActive:
		return nil
	default:
		return errors.New("RELAY_TUNNEL_REAPER must be off, dry-run or active")
	}
}
