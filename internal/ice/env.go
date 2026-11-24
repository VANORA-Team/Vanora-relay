package ice

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/pion/turn/v4"
)

// controlPortBindAttempts bounds how often binding the TCP/UDP control pair on
// an ephemeral port is retried when a port is already in use.
const controlPortBindAttempts = 16

// options is the parsed, validated server configuration. FromEnv fills it from
// the environment; tests construct it directly.
type options struct {
	publicIP    net.IP
	bindIP      net.IP
	relayBindIP net.IP

	port      int
	realm     string
	enableUDP bool
	enableTCP bool
	stunURLs  []string

	relayMinPort uint16
	relayMaxPort uint16

	maxGrants              int
	maxGrantsPerVisitor    int
	maxAllocationsPerGrant int
	logLevel               logging.LogLevel

	// allowUnsafePeers disables the public-peer filter. It exists only so
	// allocation/expiry tests can relay over loopback; it is never set from the
	// environment.
	allowUnsafePeers bool
	onRemove         func(removal)
}

// FromEnv starts a STUN/TURN server using STUN_URLS and the TURN_* environment
// variables documented in README.md. TURN_PUBLIC_IP must be the public IPv4
// address clients can reach for relaying.
func FromEnv() (*Server, error) {
	publicIP, err := envIPv4("TURN_PUBLIC_IP", "")
	if err != nil {
		return nil, err
	}
	stunURLs, err := envSTUNURLs()
	if err != nil {
		return nil, err
	}
	bindIP, err := envIPv4("TURN_BIND_IP", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	relayBindIP, err := envIPv4("TURN_RELAY_BIND_IP", bindIP.String())
	if err != nil {
		return nil, err
	}

	port, err := envInt("TURN_PORT", 3478, 0, 65535)
	if err != nil {
		return nil, err
	}
	enableUDP, err := envBool("TURN_UDP", true)
	if err != nil {
		return nil, err
	}
	enableTCP, err := envBool("TURN_TCP", true)
	if err != nil {
		return nil, err
	}

	relayMinPort, err := envInt("TURN_RELAY_MIN_PORT", 49152, 0, 65535)
	if err != nil {
		return nil, err
	}
	relayMaxPort, err := envInt("TURN_RELAY_MAX_PORT", 65535, 0, 65535)
	if err != nil {
		return nil, err
	}
	maxGrants, err := envInt("TURN_MAX_GRANTS", 4096, 1, 1_000_000)
	if err != nil {
		return nil, err
	}
	maxGrantsPerVisitor, err := envInt("TURN_MAX_GRANTS_PER_VISITOR", defaultMaxGrantsPerVisitor(maxGrants), 1, maxGrants)
	if err != nil {
		return nil, err
	}
	maxAllocationsPerGrant, err := envInt("TURN_MAX_ALLOCATIONS_PER_GRANT", 8, 1, 1024)
	if err != nil {
		return nil, err
	}

	logLevel, err := envLogLevel()
	if err != nil {
		return nil, err
	}

	realm := strings.TrimSpace(os.Getenv("TURN_REALM"))
	if realm == "" {
		realm = "vanora"
	}

	return newServer(options{
		publicIP:               publicIP,
		bindIP:                 bindIP,
		relayBindIP:            relayBindIP,
		port:                   port,
		realm:                  realm,
		enableUDP:              enableUDP,
		enableTCP:              enableTCP,
		stunURLs:               stunURLs,
		relayMinPort:           uint16(relayMinPort),
		relayMaxPort:           uint16(relayMaxPort),
		maxGrants:              maxGrants,
		maxGrantsPerVisitor:    maxGrantsPerVisitor,
		maxAllocationsPerGrant: maxAllocationsPerGrant,
		logLevel:               logLevel,
	})
}

func defaultMaxGrantsPerVisitor(maxGrants int) int {
	if maxGrants <= 1 {
		return 1
	}
	limit := maxGrants / 2
	if limit > 32 {
		limit = 32
	}
	return limit
}

func newServer(opts options) (*Server, error) {
	switch {
	case opts.publicIP == nil || opts.publicIP.To4() == nil:
		return nil, errors.New("ice: public IPv4 address is required")
	case opts.bindIP == nil || opts.bindIP.To4() == nil:
		return nil, errors.New("ice: bind IPv4 address is required")
	case opts.relayBindIP == nil || opts.relayBindIP.To4() == nil:
		return nil, errors.New("ice: relay bind IPv4 address is required")
	case opts.realm == "":
		return nil, errors.New("ice: realm is required")
	case opts.port < 0 || opts.port > 65535:
		return nil, errors.New("ice: control port out of range")
	case !opts.enableUDP && !opts.enableTCP:
		return nil, errors.New("ice: at least one control transport must be enabled")
	case opts.maxGrants <= 0:
		return nil, errors.New("ice: max grants must be positive")
	case opts.maxAllocationsPerGrant <= 0:
		return nil, errors.New("ice: max allocations per grant must be positive")
	case (opts.relayMinPort == 0) != (opts.relayMaxPort == 0):
		return nil, errors.New("ice: relay port range must set both bounds or neither")
	case opts.relayMinPort > opts.relayMaxPort:
		return nil, errors.New("ice: relay port range is inverted")
	}

	publicAddr, ok := netip.AddrFromSlice(opts.publicIP)
	if !ok {
		return nil, errors.New("ice: public IPv4 address is required")
	}

	if opts.maxGrantsPerVisitor <= 0 {
		opts.maxGrantsPerVisitor = defaultMaxGrantsPerVisitor(opts.maxGrants)
	}
	s := &Server{
		realm:                  opts.realm,
		publicIP:               publicAddr.Unmap(),
		maxGrants:              opts.maxGrants,
		maxGrantsPerVisitor:    opts.maxGrantsPerVisitor,
		maxAllocationsPerGrant: opts.maxAllocationsPerGrant,
		allowUnsafePeers:       opts.allowUnsafePeers,
		localAddrs:             hostInterfaceAddrs(),
		onRemove:               opts.onRemove,
		grants:                 make(map[string]*grant),
		byUsername:             make(map[string]*grant),
		allocRelays:            make(map[string]*relayConn),
		relays:                 make(map[string]*relayConn),
		localRelays:            make(map[netip.AddrPort]*relayConn),
		visitors:               make(map[string]*visitorUsage),
	}

	port := opts.port
	var packetConns []net.PacketConn
	var listeners []net.Listener
	closeAll := func() {
		for _, pc := range packetConns {
			_ = pc.Close()
		}
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}

	// With both control transports on an ephemeral port, bind TCP first and
	// then UDP on the same port. The two protocols draw from overlapping
	// ephemeral ranges, and Windows reports a collision as WSAEACCES rather
	// than EADDRINUSE, so any failure of this second bind is retried with a
	// fresh TCP port, within a bound.
	attempts := 1
	if opts.enableTCP && opts.enableUDP && opts.port == 0 {
		attempts = controlPortBindAttempts
	}

	for attempt := 0; ; attempt++ {
		if opts.enableTCP {
			ln, err := net.Listen("tcp4", net.JoinHostPort(opts.bindIP.String(), strconv.Itoa(port)))
			if err != nil {
				if attempt+1 < attempts {
					closeAll()
					packetConns, listeners = nil, nil
					port = 0

					continue
				}
				closeAll()

				return nil, fmt.Errorf("ice: listen tcp %s:%d: %w", opts.bindIP, port, err)
			}
			listeners = append(listeners, ln)
			if port == 0 {
				port = ln.Addr().(*net.TCPAddr).Port
			}
		}

		if opts.enableUDP {
			pc, err := net.ListenPacket("udp4", net.JoinHostPort(opts.bindIP.String(), strconv.Itoa(port)))
			if err != nil {
				if attempt+1 < attempts {
					closeAll()
					packetConns, listeners = nil, nil
					port = 0

					continue
				}
				closeAll()

				return nil, fmt.Errorf("ice: listen udp %s:%d: %w", opts.bindIP, port, err)
			}
			packetConns = append(packetConns, pc)
			if port == 0 {
				port = pc.LocalAddr().(*net.UDPAddr).Port
			}
		}

		break
	}

	s.controlAddr = net.JoinHostPort(opts.bindIP.String(), strconv.Itoa(port))

	hostPort := net.JoinHostPort(opts.publicIP.String(), strconv.Itoa(port))
	s.stunURLs = opts.stunURLs
	if len(s.stunURLs) == 0 {
		s.stunURLs = []string{"stun:" + hostPort}
	}
	if opts.enableUDP {
		s.turnURLs = append(s.turnURLs, "turn:"+hostPort+"?transport=udp")
	}
	if opts.enableTCP {
		s.turnURLs = append(s.turnURLs, "turn:"+hostPort+"?transport=tcp")
	}

	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.DefaultLogLevel = opts.logLevel

	turnConfig := turn.ServerConfig{
		Realm:         opts.realm,
		AuthHandler:   s.authenticate,
		QuotaHandler:  s.quota,
		LoggerFactory: loggerFactory,
		EventHandler: turn.EventHandler{
			OnAllocationCreated: s.allocationCreated,
			OnAllocationDeleted: s.allocationDeleted,
		},
	}
	for _, pc := range packetConns {
		turnConfig.PacketConnConfigs = append(turnConfig.PacketConnConfigs, turn.PacketConnConfig{
			PacketConn:            pc,
			RelayAddressGenerator: opts.relayGenerator(s),
			PermissionHandler:     s.peerAllowed,
		})
	}
	for _, ln := range listeners {
		turnConfig.ListenerConfigs = append(turnConfig.ListenerConfigs, turn.ListenerConfig{
			Listener:              ln,
			RelayAddressGenerator: opts.relayGenerator(s),
			PermissionHandler:     s.peerAllowed,
		})
	}

	turnServer, err := turn.NewServer(turnConfig)
	if err != nil {
		closeAll()

		return nil, fmt.Errorf("ice: start TURN server: %w", err)
	}
	s.turnServer = turnServer

	return s, nil
}

// relayGenerator returns a fresh generator for one control listener. The pion
// range generator keeps mutable state (a math/rand source) and is not safe for
// concurrent use, so listeners must not share an instance.
func (o options) relayGenerator(s *Server) turn.RelayAddressGenerator {
	var inner turn.RelayAddressGenerator
	if o.relayMinPort == 0 && o.relayMaxPort == 0 {
		inner = &turn.RelayAddressGeneratorStatic{
			RelayAddress: o.publicIP,
			Address:      o.relayBindIP.String(),
		}
	} else {
		inner = &turn.RelayAddressGeneratorPortRange{
			RelayAddress: o.publicIP,
			MinPort:      o.relayMinPort,
			MaxPort:      o.relayMaxPort,
			MaxRetries:   50,
			Address:      o.relayBindIP.String(),
		}
	}

	return &countingGenerator{inner: inner, srv: s}
}

func envSTUNURLs() ([]string, error) {
	value := strings.TrimSpace(os.Getenv("STUN_URLS"))
	switch value {
	case "":
		return []string{"stun:stun.miwifi.com:3478", "stun:stun.chat.bilibili.com:3478"}, nil
	case "local":
		return nil, nil
	}

	urls := strings.Split(value, ",")
	for i, raw := range urls {
		raw = strings.TrimSpace(raw)
		uri, err := stun.ParseURI(raw)
		if err != nil || uri.Scheme != stun.SchemeTypeSTUN || uri.Port < 1 || uri.Port > 65535 ||
			strings.ContainsAny(raw, "/\\@?# \t\r\n") {
			return nil, fmt.Errorf("ice: STUN_URLS entry %d must be a stun:host[:port] URL", i+1)
		}
		urls[i] = raw
	}

	return urls, nil
}

func envIPv4(name, fallback string) (net.IP, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		value = fallback
	}
	if value == "" {
		return nil, fmt.Errorf("ice: %s is required", name)
	}

	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("ice: %s must be an IPv4 address, got %q", name, value)
	}

	return ip.To4(), nil
}

func envInt(name string, fallback, minValue, maxValue int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}

	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("ice: %s must be an integer, got %q", name, value)
	}
	if n < minValue || n > maxValue {
		return 0, fmt.Errorf("ice: %s must be between %d and %d, got %d", name, minValue, maxValue, n)
	}

	return n, nil
}

func envBool(name string, fallback bool) (bool, error) {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch value {
	case "":
		return fallback, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("ice: %s must be a boolean, got %q", name, value)
	}
}

func envLogLevel() (logging.LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TURN_LOG_LEVEL"))) {
	case "":
		return logging.LogLevelError, nil
	case "disabled":
		return logging.LogLevelDisabled, nil
	case "error":
		return logging.LogLevelError, nil
	case "warn", "warning":
		return logging.LogLevelWarn, nil
	case "info":
		return logging.LogLevelInfo, nil
	case "debug":
		return logging.LogLevelDebug, nil
	case "trace":
		return logging.LogLevelTrace, nil
	default:
		return 0, errors.New("ice: TURN_LOG_LEVEL must be disabled, error, warn, info, debug, or trace")
	}
}
