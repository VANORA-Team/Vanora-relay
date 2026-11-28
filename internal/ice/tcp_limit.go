package ice

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

const (
	tcpFirstReadTimeout = 30 * time.Second
	tcpIdleTimeout      = 11 * time.Minute
)

// limitedListener caps concurrent TURN-over-TCP control connections, globally
// and per source IP, and enforces handshake and idle deadlines. TURN allocates a
// goroutine, a read buffer, and a socket per accepted connection, so an
// unbounded accept loop lets a single attacker exhaust the process.
type limitedListener struct {
	ln           net.Listener
	maxTotal     int
	maxPerIP     int
	firstTimeout time.Duration
	idleTimeout  time.Duration
	mu           sync.Mutex
	closed       bool
	perIP        map[string]int
	tracked      map[net.Conn]struct{}
}

func newLimitedListener(ln net.Listener, maxTotal, maxPerIP int) *limitedListener {
	if maxTotal < 1 {
		maxTotal = 1
	}
	if maxPerIP < 1 {
		maxPerIP = 1
	}
	return &limitedListener{
		ln:           ln,
		maxTotal:     maxTotal,
		maxPerIP:     maxPerIP,
		firstTimeout: tcpFirstReadTimeout,
		idleTimeout:  tcpIdleTimeout,
		perIP:        make(map[string]int),
		tracked:      make(map[net.Conn]struct{}),
	}
}

func (l *limitedListener) Addr() net.Addr { return l.ln.Addr() }

func (l *limitedListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	err := l.ln.Close()
	for conn := range l.tracked {
		_ = conn.Close()
	}
	clear(l.tracked)
	clear(l.perIP)
	return err
}

func ipKey(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok && tcp.IP != nil {
		return tcp.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return nil, err
		}
		if !l.reserve(conn) {
			_ = conn.Close()
			continue
		}
		if err := conn.SetReadDeadline(time.Now().Add(l.firstTimeout)); err != nil {
			_ = conn.Close()
			l.release(conn)
			continue
		}
		return &firstReadConn{Conn: conn, l: l}, nil
	}
}

// reserve tracks a new connection under both caps. It reports false when the
// connection is over either cap.
func (l *limitedListener) reserve(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || len(l.tracked) >= l.maxTotal {
		return false
	}
	ip := ipKey(conn.RemoteAddr())
	if l.perIP[ip] >= l.maxPerIP {
		return false
	}
	l.perIP[ip]++
	l.tracked[conn] = struct{}{}
	return true
}

// release forgets a tracked connection. It is safe to call more than once.
func (l *limitedListener) release(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tracked[conn]; !ok {
		return
	}
	delete(l.tracked, conn)
	ip := ipKey(conn.RemoteAddr())
	if l.perIP[ip] > 0 {
		l.perIP[ip]--
		if l.perIP[ip] == 0 {
			delete(l.perIP, ip)
		}
	}
}

// firstReadConn keeps the initial deadline until a complete STUN frame
// arrives. A TURN client starts with STUN before it can use ChannelData.
type firstReadConn struct {
	net.Conn
	l           *limitedListener
	readMu      sync.Mutex
	header      [20]byte
	firstBytes  int
	established bool
}

func (c *firstReadConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.established {
		if err := c.Conn.SetReadDeadline(time.Now().Add(c.l.idleTimeout)); err != nil {
			_ = c.Close()
			return 0, err
		}
	}
	n, err := c.Conn.Read(b)
	if n > 0 && !c.established {
		if c.firstBytes < len(c.header) {
			copy(c.header[c.firstBytes:], b[:n])
		}
		c.firstBytes += n
		if c.firstBytes >= len(c.header) {
			bodySize := int(binary.BigEndian.Uint16(c.header[2:4]))
			c.established = c.header[0]&0xc0 == 0 &&
				binary.BigEndian.Uint32(c.header[4:8]) == 0x2112a442 &&
				bodySize%4 == 0 && c.firstBytes >= len(c.header)+bodySize
		}
	}
	if err != nil {
		_ = c.Close()
	}
	return n, err
}

func (c *firstReadConn) Close() error {
	err := c.Conn.Close()
	c.l.release(c.Conn)
	return err
}
