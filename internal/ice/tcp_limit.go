package ice

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// tcpFirstReadTimeout bounds how long an accepted control connection may sit
// without producing any bytes. Without it a flood of idle connections pins
// one file descriptor and a goroutine each for the whole connection lifetime.
const tcpFirstReadTimeout = 30 * time.Second

// limitedListener caps concurrent TURN-over-TCP control connections, globally
// and per source IP, and enforces a first-read deadline. TURN allocates a
// goroutine, a read buffer, and a socket per accepted connection, so an
// unbounded accept loop lets a single attacker exhaust the process.
type limitedListener struct {
	ln       net.Listener
	maxTotal int
	maxPerIP int
	mu       sync.Mutex
	perIP    map[string]int
	tracked  map[net.Conn]struct{}
}

func newLimitedListener(ln net.Listener, maxTotal, maxPerIP int) net.Listener {
	if maxTotal < 1 {
		maxTotal = 1
	}
	if maxPerIP < 1 {
		maxPerIP = 1
	}
	return &limitedListener{
		ln:       ln,
		maxTotal: maxTotal,
		maxPerIP: maxPerIP,
		perIP:    make(map[string]int),
		tracked:  make(map[net.Conn]struct{}),
	}
}

func (l *limitedListener) Addr() net.Addr { return l.ln.Addr() }

func (l *limitedListener) Close() error { return l.ln.Close() }

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
		_ = conn.SetReadDeadline(time.Now().Add(tcpFirstReadTimeout))
		return &firstReadConn{Conn: conn, l: l}, nil
	}
}

// reserve tracks a new connection under both caps. It reports false when the
// connection is over either cap.
func (l *limitedListener) reserve(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.tracked) >= l.maxTotal {
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

// firstReadConn clears the idle deadline as soon as the peer produces bytes.
// TURN never manages read deadlines after Accept, so after the first
// successful read the connection is unrestricted and the cap bookkeeping
// ends at Close (or a terminal read error, which in practice ends the
// connection as well).
type firstReadConn struct {
	net.Conn
	l         *limitedListener
	firstOnce sync.Once
	cleared   atomic.Bool
}

func (c *firstReadConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.firstOnce.Do(func() {
			_ = c.Conn.SetReadDeadline(time.Time{})
			c.cleared.Store(true)
		})
	}
	if err != nil {
		c.l.release(c.Conn)
	}
	return n, err
}

func (c *firstReadConn) Close() error {
	c.l.release(c.Conn)
	return c.Conn.Close()
}
