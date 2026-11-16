package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"yadbp/internal/blacklist"
	"yadbp/internal/fragment"
	"yadbp/internal/logging"
	"yadbp/internal/resolver"
	"yadbp/internal/utils"
)

const (
	// maxHTTPHeaderSize bounds the proxy request head we buffer.
	maxHTTPHeaderSize = 64 * 1024
	// maxTLSRecordSize is the largest TLS record body accepted for
	// fragmentation. Larger records are streamed through unchanged.
	maxTLSRecordSize = 16 * 1024
	// headerReadTimeout bounds reading the HTTP request head.
	headerReadTimeout = 10 * time.Second
	// initialDataTimeout bounds waiting for the client's first tunnel payload.
	initialDataTimeout = 10 * time.Second
	// dialTimeout bounds a single upstream TCP connect.
	dialTimeout = 10 * time.Second
	// ctxTimeout bounds CONNECT setup, including DNS and any first-byte retry.
	ctxTimeout = 20 * time.Second
	// When a host has another address to try, fail over quickly. With only one
	// address, give the origin more time because a retry cannot help.
	tlsFirstByteTimeoutMulti  = 3 * time.Second
	tlsFirstByteTimeoutSingle = 5 * time.Second
	// badIPTTL is how long a host/IP pair stays marked bad after it accepts TCP
	// without sending a TLS response.
	badIPTTL = 5 * time.Minute
	// badIPCacheMax caps the number of remembered bad host/IP pairs.
	badIPCacheMax = 1000
	// dialStaggerDelay is the delay between starting additional address dials.
	dialStaggerDelay = 250 * time.Millisecond
)

// errAllSkipped is returned when every candidate address is excluded by skip.
var errAllSkipped = errors.New("all candidate addresses are marked bad")

// Options configures the proxy listener and its optional dependencies.
type Options struct {
	// Host is the listen host.
	Host string
	// Port is the listen port.
	Port int
	// BlacklistPath is used only for startup logging; the loaded list is passed
	// separately to New.
	BlacklistPath string
	// DNS is an optional custom resolver. When nil, the system resolver is used
	// with A-first lookup behavior.
	DNS *resolver.Resolver
}

// Server is an HTTP proxy. Create one with New and run it with Serve.
type Server struct {
	opts      Options
	blacklist *blacklist.List
	log       *logging.Logger
	dns       *resolver.Resolver
	badIPs    *badIPCache
}

// New builds a proxy server. blocked may be nil, in which case every TLS
// ClientHello is fragmented instead of only blacklisted hosts. log must be
// non-nil.
func New(opts Options, blocked *blacklist.List, log *logging.Logger) *Server {
	return &Server{
		opts:      opts,
		blacklist: blocked,
		log:       log,
		dns:       opts.DNS,
		badIPs:    newBadIPCache(),
	}
}

// badIPCache tracks host/IP pairs that accepted a TCP connection but did not
// send a TLS response within the first-byte deadline. Entries expire after
// badIPTTL so a temporarily unhealthy origin can be tried again later.
type badIPCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// newBadIPCache returns an empty bad-address cache.
func newBadIPCache() *badIPCache {
	return &badIPCache{entries: make(map[string]time.Time)}
}

// isBad reports whether host/IP is currently marked bad. Expired entries are
// removed as they are encountered.
func (c *badIPCache) isBad(host, ip string) bool {
	if c == nil {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := badIPKey(host, ip)
	expires, ok := c.entries[key]
	if !ok {
		return false
	}
	if time.Now().After(expires) {
		delete(c.entries, key)
		return false
	}
	return true
}

// mark records host/IP as bad for badIPTTL, evicting entries when the cache is
// full.
func (c *badIPCache) mark(host, ip string) {
	if c == nil || ip == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries == nil {
		c.entries = make(map[string]time.Time)
	}

	now := time.Now()
	if len(c.entries) >= badIPCacheMax {
		for key, expires := range c.entries {
			if now.After(expires) {
				delete(c.entries, key)
			}
		}
		for len(c.entries) >= badIPCacheMax {
			for key := range c.entries {
				delete(c.entries, key)
				break
			}
		}
	}

	c.entries[badIPKey(host, ip)] = now.Add(badIPTTL)
}

// clear removes the bad mark for host/IP after a successful TLS handshake.
func (c *badIPCache) clear(host, ip string) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, badIPKey(host, ip))
}

// clearHost removes every bad mark for host. It is used when all of the host's
// addresses were skipped and the proxy needs to try the full set again.
func (c *badIPCache) clearHost(host string) {
	if c == nil {
		return
	}

	prefix := strings.ToLower(strings.TrimSuffix(host, ".")) + "|"
	c.mu.Lock()
	defer c.mu.Unlock()

	for key := range c.entries {
		if strings.HasPrefix(key, prefix) {
			delete(c.entries, key)
		}
	}
}

// badIPKey canonicalizes the host and joins it with the IP for map storage.
func badIPKey(host, ip string) string {
	return strings.ToLower(strings.TrimSuffix(host, ".")) + "|" + ip
}

// Serve listens on the configured address and accepts connections until ctx is
// canceled or the listener fails. A context-triggered shutdown returns nil.
func (s *Server) Serve(ctx context.Context) error {
	addr := net.JoinHostPort(s.opts.Host, strconv.Itoa(s.opts.Port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer listener.Close()

	s.printStartup(addr)

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopped:
		}
	}()
	defer close(stopped)

	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept connection: %w", err)
		}

		go s.handleClient(ctx, client)
	}
}

// printStartup writes the human-readable startup summary.
func (s *Server) printStartup(addr string) {
	s.log.Printf("%s", utils.Header())
	s.log.Printf("Listening on %s", addr)

	if s.blacklist == nil {
		s.log.Printf("Blacklist: none")
	} else {
		s.log.Printf("Blacklist: %s (%d domains)", s.opts.BlacklistPath, s.blacklist.Len())
	}

	s.log.Printf("DNS Primary: %s", s.dns.Primary())
	s.log.Printf("DNS Fallback: %s", s.dns.Fallback())

	s.log.Printf("Press Ctrl+C to stop.")
}

// handleClient reads one proxy request and dispatches it to the CONNECT or
// plain-HTTP path.
func (s *Server) handleClient(ctx context.Context, client net.Conn) {
	defer client.Close()

	_ = client.SetReadDeadline(time.Now().Add(headerReadTimeout))
	reader := bufio.NewReader(client)

	header, err := readHTTPHeader(reader)
	if err != nil {
		s.log.Warnf("read request: %v", err)
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	method, host, port, err := parseRequest(header)
	if err != nil {
		s.log.Warnf("parse request: %v", err)
		writeHTTPStatus(client, http.StatusBadRequest)
		return
	}

	s.log.Debugf("%s %s", method, host)

	if method == "connect" {
		s.handleConnect(ctx, client, reader, host, port)
		return
	}

	s.handleHTTP(ctx, client, reader, header, host, port)
}

// handleConnect tunnels an HTTPS CONNECT request.
//
// It dials the target, replies with 200, then reads the first TLS record. A
// ClientHello selected for fragmentation is sent as 40-byte writes; other
// payloads, and hosts excluded by the blacklist, are forwarded unchanged. For
// a fragmented ClientHello, the first response byte is read with a short
// deadline. If the origin accepted TCP but never responded,
// sendClientHelloAndWait replays the ClientHello against another resolved
// address for the same host.
func (s *Server) handleConnect(ctx context.Context, client net.Conn, clientReader *bufio.Reader, host, port string) {
	setupCtx, cancel := context.WithTimeout(ctx, ctxTimeout)
	defer cancel()

	remote, err := s.dialRemote(setupCtx, host, port, nil)
	if err != nil {
		s.log.Errorf("%s: %v", net.JoinHostPort(host, port), err)
		writeHTTPStatus(client, http.StatusBadGateway)
		return
	}
	defer func() { _ = remote.conn.Close() }()

	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		s.log.Warnf("send connect response for %s: %v", host, err)
		return
	}

	_ = client.SetReadDeadline(time.Now().Add(initialDataTimeout))

	head := make([]byte, 5)
	if _, err = io.ReadFull(clientReader, head); err != nil {
		s.log.Warnf("read TLS header for %s: %v", host, err)
		return
	}

	recordLength := int(head[3])<<8 | int(head[4])

	if head[0] != 0x16 || recordLength == 0 || recordLength > maxTLSRecordSize {
		_ = client.SetReadDeadline(time.Time{})
		if _, err = remote.conn.Write(head); err != nil {
			s.log.Errorf("write TLS header to %s: %v", host, err)
			return
		}
		s.pipe(client, clientReader, remote.conn, host)
		return
	}

	body := make([]byte, recordLength)
	if _, err = io.ReadFull(clientReader, body); err != nil {
		s.log.Warnf("read TLS ClientHello for %s: %v", host, err)
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	// A nil blacklist means fragment every host; otherwise fragment only the
	// hosts selected by the list.
	shouldFragment := s.blacklist == nil || s.blacklist.IsBlocked(host)
	if !shouldFragment {
		s.log.Debugf("skipping fragmentation for %s: not in blacklist", host)
	}

	record := make([]byte, 0, len(head)+len(body))
	record = append(record, head...)
	record = append(record, body...)

	if !fragment.IsClientHello(record) {
		if shouldFragment {
			s.log.Debugf("not a TLS ClientHello for %s; forwarding unmodified", host)
		}
		if _, err = remote.conn.Write(record); err != nil {
			s.log.Errorf("write TLS ClientHello to %s: %v", host, err)
			return
		}
		s.pipe(client, clientReader, remote.conn, host)
		return
	}

	chunks := [][]byte{record}
	if shouldFragment {
		chunks = fragment.TCPChunks(record)
		s.log.Infof("fragmented %s into %d tcp segments", host, len(chunks))
	}

	remote, first, err := s.sendClientHelloAndWait(setupCtx, remote, host, port, chunks)
	if err != nil {
		s.log.Errorf("TLS handshake with %s: %v", host, err)
		return
	}

	if _, err = client.Write([]byte{first}); err != nil {
		s.log.Warnf("write TLS response to %s: %v", host, err)
		return
	}

	s.pipe(client, clientReader, remote.conn, host)
}

// handleHTTP forwards a plain HTTP request to the origin after resolving and
// dialing it.
func (s *Server) handleHTTP(ctx context.Context, client net.Conn, clientReader *bufio.Reader, header []byte, host, port string) {
	remote, err := s.dialRemote(ctx, host, port, nil)
	if err != nil {
		s.log.Errorf("connect %s: %v", net.JoinHostPort(host, port), err)
		writeHTTPStatus(client, http.StatusBadGateway)
		return
	}
	defer remote.conn.Close()

	if _, err = remote.conn.Write(header); err != nil {
		s.log.Errorf("write request to %s: %v", host, err)
		return
	}

	s.pipe(client, clientReader, remote.conn, host)
}

// remoteDial is an open upstream connection plus the address and candidate list
// used to choose it.
type remoteDial struct {
	conn  net.Conn
	addr  net.IPAddr
	addrs []net.IPAddr
}

// dialRemote resolves host and connects to a reachable address, skipping IPs
// marked bad for that host. If every candidate is marked bad, the host's bad
// entries are cleared and all addresses are tried once more; an explicit skip
// predicate still applies to that retry pass.
func (s *Server) dialRemote(ctx context.Context, host, port string, skip func(net.IPAddr) bool) (*remoteDial, error) {
	ctx, cancel := context.WithTimeout(ctx, ctxTimeout)
	defer cancel()

	addrs, err := s.lookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}

	skipBad := func(addr net.IPAddr) bool {
		if s.badIPs.isBad(host, addr.String()) {
			return true
		}
		return skip != nil && skip(addr)
	}

	conn, addr, err := dialAddresses(ctx, addrs, port, skipBad)
	if errors.Is(err, errAllSkipped) {
		// If every address is marked bad, clear the host's entries and try
		// all of them once. Still honor an explicit skip for the retry.
		s.badIPs.clearHost(host)
		conn, addr, err = dialAddresses(ctx, addrs, port, skip)
	}
	if err != nil {
		return nil, err
	}

	return &remoteDial{conn: conn, addr: addr, addrs: addrs}, nil
}

// lookupIP resolves host with the configured resolver, or with the system
// resolver when no custom resolver was supplied.
func (s *Server) lookupIP(ctx context.Context, host string) ([]net.IPAddr, error) {
	if s.dns != nil {
		return s.dns.LookupIP(ctx, host)
	}
	return lookupSystemIPs(ctx, host)
}

// lookupSystemIPs resolves host with the OS resolver, preferring IPv4 and
// querying IPv6 only when there is no A record. Literal IPs are returned
// without a lookup.
func lookupSystemIPs(ctx context.Context, host string) ([]net.IPAddr, error) {
	if addr, ok := parseLiteralIP(host); ok {
		return []net.IPAddr{addr}, nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err == nil && len(ips) > 0 {
		return ipsToAddrs(ips), nil
	}
	if err != nil && !isNotFound(err) {
		return nil, err
	}

	ips, err = net.DefaultResolver.LookupIP(ctx, "ip6", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("system resolver returned no addresses for %s", host)
	}
	return ipsToAddrs(ips), nil
}

// parseLiteralIP parses an IP or an IPv6 address with a zone suffix.
func parseLiteralIP(host string) (net.IPAddr, bool) {
	if ip := net.ParseIP(host); ip != nil {
		return net.IPAddr{IP: ip}, true
	}
	if i := strings.LastIndexByte(host, '%'); i > 0 {
		if ip := net.ParseIP(host[:i]); ip != nil {
			return net.IPAddr{IP: ip, Zone: host[i+1:]}, true
		}
	}
	return net.IPAddr{}, false
}

// ipsToAddrs converts net.IP values to net.IPAddr values without zones.
func ipsToAddrs(ips []net.IP) []net.IPAddr {
	addrs := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, net.IPAddr{IP: ip})
	}
	return addrs
}

// isNotFound reports whether err is a DNS name-not-found error.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// newDialer returns a dialer with a bounded connect timeout and explicit TCP
// keepalive settings. Keepalive detects peers that disappear silently after the
// connection is established; it is not a substitute for the first-byte timeout.
func newDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: dialTimeout,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     10 * time.Second,
			Interval: 5 * time.Second,
			Count:    3,
		},
	}
}

// dialAddresses races the supplied addresses, starting a new attempt every
// dialStaggerDelay or whenever an attempt fails. The first successful
// connection wins and later results are drained and closed. It returns
// errAllSkipped when skip rejects every address.
func dialAddresses(ctx context.Context, addrs []net.IPAddr, port string, skip func(net.IPAddr) bool) (net.Conn, net.IPAddr, error) {
	candidates := make([]net.IPAddr, 0, len(addrs))
	for _, addr := range addrs {
		if skip == nil || !skip(addr) {
			candidates = append(candidates, addr)
		}
	}
	if len(candidates) == 0 {
		return nil, net.IPAddr{}, errAllSkipped
	}
	addrs = candidates

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type dialResult struct {
		conn net.Conn
		addr net.IPAddr
		err  error
	}

	results := make(chan dialResult, len(addrs))
	pending := 0
	next := 0
	var lastErr error

	start := func(addr net.IPAddr) {
		pending++
		go func(addr net.IPAddr) {
			// addr.String keeps the zone for link-local IPv6 addresses.
			conn, err := newDialer().DialContext(dialCtx, "tcp", net.JoinHostPort(addr.String(), port))
			results <- dialResult{conn: conn, addr: addr, err: err}
		}(addr)
	}

	start(addrs[next])
	next++

	delay := time.NewTimer(dialStaggerDelay)
	defer delay.Stop()
	delayC := delay.C

	for pending > 0 {
		select {
		case result := <-results:
			pending--
			if result.err == nil {
				cancel()
				go func(remaining int) {
					for i := 0; i < remaining; i++ {
						if leftover := <-results; leftover.conn != nil {
							_ = leftover.conn.Close()
						}
					}
				}(pending)
				return result.conn, result.addr, nil
			}

			lastErr = result.err
			if next < len(addrs) {
				start(addrs[next])
				next++
			}
		case <-delayC:
			if next < len(addrs) {
				start(addrs[next])
				next++
				delay.Reset(dialStaggerDelay)
			} else {
				delayC = nil
			}
		}
	}

	if lastErr == nil {
		lastErr = errors.New("all connection attempts failed")
	}
	return nil, net.IPAddr{}, lastErr
}

// sendClientHelloAndWait writes the ClientHello chunks, waits for the first TLS
// response byte, and retries on another address when the first attempt times
// out. A retry is only attempted when at least two addresses exist and the
// context is still alive. The failed IP is marked bad; a successful IP clears
// any previous mark.
func (s *Server) sendClientHelloAndWait(ctx context.Context, target *remoteDial, host, port string, chunks [][]byte) (*remoteDial, byte, error) {
	first, err := writeClientHelloAndRead(ctx, target.conn, chunks, firstByteTimeout(target))
	if err == nil {
		if target.addr.IP != nil {
			s.badIPs.clear(host, target.addr.String())
		}
		return target, first, nil
	}

	if ctx.Err() != nil || len(target.addrs) <= 1 || target.addr.IP == nil {
		return target, 0, err
	}

	s.badIPs.mark(host, target.addr.String())
	s.log.Warnf("no TLS response from %s via %s: %v; retrying another address", host, target.addr.String(), err)
	_ = target.conn.Close()

	failedAddr := target.addr
	retry, dialErr := s.dialRemote(ctx, host, port, func(addr net.IPAddr) bool {
		return addr.String() == failedAddr.String()
	})
	if dialErr != nil {
		return target, 0, fmt.Errorf("retry %s: %w", host, dialErr)
	}

	first, err = writeClientHelloAndRead(ctx, retry.conn, chunks, firstByteTimeout(retry))
	if err != nil {
		s.badIPs.mark(host, retry.addr.String())
		_ = retry.conn.Close()
		return retry, 0, err
	}

	s.badIPs.clear(host, retry.addr.String())
	return retry, first, nil
}

// firstByteTimeout returns the TLS response deadline. A host with another
// address to try gets a shorter deadline so failover can happen quickly; a
// single-address host gets more time because a retry cannot help.
func firstByteTimeout(target *remoteDial) time.Duration {
	if len(target.addrs) > 1 {
		return tlsFirstByteTimeoutMulti
	}
	return tlsFirstByteTimeoutSingle
}

// writeClientHelloAndRead writes the ClientHello chunks and reads one byte from
// the origin, applying a single deadline to both operations. The deadline is
// the earlier of timeout and the context deadline.
func writeClientHelloAndRead(ctx context.Context, conn net.Conn, chunks [][]byte, timeout time.Duration) (byte, error) {
	deadline := connectionDeadline(ctx, timeout)

	if err := conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()

	for _, chunk := range chunks {
		if _, err := conn.Write(chunk); err != nil {
			return 0, err
		}
	}

	if err := conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		return 0, err
	}

	return b[0], nil
}

// connectionDeadline returns the earlier of the context deadline and a fresh
// timeout from now.
func connectionDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

// readHTTPHeader reads through the blank line that terminates the request head
// and enforces maxHTTPHeaderSize.
func readHTTPHeader(reader *bufio.Reader) ([]byte, error) {
	var header []byte

	for {
		line, err := reader.ReadBytes('\n')
		if len(header)+len(line) > maxHTTPHeaderSize {
			return nil, fmt.Errorf("request header exceeds %d bytes", maxHTTPHeaderSize)
		}
		header = append(header, line...)

		if bytes.HasSuffix(header, []byte("\r\n\r\n")) || bytes.HasSuffix(header, []byte("\n\n")) {
			return header, nil
		}

		if err != nil {
			return nil, err
		}
	}
}

// parseRequest extracts the method, target host, and port from a proxy request.
// CONNECT requests carry the authority in the request target; plain requests
// use the Host header.
func parseRequest(header []byte) (method, host, port string, err error) {
	lines := bytes.Split(header, []byte("\r\n"))
	if len(lines) == 0 {
		return "", "", "", errors.New("empty request")
	}

	requestLine := bytes.Fields(lines[0])
	if len(requestLine) < 3 {
		return "", "", "", errors.New("malformed request line")
	}

	method = string(requestLine[0])
	if strings.EqualFold(method, "connect") {
		method = "connect"
		host, port, err = splitHostPort(string(requestLine[1]), "443")
		return method, host, port, err
	}

	for _, line := range lines[1:] {
		if len(line) == 0 {
			break
		}
		if len(line) >= 5 && strings.EqualFold(string(line[:5]), "Host:") {
			host, port, err = splitHostPort(strings.TrimSpace(string(line[5:])), "80")
			return method, host, port, err
		}
	}

	return "", "", "", errors.New("missing Host header")
}

// splitHostPort parses a host or host:port, applies defaultPort when no port
// is present, and removes IPv6 brackets and the DNS root dot.
func splitHostPort(value, defaultPort string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", errors.New("empty host")
	}

	host, port, err := net.SplitHostPort(value)
	if err != nil {
		host = value
		port = defaultPort
	} else if port == "" {
		port = defaultPort
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", "", errors.New("empty host")
	}

	return host, port, nil
}

// writeHTTPStatus writes a minimal HTTP response with the given status code.
func writeHTTPStatus(conn net.Conn, code int) {
	_, _ = fmt.Fprintf(
		conn,
		"HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		code,
		http.StatusText(code),
	)
}

// pipe copies data in both directions, half-closing each connection when its
// direction finishes, and waits for both directions to complete.
func (s *Server) pipe(client net.Conn, clientReader io.Reader, remote net.Conn, host string) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(remote, clientReader); err != nil {
			s.log.Warnf("copy request to %s: %v", host, err)
		}
		closeWrite(remote)
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(client, remote); err != nil {
			s.log.Warnf("copy response from %s: %v", host, err)
		}
		closeWrite(client)
	}()

	wg.Wait()
}

// closeWrite half-closes conn when the connection supports CloseWrite, and
// otherwise closes it completely.
func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}

	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}

	_ = conn.Close()
}
