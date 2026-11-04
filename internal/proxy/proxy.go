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

	"cloak-dpi/internal/blacklist"
	"cloak-dpi/internal/fragment"
	"cloak-dpi/internal/logging"
	"cloak-dpi/internal/resolver"
)

const (
	maxHTTPHeaderSize  = 64 * 1024
	maxTLSRecordSize   = 16 * 1024
	headerReadTimeout  = 10 * time.Second
	initialDataTimeout = 10 * time.Second
	dialTimeout        = 10 * time.Second
	dialStaggerDelay   = 250 * time.Millisecond
	tcpSplitDelay      = 10 * time.Millisecond
)

type Options struct {
	Host          string
	Port          int
	BlacklistPath string
	DNS           *resolver.Resolver
}

type Server struct {
	opts      Options
	blacklist *blacklist.List
	log       *logging.Logger
	dns       *resolver.Resolver

	modeMu sync.Mutex
	modes  map[string]*fragmentModeEntry
}

func New(opts Options, blocked *blacklist.List, log *logging.Logger) *Server {
	return &Server{
		opts:      opts,
		blacklist: blocked,
		log:       log,
		dns:       opts.DNS,
		modes:     make(map[string]*fragmentModeEntry),
	}
}

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

		go s.handleClient(client)
	}
}

func (s *Server) printStartup(addr string) {
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

func (s *Server) handleClient(client net.Conn) {
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
		s.handleConnect(client, reader, host, port)
		return
	}

	s.handleHTTP(client, reader, header, host, port)
}

func (s *Server) handleConnect(client net.Conn, clientReader *bufio.Reader, host, port string) {
	remote, err := s.dialRemote(host, port)
	if err != nil {
		s.log.Errorf("%s: %v", net.JoinHostPort(host, port), err)
		writeHTTPStatus(client, http.StatusBadGateway)
		return
	}
	defer remote.Close()

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
		if _, err = remote.Write(head); err != nil {
			s.log.Errorf("write TLS header to %s: %v", host, err)
			return
		}
		s.pipe(client, clientReader, remote, host)
		return
	}

	body := make([]byte, recordLength)
	if _, err = io.ReadFull(clientReader, body); err != nil {
		s.log.Warnf("read TLS ClientHello for %s: %v", host, err)
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	shouldFragment := s.blacklist == nil || s.blacklist.IsBlocked(host)
	if !shouldFragment {
		s.log.Debugf("skipping fragmentation for %s: not in blacklist", host)
	}

	if shouldFragment {
		split, hasSNI := fragment.SNISplitOffset(body)

		if hasSNI && s.needsTCPSegments(host, port) {
			initial := make([]byte, 0, len(head)+len(body))
			initial = append(initial, head...)
			initial = append(initial, body...)
			offset := len(head) + split

			_, err = remote.Write(initial[:offset])
			if err == nil {
				// Give the first segment time to leave the host so the
				// hostname is not coalesced back into one packet.
				time.Sleep(tcpSplitDelay)
				_, err = remote.Write(initial[offset:])
			}
			if err != nil {
				s.log.Errorf("write fragmented ClientHello to %s: %v", host, err)
				return
			}

			s.log.Infof("fragmented %s into 2 tcp segments", host)
			s.pipe(client, clientReader, remote, host)
			return
		}

		if hasSNI {
			if parts, ok := fragment.ClientHello(body); ok {
				var fragmented bytes.Buffer
				for _, part := range parts {
					fragmented.Write(part)
				}
				if _, err = remote.Write(fragmented.Bytes()); err != nil {
					s.log.Errorf("write fragmented ClientHello to %s: %v", host, err)
					return
				}

				s.log.Infof("fragmented %s into %d records", host, len(parts))
				s.pipe(client, clientReader, remote, host)
				return
			}
		}

		s.log.Infof("could not locate SNI in ClientHello for %s; forwarding unmodified", host)
	}

	initial := make([]byte, 0, len(head)+len(body))
	initial = append(initial, head...)
	initial = append(initial, body...)
	if _, err = remote.Write(initial); err != nil {
		s.log.Errorf("write TLS ClientHello to %s: %v", host, err)
		return
	}

	s.pipe(client, clientReader, remote, host)
}

func (s *Server) handleHTTP(client net.Conn, clientReader *bufio.Reader, header []byte, host, port string) {
	remote, err := s.dialRemote(host, port)
	if err != nil {
		s.log.Errorf("connect %s: %v", net.JoinHostPort(host, port), err)
		writeHTTPStatus(client, http.StatusBadGateway)
		return
	}
	defer remote.Close()

	if _, err = remote.Write(header); err != nil {
		s.log.Errorf("write request to %s: %v", host, err)
		return
	}

	s.pipe(client, clientReader, remote, host)
}

func (s *Server) dialRemote(host, port string) (net.Conn, error) {
	return s.dialRemoteContext(context.Background(), host, port)
}

func (s *Server) dialRemoteContext(ctx context.Context, host, port string) (net.Conn, error) {
	if s.dns == nil {
		dialer := net.Dialer{Timeout: dialTimeout}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}

	addrs, err := s.dns.LookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	return dialAddresses(ctx, addrs, port)
}

func dialAddresses(ctx context.Context, addrs []net.IPAddr, port string) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no addresses to dial")
	}

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type dialResult struct {
		conn net.Conn
		err  error
	}

	results := make(chan dialResult, len(addrs))
	pending := 0
	next := 0
	var lastErr error

	start := func(addr net.IPAddr) {
		pending++
		go func() {
			dialer := net.Dialer{Timeout: dialTimeout}
			conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(addr.IP.String(), port))
			results <- dialResult{conn: conn, err: err}
		}()
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
				return result.conn, nil
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
	return nil, lastErr
}

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

func writeHTTPStatus(conn net.Conn, code int) {
	_, _ = fmt.Fprintf(
		conn,
		"HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		code,
		http.StatusText(code),
	)
}

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
