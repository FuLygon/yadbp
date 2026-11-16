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
	"testing"
	"time"

	"yadbp/internal/logging"
)

func testLogger() *logging.Logger {
	return logging.New(logging.Silent, io.Discard)
}

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantMethod string
		wantHost   string
		wantPort   string
		wantErr    bool
	}{
		{
			name:       "CONNECT with port",
			header:     "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
			wantMethod: "connect",
			wantHost:   "example.com",
			wantPort:   "443",
		},
		{
			name:       "CONNECT default port",
			header:     "connect example.com HTTP/1.1\r\n\r\n",
			wantMethod: "connect",
			wantHost:   "example.com",
			wantPort:   "443",
		},
		{
			name:       "CONNECT IPv6",
			header:     "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n",
			wantMethod: "connect",
			wantHost:   "2001:db8::1",
			wantPort:   "8443",
		},
		{
			name:       "plain HTTP default port",
			header:     "GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantMethod: "GET",
			wantHost:   "example.com",
			wantPort:   "80",
		},
		{
			name:       "plain HTTP explicit port",
			header:     "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
			wantMethod: "GET",
			wantHost:   "example.com",
			wantPort:   "8080",
		},
		{
			name:       "plain HTTP trailing root dot",
			header:     "GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n",
			wantMethod: "GET",
			wantHost:   "example.com",
			wantPort:   "80",
		},
		{
			name:    "missing Host header",
			header:  "GET / HTTP/1.1\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "malformed request line",
			header:  "GET\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "empty request",
			header:  "",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			method, host, port, err := parseRequest([]byte(test.header))
			if test.wantErr {
				if err == nil {
					t.Fatal("parseRequest() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRequest() error = %v", err)
			}
			if method != test.wantMethod || host != test.wantHost || port != test.wantPort {
				t.Fatalf("parseRequest() = (%q, %q, %q), want (%q, %q, %q)",
					method, host, port, test.wantMethod, test.wantHost, test.wantPort)
			}
		})
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		defaultPort string
		wantHost    string
		wantPort    string
		wantErr     bool
	}{
		{name: "host only", value: "example.com", defaultPort: "80", wantHost: "example.com", wantPort: "80"},
		{name: "host and port", value: "example.com:443", defaultPort: "80", wantHost: "example.com", wantPort: "443"},
		{name: "empty port", value: "example.com:", defaultPort: "80", wantHost: "example.com", wantPort: "80"},
		{name: "IPv6", value: "[2001:db8::1]:443", defaultPort: "80", wantHost: "2001:db8::1", wantPort: "443"},
		{name: "IPv6 without port", value: "[2001:db8::1]", defaultPort: "80", wantHost: "2001:db8::1", wantPort: "80"},
		{name: "trailing root dot", value: "example.com.", defaultPort: "80", wantHost: "example.com", wantPort: "80"},
		{name: "empty host", value: ":443", defaultPort: "80", wantErr: true},
		{name: "empty value", value: " ", defaultPort: "80", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, port, err := splitHostPort(test.value, test.defaultPort)
			if test.wantErr {
				if err == nil {
					t.Fatal("splitHostPort() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("splitHostPort() error = %v", err)
			}
			if host != test.wantHost || port != test.wantPort {
				t.Fatalf("splitHostPort() = (%q, %q), want (%q, %q)", host, port, test.wantHost, test.wantPort)
			}
		})
	}
}

func TestReadHTTPHeader(t *testing.T) {
	t.Run("CRLF preserves pipelined bytes", func(t *testing.T) {
		reader := bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody"))
		header, err := readHTTPHeader(reader)
		if err != nil {
			t.Fatalf("readHTTPHeader() error = %v", err)
		}
		if got, want := string(header), "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"; got != want {
			t.Fatalf("header = %q, want %q", got, want)
		}
		rest, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read leftover: %v", err)
		}
		if got, want := string(rest), "body"; got != want {
			t.Fatalf("leftover = %q, want %q", got, want)
		}
	})

	t.Run("LF only", func(t *testing.T) {
		reader := bufio.NewReader(strings.NewReader("GET / HTTP/1.1\nHost: example.com\n\n"))
		header, err := readHTTPHeader(reader)
		if err != nil {
			t.Fatalf("readHTTPHeader() error = %v", err)
		}
		if len(header) == 0 {
			t.Fatal("readHTTPHeader() returned an empty header")
		}
	})

	t.Run("too large", func(t *testing.T) {
		reader := bufio.NewReader(strings.NewReader(strings.Repeat("A", maxHTTPHeaderSize+1)))
		if _, err := readHTTPHeader(reader); err == nil {
			t.Fatal("readHTTPHeader() error = nil, want an error")
		}
	})

	t.Run("incomplete", func(t *testing.T) {
		reader := bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\n"))
		if _, err := readHTTPHeader(reader); err == nil {
			t.Fatal("readHTTPHeader() error = nil, want an error")
		}
	})
}

func TestParseLiteralIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantIP   string
		wantZone string
		wantOK   bool
	}{
		{name: "IPv4", input: "192.0.2.1", wantIP: "192.0.2.1", wantOK: true},
		{name: "IPv6", input: "2001:db8::1", wantIP: "2001:db8::1", wantOK: true},
		{name: "IPv6 zone", input: "fe80::1%eth0", wantIP: "fe80::1", wantZone: "eth0", wantOK: true},
		{name: "hostname", input: "example.com", wantOK: false},
		{name: "invalid", input: "not-an-ip", wantOK: false},
		{name: "empty", input: "", wantOK: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr, ok := parseLiteralIP(test.input)
			if ok != test.wantOK {
				t.Fatalf("parseLiteralIP(%q) ok = %v, want %v", test.input, ok, test.wantOK)
			}
			if !test.wantOK {
				return
			}
			if got := addr.IP.String(); got != test.wantIP {
				t.Errorf("parseLiteralIP(%q) IP = %q, want %q", test.input, got, test.wantIP)
			}
			if addr.Zone != test.wantZone {
				t.Errorf("parseLiteralIP(%q) zone = %q, want %q", test.input, addr.Zone, test.wantZone)
			}
		})
	}
}

func TestIPsToAddrs(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}
	addrs := ipsToAddrs(ips)
	if len(addrs) != len(ips) {
		t.Fatalf("len(ipsToAddrs()) = %d, want %d", len(addrs), len(ips))
	}
	for i := range ips {
		if !addrs[i].IP.Equal(ips[i]) {
			t.Errorf("addrs[%d].IP = %v, want %v", i, addrs[i].IP, ips[i])
		}
	}
}

func TestBadIPCache(t *testing.T) {
	cache := newBadIPCache()

	if cache.isBad("example.com", "192.0.2.1") {
		t.Fatal("new cache reported an address as bad")
	}

	cache.mark("Example.COM.", "192.0.2.1")
	if !cache.isBad("example.com", "192.0.2.1") {
		t.Fatal("marked address was not reported as bad")
	}

	cache.clear("EXAMPLE.com", "192.0.2.1")
	if cache.isBad("example.com", "192.0.2.1") {
		t.Fatal("cleared address is still marked bad")
	}

	cache.mark("example.com", "192.0.2.1")
	cache.mark("example.com", "192.0.2.2")
	cache.mark("other.test", "192.0.2.1")
	cache.clearHost("EXAMPLE.COM.")
	if cache.isBad("example.com", "192.0.2.1") || cache.isBad("example.com", "192.0.2.2") {
		t.Fatal("clearHost left an address for the host marked bad")
	}
	if !cache.isBad("other.test", "192.0.2.1") {
		t.Fatal("clearHost removed an address for another host")
	}

	var nilCache *badIPCache
	if nilCache.isBad("example.com", "192.0.2.1") {
		t.Fatal("nil cache reported an address as bad")
	}
	nilCache.mark("example.com", "192.0.2.1")
	nilCache.clear("example.com", "192.0.2.1")
	nilCache.clearHost("example.com")
}

func TestBadIPCacheExpiry(t *testing.T) {
	cache := newBadIPCache()
	key := badIPKey("expired.test", "192.0.2.3")

	cache.mu.Lock()
	cache.entries[key] = time.Now().Add(-time.Second)
	cache.mu.Unlock()

	if cache.isBad("expired.test", "192.0.2.3") {
		t.Fatal("expired address is still marked bad")
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	if _, ok := cache.entries[key]; ok {
		t.Fatal("expired entry was not removed")
	}
}

func TestBadIPCacheCapacity(t *testing.T) {
	cache := newBadIPCache()
	for i := 0; i < badIPCacheMax+10; i++ {
		cache.mark(fmt.Sprintf("host-%d.test", i), fmt.Sprintf("192.0.2.%d", i%256))
	}

	cache.mu.Lock()
	got := len(cache.entries)
	cache.mu.Unlock()

	if got > badIPCacheMax {
		t.Fatalf("cache length = %d, want <= %d", got, badIPCacheMax)
	}
}

func TestFirstByteTimeout(t *testing.T) {
	one := &remoteDial{addrs: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}}
	if got := firstByteTimeout(one); got != tlsFirstByteTimeoutSingle {
		t.Fatalf("single address timeout = %s, want %s", got, tlsFirstByteTimeoutSingle)
	}

	two := &remoteDial{addrs: []net.IPAddr{
		{IP: net.ParseIP("192.0.2.1")},
		{IP: net.ParseIP("192.0.2.2")},
	}}
	if got := firstByteTimeout(two); got != tlsFirstByteTimeoutMulti {
		t.Fatalf("multiple address timeout = %s, want %s", got, tlsFirstByteTimeoutMulti)
	}
}

func TestConnectionDeadlineUsesEarlierContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ctxDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context has no deadline")
	}
	if got := connectionDeadline(ctx, 2*time.Minute); !got.Equal(ctxDeadline) {
		t.Fatalf("connectionDeadline() = %s, want context deadline %s", got, ctxDeadline)
	}

	start := time.Now()
	got := connectionDeadline(context.Background(), 50*time.Millisecond)
	if remaining := time.Until(got); remaining <= 0 || remaining > time.Second {
		t.Fatalf("connectionDeadline() = %s, want about 50ms from %s", got, start)
	}
}

func TestWriteClientHelloAndRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	chunks := [][]byte{[]byte("hello"), []byte(" "), []byte("world")}
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, len("hello world"))
		if _, err := io.ReadFull(server, buf); err != nil {
			serverErr <- err
			return
		}
		if got, want := string(buf), "hello world"; got != want {
			serverErr <- fmt.Errorf("server read %q, want %q", got, want)
			return
		}
		_, err := server.Write([]byte{0x42})
		serverErr <- err
	}()

	first, err := writeClientHelloAndRead(context.Background(), client, chunks, time.Second)
	if err != nil {
		t.Fatalf("writeClientHelloAndRead() error = %v", err)
	}
	if first != 0x42 {
		t.Fatalf("writeClientHelloAndRead() = %#x, want 0x42", first)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestWriteClientHelloAndReadTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	readDone := make(chan struct{})
	go func() {
		_ = server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 1)
		_, _ = io.ReadFull(server, buf)
		close(readDone)
	}()

	start := time.Now()
	_, err := writeClientHelloAndRead(context.Background(), client, [][]byte{{0x16}}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("writeClientHelloAndRead() error = nil, want a timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout took %s, want less than 1s", elapsed)
	}

	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("server read did not finish")
	}
}

func TestDialAddresses(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	conn, addr, err := dialAddresses(context.Background(), []net.IPAddr{
		{IP: net.ParseIP("127.0.0.1")},
	}, port, nil)
	if err != nil {
		t.Fatalf("dialAddresses() error = %v", err)
	}
	defer conn.Close()

	if got, want := addr.IP.String(), "127.0.0.1"; got != want {
		t.Fatalf("dialAddresses() address = %s, want %s", got, want)
	}

	select {
	case serverConn := <-accepted:
		_ = serverConn.Close()
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not accept the connection")
	}
}

func TestDialAddressesAllSkipped(t *testing.T) {
	_, _, err := dialAddresses(context.Background(), []net.IPAddr{
		{IP: net.ParseIP("192.0.2.1")},
	}, "443", func(net.IPAddr) bool { return true })
	if !errors.Is(err, errAllSkipped) {
		t.Fatalf("dialAddresses() error = %v, want errAllSkipped", err)
	}
}

func TestWriteHTTPStatus(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	want := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	buf := make([]byte, len(want))
	readErr := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, buf)
		readErr <- err
	}()

	writeHTTPStatus(client, http.StatusBadGateway)
	if err := <-readErr; err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := string(buf); got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

func TestPrintStartup(t *testing.T) {
	var output bytes.Buffer
	logger := logging.New(logging.Silent, &output)
	server := New(Options{Host: "127.0.0.1", Port: 8888}, nil, logger)

	server.printStartup("127.0.0.1:8888")

	got := output.String()
	for _, want := range []string{
		"yadbp",
		"Listening on 127.0.0.1:8888",
		"Blacklist: none",
		"DNS Primary: system",
		"DNS Fallback: none",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("startup output does not contain %q:\n%s", want, got)
		}
	}
}

func TestHandleClientForwardsHTTP(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backend.Close()

	backendDone := make(chan error, 1)
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		header, err := readHTTPHeader(bufio.NewReader(conn))
		if err != nil {
			backendDone <- err
			return
		}
		if !bytes.Contains(header, []byte("Host: "+backend.Addr().String())) {
			backendDone <- fmt.Errorf("backend header missing Host: %q", header)
			return
		}
		_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		backendDone <- err
	}()

	server := New(Options{}, nil, testLogger())
	proxyConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go server.handleClient(context.Background(), proxyConn)

	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	request := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", backend.Addr(), backend.Addr())
	if _, err := io.WriteString(clientConn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}

	response, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got, want := string(response), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
	if err := <-backendDone; err != nil {
		t.Fatalf("backend error: %v", err)
	}
}

func TestHandleClientForwardsConnectClientHello(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer backend.Close()

	helloBody := bytes.Repeat([]byte{0xaa}, 100)
	helloBody[0] = 0x01
	hello := make([]byte, 5+len(helloBody))
	hello[0] = 0x16
	hello[1] = 0x03
	hello[2] = 0x01
	hello[3] = byte(len(helloBody) >> 8)
	hello[4] = byte(len(helloBody))
	copy(hello[5:], helloBody)

	backendDone := make(chan error, 1)
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		got := make([]byte, len(hello))
		if _, err := io.ReadFull(conn, got); err != nil {
			backendDone <- err
			return
		}
		if !bytes.Equal(got, hello) {
			backendDone <- fmt.Errorf("backend received a different ClientHello")
			return
		}
		_, err = conn.Write([]byte{0x99})
		backendDone <- err
	}()

	server := New(Options{}, nil, testLogger())
	proxyConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go server.handleClient(context.Background(), proxyConn)

	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(clientConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", backend.Addr(), backend.Addr()); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	reader := bufio.NewReader(clientConn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if got, want := status, "HTTP/1.1 200 Connection Established\r\n"; got != want {
		t.Fatalf("CONNECT status = %q, want %q", got, want)
	}
	if blank, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read CONNECT blank line: %v", err)
	} else if blank != "\r\n" {
		t.Fatalf("CONNECT blank line = %q, want %q", blank, "\r\n")
	}

	if _, err := clientConn.Write(hello); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}

	var first [1]byte
	if _, err := io.ReadFull(reader, first[:]); err != nil {
		t.Fatalf("read TLS first byte: %v", err)
	}
	if first[0] != 0x99 {
		t.Fatalf("TLS first byte = %#x, want 0x99", first[0])
	}
	if err := <-backendDone; err != nil {
		t.Fatalf("backend error: %v", err)
	}
}
