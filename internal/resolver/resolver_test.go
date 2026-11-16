package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"yadbp/internal/logging"
)

func testLogger() *logging.Logger {
	return logging.New(logging.Silent, io.Discard)
}

func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "IPv4", value: " 1.1.1.1:53 ", want: "1.1.1.1:53"},
		{name: "IPv6", value: "[2001:db8::1]:53", want: "[2001:db8::1]:53"},
		{name: "missing port", value: "1.1.1.1", wantErr: true},
		{name: "hostname", value: "dns.example:53", wantErr: true},
		{name: "zero port", value: "1.1.1.1:0", wantErr: true},
		{name: "large port", value: "1.1.1.1:65536", wantErr: true},
		{name: "non-numeric port", value: "1.1.1.1:domain", wantErr: true},
		{name: "empty", value: " ", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeAddress(test.value)
			if test.wantErr {
				if err == nil {
					t.Fatal("normalizeAddress() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeAddress() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("normalizeAddress() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNewValidation(t *testing.T) {
	logger := testLogger()

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "missing primary timeout",
			cfg:     Config{Primary: "1.1.1.1:53", HealthcheckInterval: time.Second, Logger: logger},
			wantErr: "primary dns timeout",
		},
		{
			name:    "missing healthcheck interval",
			cfg:     Config{Primary: "1.1.1.1:53", PrimaryTimeout: time.Second, Logger: logger},
			wantErr: "health check interval",
		},
		{
			name:    "missing logger",
			cfg:     Config{Primary: "1.1.1.1:53", PrimaryTimeout: time.Second, HealthcheckInterval: time.Second},
			wantErr: "logger is required",
		},
		{
			name:    "invalid primary",
			cfg:     Config{Primary: "1.1.1.1", PrimaryTimeout: time.Second, HealthcheckInterval: time.Second, Logger: logger},
			wantErr: "primary dns",
		},
		{
			name:    "invalid fallback",
			cfg:     Config{Primary: "1.1.1.1:53", Fallback: "bad", PrimaryTimeout: time.Second, HealthcheckInterval: time.Second, Logger: logger},
			wantErr: "fallback dns",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.cfg)
			if err == nil {
				t.Fatal("New() error = nil, want an error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("New() error = %q, want it to contain %q", err, test.wantErr)
			}
		})
	}
}

func TestNewValidAndAccessors(t *testing.T) {
	resolver, err := New(Config{
		Primary:             " 1.1.1.1:53 ",
		Fallback:            " 8.8.8.8:53 ",
		PrimaryTimeout:      time.Second,
		HealthcheckInterval: time.Hour,
		Logger:              testLogger(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer resolver.Close()

	if got, want := resolver.Primary(), "1.1.1.1:53"; got != want {
		t.Errorf("Primary() = %q, want %q", got, want)
	}
	if got, want := resolver.Fallback(), "8.8.8.8:53"; got != want {
		t.Errorf("Fallback() = %q, want %q", got, want)
	}
}

func TestNilResolver(t *testing.T) {
	var resolver *Resolver

	if got, want := resolver.Primary(), "system"; got != want {
		t.Errorf("nil Primary() = %q, want %q", got, want)
	}
	if got, want := resolver.Fallback(), "none"; got != want {
		t.Errorf("nil Fallback() = %q, want %q", got, want)
	}
	resolver.Close()
}

func TestLookupIPLiteralAndEmpty(t *testing.T) {
	resolver := &Resolver{log: testLogger()}

	addrs, err := resolver.LookupIP(context.Background(), " 192.0.2.1. ")
	if err != nil {
		t.Fatalf("LookupIP(literal) error = %v", err)
	}
	if len(addrs) != 1 || addrs[0].IP.String() != "192.0.2.1" {
		t.Fatalf("LookupIP(literal) = %v, want 192.0.2.1", addrs)
	}

	if _, err := resolver.LookupIP(context.Background(), " "); err == nil {
		t.Fatal("LookupIP(empty) error = nil, want an error")
	}
}

func TestResolverCache(t *testing.T) {
	resolver := &Resolver{
		log:   testLogger(),
		cache: make(map[string]cacheEntry),
	}
	addrs := []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}
	resolver.store("example.com", addrs)

	got, ok := resolver.cached("example.com")
	if !ok {
		t.Fatal("cached() did not find a stored entry")
	}
	if len(got) != 1 || got[0].IP.String() != "192.0.2.10" {
		t.Fatalf("cached() = %v, want 192.0.2.10", got)
	}

	got[0].IP[0] = 203
	again, ok := resolver.cached("example.com")
	if !ok {
		t.Fatal("cached() did not find the entry after mutation")
	}
	if got := again[0].IP.String(); got != "192.0.2.10" {
		t.Fatalf("cached() after mutating the returned slice = %s, want 192.0.2.10", got)
	}

	resolver.cache["expired.test"] = cacheEntry{
		addrs:   addrs,
		expires: time.Now().Add(-time.Second),
	}
	if _, ok := resolver.cached("expired.test"); ok {
		t.Fatal("cached() returned an expired entry")
	}
	if _, ok := resolver.cache["expired.test"]; ok {
		t.Fatal("cached() did not remove the expired entry")
	}
}

func TestResolverCacheLRU(t *testing.T) {
	resolver := &Resolver{
		log:   testLogger(),
		cache: make(map[string]cacheEntry),
	}
	now := time.Now()
	addrs := []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}

	for i := 0; i < cacheMaxEntries; i++ {
		name := fmt.Sprintf("host-%04d.test", i)
		resolver.cache[name] = cacheEntry{
			addrs:    addrs,
			expires:  now.Add(time.Hour),
			lastUsed: now.Add(time.Duration(i) * time.Millisecond),
		}
	}

	resolver.store("new.test", addrs)

	if _, ok := resolver.cache["host-0000.test"]; ok {
		t.Fatal("store() did not evict the least recently used entry")
	}
	if _, ok := resolver.cache["new.test"]; !ok {
		t.Fatal("store() did not insert the new entry")
	}
	if got, want := len(resolver.cache), cacheMaxEntries; got != want {
		t.Fatalf("cache length = %d, want %d", got, want)
	}
}

func TestCloneAddrsAndFormat(t *testing.T) {
	original := []net.IPAddr{
		{IP: net.ParseIP("192.0.2.1")},
		{IP: net.ParseIP("2001:db8::1"), Zone: "eth0"},
	}
	cloned := cloneAddrs(original)
	cloned[0].IP[0] = 203
	cloned[1].Zone = "other"

	if got := original[0].IP.String(); got != "192.0.2.1" {
		t.Errorf("clone mutation changed original IP to %s", got)
	}
	if got := original[1].Zone; got != "eth0" {
		t.Errorf("clone mutation changed original zone to %q", got)
	}

	if got, want := formatAddrs(original), "192.0.2.1, 2001:db8::1"; got != want {
		t.Errorf("formatAddrs() = %q, want %q", got, want)
	}
}

func TestIsNotFound(t *testing.T) {
	notFound := &net.DNSError{IsNotFound: true}
	if !isNotFound(notFound) {
		t.Fatal("isNotFound(direct) = false, want true")
	}
	if !isNotFound(fmt.Errorf("wrapped: %w", notFound)) {
		t.Fatal("isNotFound(wrapped) = false, want true")
	}
	if isNotFound(errors.New("other error")) {
		t.Fatal("isNotFound(other) = true, want false")
	}
}

func TestEndpointLookupAFirst(t *testing.T) {
	server := newTestDNSServer(t, func(name string, qtype uint16) testDNSResponse {
		switch qtype {
		case 1:
			return testDNSResponse{a: []net.IP{net.ParseIP("192.0.2.10")}}
		case 28:
			return testDNSResponse{aaaa: []net.IP{net.ParseIP("2001:db8::10")}}
		default:
			return testDNSResponse{rcode: 3}
		}
	})
	endpoint := newEndpoint(server.addr())

	addrs, err := endpoint.lookup(context.Background(), "a-first.test", time.Second)
	if err != nil {
		t.Fatalf("lookup() error = %v", err)
	}
	if len(addrs) != 1 || addrs[0].IP.String() != "192.0.2.10" {
		t.Fatalf("lookup() = %v, want 192.0.2.10", addrs)
	}

	queries := server.queried()
	if len(queries) != 1 || queries[0].qtype != 1 {
		t.Fatalf("DNS queries = %v, want only one A query", queries)
	}
}

func TestEndpointLookupFallsBackToAAAA(t *testing.T) {
	server := newTestDNSServer(t, func(name string, qtype uint16) testDNSResponse {
		switch qtype {
		case 1:
			return testDNSResponse{rcode: 3}
		case 28:
			return testDNSResponse{aaaa: []net.IP{net.ParseIP("2001:db8::20")}}
		default:
			return testDNSResponse{rcode: 3}
		}
	})
	endpoint := newEndpoint(server.addr())

	addrs, err := endpoint.lookup(context.Background(), "aaaa-only.test", time.Second)
	if err != nil {
		t.Fatalf("lookup() error = %v", err)
	}
	if len(addrs) != 1 || addrs[0].IP.String() != "2001:db8::20" {
		t.Fatalf("lookup() = %v, want 2001:db8::20", addrs)
	}

	// Linux and macOS may append DNS search domains after an NXDOMAIN, so the
	// server can receive extra A queries for names such as
	// "aaaa-only.test.local". Only assert on queries for the requested name.
	var queries []testDNSQuery
	for _, query := range server.queried() {
		if query.name == "aaaa-only.test" {
			queries = append(queries, query)
		}
	}
	if len(queries) != 2 || queries[0].qtype != 1 || queries[1].qtype != 28 {
		t.Fatalf("DNS queries for aaaa-only.test = %v, want A then AAAA", queries)
	}
}

func TestLookupIPUsesCache(t *testing.T) {
	server := newTestDNSServer(t, func(name string, qtype uint16) testDNSResponse {
		if qtype == 1 {
			return testDNSResponse{a: []net.IP{net.ParseIP("192.0.2.30")}}
		}
		return testDNSResponse{rcode: 3}
	})
	resolver, err := New(Config{
		Primary:             server.addr(),
		PrimaryTimeout:      time.Second,
		HealthcheckInterval: time.Hour,
		Logger:              testLogger(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer resolver.Close()

	for i := 0; i < 2; i++ {
		addrs, err := resolver.LookupIP(context.Background(), "cache.test")
		if err != nil {
			t.Fatalf("LookupIP() error = %v", err)
		}
		if len(addrs) != 1 || addrs[0].IP.String() != "192.0.2.30" {
			t.Fatalf("LookupIP() = %v, want 192.0.2.30", addrs)
		}
	}

	if got, want := len(server.queried()), 1; got != want {
		t.Fatalf("DNS query count = %d, want %d", got, want)
	}
}

func TestLookupIPUsesFallback(t *testing.T) {
	primary := newTestDNSServer(t, func(name string, qtype uint16) testDNSResponse {
		return testDNSResponse{drop: true}
	})
	fallback := newTestDNSServer(t, func(name string, qtype uint16) testDNSResponse {
		if qtype == 1 {
			return testDNSResponse{a: []net.IP{net.ParseIP("192.0.2.40")}}
		}
		return testDNSResponse{rcode: 3}
	})

	resolver, err := New(Config{
		Primary:             primary.addr(),
		Fallback:            fallback.addr(),
		PrimaryTimeout:      100 * time.Millisecond,
		HealthcheckInterval: time.Hour,
		Logger:              testLogger(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer resolver.Close()

	addrs, err := resolver.LookupIP(context.Background(), "fallback.test")
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if len(addrs) != 1 || addrs[0].IP.String() != "192.0.2.40" {
		t.Fatalf("LookupIP() = %v, want 192.0.2.40", addrs)
	}
	if resolver.isPrimaryUp() {
		t.Fatal("primary is still marked up after a timeout")
	}
	if len(primary.queried()) == 0 {
		t.Fatal("primary was not queried")
	}
	if got, want := len(fallback.queried()), 1; got != want {
		t.Fatalf("fallback query count = %d, want %d", got, want)
	}
}

func TestLookupIPDoesNotUseFallbackForNotFound(t *testing.T) {
	primary := newTestDNSServer(t, func(name string, qtype uint16) testDNSResponse {
		return testDNSResponse{rcode: 3}
	})
	fallback := newTestDNSServer(t, func(name string, qtype uint16) testDNSResponse {
		if qtype == 1 {
			return testDNSResponse{a: []net.IP{net.ParseIP("192.0.2.50")}}
		}
		return testDNSResponse{rcode: 3}
	})

	resolver, err := New(Config{
		Primary:             primary.addr(),
		Fallback:            fallback.addr(),
		PrimaryTimeout:      time.Second,
		HealthcheckInterval: time.Hour,
		Logger:              testLogger(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer resolver.Close()

	if _, err := resolver.LookupIP(context.Background(), "missing.test"); err == nil {
		t.Fatal("LookupIP() error = nil, want a not-found error")
	}
	if len(fallback.queried()) != 0 {
		t.Fatalf("fallback was queried %d times for an authoritative not-found result", len(fallback.queried()))
	}
}

func TestCheckPrimaryRecovers(t *testing.T) {
	server := newTestDNSServer(t, func(name string, qtype uint16) testDNSResponse {
		if qtype == 1 {
			return testDNSResponse{a: []net.IP{net.ParseIP("192.0.2.60")}}
		}
		return testDNSResponse{rcode: 3}
	})
	resolver := &Resolver{
		primary:   newEndpoint(server.addr()),
		timeout:   time.Second,
		interval:  time.Hour,
		log:       testLogger(),
		primaryUp: false,
		cache:     make(map[string]cacheEntry),
		inflight:  make(map[string]*call),
	}

	resolver.checkPrimary()
	if !resolver.isPrimaryUp() {
		t.Fatal("checkPrimary() did not mark a recovered primary as up")
	}
}

type testDNSResponse struct {
	drop  bool
	rcode int
	a     []net.IP
	aaaa  []net.IP
}

type testDNSQuery struct {
	name  string
	qtype uint16
}

type testDNSQuestion struct {
	name  string
	qtype uint16
	end   int
}

type testDNSServer struct {
	conn    net.PacketConn
	reply   func(string, uint16) testDNSResponse
	mu      sync.Mutex
	queries []testDNSQuery
	done    chan struct{}
}

func newTestDNSServer(t *testing.T, reply func(string, uint16) testDNSResponse) *testDNSServer {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen DNS server: %v", err)
	}

	server := &testDNSServer{
		conn:  conn,
		reply: reply,
		done:  make(chan struct{}),
	}
	go server.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		<-server.done
	})

	return server
}

func (s *testDNSServer) addr() string {
	return s.conn.LocalAddr().String()
}

func (s *testDNSServer) queried() []testDNSQuery {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]testDNSQuery, len(s.queries))
	copy(out, s.queries)
	return out
}

func (s *testDNSServer) serve() {
	defer close(s.done)

	buf := make([]byte, 1500)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}

		question, ok := parseTestDNSQuestion(buf[:n])
		if !ok {
			continue
		}

		s.mu.Lock()
		s.queries = append(s.queries, testDNSQuery{name: question.name, qtype: question.qtype})
		s.mu.Unlock()

		response := s.reply(question.name, question.qtype)
		if response.drop {
			continue
		}

		packet := buildTestDNSResponse(buf[:n], question, response)
		if _, err := s.conn.WriteTo(packet, addr); err != nil {
			return
		}
	}
}

func parseTestDNSQuestion(msg []byte) (testDNSQuestion, bool) {
	if len(msg) < 12 {
		return testDNSQuestion{}, false
	}

	offset := 12
	var labels []string
	for {
		if offset >= len(msg) {
			return testDNSQuestion{}, false
		}
		length := int(msg[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xc0 != 0 || length > 63 || offset+length > len(msg) {
			return testDNSQuestion{}, false
		}
		labels = append(labels, string(msg[offset:offset+length]))
		offset += length
	}

	if offset+4 > len(msg) {
		return testDNSQuestion{}, false
	}

	return testDNSQuestion{
		name:  strings.ToLower(strings.Join(labels, ".")),
		qtype: binary.BigEndian.Uint16(msg[offset : offset+2]),
		end:   offset + 4,
	}, true
}

type testDNSAnswer struct {
	typ  uint16
	data []byte
}

func buildTestDNSResponse(query []byte, question testDNSQuestion, response testDNSResponse) []byte {
	var answers []testDNSAnswer
	if response.rcode == 0 {
		for _, ip := range response.a {
			if v4 := ip.To4(); v4 != nil {
				answers = append(answers, testDNSAnswer{typ: 1, data: v4})
			}
		}
		for _, ip := range response.aaaa {
			if ip.To4() == nil {
				if v6 := ip.To16(); v6 != nil {
					answers = append(answers, testDNSAnswer{typ: 28, data: v6})
				}
			}
		}
	}

	header := make([]byte, 12)
	copy(header[:2], query[:2])
	binary.BigEndian.PutUint16(header[2:4], uint16(0x8180)|uint16(response.rcode&0xf))
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], uint16(len(answers)))

	packet := append([]byte{}, header...)
	packet = append(packet, query[12:question.end]...)
	for _, answer := range answers {
		packet = append(packet, 0xc0, 0x0c)
		packet = binary.BigEndian.AppendUint16(packet, answer.typ)
		packet = binary.BigEndian.AppendUint16(packet, 1)
		packet = binary.BigEndian.AppendUint32(packet, 60)
		packet = binary.BigEndian.AppendUint16(packet, uint16(len(answer.data)))
		packet = append(packet, answer.data...)
	}

	return packet
}
