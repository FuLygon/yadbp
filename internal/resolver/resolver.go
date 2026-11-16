package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"yadbp/internal/logging"
)

const (
	// fallbackTimeout bounds a query to the fallback DNS server.
	fallbackTimeout = 5 * time.Second
	// cacheTTL is how long resolved address sets are cached.
	cacheTTL = 60 * time.Second
	// cacheMaxEntries caps the number of cached hostnames.
	cacheMaxEntries = 1000
	// healthcheckHost is the name probed while the primary is marked down.
	healthcheckHost = "example.com"
)

// Config configures a Resolver.
type Config struct {
	// Primary is the primary DNS server in ip:port form.
	Primary string
	// Fallback is an optional fallback DNS server in ip:port form.
	Fallback string
	// PrimaryTimeout bounds each primary DNS query.
	PrimaryTimeout time.Duration
	// HealthcheckInterval controls how often a down primary is probed.
	HealthcheckInterval time.Duration
	// Logger receives debug and status messages.
	Logger *logging.Logger
}

// Resolver resolves hostnames using a primary DNS server, an optional fallback,
// request collapsing, and a bounded cache. It is safe for concurrent use.
type Resolver struct {
	primary  *endpoint
	fallback *endpoint
	timeout  time.Duration
	interval time.Duration
	log      *logging.Logger

	mu        sync.Mutex
	primaryUp bool
	probing   bool
	cache     map[string]cacheEntry
	inflight  map[string]*call
	lastSweep time.Time

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// endpoint is a DNS server address and the net.Resolver configured to reach it.
type endpoint struct {
	addr     string
	resolver *net.Resolver
}

// cacheEntry holds a cached address set and its LRU bookkeeping.
type cacheEntry struct {
	addrs    []net.IPAddr
	expires  time.Time
	lastUsed time.Time
}

// call collapses concurrent lookups for the same hostname.
type call struct {
	wg    sync.WaitGroup
	addrs []net.IPAddr
	err   error
}

// New validates cfg and returns a resolver. When Fallback is set, New also
// starts the background health loop that promotes the primary again after it
// recovers; call Close to stop it.
func New(cfg Config) (*Resolver, error) {
	if cfg.PrimaryTimeout <= 0 {
		return nil, errors.New("primary dns timeout must be greater than zero")
	}
	if cfg.HealthcheckInterval <= 0 {
		return nil, errors.New("primary dns health check interval must be greater than zero")
	}
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}

	primaryAddr, err := normalizeAddress(cfg.Primary)
	if err != nil {
		return nil, fmt.Errorf("primary dns: %w", err)
	}

	r := &Resolver{
		primary:   newEndpoint(primaryAddr),
		timeout:   cfg.PrimaryTimeout,
		interval:  cfg.HealthcheckInterval,
		log:       cfg.Logger,
		primaryUp: true,
		cache:     make(map[string]cacheEntry),
		inflight:  make(map[string]*call),
	}

	if cfg.Fallback != "" {
		fallbackAddr, err := normalizeAddress(cfg.Fallback)
		if err != nil {
			return nil, fmt.Errorf("fallback dns: %w", err)
		}
		r.fallback = newEndpoint(fallbackAddr)
	}

	if r.fallback != nil {
		r.stop = make(chan struct{})
		r.done = make(chan struct{})
		go r.healthLoop()
	}

	return r, nil
}

// Primary returns the primary server address, or "system" for a nil resolver.
func (r *Resolver) Primary() string {
	if r == nil {
		return "system"
	}
	return r.primary.addr
}

// Fallback returns the fallback server address, or "none" when no fallback is
// configured.
func (r *Resolver) Fallback() string {
	if r == nil || r.fallback == nil {
		return "none"
	}
	return r.fallback.addr
}

// Close stops the health loop. It is safe to call more than once and is a no-op
// for a nil resolver or a resolver without a fallback.
func (r *Resolver) Close() {
	if r == nil || r.stop == nil {
		return
	}
	r.closeOnce.Do(func() {
		close(r.stop)
		<-r.done
	})
}

// LookupIP resolves host to a list of addresses. Literal IPs are returned
// directly. Results are cached for cacheTTL, and concurrent lookups for the
// same host share one DNS request. The resolver's address order is preserved.
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil, errors.New("empty host")
	}

	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	if addrs, ok := r.cached(host); ok {
		r.log.Debugf("resolved %s (cached) -> %s", host, formatAddrs(addrs))
		return addrs, nil
	}

	r.mu.Lock()
	if c, ok := r.inflight[host]; ok {
		r.mu.Unlock()
		c.wg.Wait()
		return c.addrs, c.err
	}
	c := &call{}
	c.wg.Add(1)
	r.inflight[host] = c
	r.mu.Unlock()

	c.addrs, c.err = r.resolve(ctx, host)

	r.mu.Lock()
	delete(r.inflight, host)
	r.mu.Unlock()
	c.wg.Done()

	if c.err == nil {
		r.store(host, c.addrs)
	}

	return c.addrs, c.err
}

// resolve applies primary/fallback policy. A name-not-found answer from the
// primary is authoritative and is not retried against the fallback; other
// primary failures mark it down and use the fallback. If the primary was
// already marked down and the fallback also fails, the primary is tried once as
// a last resort.
func (r *Resolver) resolve(ctx context.Context, host string) (addrs []net.IPAddr, err error) {
	start := time.Now()
	source := ""

	defer func() {
		elapsed := time.Since(start).Round(time.Millisecond)
		if err != nil {
			r.log.Debugf("failed to resolve %s after %s: %v", host, elapsed, err)
			return
		}
		r.log.Debugf("resolved %s via %s (%s) -> %s", host, source, elapsed, formatAddrs(addrs))
	}()

	if r.fallback == nil {
		result, lookupErr := r.primary.lookup(ctx, host, r.timeout)
		if lookupErr != nil {
			return nil, lookupErr
		}
		source = "primary " + r.primary.addr
		return result, nil
	}

	var primaryErr error
	primaryTried := false

	if r.isPrimaryUp() {
		primaryTried = true
		result, lookupErr := r.primary.lookup(ctx, host, r.timeout)
		switch {
		case lookupErr == nil:
			source = "primary " + r.primary.addr
			return result, nil
		case isNotFound(lookupErr):
			return nil, lookupErr
		default:
			primaryErr = lookupErr
			r.markPrimaryDown(lookupErr)
		}
	} else {
		primaryErr = errors.New("primary marked down")
	}

	fallbackAddrs, fallbackErr := r.fallback.lookup(ctx, host, fallbackTimeout)
	if fallbackErr == nil {
		source = "fallback " + r.fallback.addr
		return fallbackAddrs, nil
	}

	if !primaryTried {
		result, lookupErr := r.primary.lookup(ctx, host, r.timeout)
		if lookupErr == nil {
			r.markPrimaryUp()
			source = "primary " + r.primary.addr + " (last resort)"
			return result, nil
		}
		primaryErr = lookupErr
	}

	return nil, fmt.Errorf(
		"no dns server returned an address for %s (primary: %v, fallback: %v)",
		host, primaryErr, fallbackErr,
	)
}

// isPrimaryUp reports whether the primary is currently considered reachable.
func (r *Resolver) isPrimaryUp() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.primaryUp
}

// markPrimaryDown records a primary failure and logs the transition once.
func (r *Resolver) markPrimaryDown(err error) {
	r.mu.Lock()
	wasUp := r.primaryUp
	r.primaryUp = false
	r.mu.Unlock()

	if !wasUp {
		return
	}

	if r.fallback != nil {
		r.log.Warnf(
			"primary %s unreachable (%v); using fallback %s, re-checking every %s",
			r.primary.addr, err, r.fallback.addr, r.interval,
		)
		return
	}

	r.log.Warnf("primary %s unreachable (%v)", r.primary.addr, err)
}

// markPrimaryUp records a primary recovery and logs the transition once.
func (r *Resolver) markPrimaryUp() {
	r.mu.Lock()
	wasUp := r.primaryUp
	r.primaryUp = true
	r.mu.Unlock()

	if !wasUp {
		r.log.Infof("primary %s recovered; preferring it again", r.primary.addr)
	}
}

// healthLoop periodically checks whether a down primary has recovered.
func (r *Resolver) healthLoop() {
	defer close(r.done)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.checkPrimary()
		}
	}
}

// checkPrimary probes the primary once when it is down and no probe is already
// running. A successful probe marks the primary up again.
func (r *Resolver) checkPrimary() {
	r.mu.Lock()
	if r.primaryUp || r.probing {
		r.mu.Unlock()
		return
	}
	r.probing = true
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.probing = false
		r.mu.Unlock()
	}()

	if _, err := r.primary.lookup(context.Background(), healthcheckHost, r.timeout); err != nil {
		r.log.Debugf("primary %s still unreachable: %v", r.primary.addr, err)
		return
	}

	r.markPrimaryUp()
}

// cached returns a copy of the cached addresses for host and refreshes its LRU
// timestamp. Expired entries are removed.
func (r *Resolver) cached(host string) ([]net.IPAddr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	entry, ok := r.cache[host]
	if !ok {
		return nil, false
	}
	if now.After(entry.expires) {
		delete(r.cache, host)
		return nil, false
	}
	entry.lastUsed = now
	r.cache[host] = entry

	return cloneAddrs(entry.addrs), true
}

// store inserts or replaces a cache entry. It periodically sweeps expired
// entries and enforces the hard cap by evicting the least recently used host.
func (r *Resolver) store(host string, addrs []net.IPAddr) {
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Expired entries are otherwise only removed when the same host is looked
	// up again, so sweep them periodically to keep the cache bounded.
	if now.Sub(r.lastSweep) >= cacheTTL {
		r.sweepExpiredLocked(now)
		r.lastSweep = now
	}

	// Also enforce a hard cap so a burst of unique hostnames cannot grow the
	// cache without limit between sweeps. Evict the least recently used entry
	// when the cap is reached.
	if _, exists := r.cache[host]; !exists && len(r.cache) >= cacheMaxEntries {
		r.sweepExpiredLocked(now)
		for len(r.cache) >= cacheMaxEntries {
			oldestName := ""
			var oldestUsed time.Time
			for name, entry := range r.cache {
				if oldestName == "" || entry.lastUsed.Before(oldestUsed) {
					oldestName = name
					oldestUsed = entry.lastUsed
				}
			}
			if oldestName == "" {
				break
			}
			delete(r.cache, oldestName)
		}
	}

	r.cache[host] = cacheEntry{
		addrs:    cloneAddrs(addrs),
		expires:  now.Add(cacheTTL),
		lastUsed: now,
	}
}

// sweepExpiredLocked removes expired entries. The caller must hold r.mu.
func (r *Resolver) sweepExpiredLocked(now time.Time) {
	for name, entry := range r.cache {
		if now.After(entry.expires) {
			delete(r.cache, name)
		}
	}
}

// newEndpoint returns a DNS endpoint that always dials the configured server
// address, bypassing the system resolver.
func newEndpoint(addr string) *endpoint {
	e := &endpoint{addr: addr}
	e.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, network, e.addr)
		},
	}
	return e
}

// lookup resolves host using IPv4 first. AAAA is queried only when the host
// has no A record, so a blackholed IPv6 route cannot delay or break an
// IPv4-capable host. Returned addresses stay in the resolver's order.
func (e *endpoint) lookup(ctx context.Context, host string, timeout time.Duration) ([]net.IPAddr, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := e.lookupFamily(ctx, host, "ip4")
	if err == nil && len(addrs) > 0 {
		return addrs, nil
	}
	if err != nil && !isNotFound(err) {
		return nil, err
	}

	addrs, err = e.lookupFamily(ctx, host, "ip6")
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s returned no addresses for %s", e.addr, host)
	}
	return addrs, nil
}

// lookupFamily queries one address family (usually "ip4" or "ip6").
func (e *endpoint) lookupFamily(ctx context.Context, host, network string) ([]net.IPAddr, error) {
	ips, err := e.resolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	addrs := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, net.IPAddr{IP: ip})
	}
	return addrs, nil
}

// normalizeAddress validates an ip:port DNS server address and returns its
// canonical form.
func normalizeAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("address is empty")
	}

	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: expected ip:port (default port for most dns server is 53)", value)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("invalid address %q: host must be an ip, not a hostname", value)
	}

	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", fmt.Errorf("invalid address %q: invalid port %q", value, port)
	}

	return net.JoinHostPort(ip.String(), port), nil
}

// cloneAddrs returns a deep copy of addrs so cache users cannot mutate cached
// address slices.
func cloneAddrs(addrs []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, len(addrs))
	for i, addr := range addrs {
		out[i] = net.IPAddr{IP: append(net.IP(nil), addr.IP...), Zone: addr.Zone}
	}
	return out
}

// formatAddrs returns a comma-separated list of IPs for debug logging.
func formatAddrs(addrs []net.IPAddr) string {
	values := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		values = append(values, addr.IP.String())
	}
	return strings.Join(values, ", ")
}

// isNotFound reports whether err is a DNS name-not-found error.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
