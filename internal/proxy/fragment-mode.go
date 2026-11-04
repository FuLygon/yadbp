package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"time"

	"cloak-dpi/internal/fragment"
)

const (
	fragmentModeTTL      = 10 * time.Minute
	fragmentProbeTimeout = 5 * time.Second
)

type fragmentModeEntry struct {
	ready    chan struct{}
	finished bool
	tcp      bool
	expires  time.Time
}

// needsTCPSegments reports whether record-level fragmentation breaks the TLS
// handshake for host. Some TLS frontends, such as DDoS-Guard, only inspect the
// first TLS record to find the SNI. If the ClientHello is split across records
// they cannot route the connection and answer with a default self-signed
// certificate. For those hosts the ClientHello is kept in a single record and
// split at the TCP level instead.
//
// The check is done once per host and cached.
func (s *Server) needsTCPSegments(host, port string) bool {
	now := time.Now()

	s.modeMu.Lock()
	entry, ok := s.modes[host]
	if ok && (!entry.finished || now.Before(entry.expires)) {
		s.modeMu.Unlock()
		<-entry.ready
		return entry.tcp
	}

	entry = &fragmentModeEntry{ready: make(chan struct{})}
	s.modes[host] = entry
	s.modeMu.Unlock()

	tcp := !s.recordFragmentationWorks(host, port)

	s.modeMu.Lock()
	entry.tcp = tcp
	entry.finished = true
	entry.expires = time.Now().Add(fragmentModeTTL)
	close(entry.ready)
	s.modeMu.Unlock()

	return tcp
}

// recordFragmentationWorks probes host with a record-fragmented ClientHello and
// inspects the certificate the server presents. A self-signed certificate means
// the server did not see the SNI and fell back to its default certificate.
func (s *Server) recordFragmentationWorks(host, port string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), fragmentProbeTimeout)
	defer cancel()

	conn, err := s.dialRemoteContext(ctx, host, port)
	if err != nil {
		s.log.Debugf("fragmentation probe for %s: %v", host, err)
		return true
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(fragmentProbeTimeout))

	probe := tls.Client(&fragmentingConn{Conn: conn}, &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // the probe only inspects the certificate
	})

	if err = probe.HandshakeContext(ctx); err != nil {
		s.log.Debugf("fragmentation probe for %s: %v", host, err)
		return true
	}

	certs := probe.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return true
	}

	cert := certs[0]
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return true
	}

	s.log.Debugf("record fragmentation breaks TLS for %s (probe got a self-signed certificate); using tcp segmentation", host)
	return false
}

// fragmentingConn rewrites the first TLS record written through it into the same
// record fragmentation the proxy applies to real connections.
type fragmentingConn struct {
	net.Conn
	fragmented bool
}

func (c *fragmentingConn) Write(p []byte) (int, error) {
	if c.fragmented || len(p) < 5 || p[0] != 0x16 {
		return c.Conn.Write(p)
	}

	parts, ok := fragment.ClientHello(p[5:])
	if !ok {
		return c.Conn.Write(p)
	}
	c.fragmented = true

	fragmented := make([]byte, 0, len(p)+5*len(parts))
	for _, part := range parts {
		fragmented = append(fragmented, part...)
	}

	if _, err := c.Conn.Write(fragmented); err != nil {
		return 0, err
	}
	return len(p), nil
}
