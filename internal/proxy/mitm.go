package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"time"

	"github.com/Tarekinh0/qindu/internal/logging"
)

// handleMITM establishes a Man-in-the-Middle TLS connection for AI domain traffic.
//
// Flow:
//  1. Get or generate a leaf certificate for the target host
//  2. Perform TLS handshake with the browser (Qindu acts as the server)
//  3. Perform TLS handshake with the upstream AI service (Qindu acts as client)
//  4. Forward HTTP request/response through the interceptor pipeline
//
// The leaf certificate is cached in memory and never persisted to disk.
// Upstream TLS is validated against the system certificate pool (no InsecureSkipVerify by default).
func (p *Proxy) handleMITM(clientConn net.Conn, host, port string) {
	startTime := time.Now()
	stats := &forwardStats{}

	defer func() { _ = clientConn.Close() }()

	// 1. Get or create leaf certificate for the host
	leafCert, err := p.certCache.GetOrCreate(host, p.ca)
	if err != nil {
		p.logger.Error("failed to get leaf certificate",
			"host", host,
			"error", err,
		)
		p.sendBadGateway(clientConn)
		logging.LogConnection(p.logger, logging.ConnectionLogEntry{
			Timestamp:  logging.NowUTC(),
			Host:       host,
			Status:     502,
			DurationMs: logging.DurationMs(startTime),
			BytesIn:    stats.bytesIn.Load(),
			BytesOut:   stats.bytesOut.Load(),
			Mode:       "mitm",
		})
		return
	}

	// 2. TLS handshake with browser (Qindu as TLS server)
	browserTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		MinVersion:   tls.VersionTLS12,
	}

	browserConn := tls.Server(clientConn, browserTLSConfig)
	if hsErr := browserConn.Handshake(); hsErr != nil {
		p.logger.Error("browser TLS handshake failed",
			"host", host,
			"error", hsErr,
		)
		logging.LogConnection(p.logger, logging.ConnectionLogEntry{
			Timestamp:  logging.NowUTC(),
			Host:       host,
			Status:     502,
			DurationMs: logging.DurationMs(startTime),
			BytesIn:    stats.bytesIn.Load(),
			BytesOut:   stats.bytesOut.Load(),
			Mode:       "mitm",
		})
		return
	}
	defer func() { _ = browserConn.Close() }()

	// 3. TLS handshake with upstream AI service (Qindu as TLS client)
	upstreamTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if p.config.UpstreamInsecure() {
		p.logger.Warn("upstream TLS validation is DISABLED (insecure mode) - FOR DEBUGGING ONLY")
		upstreamTLSConfig.InsecureSkipVerify = true
	} else {
		// SR3: Use system certificate pool for upstream validation
		if p.rootCAs != nil {
			upstreamTLSConfig.RootCAs = p.rootCAs
		} else {
			upstreamTLSConfig.RootCAs, _ = x509.SystemCertPool()
		}
		// Verify hostname (Go default - no override needed)
	}

	// Dial upstream with TLS, using the port from the CONNECT request
	targetAddr := net.JoinHostPort(host, port)
	var upstreamConn *tls.Conn
	if p.dialTLS != nil {
		upstreamConn, err = p.dialTLS("tcp", targetAddr, upstreamTLSConfig)
	} else {
		upstreamConn, err = tls.Dial("tcp", targetAddr, upstreamTLSConfig)
	}
	if err != nil {
		p.logger.Error("upstream TLS connection failed",
			"host", host,
			"error", err,
		)
		p.sendBadGateway(browserConn)
		logging.LogConnection(p.logger, logging.ConnectionLogEntry{
			Timestamp:  logging.NowUTC(),
			Host:       host,
			Status:     502,
			DurationMs: logging.DurationMs(startTime),
			BytesIn:    stats.bytesIn.Load(),
			BytesOut:   stats.bytesOut.Load(),
			Mode:       "mitm",
		})
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	// 4. Forward HTTP requests through the interceptor pipeline
	// Handle multiple requests on the same connection (HTTP keep-alive)
	// Create buffered readers ONCE to avoid discarding bytes between iterations.
	browserReader := bufio.NewReader(browserConn)
	upstreamReader := bufio.NewReader(upstreamConn)
	lastStatus := 200
	for {
		status, fwdErr := forwardRequestAndResponse(browserReader, browserConn, upstreamReader, upstreamConn, p.interceptor, stats)
		if fwdErr != nil {
			if fwdErr != io.EOF {
				p.logger.Debug("forward error",
					"host", host,
					"error", fwdErr,
				)
			}
			// Capture the status from the failed request when available
			if status != 0 {
				lastStatus = status
			}
			break
		}

		lastStatus = status
		// Only log connection metrics (no bodies, no headers)
		p.logger.Debug("request processed",
			"host", host,
			"status", status,
		)
	}

	// Log connection summary
	logging.LogConnection(p.logger, logging.ConnectionLogEntry{
		Timestamp:  logging.NowUTC(),
		Host:       host,
		Status:     lastStatus,
		DurationMs: logging.DurationMs(startTime),
		BytesIn:    stats.bytesIn.Load(),
		BytesOut:   stats.bytesOut.Load(),
		Mode:       "mitm",
	})
}

// sendBadGateway writes a minimal 502 Bad Gateway response.
// No stack traces or internal details are exposed to the client.
func (p *Proxy) sendBadGateway(conn io.Writer) {
	msg := "HTTP/1.1 502 Bad Gateway\r\n" +
		"Content-Type: application/json\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		`{"error":"bad_gateway","detail":"upstream connection failed"}` + "\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		p.logger.Debug("sendBadGateway write failed", "error", err)
	}
}
