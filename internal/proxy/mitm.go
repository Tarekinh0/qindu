package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Tarekinh0/qindu/internal/logging"
	"github.com/Tarekinh0/qindu/internal/session"
	"github.com/Tarekinh0/qindu/internal/tokenize"
	"github.com/Tarekinh0/qindu/internal/vault"
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

	// 4. Enforce mode: resolve user SID, create per-user vault, and prepare for tokenizer injection.
	// Only wired for enforce mode — monitor/transparent skip this entirely.
	var userVault *vault.Vault // non-nil only for enforce mode
	if p.config.Agent.Mode == "enforce" {
		if p.vaultManager == nil {
			p.logger.Error("enforce mode requires a VaultManager",
				"pii_values_logged", false,
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

		// Resolve the user from the TCP connection (SID on Windows, current user on Unix).
		localPort := uint16(clientConn.LocalAddr().(*net.TCPAddr).Port)
		resolved, err := session.LookupVaultPathForPort(localPort)
		if err != nil {
			p.logger.Error("enforce: SID resolution failed, rejecting connection (fail-closed)",
				"error", "user resolution failed",
				"pii_values_logged", false,
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

		// Create or reuse per-user vault (fail-closed: 502 on error).
		userVault, err = p.vaultManager.GetOrCreate(resolved, 0)
		if err != nil {
			p.logger.Error("enforce: vault creation failed, rejecting connection (fail-closed)",
				"error", "vault initialization failed",
				"pii_values_logged", false,
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
	}

	// 5. Forward HTTP requests through the interceptor pipeline
	// Handle multiple requests on the same connection (HTTP keep-alive)
	// Create buffered readers ONCE to avoid discarding bytes between iterations.
	browserReader := bufio.NewReader(browserConn)
	upstreamReader := bufio.NewReader(upstreamConn)
	lastStatus := 200
	for {
		// 5.1 Read request from browser (shared for all modes).
		req, err := http.ReadRequest(browserReader)
		if err != nil {
			if err != io.EOF {
				p.logger.Debug("forward error",
					"host", host,
					"error", err,
				)
			}
			break
		}

		// 5.2 Enforce mode: derive conversation ID, create per-request tokenizer,
		// inject into request context. Then delegate to shared forwarding helper.
		var status int
		var fwdErr error

		if p.config.Agent.Mode == "enforce" {
			var convID string
			if req.URL != nil {
				convID = deriveConversationID(req.URL.Path)
			} else {
				convID = deriveConversationID("")
			}
			providerName := p.resolveProviderForHost(host)

			tokenizer := tokenize.New(p.engine,
				tokenize.WithPersister(userVault),
				tokenize.WithProvider(providerName),
				tokenize.WithConversationID(convID),
				tokenize.WithLogger(p.logger),
			)
			ctx := tokenize.ContextWithTokenizer(req.Context(), tokenizer)
			req = req.WithContext(ctx)

			status, fwdErr = forwardHTTPRoundTrip(req, browserConn, upstreamReader, upstreamConn, p.interceptor, stats)
			_ = tokenizer.Close() // explicit close in loop — defers accumulate (PR-003)
		} else {
			status, fwdErr = forwardHTTPRoundTrip(req, browserConn, upstreamReader, upstreamConn, p.interceptor, stats)
		}

		if fwdErr != nil {
			p.logger.Debug("forward error",
				"host", host,
				"error", fwdErr,
			)
			if status != 0 {
				lastStatus = status
			}
			break
		}

		lastStatus = status
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
