package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Tarekinh0/qindu/internal/logging"
	"github.com/Tarekinh0/qindu/internal/policy"
)

// handleCONNECT processes HTTP CONNECT requests.
// It hijacks the connection from the HTTP server and routes the traffic
// either through MITM (AI domains) or blind tunnel (all other domains).
func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	if hostPort == "" {
		http.Error(w, "Bad Request: missing host", http.StatusBadRequest)
		return
	}

	// Extract hostname and port from CONNECT target.
	// If no port is specified, default to 443 (standard HTTPS).
	hostOnly, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		hostOnly = hostPort
		port = "443"
	}

	startTime := time.Now()
	stats := &forwardStats{}

	// Route: determine MITM or Tunnel based on domain (hostname only, no port)
	action := p.domainRouter.Route(hostOnly)
	p.logger.Debug("CONNECT request",
		"host", hostOnly,
		"port", port,
		"action", string(action),
	)

	// Hijack the connection from the HTTP server
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("server does not support hijacking")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("failed to hijack connection",
			"host", hostOnly,
			"error", err,
		)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// handleMITM manages clientConn lifecycle; all other paths close here.
	mitm := false
	defer func() {
		if !mitm {
			_ = clientConn.Close()
		}
	}()

	// Send 200 Connection Established to the client
	if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		p.logger.Debug("client disconnected before CONNECT response", "host", hostOnly, "error", err)
		return
	}
	if err := bufrw.Flush(); err != nil {
		p.logger.Debug("flush failed after CONNECT response", "host", hostOnly, "error", err)
		return
	}

	// Route based on action
	switch action {
	case policy.ActionMITM:
		mitm = true
		p.logger.Info("MITM connection",
			"host", hostOnly,
			"port", port,
			"action", "mitm",
		)
		p.handleMITM(clientConn, hostOnly, port)
		return

	case policy.ActionTunnel:
		p.logger.Info("tunnel connection (blind)",
			"host", hostOnly,
			"port", port,
			"action", "tunnel",
		)
		p.handleTunnel(clientConn, hostOnly, port, startTime, stats)
		return

	default:
		p.logger.Error("unknown routing action",
			"host", hostOnly,
			"action", string(action),
		)
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 500 Internal Server Error\r\n\r\n")
	}
}

// handleTunnel performs a blind TCP relay for non-AI domain traffic.
// No TLS decryption occurs. Traffic is copied bidirectionally between
// the browser and the upstream server.
func (p *Proxy) handleTunnel(clientConn net.Conn, host, port string, startTime time.Time, stats *forwardStats) {
	upstreamConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		p.logger.Error("tunnel upstream connection failed",
			"host", host,
			"port", port,
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
			Mode:       "tunnel",
		})
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	// Bidirectional blind copy.
	// Both directions must complete before logging to ensure accurate byte counts.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, forwardingBufferSize)
		n, _ := io.CopyBuffer(upstreamConn, clientConn, buf)
		stats.bytesIn.Add(n)
		// Signal the other direction to stop by closing the write side
		if tcpConn, ok := upstreamConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()
	buf := make([]byte, forwardingBufferSize)
	n, _ := io.CopyBuffer(clientConn, upstreamConn, buf)
	stats.bytesOut.Add(n)
	// Signal the goroutine to stop
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	wg.Wait()

	// Log connection summary (SR5: metadata only, no headers/bodies)
	logging.LogConnection(p.logger, logging.ConnectionLogEntry{
		Timestamp:  logging.NowUTC(),
		Host:       host,
		Status:     200,
		DurationMs: logging.DurationMs(startTime),
		BytesIn:    stats.bytesIn.Load(),
		BytesOut:   stats.bytesOut.Load(),
		Mode:       "tunnel",
	})
}
