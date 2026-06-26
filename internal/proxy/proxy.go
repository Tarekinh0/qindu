package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"time"

	"github.com/Tarekinh0/qindu/internal/policy"
	"github.com/Tarekinh0/qindu/internal/service"
	qinduTls "github.com/Tarekinh0/qindu/internal/tls"
)

// DialFunc is a function that establishes a TLS connection to an upstream server.
type DialFunc func(network, addr string, config *tls.Config) (*tls.Conn, error)

// Proxy is the main Qindu HTTP/S proxy that handles CONNECT tunneling
// and local endpoints (PAC, health).
type Proxy struct {
	startTime    time.Time
	interceptor  Interceptor
	config       *policy.Config
	ca           *qinduTls.CA
	certCache    *qinduTls.CertCache
	domainRouter *policy.DomainRouter
	logger       *slog.Logger
	rootCAs      *x509.CertPool
	dialTLS      DialFunc
	version      string
}

// NewProxy creates a new Proxy instance.
func NewProxy(
	cfg *policy.Config,
	ca *qinduTls.CA,
	certCache *qinduTls.CertCache,
	logger *slog.Logger,
	version string,
) *Proxy {
	return &Proxy{
		config:       cfg,
		ca:           ca,
		certCache:    certCache,
		domainRouter: policy.NewDomainRouter(cfg.AllAIDomains()),
		interceptor:  &NoOpInterceptor{},
		logger:       logger,
		startTime:    time.Now(),
		version:      version,
	}
}

// ServeHTTP implements the http.Handler interface.
// It dispatches CONNECT requests to the CONNECT handler and
// GET/HEAD requests to local endpoints (PAC, health).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodConnect:
		p.handleCONNECT(w, r)
	default:
		p.handleHTTP(w, r)
	}
}

// handleHTTP processes non-CONNECT HTTP requests (PAC, health).
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/proxy.pac":
		p.handlePAC(w, r)
	case "/health":
		p.handleHealth(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handlePAC serves the dynamically-generated PAC file.
// Content-Type is set to application/x-ns-proxy-autoconfig.
func (p *Proxy) handlePAC(w http.ResponseWriter, r *http.Request) {
	domains := p.config.AllAIDomains()
	pacContent := policy.GeneratePAC(domains, p.config.ListenAddress())

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(pacContent)); err != nil {
		p.logger.Error("failed to write PAC response", "error", err)
	}
}

// handleHealth delegates to the service package's properly-typed health handler.
func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	service.HealthHandler(p.startTime, p.version)(w, r)
}
