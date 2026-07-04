package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Tarekinh0/qindu/internal/interceptor"
	"github.com/Tarekinh0/qindu/internal/pii"
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
// Returns an error if proxy initialization fails, including when
// an unimplemented agent.mode (e.g., "enforce") is requested.
func NewProxy(
	cfg *policy.Config,
	ca *qinduTls.CA,
	certCache *qinduTls.CertCache,
	logger *slog.Logger,
	version string,
) (*Proxy, error) {
	// Select the appropriate interceptor based on configured mode.
	// Engine creation is deferred to selectInterceptor to avoid
	// paying for what we don't use in transparent mode (PR-100).
	selectedInterceptor, err := selectInterceptor(cfg, logger)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		config:       cfg,
		ca:           ca,
		certCache:    certCache,
		domainRouter: policy.NewDomainRouter(cfg.AllAIDomains()),
		interceptor:  selectedInterceptor,
		logger:       logger,
		startTime:    time.Now(),
		version:      version,
	}, nil
}

// selectInterceptor chooses the appropriate Interceptor implementation
// based on the agent.mode config field (SR-12).
// Returns an error when the requested mode cannot be activated,
// including when "enforce" is requested before implementation (PR-001).
// The PII detection engine is only created for monitor mode to avoid
// paying for what we don't use in transparent mode (PR-100).
func selectInterceptor(cfg *policy.Config, logger *slog.Logger) (Interceptor, error) {
	mode := cfg.Agent.Mode

	switch mode {
	case "transparent":
		// Zero detection, zero inspection — equivalent to current behavior.
		return &NoOpInterceptor{}, nil

	case "monitor":
		// Create the PII detection engine only for monitor mode (DPO-R7, SR-12).
		// The engine is concurrent-safe and shared across all connections.
		// Registration order: EMAIL before NAME (dependency).
		engine := pii.NewEngine(pii.DefaultMaxInputBytes,
			pii.NewEmailRecognizer(),
			pii.NewPhoneRecognizer(),
			pii.NewIBANRecognizer(),
			pii.NewCreditCardRecognizer(),
			pii.NewJWTRecognizer(),
			pii.NewSecretPrefixRecognizer(),
			pii.NewSecretEntropyRecognizer(),
			pii.NewPrivateKeyRecognizer(),
			pii.NewNameFromEmailRecognizer(),
		)

		// PII detection enabled, traffic forwarded unmodified.
		logger.Info("Monitor mode active: PII detection enabled, traffic passed through unmodified. PII still reaches AI providers. Use enforce mode to tokenize PII.",
			"pii_logging", cfg.Logging.PIILogging,
		)
		// maxInputLen is read from the engine itself — no redundant parameter (PR-102).
		return interceptor.NewMonitorInterceptor(engine, cfg.Logging.PIILogging, logger), nil

	case "enforce":
		// Enforce mode is not yet implemented (QINDU-0009).
		// The proxy MUST refuse to start with a clear fatal error.
		// No silent fallback — users must never be misled into thinking
		// PII is being tokenized when it is not (PR-001).
		return nil, fmt.Errorf("agent.mode 'enforce' is not yet implemented in this version")

	default:
		// Unknown/unsupported mode — defensive fallback to NoOpInterceptor.
		logger.Error("Unknown agent.mode, falling back to transparent (NoOpInterceptor)",
			"mode", mode,
		)
		return &NoOpInterceptor{}, nil
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
