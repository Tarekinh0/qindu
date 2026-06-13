//go:build windows

package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sys/windows/svc"
)

// serviceHandler implements the Windows service interface.
// When Stop/Shutdown is received, it triggers http.Server.Shutdown
// for graceful connection draining.
type serviceHandler struct {
	server *http.Server
	logger *slog.Logger
}

// Execute is the main service callback. It runs the proxy and handles
// service control requests (stop, shutdown).
func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending}

	// Start the HTTP server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		h.logger.Info("proxy listening", "addr", h.server.Addr)
		errCh <- h.server.ListenAndServe()
	}()

	s <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case err := <-errCh:
			if err != nil && err != http.ErrServerClosed {
				h.logger.Error("proxy exited with error", "error", err)
				return false, 1
			}
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				h.logger.Info("service stop requested, draining connections",
					"timeout_seconds", 30,
				)

				// PR-001 FIX: Trigger graceful shutdown of the HTTP server.
				// This stops accepting new connections and drains existing ones.
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				if err := h.server.Shutdown(ctx); err != nil {
					h.logger.Error("graceful shutdown error", "error", err)
				}

				// Wait for ListenAndServe to return (via errCh) or timeout
				select {
				case <-errCh:
					h.logger.Info("service stopped gracefully")
				case <-time.After(30 * time.Second):
					h.logger.Error("service stop timed out after 30s")
				}
				return false, 0

			default:
				h.logger.Warn("unexpected service control request",
					"cmd", fmt.Sprintf("%d", c.Cmd),
				)
			}
		}
	}
}

// RunService starts the Windows service with the given name.
// The HTTP server is started and gracefully shut down on service stop.
func RunService(name string, server *http.Server, logger *slog.Logger) error {
	handler := &serviceHandler{
		server: server,
		logger: logger,
	}

	err := svc.Run(name, handler)
	if err != nil {
		return fmt.Errorf("service %s failed: %w", name, err)
	}
	return nil
}

// IsServiceSession returns true if the process is running as a Windows service
// (not in an interactive session). Returns false on non-Windows.
func IsServiceSession() (bool, error) {
	isInteractive, err := svc.IsAnInteractiveSession()
	if err != nil {
		return false, err
	}
	return !isInteractive, nil
}
