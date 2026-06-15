package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Tarekinh0/qindu/internal/constants"
)

// GracefulShutdownTimeout is the maximum time to wait for connections to drain.
// Deprecated: Use constants.GracefulShutdownTimeout directly.
const GracefulShutdownTimeout = constants.GracefulShutdownTimeout

// WaitForShutdown blocks until a shutdown signal is received (SIGINT, SIGTERM),
// then calls http.Server.Shutdown with a 30-second timeout.
// It logs the shutdown progress and returns an error if connections are forcefully terminated.
func WaitForShutdown(server *http.Server, logger *slog.Logger) error {
	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logger.Info("received shutdown signal",
		"signal", sig.String(),
	)

	// Create context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), GracefulShutdownTimeout)
	defer cancel()

	logger.Info("starting graceful shutdown",
		"timeout_seconds", GracefulShutdownTimeout.Seconds(),
	)

	// Shutdown the server (stop accepting new connections, drain existing ones)
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown error",
			"error", err,
		)
		return err
	}

	logger.Info("server stopped gracefully")
	return nil
}
