// Package service provides the Windows service handler and health endpoint.
package service

import (
	"encoding/json"
	"net/http"
	"time"
)

// HealthResponse is the minimal health check payload.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Uptime  string `json:"uptime,omitempty"`
}

// HealthHandler returns an http.HandlerFunc that serves a minimal health check.
// The response contains only status, version, and uptime.
// No internal state, config details, or sensitive data is exposed.
func HealthHandler(startTime time.Time, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := HealthResponse{
			Status:  "up",
			Version: version,
			Uptime:  time.Since(startTime).String(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(resp)
	}
}
