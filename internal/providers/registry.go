// Package providers defines the provider-agnostic plugin interface and shared types.
package providers

import (
	"log/slog"
	"sync"
)

// PluginFactory is a function that creates a ProviderPlugin given a logger.
type PluginFactory func(logger *slog.Logger) ProviderPlugin

var (
	// registryMu guards the registry map for concurrent access.
	// Currently all Register() calls happen in init() before main(), but the
	// guard is cheap and prevents future data races if runtime registration
	// is added (e.g., hot-reload).
	registryMu sync.RWMutex
	// registry holds registered provider plugin factories.
	// Plugins register themselves via Register() in init() functions.
	registry = map[string]PluginFactory{}
)

// Register registers a provider plugin factory under the given name.
// Plugins call this in their init() to self-register without requiring
// changes to proxy.go (Open/Closed Principle, PR-100).
func Register(name string, factory PluginFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// Create creates a ProviderPlugin by name from the registry.
// Returns nil if no plugin is registered under the given name.
func Create(name string, logger *slog.Logger) ProviderPlugin {
	registryMu.RLock()
	factory, ok := registry[name]
	registryMu.RUnlock()
	if ok {
		return factory(logger)
	}
	return nil
}
