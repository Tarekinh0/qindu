// Package all imports all provider plugins for their side-effects (init registration).
// Import this package in any binary that needs all providers registered.
// Adding a new provider only requires: 1) create the plugin with init()-based
// registration, 2) add a blank import here — no changes needed in proxy.go.
//
// Usage:
//
//	import _ "github.com/Tarekinh0/qindu/internal/providers/all"
package all

import (
	_ "github.com/Tarekinh0/qindu/internal/providers/chatgpt"
)
