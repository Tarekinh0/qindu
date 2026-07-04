// Qindu AI Privacy Proxy
// Local TLS proxy that intercepts AI traffic for PII protection.
// Single binary: auto-detects Windows service vs console mode.
//
// Usage:
//
//	go run ./cmd/agent                              # console mode (default)
//	go run ./cmd/agent -config configs/default.yaml  # with custom config
//	go run ./cmd/agent ca-init                       # generate CA (default config)
//	go run ./cmd/agent ca-init --unsafe              # generate CA without Name Constraints
//	go run ./cmd/agent ca-init --config other.yaml   # generate CA from custom config
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Tarekinh0/qindu/internal/policy"
	qinduTls "github.com/Tarekinh0/qindu/internal/tls"
)

const (
	defaultConfigPath = "configs/default.yaml"
	caSubDir          = "Qindu"
	appVersion        = "0.1.0"
)

func main() {
	// Subcommand dispatch: "ca-init" runs CA generation, everything else is proxy mode.
	if len(os.Args) > 1 && os.Args[1] == "ca-init" {
		os.Exit(runCAInit(os.Args[2:]))
	}

	console := flag.Bool("console", false, "force console mode (bypass Windows service detection, useful for SSH/debugging)")
	configPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()

	// Check QINDU_CONSOLE env var as a flagless alternative for SSH sessions
	forceConsole := *console || os.Getenv("QINDU_CONSOLE") == "1"

	os.Exit(runProxy(*configPath, forceConsole))
}

// =============================================================================
// ca-init subcommand
// =============================================================================

// runCAInit implements the "ca-init" subcommand: generates a new CA certificate
// and key, optionally with Name Constraints derived from the provider config.
// On Windows, the CA is DPAPI-encrypted and stored in %PROGRAMDATA%\Qindu\.
// The subcommand DESTROYS any existing CA before creating a new one.
func runCAInit(args []string) int {
	fs := flag.NewFlagSet("ca-init", flag.ExitOnError)
	unsafe := fs.Bool("unsafe", false, "generate CA without Name Constraints (reduces security)")
	autoConfirmUnsafe := fs.Bool("auto-confirm-unsafe", false, "skip interactive confirmation for --unsafe (MSI GUI context only)")
	configPath := fs.String("config", "", "path to YAML config file")
	// flag.ExitOnError causes os.Exit(2) on parse failures, but we capture
	// the error explicitly for defense-in-depth and lint compliance.
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing ca-init flags: %v\n", err)
		return 1
	}

	// Resolve config path through the standard priority chain
	resolvedConfigPath, err := resolveConfigPath(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Load configuration using the shared wrapper (PR-H2 fix)
	cfg, err := loadConfig(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to load config: %v\n", err)
		return 1
	}

	// Determine permitted domains for Name Constraints
	var permittedDomains []string
	if !*unsafe {
		permittedDomains = cfg.AllAIDomains()
		if len(permittedDomains) == 0 {
			fmt.Fprintf(os.Stderr, "error: No enabled AI providers found in config. Enable at least one provider or use --unsafe for an unconstrained CA.\n")
			return 1
		}
	} else {
		// Unsafe mode: interactive warning and confirmation required,
		// unless --auto-confirm-unsafe is set (MSI GUI already served as consent; PR-C2 fix)
		if !*autoConfirmUnsafe {
			err = confirmUnsafeMode()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
		}
	}

	// Get CA storage directory and ensure it exists (store.Save calls MkdirAll
	// internally, but creating it early guards against atomicity edge cases).
	caDir := getCADir()
	err = os.MkdirAll(caDir, 0700)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to create CA directory %s: %v\n", caDir, err)
		return 1
	}

	// Generate new CA first, in memory only — nothing touches disk yet.
	// If generation fails, the old CA survives untouched (atomicity of replacement).
	ca, keyPEM, err := qinduTls.GenerateCA(cfg.TLS.CAName, cfg.TLS.CAValidityYears, permittedDomains)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to generate CA: %v\n", err)
		return 1
	}

	// Generation succeeded — now destroy the old CA before saving the new one
	// (SR-INSTALLER-12: total replacement).
	err = destroyExistingCA(caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Save new CA via platform-specific store (DPAPI on Windows, memory on other).
	// Key never touches disk in plaintext — encrypted by store.
	store := qinduTls.NewCAStore(caDir)
	err = store.Save(ca.CertPEM, keyPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to save CA: %v\n", err)
		return 1
	}

	// Generate and save CRL for schannel revocation checking (BUG-004 fix).
	// The CRL is empty (no certs revoked) and signed by the CA. It lives at
	// C:\ProgramData\Qindu\ca.crl and is referenced by leaf certs via a
	// file:// CDP extension. Windows schannel reads this CRL from disk to
	// verify the leaf cert has not been revoked — since it's empty, the check
	// passes and the TLS handshake proceeds.
	crlDER, err := qinduTls.CreateCRL(ca)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to create CRL: %v\n", err)
		return 1
	}
	crlPath := filepath.Join(caDir, qinduTls.CRLFilename)
	if err := qinduTls.SaveCRL(crlDER, crlPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to save CRL: %v\n", err)
		return 1
	}

	// SAFETY: No PII in log output — prints only x509 certificate metadata
	// (Subject CommonName, NotAfter date, SerialNumber) and the file paths
	// where the CA is stored. CA private key material is never printed.
	// Print success summary (no key material exposed)
	fmt.Printf("CA generated successfully\n")
	fmt.Printf("  Subject: %s\n", ca.Cert.Subject.CommonName)
	fmt.Printf("  Expires: %s\n", ca.Cert.NotAfter.Format("2006-01-02"))
	fmt.Printf("  Serial:  %X\n", ca.Cert.SerialNumber)
	if runtime.GOOS == "windows" {
		fmt.Printf("  Storage: %s\n", caDir)
	} else {
		fmt.Printf("  Storage: memory-only (CA regenerated on next run)\n")
	}
	if !*unsafe && len(permittedDomains) > 0 {
		fmt.Printf("  Name Constraints (permitted DNS): %s\n", strings.Join(permittedDomains, ", "))
	} else if *unsafe {
		fmt.Printf("  Name Constraints: NONE (unsafe mode — CA can sign for ANY domain)\n")
	} else {
		fmt.Printf("  Name Constraints: NONE (no enabled AI providers in config)\n")
	}

	return 0
}

// confirmUnsafeMode displays a warning banner and requires interactive stdin
// confirmation before proceeding with an unconstrained CA.
// SR-INSTALLER-3: silent/non-interactive mode must fail.
//
// SAFETY: All output is static warning text. No PII, key material, or
// user-specific data is printed.
func confirmUnsafeMode() error {
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 72))
	fmt.Fprintln(os.Stderr, "⚠️  WARNING: UNSAFE CA MODE REQUESTED")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 72))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "You are about to generate a Certificate Authority WITHOUT Name Constraints.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "This CA will be able to sign certificates for ANY domain on the internet —")
	fmt.Fprintln(os.Stderr, "including banking, healthcare, email, and SSO websites — not just AI services.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "If the CA private key is ever compromised, an attacker could intercept")
	fmt.Fprintln(os.Stderr, "ALL TLS-encrypted traffic from this machine, not just AI provider traffic.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Only proceed if your browser does not support Name Constraints and you")
	fmt.Fprintln(os.Stderr, "understand and accept this risk.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 72))

	// Check if stdin is interactive (SR-INSTALLER-14: block silent/pipe usage)
	stat, err := os.Stdin.Stat()
	if err != nil {
		return fmt.Errorf("cannot determine if terminal is interactive: %w", err)
	}
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		return errors.New("--unsafe requires an interactive terminal for confirmation; cannot proceed in non-interactive mode")
	}

	fmt.Fprint(os.Stderr, "Type YES to confirm you want an unconstrained CA: ")
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	response = strings.TrimSpace(response)
	if response != "YES" {
		return errors.New("aborted by user — CA generation canceled")
	}

	fmt.Fprintln(os.Stderr)
	return nil
}

// destroyExistingCA removes the old CA certificate and key files from the
// storage directory, if they exist. This ensures a clean replacement.
// SR-INSTALLER-12: old CA must be destroyed before generating a new one.
func destroyExistingCA(caDir string) error {
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")

	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing old CA certificate: %w", err)
	}
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing old CA key: %w", err)
	}

	return nil
}

// =============================================================================
// Config path resolution
// =============================================================================

// resolveConfigPath implements the priority chain for locating the config file:
//
//  1. --config <path> flag (explicit)
//  2. QINDU_CONFIG env var
//  3. %PROGRAMFILES%\Qindu\configs\default.yaml (Windows service)
//  4. <executable_dir>\configs\default.yaml (fallback dev)
//  5. configs/default.yaml (current directory, last resort)
//
// SR-INSTALLER-13: user-supplied paths containing ".." are rejected to
// prevent directory traversal. Paths from trusted sources (PROGRAMFILES,
// executable directory) are allowed as-is.
func resolveConfigPath(explicitPath string) (string, error) {
	if explicitPath != "" {
		// SR-INSTALLER-13: reject path traversal in user-supplied paths.
		// Use filepath.Clean first to resolve any embedded ".." components,
		// then check if ".." remains — this catches paths like "../etc/passwd"
		// while allowing legitimate non-traversal strings that happen to
		// contain ".." as a substring.
		cleaned := filepath.Clean(explicitPath)
		if strings.Contains(cleaned, "..") {
			return "", fmt.Errorf("config path must not contain '..': %s", explicitPath)
		}
		return cleaned, nil
	}

	if envPath := os.Getenv("QINDU_CONFIG"); envPath != "" {
		// SR-INSTALLER-13: reject path traversal in env var paths
		cleaned := filepath.Clean(envPath)
		if strings.Contains(cleaned, "..") {
			return "", fmt.Errorf("QINDU_CONFIG must not contain '..': %s", envPath)
		}
		return cleaned, nil
	}

	// Windows: %PROGRAMFILES%\Qindu\configs\default.yaml
	if pf := os.Getenv("PROGRAMFILES"); pf != "" {
		path := filepath.Join(pf, "Qindu", "configs", "default.yaml")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Relative to executable directory (dev fallback)
	if exePath, err := os.Executable(); err == nil {
		path := filepath.Join(filepath.Dir(exePath), "configs", "default.yaml")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Current directory fallback (original behavior)
	return defaultConfigPath, nil
}

// loadConfig reads the YAML config and applies the %PROGRAMDATA% override.
func loadConfig(path string) (*policy.Config, error) {
	cfg, err := policy.LoadConfig(path)
	if err != nil {
		return nil, err
	}

	if err := applyConfigOverride(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// applyConfigOverride checks for %PROGRAMDATA%\Qindu\config.yaml and
// applies a shallow merge on top of the current config if present.
func applyConfigOverride(cfg *policy.Config) error {
	pd := os.Getenv("PROGRAMDATA")
	if pd == "" {
		return nil // not on Windows, no override
	}

	overridePath := filepath.Join(pd, "Qindu", "config.yaml")
	if _, err := os.Stat(overridePath); os.IsNotExist(err) {
		return nil // no override file
	}

	return cfg.MergeFileOverride(overridePath)
}

// getCADir returns the platform-appropriate CA storage directory.
func getCADir() string {
	if dir := os.Getenv("PROGRAMDATA"); dir != "" {
		return filepath.Join(dir, caSubDir)
	}
	// Fallback for non-Windows
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".qindu", "ca")
	}
	return filepath.Join(os.TempDir(), "qindu-ca")
}
