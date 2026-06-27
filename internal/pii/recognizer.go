package pii

// Recognizer is the interface each detector implements.
// Each recognizer is responsible for one entity type.
//
// Implementations must be:
//   - Stateless: no mutable shared state between calls
//   - Safe for concurrent use: compiled regexes (*regexp.Regexp) are immutable
//     after construction and safe for concurrent reads
//   - Panic-free: Detect must return nil or empty slice on any input, never panic
type Recognizer interface {
	// Detect scans text and returns all detected entities of its type.
	// Returns nil or empty slice if nothing found.
	// Must never panic; all errors are returned as empty results.
	Detect(text string) []Entity

	// Type returns the entity type this recognizer detects.
	Type() EntityType
}

// EmailAwareRecognizer is an optional interface for recognizers that need
// access to previously detected EMAIL entities (e.g., NAME from email).
//
// The Engine checks if a recognizer implements this interface and calls
// DetectWithEmails after EMAIL detection is complete.
type EmailAwareRecognizer interface {
	Recognizer

	// DetectWithEmails scans text using the provided EMAIL entities as
	// triggers. Returns all detected entities of its type.
	DetectWithEmails(text string, emails []Entity) []Entity
}
