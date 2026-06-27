// Package pii implements a local, in-memory PII detection engine.
// All processing is local with zero network, zero filesystem, zero persistence.
package pii

import "fmt"

// EntityType identifies the kind of PII detected.
type EntityType string

const (
	Email      EntityType = "EMAIL"
	Phone      EntityType = "PHONE"
	IBAN       EntityType = "IBAN"
	CreditCard EntityType = "CREDIT_CARD"
	JWT        EntityType = "JWT"
	Name       EntityType = "NAME"
	Secret     EntityType = "SECRET"
	PrivateKey EntityType = "PRIVATE_KEY"
)

// SourceKind tags how the entity was detected (provenance).
// Enables granular tokenization policy in QINDU-0006.
type SourceKind string

const (
	SourceRegex          SourceKind = "regex"
	SourceLuhn           SourceKind = "luhn"
	SourceMod97          SourceKind = "mod97"
	SourceStructural     SourceKind = "structural"
	SourceEmailInference SourceKind = "email_inference"
	SourcePrefix         SourceKind = "prefix"
	SourceEntropy        SourceKind = "entropy"
	SourcePEMArmor       SourceKind = "pem_armor"
)

// Entity represents a detected PII instance with position and metadata.
//
// CRITICAL: The Value field contains actual PII. It must NEVER be logged,
// printed, or included in error messages. Use SafeString() for any output.
type Entity struct {
	Value      string     `json:"-"` // PII value - MUST NEVER BE LOGGED
	Type       EntityType `json:"type"`
	Source     SourceKind `json:"source"`
	Confidence float64    `json:"confidence"`
	Start      int        `json:"start"` // Byte offset in original text
	End        int        `json:"end"`   // Byte offset (exclusive)
}

// SafeString returns a redacted representation of the entity suitable for
// logging and debugging. It never includes the Value field.
//
// Format: "TYPE(src=source, conf=0.XX, pos=start-end)"
func (e Entity) SafeString() string {
	return fmt.Sprintf("%s(src=%s, conf=%.2f, pos=%d-%d)",
		e.Type, e.Source, e.Confidence, e.Start, e.End)
}

// String returns SafeString() — this ensures that even accidental use of
// fmt.Sprintf("%s", entity) or fmt.Println(entity) never leaks PII.
func (e Entity) String() string {
	return e.SafeString()
}
