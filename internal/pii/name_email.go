package pii

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// nameStopWords is a set of local-part values that should NOT trigger NAME
// inference. These are role accounts, not personal names.
//
// Purpose: prevent role accounts (support@, noreply@) from generating
// false NAME entities per DPO condition 7.1.
var nameStopWords = map[string]bool{
	"support":       true,
	"noreply":       true,
	"no-reply":      true,
	"info":          true,
	"contact":       true,
	"admin":         true,
	"help":          true,
	"sales":         true,
	"hello":         true,
	"team":          true,
	"service":       true,
	"office":        true,
	"billing":       true,
	"abuse":         true,
	"postmaster":    true,
	"webmaster":     true,
	"hostmaster":    true,
	"mail":          true,
	"news":          true,
	"newsletter":    true,
	"root":          true,
	"test":          true,
	"demo":          true,
	"sample":        true,
	"notifications": true,
}

// NameFromEmailRecognizer infers NAME entities from previously detected
// EMAIL entities by extracting and processing the local-part.
//
// It implements both Recognizer and EmailAwareRecognizer.
type NameFromEmailRecognizer struct{}

// NewNameFromEmailRecognizer creates a new NAME-from-email recognizer.
func NewNameFromEmailRecognizer() *NameFromEmailRecognizer {
	return &NameFromEmailRecognizer{}
}

// Type returns NAME.
func (r *NameFromEmailRecognizer) Type() EntityType {
	return Name
}

// Detect returns nil — the NAME recognizer requires EMAIL entities.
// Use DetectWithEmails instead.
func (r *NameFromEmailRecognizer) Detect(text string) []Entity {
	return nil
}

// DetectWithEmails scans the provided EMAIL entities and infers NAME entities
// from their local-parts.
func (r *NameFromEmailRecognizer) DetectWithEmails(text string, emails []Entity) []Entity {
	if len(emails) == 0 {
		return nil
	}

	var entities []Entity
	for _, emailEntity := range emails {
		if emailEntity.Type != Email {
			continue
		}
		email := emailEntity.Value
		atIdx := strings.IndexByte(email, '@')
		if atIdx <= 0 {
			continue
		}
		localPart := email[:atIdx]

		name, confidence := inferNameFromLocalPart(localPart)
		if name == "" {
			continue
		}

		// NAME entity is co-located with the source EMAIL entity.
		entities = append(entities, Entity{
			Type:       Name,
			Value:      name,
			Confidence: confidence,
			Source:     SourceEmailInference,
			Start:      emailEntity.Start,
			End:        emailEntity.End,
		})
	}

	if len(entities) == 0 {
		return nil
	}
	return entities
}

// inferNameFromLocalPart attempts to extract a person name from an email
// local-part. Returns the inferred name and confidence, or empty string if
// inference is not possible.
func inferNameFromLocalPart(localPart string) (string, float64) {
	// Strip +suffix (Gmail-style aliasing).
	if plusIdx := strings.IndexByte(localPart, '+'); plusIdx >= 0 {
		localPart = localPart[:plusIdx]
	}

	// Normalize case.
	localLower := strings.ToLower(localPart)

	// Check stop words on the full local part (case-insensitive).
	if nameStopWords[localLower] {
		return "", 0
	}

	// Split on '.' or '_'.
	var parts []string
	if dotIdx := strings.IndexByte(localPart, '.'); dotIdx >= 0 {
		_ = dotIdx
		parts = strings.Split(localPart, ".")
	} else if usIdx := strings.IndexByte(localPart, '_'); usIdx >= 0 {
		_ = usIdx
		parts = strings.Split(localPart, "_")
	} else {
		// No separator — single segment. Per story spec:
		// "Single segment: blocked" — do not emit NAME for unseparated local-parts.
		return "", 0
	}

	// Process each segment.
	var validParts []string
	allValid := true
	borderline := false
	for _, part := range parts {
		if len(part) == 0 {
			allValid = false
			continue
		}
		if isSingleChar(part) {
			borderline = true
			validParts = append(validParts, titleCase(part))
			continue
		}
		if !isNameSegment(part) {
			allValid = false
			break
		}
		validParts = append(validParts, titleCase(part))
	}

	if !allValid || len(validParts) < 1 {
		return "", 0
	}

	// Confidence based on segment quality.
	confidence := 0.70
	if borderline {
		confidence = 0.55
	}

	return strings.Join(validParts, " "), confidence
}

// isNameSegment checks if a string looks like a name segment:
// - ≥ 2 alpha chars
// - Starts with a letter
// - Not purely numeric
// - Not a stop word
func isNameSegment(s string) bool {
	lower := strings.ToLower(s)

	// Check stop words.
	if nameStopWords[lower] {
		return false
	}

	// Must be ≥ 2 chars.
	if utf8.RuneCountInString(s) < 2 {
		return false
	}

	// Must start with a letter.
	first, _ := utf8.DecodeRuneInString(s)
	if !unicode.IsLetter(first) {
		return false
	}

	// Must not be purely numeric.
	isNumeric := true
	for _, r := range s {
		if r < '0' || r > '9' {
			isNumeric = false
			break
		}
	}
	return !isNumeric
}

// isSingleChar checks if a string is a single character.
func isSingleChar(s string) bool {
	return utf8.RuneCountInString(s) == 1
}

// titleCase converts a string to title case (first letter uppercase, rest lowercase).
func titleCase(s string) string {
	if len(s) == 0 {
		return s
	}
	lower := strings.ToLower(s)
	first, size := utf8.DecodeRuneInString(lower)
	if first == utf8.RuneError {
		return s
	}
	return string(unicode.ToUpper(first)) + lower[size:]
}
