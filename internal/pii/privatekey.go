package pii

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// privateKeyHeaders maps PEM armor headers to their confidence scores.
// Detects RSA, EC, DSA, OpenSSH, PGP, and PKCS#8 private keys.
var privateKeyHeaders = map[string]float64{
	"RSA PRIVATE KEY":       0.95,
	"EC PRIVATE KEY":        0.95,
	"DSA PRIVATE KEY":       0.95,
	"OPENSSH PRIVATE KEY":   0.95,
	"PGP PRIVATE KEY BLOCK": 0.95,
	"ENCRYPTED PRIVATE KEY": 0.90,
	"PRIVATE KEY":           0.90,
}

// pemBeginPattern matches PEM header lines.
var pemBeginRe = regexp.MustCompile(`-----BEGIN ([A-Z][A-Z ]+)-----`)

// PrivateKeyRecognizer detects PEM/SSH/PGP private key armor blocks.
type PrivateKeyRecognizer struct{}

// NewPrivateKeyRecognizer creates a new PRIVATE_KEY recognizer.
func NewPrivateKeyRecognizer() *PrivateKeyRecognizer {
	return &PrivateKeyRecognizer{}
}

// Type returns PRIVATE_KEY.
func (r *PrivateKeyRecognizer) Type() EntityType {
	return PrivateKey
}

// Detect finds private key PEM blocks in the given text.
// It detects multi-line PEM armor blocks: header + body + footer.
func (r *PrivateKeyRecognizer) Detect(text string) []Entity {
	var entities []Entity

	// Find all BEGIN markers.
	beginMatches := pemBeginRe.FindAllStringSubmatchIndex(text, -1)
	if len(beginMatches) == 0 {
		return nil
	}

	for _, beginGroup := range beginMatches {
		// beginGroup indices (always len ≥ 4 for this regex):
		// [0], [1] = full match span
		// [2], [3] = capture group (key type name)
		beginStart := beginGroup[0]
		beginEnd := beginGroup[1] // Full BEGIN header end position.
		keyType := text[beginGroup[2]:beginGroup[3]]

		// Check if this is a known private key type.
		confidence, ok := privateKeyHeaders[keyType]
		if !ok {
			continue
		}

		// Find the matching END marker after this BEGIN.
		endPattern := "-----END " + keyType + "-----"
		endIdx := strings.Index(text[beginStart:], endPattern)
		if endIdx < 0 {
			continue
		}
		endStart := beginStart + endIdx
		endEnd := endStart + len(endPattern)

		// Extract the body between header and footer.
		// Find the newline after the BEGIN line.
		beginLineEnd := strings.IndexByte(text[beginStart:], '\n')
		var bodyStart int
		if beginLineEnd < 0 {
			// No newline found — body starts right after the BEGIN header.
			// beginEnd points to the character after "-----".
			bodyStart = beginEnd
		} else {
			bodyStart = beginStart + beginLineEnd + 1
		}

		// Find the trailing newline before the END line (if any).
		bodyEnd := endStart
		if bodyEnd > bodyStart && text[bodyEnd-1] == '\n' {
			bodyEnd--
		}

		body := text[bodyStart:bodyEnd]
		body = strings.TrimSpace(body)
		body = strings.ReplaceAll(body, "\n", "")
		body = strings.ReplaceAll(body, "\r", "")

		// Validate body: must be valid base64 and ≥ 40 chars after trim.
		if len(body) < 40 {
			confidence = 0.70 // Header found but body too short.
		} else {
			// Check if body is valid base64.
			if !isValidPEMBase64(body) {
				confidence = 0.70
			}
		}

		// Emit the entire block (header through footer) as one entity.
		block := text[beginStart:endEnd]
		entities = append(entities, Entity{
			Type:       PrivateKey,
			Value:      block,
			Confidence: confidence,
			Source:     SourcePEMArmor,
			Start:      beginStart,
			End:        endEnd,
		})
	}

	if len(entities) == 0 {
		return nil
	}
	return entities
}

// isValidPEMBase64 checks if a string is valid base64 (PEM encoding).
// PEM uses standard base64 (not base64url).
func isValidPEMBase64(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Add padding if needed.
	padded := s
	mod := len(padded) % 4
	if mod > 0 {
		padded += strings.Repeat("=", 4-mod)
	}
	_, err := base64.StdEncoding.DecodeString(padded)
	return err == nil
}
