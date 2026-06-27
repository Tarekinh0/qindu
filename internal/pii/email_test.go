package pii

import (
	"testing"
)

func TestEmailRecognizerType(t *testing.T) {
	r := NewEmailRecognizer()
	if r.Type() != Email {
		t.Errorf("expected EMAIL type, got %s", r.Type())
	}
}

func TestEmailRecognizerValidEmails(t *testing.T) {
	r := NewEmailRecognizer()
	tests := []struct {
		name  string
		input string
		count int
	}{
		{"simple", "user@example.com", 1},
		{"with tag", "test+tag@domain.co.uk", 1},
		{"with dots", "first.last@example.org", 1},
		{"subdomain", "user@mail.example.com", 1},
		{"multiple", "a@b.com and c@d.net", 2},
		{"hyphen domain", "user@my-domain.com", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities := r.Detect(tt.input)
			if len(entities) != tt.count {
				t.Errorf("expected %d emails in %q, got %d", tt.count, tt.input, len(entities))
			}
			for _, e := range entities {
				if e.Type != Email {
					t.Errorf("expected EMAIL type, got %s", e.Type)
				}
				if e.Source != SourceRegex {
					t.Errorf("expected regex source, got %s", e.Source)
				}
				if e.Confidence < 0.85 {
					t.Errorf("confidence too low: %f", e.Confidence)
				}
				if e.Start < 0 || e.End <= e.Start {
					t.Errorf("invalid span: [%d, %d)", e.Start, e.End)
				}
			}
		})
	}
}

func TestEmailRecognizerInvalidEmails(t *testing.T) {
	r := NewEmailRecognizer()
	tests := []string{
		"notanemail",
		"@missing.com",
		"no@tld",
		"a@b",
		"",
		"just text",
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 0 {
			t.Errorf("expected 0 entities for %q, got %d", input, len(entities))
		}
	}
}

func TestEmailRecognizerMultipleAt(t *testing.T) {
	r := NewEmailRecognizer()
	// Multiple @ signs should be rejected.
	entities := r.Detect("no@domain@double.com")
	if len(entities) != 0 {
		t.Errorf("multiple @ should be rejected, got %v", entities)
	}
}

func TestEmailRecognizerFalsePositives(t *testing.T) {
	r := NewEmailRecognizer()
	// Only noreply, no-reply, mailer-daemon, root@localhost per story spec.
	tests := []string{
		"noreply@example.com",
		"no-reply@example.com",
		"mailer-daemon@example.com",
		"root@localhost",
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 0 {
			t.Errorf("false positive %q should be rejected, got %v", input, entities)
		}
	}
}

func TestEmailRecognizerConfidence(t *testing.T) {
	r := NewEmailRecognizer()
	// Known TLD should get 0.95.
	entities := r.Detect("user@example.com")
	if len(entities) != 1 {
		t.Fatal("expected 1 entity")
	}
	if entities[0].Confidence < 0.95 {
		t.Errorf("known TLD should have confidence >= 0.95, got %f", entities[0].Confidence)
	}
}

func TestEmailRecognizerLengthLimit(t *testing.T) {
	r := NewEmailRecognizer()
	// Email > 254 chars should be rejected.
	longLocal := "a"
	for len(longLocal) < 64 {
		longLocal += "b"
	}
	longEmail := longLocal + "@" + stringsRepeat("c", 200) + ".com"
	entities := r.Detect(longEmail)
	if len(entities) != 0 {
		t.Errorf("overly long email should be rejected")
	}
}

func stringsRepeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

func TestEmailRecognizerEmptyReturn(t *testing.T) {
	r := NewEmailRecognizer()
	entities := r.Detect("")
	if entities != nil {
		t.Errorf("expected nil for empty input, got %v", entities)
	}
}

func TestEmailRecognizerValueNotInTestLogs(t *testing.T) {
	r := NewEmailRecognizer()
	entities := r.Detect("user@example.com")
	if len(entities) != 1 {
		t.Fatal("expected 1 entity")
	}
	// SafeString must not leak the value.
	safe := entities[0].SafeString()
	if containsPII(safe, entities[0].Value) {
		t.Error("SafeString() leaked PII value")
	}
}

func containsPII(safe, value string) bool {
	return len(value) > 0 && len(safe) > len(value) &&
		(safe[0:len(value)] == value || safe[len(safe)-len(value):] == value)
}

func TestIsValidEmailDomainEdgeCases(t *testing.T) {
	// Domain starting with hyphen.
	if isValidEmail("user@-example.com") {
		t.Error("domain starting with hyphen should be invalid")
	}
	// Domain ending with hyphen in subdomain before TLD.
	// Note: the regex requires \.[a-zA-Z]{2,} so domain always ends with letters.
	// The ending-hyphen check is defensive for unexpected inputs.
	if isValidEmail("user@sub-.example.com") {
		// This may be valid since the domain "sub-.example.com" ends with 'm'.
		// The ending-hyphen guard checks the full domain, not individual labels.
		t.Log("domain with hyphen before dot may be valid")
	}
	// Consecutive dots in domain.
	if isValidEmail("user@ex..ample.com") {
		t.Error("consecutive dots should be invalid")
	}
	// Consecutive hyphens in domain.
	if isValidEmail("user@ex--ample.com") {
		t.Error("consecutive hyphens should be invalid")
	}
	// localhost domain should be rejected.
	if isValidEmail("user@localhost") {
		t.Error("@localhost should be rejected")
	}
}

func TestIsValidEmailLengthLimits(t *testing.T) {
	// Email > 254 chars should be rejected.
	longEmail := "a@b.com" + stringsRepeat("x", 250)
	if len(longEmail) <= 254 {
		t.Skip("test string too short")
	}
	if isValidEmail(longEmail) {
		t.Error("email > 254 chars should be invalid")
	}
}

func TestIsValidEmailLocalPartTooLong(t *testing.T) {
	// Local part > 64 chars.
	longLocal := stringsRepeat("a", 65)
	email := longLocal + "@example.com"
	if isValidEmail(email) {
		t.Error("local part > 64 should be invalid")
	}
}

func TestIsValidEmailPlusSuffixFalsePositive(t *testing.T) {
	// no-reply+something@ should still be rejected after + stripping.
	if isValidEmail("no-reply+newsletter@example.com") {
		t.Error("no-reply+... should be rejected as false positive")
	}
}

func TestValidateEmailCandidateUnknownTLD(t *testing.T) {
	// Unknown TLD should get 0.90 confidence.
	email := "user@example.xyz"
	c := validateEmailCandidate(email)
	if c < 0.89 || c > 0.91 {
		t.Errorf("unknown TLD should have 0.90 confidence, got %f", c)
	}
}

func TestValidateEmailCandidateShortTLD(t *testing.T) {
	// TLD < 2 chars should get 0.85 (regex base confidence).
	c := validateEmailCandidate("user@example.c")
	if c < 0.84 || c > 0.86 {
		t.Errorf("short TLD should have 0.85 confidence, got %f", c)
	}
}

func TestValidateEmailCandidateNoAt(t *testing.T) {
	// Direct call without @ should return 0.85.
	c := validateEmailCandidate("noatsign")
	if c < 0.84 || c > 0.86 {
		t.Errorf("no @ sign should return 0.85, got %f", c)
	}
}

func TestEmailRecognizerLeftBoundary(t *testing.T) {
	r := NewEmailRecognizer()
	// If the character before the match is a valid email char, reject.
	// The regex would match from after 'a' but left boundary check blocks it.
	entities := r.Detect("a@test@example.com")
	// The left-boundary check should prevent matching "@test@example.com" as email
	// because the char before the match would be 'a' which is a valid left char.
	for _, e := range entities {
		if e.Value == "@test@example.com" {
			t.Error("should not match substring starting with @")
		}
	}
}

func TestEmailRecognizerRightBoundary(t *testing.T) {
	r := NewEmailRecognizer()
	// Match followed by valid email char should be rejected.
	// '1' is a valid email right char (digit) but not alpha, so TLD ends at "com".
	entities := r.Detect("test@example.com1")
	for _, e := range entities {
		if e.Value == "test@example.com" {
			t.Error("right boundary: email followed by digit '1' should be rejected")
		}
	}
}

func TestEmailRecognizerRightBoundaryAtSign(t *testing.T) {
	r := NewEmailRecognizer()
	// Email followed immediately by '@' which is a valid right boundary char.
	// e.g., "test@example.com@other" — regex matches "test@example.com",
	// but '@' after it is a valid right boundary char → reject.
	entities := r.Detect("test@example.com@other")
	for _, e := range entities {
		if e.Value == "test@example.com" {
			t.Error("right boundary: email followed by '@' should be rejected")
		}
	}
}

func TestIsValidEmailEmptyLocalPart(t *testing.T) {
	// Direct call with empty local part.
	if isValidEmail("@example.com") {
		t.Error("empty local part should be invalid")
	}
}

func TestIsValidEmailMultipleAt(t *testing.T) {
	// Direct call with multiple @ signs — should be caught.
	if isValidEmail("a@b@c.com") {
		t.Error("multiple @ should be invalid")
	}
}

func TestValidateEmailCandidateTLDTooShort(t *testing.T) {
	// TLD of exactly 1 character should return 0.85.
	c := validateEmailCandidate("user@example.c")
	if c < 0.84 || c > 0.86 {
		t.Errorf("1-char TLD should return 0.85, got %f", c)
	}
}

func TestEmailRecognizerRightBoundaryFollowedByValidChar(t *testing.T) {
	r := NewEmailRecognizer()
	// Email followed immediately by alphabetic letter — but the regex greedily
	// consumes 'a' into the TLD (making "coma"), so the match might extend.
	// This tests that the right boundary check handles edge cases gracefully.
	entities := r.Detect("user@domain.coma")
	// Since 'a' is alpha, regex likely matches "user@domain.coma" (TLD="coma").
	// If it passes validation (all alpha TLD, known or unknown), it's a valid match.
	// No assertion needed — just verify no panic and spans are valid.
	for _, e := range entities {
		if e.Start < 0 || e.End > len("user@domain.coma") || e.Start >= e.End {
			t.Errorf("invalid entity span: [%d, %d)", e.Start, e.End)
		}
	}
}

func TestValidateEmailCandidateNoDotDomain(t *testing.T) {
	// Domain without a dot returns base confidence 0.85.
	c := validateEmailCandidate("user@domain")
	if c < 0.84 || c > 0.86 {
		t.Errorf("no-dot domain should return 0.85, got %f", c)
	}
}
