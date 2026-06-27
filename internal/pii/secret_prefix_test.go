package pii

import (
	"testing"
)

func TestSecretPrefixRecognizerType(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	if r.Type() != Secret {
		t.Errorf("expected SECRET type, got %s", r.Type())
	}
}

func TestSecretPrefixRecognizerOpenAI(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// Synthetic test key with obviously fake suffix (alphanumeric only for generic sk-).
	tests := []string{
		"sk-" + stringsRepeat("A", 32),                      // Generic sk-
		"sk-proj-testprojkey1234567890abcdefghijklmnopqrst", // sk-proj-
		"sk-svcacct-testsvcacctkeyabcdefghijklmnopqrstuvwx", // sk-svcacct-
		"sk-admin-testadminkeyabcdefghijklmnopqrstuvwxyz12", // sk-admin-
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 1 {
			t.Errorf("expected 1 entity for %q, got %d", input, len(entities))
		}
		if len(entities) > 0 && entities[0].Type != Secret {
			t.Errorf("expected SECRET type, got %s", entities[0].Type)
		}
	}
}

func TestSecretPrefixRecognizerAnthropic(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// Synthetic Anthropic key.
	input := "sk-ant-api03-" + stringsRepeat("A", 95) + "AA"
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Errorf("expected 1 Anthropic key, got %d", len(entities))
	}
}

func TestSecretPrefixRecognizerGitHub(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	tests := []string{
		"ghp_" + stringsRepeat("A", 36),
		"gho_" + stringsRepeat("a", 36),
		"github_pat_" + stringsRepeat("X", 30),
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 1 {
			t.Errorf("expected 1 GitHub key for prefix in %q, got %d", input, len(entities))
		}
	}
}

func TestSecretPrefixRecognizerAWS(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	tests := []string{
		"AKIA" + stringsRepeat("A", 16),
		"ASIA" + stringsRepeat("B", 16),
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 1 {
			t.Errorf("expected 1 AWS key for %q, got %d", input, len(entities))
		}
	}
}

func TestSecretPrefixRecognizerHuggingFace(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	input := "hf_" + stringsRepeat("x", 34)
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Errorf("expected 1 HuggingFace key, got %d", len(entities))
	}
}

func TestSecretPrefixRecognizerSlack(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	input := "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwxyz"
	entities := r.Detect(input)
	if len(entities) < 1 {
		t.Errorf("expected Slack bot token, got %d", len(entities))
	}
}

func TestSecretPrefixRecognizerStripe(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	input := "sk_live_" + stringsRepeat("a", 30)
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Errorf("expected 1 Stripe key, got %d", len(entities))
	}
}

func TestSecretPrefixRecognizerLongestPrefixFirst(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// "sk-proj-" should match before "sk-" (longest prefix first).
	input := "sk-proj-testkey1234567890abcdefghijklmnopqrstuvwxyz"
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
	// Should be the longer match (sk-proj-), so confidence should be 0.85.
	if entities[0].Confidence < 0.84 {
		t.Errorf("longest prefix match should have 0.85 confidence, got %f", entities[0].Confidence)
	}
}

func TestSecretPrefixRecognizerGenericSkLowerConfidence(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// Generic "sk-" without sub-prefix should get 0.70 confidence.
	input := "sk-" + stringsRepeat("a", 32)
	entities := r.Detect(input)
	if len(entities) < 1 {
		t.Fatalf("expected 1 entity for generic sk-, got %d", len(entities))
	}
	hasGeneric := false
	for _, e := range entities {
		if e.Confidence < 0.75 {
			hasGeneric = true
		}
	}
	if !hasGeneric {
		t.Error("expected generic sk- to have lower confidence")
	}
}

func TestSecretPrefixRecognizerInvalid(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	tests := []string{
		"",
		"not a secret",
		"sk", // Too short (min prefix is 1 for "T" but needs full match).
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 0 {
			t.Errorf("expected 0 entities for %q, got %d", input, len(entities))
		}
	}
}

func TestSecretPrefixRecognizerEmptyText(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	entities := r.Detect("")
	if entities != nil {
		t.Errorf("expected nil for empty input, got %v", entities)
	}
}

func TestSecretPrefixRecognizerShortText(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// Text shorter than minimum prefix length.
	entities := r.Detect("ab")
	if entities != nil {
		t.Errorf("expected nil for very short text, got %v", entities)
	}
}

func TestSecretPrefixRecognizerSpanValidation(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	text := "api key: " + "sk-" + stringsRepeat("A", 32)
	entities := r.Detect(text)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
	e := entities[0]
	if e.Start < 9 || e.End > len(text) {
		t.Errorf("invalid span: [%d, %d)", e.Start, e.End)
	}
}

func TestSecretPrefixRecognizerDatabaseURLs(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	tests := []string{
		"postgresql://user:password@localhost:5432/db",
		"mysql://root:secret@localhost:3306/mydb",
		"mongodb+srv://admin:pass123@cluster.example.com",
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) < 1 {
			t.Errorf("expected at least 1 entity for %q, got %d", input, len(entities))
		}
	}
}

func TestIsURLContext(t *testing.T) {
	if !isURLContext("https://api.example.com?token=sk-live-abc", 41) {
		t.Error("should detect URL context near token")
	}
	if isURLContext("just a sk-test-key", 7) {
		t.Error("should not detect URL context in plain text")
	}
}

func TestSecretPrefixRecognizerURLExclusion(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// A prefix match within a URL context should be excluded by isURLContext.
	// The "sk-" token appears after "https://" so it should be skipped.
	input := "https://api.example.com?api_key=sk-test-1234567890abcdef1234567890abcdefgh"
	entities := r.Detect(input)
	for _, e := range entities {
		if e.Start != -1 {
			t.Errorf("URL context token should be excluded, got entity at [%d, %d): %s",
				e.Start, e.End, e.SafeString())
		}
	}
}

func TestSecretPrefixRecognizerRegexNonMatch(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// A prefix "sk-" is found but the following characters don't satisfy
	// the regex (need >= 32 alphanumeric chars after "sk-").
	// "sk-short" has only 5 chars after prefix → regex won't match.
	// This covers the "continue" after regex non-match.
	entities := r.Detect("my sk-short token here")
	if len(entities) != 0 {
		t.Errorf("short prefix match should not produce entity, got %d", len(entities))
	}
}

func TestSecretPrefixRecognizerDedup(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// Text contains the same GitHub token twice. Each instance has a different
	// span, but we want to verify the seen map works correctly.
	input := "ghp_" + stringsRepeat("A", 36) + " and again ghp_" + stringsRepeat("B", 36)
	entities := r.Detect(input)
	if len(entities) != 2 {
		t.Errorf("expected 2 distinct GitHub tokens, got %d", len(entities))
	}
}

func TestSecretPrefixRecognizerTwilio(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// Twilio AC and SK prefixes.
	input := "Twilio sid: AC" + stringsRepeat("a", 32)
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Errorf("expected 1 Twilio AC token, got %d", len(entities))
	}
}

func TestSecretPrefixRecognizerMailgun(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// Mailgun key- prefix.
	input := "key-" + stringsRepeat("a", 32)
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Errorf("expected 1 Mailgun token, got %d", len(entities))
	}
}

func TestSecretPrefixRecognizerGoogleAPI(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// Google API key (AIza prefix).
	input := "AIza" + stringsRepeat("a", 35)
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Errorf("expected 1 Google API key, got %d", len(entities))
	}
}

// TestSecretPrefixRecognizerURLExclusionDetect covers the isURLContext continue
// branch in the Detect loop. The prefix match occurs after an https:// scheme
// within 2000 chars, so isURLContext returns true and the entity is skipped.
func TestSecretPrefixRecognizerURLExclusionDetect(t *testing.T) {
	r := NewSecretPrefixRecognizer()
	// "sk-" prefix appears after "https://", regex matches the 32 A chars.
	input := "https://api.example.com?key=sk-" + stringsRepeat("A", 32)
	entities := r.Detect(input)
	// The sk- token is in a URL context, so it should be excluded.
	if len(entities) != 0 {
		t.Errorf("URL context sk- token should be excluded, got %d entities", len(entities))
	}
}
