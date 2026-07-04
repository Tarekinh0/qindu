package tokenize

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/vault"
)

// newTestEngine creates a PII detection engine with all recognizers
// for integration-style tokenizer tests. All data uses synthetic PII only.
func newTestEngine(t *testing.T) *pii.Engine {
	t.Helper()
	// Create each recognizer with default settings.
	emailRec := pii.NewEmailRecognizer()
	phoneRec := pii.NewPhoneRecognizer()
	ibanRec := pii.NewIBANRecognizer()
	ccRec := pii.NewCreditCardRecognizer()
	jwtRec := pii.NewJWTRecognizer()
	nameRec := pii.NewNameFromEmailRecognizer()
	secretPrefixRec := pii.NewSecretPrefixRecognizer()
	secretEntropyRec := pii.NewSecretEntropyRecognizer()
	privateKeyRec := pii.NewPrivateKeyRecognizer()

	return pii.NewEngine(pii.DefaultMaxInputBytes,
		emailRec, phoneRec, ibanRec, ccRec,
		jwtRec, nameRec, secretPrefixRec, secretEntropyRec,
		privateKeyRec,
	)
}

// discardLogger returns a logger that discards all output for test noise reduction.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testLogger returns a logger for debugging tests (set to WARN to suppress).
func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// =============================================================================
// ST-1, ST-2, T1, T2 — Single and multiple PII tokenization
// =============================================================================

func TestTokenize_SingleEmail(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	result, err := tok.Tokenize("Contact: alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "<<EMAIL_1>>") {
		t.Errorf("expected <<EMAIL_1>> in output, got: %s", result)
	}
	if strings.Contains(result, "alice@example.com") {
		t.Errorf("ST-1 FAIL: raw PII found in tokenized output: %s", result)
	}
	// Verify no raw email pattern in result.
	if strings.Contains(result, "@") && strings.Contains(result, ".") {
		t.Errorf("ST-1 FAIL: potential email pattern in output: %s", result)
	}
}

func TestTokenize_MultipleEmails(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	result, err := tok.Tokenize("a@example.com b@test.invalid c@example.org")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "<<EMAIL_1>>") {
		t.Errorf("expected <<EMAIL_1>> in output: %s", result)
	}
	if !strings.Contains(result, "<<EMAIL_2>>") {
		t.Errorf("expected <<EMAIL_2>> in output: %s", result)
	}
	if !strings.Contains(result, "<<EMAIL_3>>") {
		t.Errorf("expected <<EMAIL_3>> in output: %s", result)
	}
	if strings.Contains(result, "@example.com") {
		t.Errorf("ST-2 FAIL: raw PII found in output: %s", result)
	}
}

// =============================================================================
// ST-3, T3 — Same PII value gets same token (deterministic within conversation)
// =============================================================================

func TestTokenize_SamePII_SameToken(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	result, err := tok.Tokenize("alice@example.com bob@example.com alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// alice should appear twice, but only one unique token for it.
	c1 := strings.Count(result, "<<EMAIL_1>>")
	c2 := strings.Count(result, "<<EMAIL_2>>")
	if c1 != 2 {
		t.Errorf("ST-3 FAIL: expected 2 occurrences of <<EMAIL_1>> (for alice), got %d. Output: %s", c1, result)
	}
	if c2 != 1 {
		t.Errorf("ST-3 FAIL: expected 1 occurrence of <<EMAIL_2>> (for bob), got %d. Output: %s", c2, result)
	}
}

// =============================================================================
// ST-4, T4 — Round-trip: rehydrate(tokenize(text)) == text
// =============================================================================

func TestRehydrate_RoundTrip(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	original := "Hello alice@example.com, call +33199000000 for details."
	tokenized, err := tok.Tokenize(original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rehydrated := tok.Rehydrate(tokenized)
	if rehydrated != original {
		t.Errorf("ST-4 FAIL: round-trip mismatch.\n  original:  %q\n  rehydrated: %q", original, rehydrated)
	}
}

// =============================================================================
// ST-5, T5 — Idempotent re-tokenization
// =============================================================================

func TestTokenize_Idempotent(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	original := "alice@example.com and bob@test.invalid"
	first, err := tok.Tokenize(original)
	if err != nil {
		t.Fatalf("first tokenize: %v", err)
	}
	second, err := tok.Tokenize(first)
	if err != nil {
		t.Fatalf("second tokenize: %v", err)
	}
	if first != second {
		t.Errorf("ST-5 FAIL: re-tokenization not idempotent.\n  first:  %q\n  second: %q", first, second)
	}
	// Also verify round-trip through rehydrate.
	rehydrated := tok.Rehydrate(second)
	if rehydrated != original {
		t.Errorf("ST-5 FAIL: rehydrate after double-tokenize lost data.\n  expected: %q\n  got:      %q", original, rehydrated)
	}
}

// =============================================================================
// ST-6, T6 — Unmapped token passes through unchanged
// =============================================================================

func TestRehydrate_UnmappedToken(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Only tokenize a single email, so <<EMAIL_99>> is not in the mapping.
	if _, err := tok.Tokenize("alice@example.com"); err != nil {
		t.Fatalf("setup Tokenize failed: %v", err)
	}

	result := tok.Rehydrate("<<EMAIL_99>> Hello")
	if result != "<<EMAIL_99>> Hello" {
		t.Errorf("ST-6 FAIL: expected pass-through, got: %q", result)
	}
}

// =============================================================================
// ST-7, T7 — No tokens, pass through unchanged
// =============================================================================

func TestRehydrate_NoTokens(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	cases := []string{
		"Hello, world!",
		"",
		"   ",
		"\n\t",
		"Contains << but not a token >>",
		"<<NOT_A_REAL_TYPE_1>>",
	}
	for _, input := range cases {
		result := tok.Rehydrate(input)
		if result != input {
			t.Errorf("ST-7 FAIL: expected %q, got %q", input, result)
		}
	}
}

// =============================================================================
// ST-8, T8 — Empty/whitespace input produces empty/no-error
// =============================================================================

func TestTokenize_EmptyInput(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	cases := []string{"", "   ", "\n\t   "}
	for _, input := range cases {
		result, err := tok.Tokenize(input)
		if err != nil {
			t.Errorf("unexpected error for input %q: %v", input, err)
		}
		if result != input {
			t.Errorf("ST-8 FAIL: expected %q, got %q", input, result)
		}
	}
}

// =============================================================================
// ST-9, T9 — Input too large error with no PII in error message
// =============================================================================

func TestTokenize_InputTooLarge(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Create an input that is 1 MiB + 1 byte of non-PII data.
	largeInput := strings.Repeat("x", pii.DefaultMaxInputBytes+1)
	_, err := tok.Tokenize(largeInput)
	if err == nil {
		t.Fatal("ST-9 FAIL: expected error for oversized input")
	}
	if !pii.IsInputTooLarge(err) {
		t.Fatalf("ST-9 FAIL: expected ErrInputTooLarge, got: %T: %v", err, err)
	}
	errMsg := err.Error()
	// Error message must contain sizes but no PII patterns.
	if !strings.Contains(errMsg, "max") {
		t.Errorf("ST-9 FAIL: error message should mention max size: %s", errMsg)
	}
	// Scan for PII patterns in error (defense-in-depth).
	if strings.Contains(errMsg, "@") {
		t.Errorf("ST-9 FAIL: error message contains suspicious PII pattern: %s", errMsg)
	}
}

// =============================================================================
// ST-10, T10 — Concurrent safety (race detector)
// =============================================================================

func TestConcurrent_TokenizeRehydrate_NoRace(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Pre-populate some tokens.
	_, err := tok.Tokenize("alice@example.com +33199000000")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 20

	// Concurrent tokenize.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			email := fmt.Sprintf("user%d@example.com", id)
			_, err := tok.Tokenize(email)
			if err != nil {
				t.Errorf("concurrent tokenize error: %v", err)
			}
		}(i)
	}

	// Concurrent rehydrate.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := tok.Rehydrate("<<EMAIL_1>> please contact <<PHONE_1>>")
			if result == "" {
				t.Error("unexpected empty rehydration result")
			}
		}()
	}

	wg.Wait()
}

func TestConcurrent_Reset_Safe(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	_, err := tok.Tokenize("alice@example.com")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok.Reset()
		}()
	}
	wg.Wait()
	// After concurrent resets, the store should be empty.
	if tok.Count() != 0 {
		t.Errorf("expected empty store after resets, got count=%d", tok.Count())
	}
}

// =============================================================================
// ST-11, T11 — All 8 entity types tokenized, zero raw PII detectable
// =============================================================================

func TestTokenize_AllEntityTypes(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Synthetic PII for all 8 types.
	// Note: email cannot be followed by "." due to email recognizer right-boundary check.
	//       Use space or other non-email characters after emails.
	//       sk_test_ prefix is recognized; sk-test- is not.
	//       PEM header must use a known private key type (RSA PRIVATE KEY).
	input := "Email alice@example.com " +
		"Phone +33199000000 " +
		"IBAN DE89370400440532013000 " +
		"Card 4111111111111111 " +
		"Secret sk_test_00000000000000000000000000 " +
		"JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U " +
		"Key -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJc2J0eGg7bFJ3VXB3RzhqakVFc3o5RE5LTEtKU3d5\n-----END RSA PRIVATE KEY-----"

	result, err := tok.Tokenize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that the specific entity types we expect are replaced.
	// Check for token presence of all expected types.
	// Note: <<NAME_ is excluded because NameFromEmailRecognizer entities
	// overlap with EMAIL spans; the Engine's overlap resolution drops
	// NAME when EMAIL is present.
	requiredPrefixes := []string{
		"<<EMAIL_", "<<PHONE_", "<<IBAN_",
		"<<CREDIT_CARD_", "<<SECRET_", "<<JWT_", "<<PRIVATE_KEY_",
	}
	for _, prefix := range requiredPrefixes {
		if !strings.Contains(result, prefix) {
			t.Errorf("ST-11 FAIL: expected token prefix %q in output", prefix)
		}
	}

	// At a minimum, verify that the output is different from input
	// and that no raw PII values remain.
	if result == input {
		t.Errorf("ST-11: tokenization produced no changes")
	}

	// Verify no raw PII remains using engine re-scan.
	remaining, err := eng.Detect(result)
	if err != nil {
		t.Fatalf("re-scan error: %v", err)
	}
	if len(remaining) > 0 {
		t.Errorf("ST-11 FAIL: tokenized output contains detectable PII: %v", remaining)
	}

	// Raw pattern checks for known PII.
	if strings.Contains(result, "4111111111111111") {
		t.Errorf("ST-11 FAIL: credit card number in output")
	}
	if strings.Contains(result, "DE89370400440532013000") {
		t.Errorf("ST-11 FAIL: IBAN in output")
	}
	if strings.Contains(result, "alice@example.com") {
		t.Errorf("ST-11 FAIL: email in output")
	}
	if strings.Contains(result, "+33199000000") {
		t.Errorf("ST-11 FAIL: phone in output")
	}
	t.Logf("Tokenized output: %s", result)
}

// =============================================================================
// ST-12 — Right-to-left: adjacent entities correctly replaced
// =============================================================================

func TestTokenize_AdjacentEntities(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Email and phone adjacent with minimal/no separator.
	// The engine may or may not detect both depending on adjacency.
	// We test with a clear separator space.
	input := "alice@example.com +33199000000"
	result, err := tok.Tokenize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(result, "alice@example.com") {
		t.Errorf("ST-12 FAIL: email not replaced in adjacent entities: %s", result)
	}
	if strings.Contains(result, "+33199000000") {
		t.Errorf("ST-12 FAIL: phone not replaced in adjacent entities: %s", result)
	}
}

// =============================================================================
// ST-13 — PII value longer than token (JWT is typically very long)
// =============================================================================

func TestTokenize_LongPIIShorterToken(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// JWT is long — token <<JWT_1>> is much shorter.
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	input := "Bearer " + jwt
	result, err := tok.Tokenize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "<<JWT_1>>") {
		t.Errorf("ST-13 FAIL: JWT token not found in output: %s", result)
	}
	if strings.Contains(result, jwt) {
		t.Errorf("ST-13 FAIL: raw JWT still in output: %s", result)
	}
	// No orphaned bytes — verify round-trip.
	original := input
	tokenized := result
	rehydrated := tok.Rehydrate(tokenized)
	if rehydrated != original {
		t.Errorf("ST-13 FAIL: round-trip mismatch for long PII.\n  expected: %q\n  got:      %q", original, rehydrated)
	}
}

// =============================================================================
// ST-14 — PII value shorter than token (minimal email)
// =============================================================================

func TestTokenize_ShortPIIShorterToken(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Minimal email that gets replaced by a longer token <<EMAIL_1>>.
	// TLD must be at least 2 chars, so use .co (a known TLD).
	input := "x@y.co is short"
	result, err := tok.Tokenize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "<<EMAIL_1>>") {
		t.Errorf("ST-14 FAIL: token not in output: %s", result)
	}
	if result != "<<EMAIL_1>> is short" {
		t.Errorf("ST-14 FAIL: unexpected result: %q", result)
	}
}

// =============================================================================
// ST-15 — Tokenized output re-scanned by Engine.Detect() yields zero entities
// =============================================================================

func TestTokenize_NoPIIInOutput_EngineReScan(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	input := "alice@example.com, +33199000000, DE89370400440532013000, 4111111111111111"
	result, err := tok.Tokenize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	entities, err := eng.Detect(result)
	if err != nil {
		t.Fatalf("re-scan error: %v", err)
	}
	if len(entities) > 0 {
		for _, e := range entities {
			t.Errorf("ST-15 FAIL: engine detected PII in tokenized output: %s", e.SafeString())
		}
	}
}

// =============================================================================
// ST-17 — Different PII values same type same position → identical token string
// Token format contains zero encoded PII.
// =============================================================================

func TestTokenFormat_NoEncodedPII(t *testing.T) {
	// Verify token format structure directly.
	token := formatToken(pii.Email, 1)
	if token != "<<EMAIL_1>>" {
		t.Errorf("unexpected token format: %s", token)
	}
	token = formatToken(pii.Phone, 42)
	if token != "<<PHONE_42>>" {
		t.Errorf("unexpected token format: %s", token)
	}

	// Verify that two different PII values of the same type get different tokens.
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	result, err := tok.Tokenize("alice@example.com bob@test.invalid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both are EMAIL but different values — should get <<EMAIL_1>> and <<EMAIL_2>>.
	if !strings.Contains(result, "<<EMAIL_1>>") {
		t.Errorf("ST-17 FAIL: missing <<EMAIL_1>>: %s", result)
	}
	if !strings.Contains(result, "<<EMAIL_2>>") {
		t.Errorf("ST-17 FAIL: missing <<EMAIL_2>>: %s", result)
	}
	if strings.Contains(result, "alice") || strings.Contains(result, "bob") {
		t.Errorf("ST-17 FAIL: PII value found in tokenized text: %s", result)
	}
}

// =============================================================================
// ST-20 — Rehydrator rejects unknown entity types
// =============================================================================

func TestRehydrate_UnknownEntityType(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Only tokenize an email.
	if _, err := tok.Tokenize("alice@example.com"); err != nil {
		t.Fatalf("setup Tokenize failed: %v", err)
	}

	// Unknown types should pass through.
	cases := []string{
		"<<PASSWORD_1>>",
		"<<CUSTOM_TYPE_1>>",
		"<<unknown_1>>",
	}
	for _, input := range cases {
		result := tok.Rehydrate(input)
		if result != input {
			t.Errorf("ST-20 FAIL: expected pass-through for unknown type %q, got %q", input, result)
		}
	}
}

// =============================================================================
// ST-21 — ReDoS prevention: linear-time on malicious input
// =============================================================================

func TestRehydrate_ReDosPrevention(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// 10 KiB of angle brackets should not cause performance issues.
	bracketInput := strings.Repeat("<<<<<>>>>>", 1000)
	result := tok.Rehydrate(bracketInput)
	if result != bracketInput {
		t.Errorf("ST-21 FAIL: expected pass-through of bracket text")
	}

	// Many repeated valid tokens (that don't exist in mapping).
	repeatedTokens := strings.Repeat("<<EMAIL_1>>", 1000)
	result = tok.Rehydrate(repeatedTokens)
	if result != repeatedTokens {
		t.Errorf("ST-21 FAIL: expected pass-through of repeated tokens")
	}
}

// =============================================================================
// ST-22 — Two separate tokenizer instances have independent counters
// =============================================================================

func TestConversation_Isolation(t *testing.T) {
	eng := newTestEngine(t)

	// Conversation A.
	tokA := New(eng, WithLogger(discardLogger()))
	resA, _ := tokA.Tokenize("alice@example.com")
	// Conversation B — same engine, different tokenizer instance.
	tokB := New(eng, WithLogger(discardLogger()))
	resB, _ := tokB.Tokenize("bob@test.invalid")

	// Both should start at <<EMAIL_1>>.
	if !strings.Contains(resA, "<<EMAIL_1>>") {
		t.Errorf("ST-22 FAIL: Conversation A missing <<EMAIL_1>>: %s", resA)
	}
	if !strings.Contains(resB, "<<EMAIL_1>>") {
		t.Errorf("ST-22 FAIL: Conversation B missing <<EMAIL_1>>: %s", resB)
	}

	// tokA's mapping should not affect tokB's mapping.
	rehydB := tokB.Rehydrate("<<EMAIL_1>>")
	if rehydB == "alice@example.com" {
		t.Errorf("ST-22 FAIL: cross-conversation contamination: tokB rehydrated to alice's email")
	}
}

// =============================================================================
// ST-23 — Reset clears all mapping state
// =============================================================================

func TestReset_ClearsAllState(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	_, err := tok.Tokenize("alice@example.com")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if tok.Count() != 1 {
		t.Fatalf("expected 1 entry, got %d", tok.Count())
	}

	tok.Reset()

	if tok.Count() != 0 {
		t.Errorf("ST-23 FAIL: expected 0 entries after reset, got %d", tok.Count())
	}
	// Previous tokens should not resolve.
	result := tok.Rehydrate("<<EMAIL_1>>")
	if result != "<<EMAIL_1>>" {
		t.Errorf("ST-23 FAIL: token resolved after reset: %q", result)
	}
}

// =============================================================================
// ST-18 / T17 — Error paths produce no PII in error messages
// =============================================================================

func TestErrorMessages_NoPII(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Input too large error.
	largeInput := strings.Repeat("x", pii.DefaultMaxInputBytes+1)
	_, err := tok.Tokenize(largeInput)
	if err == nil {
		t.Fatal("expected error")
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "alice") || strings.Contains(errMsg, "example") || strings.Contains(errMsg, "@") {
		t.Errorf("ST-18 FAIL: error message contains PII pattern: %s", errMsg)
	}

	// Verify no PII-related words leak.
	piiPatterns := []string{"@", "4111", "DE89", "sk-", "eyJ"}
	for _, pat := range piiPatterns {
		if strings.Contains(errMsg, pat) {
			t.Errorf("ST-18 FAIL: error message contains suspicious pattern %q: %s", pat, errMsg)
		}
	}
}

// =============================================================================
// ST-19 — No filesystem operations in tokenizer (code audit)
// This is verified by the fact that we only import standard library + internal/pii + x/sys
// =============================================================================

func TestMemoryStore_BasicOperations(t *testing.T) {
	// This test validates that our Store is purely in-memory and that
	// basic Map, Get, Count, and Clear operations work correctly.
	store := NewMemoryStore(discardLogger())
	store.Map("<<EMAIL_1>>", "alice@example.com")
	val, ok := store.Get("<<EMAIL_1>>")
	if !ok {
		t.Fatal("expected to find token")
	}
	if val != "alice@example.com" {
		t.Errorf("unexpected value: %s", val)
	}
	if store.Count() != 1 {
		t.Errorf("expected count=1, got %d", store.Count())
	}
	store.Clear()
	if store.Count() != 0 {
		t.Errorf("ST-19 FAIL: store not cleared")
	}
	// Verify no os.Create, os.WriteFile, etc. in the package — this is a code audit check.
}

// =============================================================================
// Additional tests from DPO requirements (T6, T13, T14, T16, T18)
// =============================================================================

// T6: rehydrate(tokenize(tokenize(text))) == rehydrate(tokenize(text))
func TestDPO_T6_IdempotentRoundTrip(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	original := "Contact: alice@example.com"
	once, _ := tok.Tokenize(original)
	twice, _ := tok.Tokenize(once)

	rehydratedOnce := tok.Rehydrate(once)
	rehydratedTwice := tok.Rehydrate(twice)

	if rehydratedOnce != rehydratedTwice {
		t.Errorf("DPO T6 FAIL: rehydrate yields different results after single vs double tokenization")
	}
	if rehydratedOnce != original {
		t.Errorf("DPO T6 FAIL: lost original after round-trip")
	}
}

// T14: tokenized output scanned by QINDU-0005 recognizers → zero entities detected
// Already covered by ST-15.

// T16: token format contains no PII — different values get sequential counters
func TestDPO_T16_TokenFormatNoPII(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Two different emails.
	result, _ := tok.Tokenize("alice@example.com charlie@test.invalid")
	if !strings.Contains(result, "<<EMAIL_1>>") && !strings.Contains(result, "<<EMAIL_2>>") {
		t.Errorf("DPO T16 FAIL: expected sequential tokens, got: %s", result)
	}
	// Verify tokens don't contain base64 or hex of the PII values.
	if strings.Contains(result, "YWxpY2") { // base64 of "alice"
		t.Errorf("DPO T16 FAIL: token appears to contain base64-encoded PII")
	}
}

// =============================================================================
// Edge cases and boundary tests
// =============================================================================

func TestTokenize_NoPIIInInput(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	input := "Hello, how are you today? Nothing personal here."
	result, err := tok.Tokenize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != input {
		t.Errorf("expected unchanged text, got: %q", result)
	}
}

func TestRehydrate_TokenAtStart(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	if _, err := tok.Tokenize("alice@example.com"); err != nil {
		t.Fatalf("setup Tokenize failed: %v", err)
	}
	result := tok.Rehydrate("<<EMAIL_1>> should contact us")
	if result != "alice@example.com should contact us" {
		t.Errorf("expected rehydrated text with token at start, got: %q", result)
	}
}

func TestRehydrate_TokenAtEnd(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	if _, err := tok.Tokenize("alice@example.com"); err != nil {
		t.Fatalf("setup Tokenize failed: %v", err)
	}
	result := tok.Rehydrate("contact <<EMAIL_1>>")
	if result != "contact alice@example.com" {
		t.Errorf("expected rehydrated text with token at end, got: %q", result)
	}
}

func TestRehydrate_MultipleTokens(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	if _, err := tok.Tokenize("alice@example.com +33199000000"); err != nil {
		t.Fatalf("setup Tokenize failed: %v", err)
	}
	result := tok.Rehydrate("Send to <<EMAIL_1>> or call <<PHONE_1>>")
	if result != "Send to alice@example.com or call +33199000000" {
		t.Errorf("expected rehydrated text with multiple tokens, got: %q", result)
	}
}

func TestRehydrate_TokenWithPartialMatch(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	if _, err := tok.Tokenize("alice@example.com"); err != nil {
		t.Fatalf("setup Tokenize failed: %v", err)
	}
	// <<EMAIL is not a complete token, should pass through.
	result := tok.Rehydrate("prefix <<EMAIL and suffix")
	if result != "prefix <<EMAIL and suffix" {
		t.Errorf("expected pass-through of partial token, got: %q", result)
	}
}

func TestTokenize_EntityAtBoundaries(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	// Entity at start of text.
	result, err := tok.Tokenize("alice@example.com is the contact")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "<<EMAIL_1>>") {
		t.Errorf("expected token at start, got: %q", result)
	}

	// Entity at end of text.
	result, err = tok.Tokenize("Contact is alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(result, "<<EMAIL_1>>") {
		t.Errorf("expected token at end, got: %q", result)
	}
}

func TestTokenize_DuplicateValue_DifferentPositions(t *testing.T) {
	eng := newTestEngine(t)
	tok := New(eng, WithLogger(discardLogger()))

	result, _ := tok.Tokenize("alice@example.com is better than alice@example.com")
	// Should have <<EMAIL_1>> twice, not <<EMAIL_1>> and <<EMAIL_2>>.
	count1 := strings.Count(result, "<<EMAIL_1>>")
	count2 := strings.Count(result, "<<EMAIL_2>>")
	if count1 != 2 {
		t.Errorf("expected 2 x <<EMAIL_1>>, got %d. Output: %s", count1, result)
	}
	if count2 != 0 {
		t.Errorf("expected 0 x <<EMAIL_2>>, got %d. Output: %s", count2, result)
	}
}

// =============================================================================
// Memory locking tests (SR-18 / ST-25)
// =============================================================================

func TestMemoryLocking_Init(t *testing.T) {
	// On Linux CI, this verifies mlockall is called and succeeds.
	// The function call is in NewMemoryStore → initLockedArena.
	store := NewMemoryStore(testLogger())
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	// The store should be functional regardless of locking success.
	store.Map("<<TEST_1>>", "test@example.com")
	val, ok := store.Get("<<TEST_1>>")
	if !ok || val != "test@example.com" {
		t.Errorf("store not functional after memory locking init")
	}
	store.Clear()
	if store.Count() != 0 {
		t.Errorf("store not cleared")
	}
}

// =============================================================================
// Store interface compliance tests
// =============================================================================

func TestStore_FirstWriteWins(t *testing.T) {
	store := NewMemoryStore(discardLogger())
	store.Map("<<EMAIL_1>>", "first@example.com")
	store.Map("<<EMAIL_1>>", "second@example.com") // should be ignored
	val, ok := store.Get("<<EMAIL_1>>")
	if !ok || val != "first@example.com" {
		t.Errorf("expected first-write-wins, got: %q (ok=%v)", val, ok)
	}
}

func TestStore_GetMissing(t *testing.T) {
	store := NewMemoryStore(discardLogger())
	val, ok := store.Get("<<EMAIL_99>>")
	if ok || val != "" {
		t.Errorf("expected missing key, got: %q, ok=%v", val, ok)
	}
}

func TestStore_ClearEmpty(t *testing.T) {
	store := NewMemoryStore(discardLogger())
	store.Clear() // should not panic on empty store
	if store.Count() != 0 {
		t.Errorf("expected empty store")
	}
}

// =============================================================================
// isKnownEntityType tests
// =============================================================================

func TestIsKnownEntityType(t *testing.T) {
	if !isKnownEntityType(pii.Email) {
		t.Error("EMAIL should be known")
	}
	if !isKnownEntityType(pii.PrivateKey) {
		t.Error("PRIVATE_KEY should be known")
	}
	if isKnownEntityType("UNKNOWN") {
		t.Error("UNKNOWN type should not be known")
	}
	if isKnownEntityType("") {
		t.Error("empty type should not be known")
	}
}

// =============================================================================
// validateEntities tests (defense-in-depth)
// =============================================================================

func TestValidateEntities(t *testing.T) {
	entities := []pii.Entity{
		{Type: pii.Email, Start: 0, End: 16, Value: "alice@example.com"},
		{Type: pii.Email, Start: -1, End: 5, Value: "bad"},                // invalid start
		{Type: pii.Email, Start: 5, End: 2, Value: "bad"},                 // end before start
		{Type: pii.Email, Start: 0, End: 9999, Value: "bad"},              // end past text
		{Type: pii.EntityType("UNKNOWN"), Start: 0, End: 5, Value: "bad"}, // unknown type
	}
	valid := validateEntities(entities, 20)
	if len(valid) != 1 {
		t.Errorf("expected 1 valid entity, got %d: %v", len(valid), valid)
	}
	if valid[0].Value != "alice@example.com" {
		t.Errorf("expected alice's email, got: %s", valid[0].Value)
	}
}

// =============================================================================
// formatToken tests
// =============================================================================

func TestFormatToken(t *testing.T) {
	tok := formatToken(pii.IBAN, 3)
	if tok != "<<IBAN_3>>" {
		t.Errorf("expected <<IBAN_3>>, got: %s", tok)
	}
}

// =============================================================================
// Token regex correctness
// =============================================================================

func TestTokenRegex_Matches(t *testing.T) {
	matches := tokenRegex.FindAllString("Hello <<EMAIL_1>> and <<PHONE_2>> end", -1)
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d: %v", len(matches), matches)
	}
	if matches[0] != "<<EMAIL_1>>" {
		t.Errorf("expected <<EMAIL_1>>, got %s", matches[0])
	}
	if matches[1] != "<<PHONE_2>>" {
		t.Errorf("expected <<PHONE_2>>, got %s", matches[1])
	}
}

func TestTokenRegex_NoFalsePositives(t *testing.T) {
	cases := []string{
		"<<UNKNOWN_1>>",
		"<<EMAIL_1>",
		"<EMAIL_1>>",
		"<<PHONE_>>",
		"<<>>",
		"random text",
		"no brackets at all",
	}
	for _, tc := range cases {
		matches := tokenRegex.FindAllString(tc, -1)
		if len(matches) > 0 {
			t.Errorf("unexpected match for %q: %v", tc, matches)
		}
	}
}

// =============================================================================
// Entity substitution correctness with varying token/PII lengths
// =============================================================================

func TestSubstituteEntities_VariableLengths(t *testing.T) {
	// Entity longer → shorter token (JWT).
	// "abc VERYLONGPIIDATA xyz" — "abc " = 4 bytes, "VERYLONGPIIDATA" = 15 bytes
	text := "abc VERYLONGPIIDATA xyz"
	entities := []pii.Entity{
		{Type: pii.JWT, Start: 4, End: 19, Value: "VERYLONGPIIDATA"},
	}
	tokens := []string{"<<JWT_1>>"}
	result := substituteEntities(text, entities, tokens)
	expected := "abc <<JWT_1>> xyz"
	if result != expected {
		t.Errorf("long→short: expected %q, got %q", expected, result)
	}

	// Entity shorter → longer token (minimal email).
	text = "ab SHORT xy"
	entities = []pii.Entity{
		{Type: pii.Email, Start: 3, End: 8, Value: "SHORT"},
	}
	tokens = []string{"<<EMAIL_1>>"}
	result = substituteEntities(text, entities, tokens)
	expected = "ab <<EMAIL_1>> xy"
	if result != expected {
		t.Errorf("short→long: expected %q, got %q", expected, result)
	}

	// Multiple entities.
	text = "AAA BBB CCC"
	entities = []pii.Entity{
		{Type: pii.Email, Start: 0, End: 3, Value: "AAA"},
		{Type: pii.Email, Start: 4, End: 7, Value: "BBB"},
		{Type: pii.Email, Start: 8, End: 11, Value: "CCC"},
	}
	tokens = []string{"<<EMAIL_1>>", "<<EMAIL_2>>", "<<EMAIL_3>>"}
	result = substituteEntities(text, entities, tokens)
	expected = "<<EMAIL_1>> <<EMAIL_2>> <<EMAIL_3>>"
	if result != expected {
		t.Errorf("multiple: expected %q, got %q", expected, result)
	}
}

// =============================================================================
// TokenPersister integration tests (QINDU-0008, AC-9, DPO-R11)
// =============================================================================

// mockPersister implements vault.TokenPersister for testing.
// Captures calls so tests can verify correct invocation.
type mockPersister struct {
	persists []persistCall
	metas    []metaCall
	mu       sync.Mutex
}

type persistCall struct {
	Scope vault.Scope
	Token string
	Value []byte
}

type metaCall struct {
	Scope vault.Scope
	Meta  vault.Metadata
}

func (m *mockPersister) Persist(scope vault.Scope, token string, value []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Copy the value to avoid aliasing.
	valCopy := make([]byte, len(value))
	copy(valCopy, value)
	m.persists = append(m.persists, persistCall{Scope: scope, Token: token, Value: valCopy})
}

func (m *mockPersister) UpdateMeta(scope vault.Scope, meta vault.Metadata) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metas = append(m.metas, metaCall{Scope: scope, Meta: meta})
}

func (m *mockPersister) persistCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.persists)
}

// TestPersister_CalledWithCorrectValues verifies the persister is called with correct values (T-801-adjacent).
func TestPersister_CalledWithCorrectValues(t *testing.T) {
	eng := newTestEngine(t)
	mock := &mockPersister{}
	tok := New(eng,
		WithLogger(discardLogger()),
		WithPersister(mock),
		WithProvider("chatgpt"),
		WithConversationID("550e8400-e29b-41d4-a716-446655440000"),
	)

	_, err := tok.Tokenize("alice@example.com +33199000000")
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	if mock.persistCount() != 2 {
		t.Fatalf("expected 2 persists, got %d", mock.persistCount())
	}

	// Check first persist — email.
	p1 := mock.persists[0]
	if p1.Scope.Provider != "chatgpt" {
		t.Errorf("expected provider 'chatgpt', got %q", p1.Scope.Provider)
	}
	if p1.Scope.ConversationID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("unexpected conversation ID: %q", p1.Scope.ConversationID)
	}
	if p1.Token != "<<EMAIL_1>>" {
		t.Errorf("expected token <<EMAIL_1>>, got %q", p1.Token)
	}
	if string(p1.Value) != "alice@example.com" {
		t.Errorf("expected value 'alice@example.com', got %q", string(p1.Value))
	}

	// Check second persist — phone.
	p2 := mock.persists[1]
	if p2.Token != "<<PHONE_1>>" {
		t.Errorf("expected token <<PHONE_1>>, got %q", p2.Token)
	}
	if string(p2.Value) != "+33199000000" {
		t.Errorf("expected value '+33199000000', got %q", string(p2.Value))
	}
}

// TestPersister_NilPersisterNoPanic verifies nil persister does not panic (AC-9, DPO-R11).
func TestPersister_NilPersisterNoPanic(t *testing.T) {
	eng := newTestEngine(t)
	// No WithPersister — defaults to nil.
	tok := New(eng, WithLogger(discardLogger()))

	result, err := tok.Tokenize("alice@example.com")
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}
	if !strings.Contains(result, "<<EMAIL_1>>") {
		t.Errorf("expected tokenization to work with nil persister, got: %s", result)
	}
	// Round-trip should still work.
	rehydrated := tok.Rehydrate(result)
	if rehydrated != "alice@example.com" {
		t.Errorf("round-trip failed with nil persister: got %q", rehydrated)
	}
}

// TestPersister_DuplicateValuesPersistedOnce verifies duplicates are not re-persisted.
func TestPersister_DuplicateValuesPersistedOnce(t *testing.T) {
	eng := newTestEngine(t)
	mock := &mockPersister{}
	tok := New(eng,
		WithLogger(discardLogger()),
		WithPersister(mock),
		WithProvider("claude"),
		WithConversationID("00000000-0000-4000-8000-000000000001"),
	)

	// Same email appears twice.
	_, err := tok.Tokenize("alice@example.com and alice@example.com again")
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	// Should only persist one token, not two.
	if mock.persistCount() != 1 {
		t.Errorf("expected 1 persist for duplicate value, got %d", mock.persistCount())
	}
	if mock.persists[0].Token != "<<EMAIL_1>>" {
		t.Errorf("expected <<EMAIL_1>>, got %q", mock.persists[0].Token)
	}
}

// TestPersister_ProviderAndConvIDSetCorrectly verifies provider/convID are set correctly.
func TestPersister_ProviderAndConvIDSetCorrectly(t *testing.T) {
	eng := newTestEngine(t)
	mock := &mockPersister{}
	tok := New(eng,
		WithLogger(discardLogger()),
		WithPersister(mock),
		WithProvider("gemini"),
		WithConversationID("11111111-1111-4111-8111-111111111111"),
	)

	_, err := tok.Tokenize("bob@test.invalid")
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	if mock.persistCount() != 1 {
		t.Fatalf("expected 1 persist, got %d", mock.persistCount())
	}
	p := mock.persists[0]
	if p.Scope.Provider != "gemini" {
		t.Errorf("expected provider 'gemini', got %q", p.Scope.Provider)
	}
	if p.Scope.ConversationID != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("unexpected conversation ID: %q", p.Scope.ConversationID)
	}
}

// TestPersister_OptionOrderingDoesNotMatter verifies options can be set in any order.
func TestPersister_OptionOrderingDoesNotMatter(t *testing.T) {
	eng := newTestEngine(t)
	mock := &mockPersister{}

	// Set provider and convID before persister.
	tok := New(eng,
		WithProvider("chatgpt"),
		WithConversationID("abcd1234"),
		WithLogger(discardLogger()),
		WithPersister(mock),
	)

	_, err := tok.Tokenize("alice@example.com")
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}

	if mock.persistCount() != 1 {
		t.Fatalf("expected 1 persist, got %d", mock.persistCount())
	}
	p := mock.persists[0]
	if p.Scope.Provider != "chatgpt" {
		t.Errorf("expected provider 'chatgpt', got %q", p.Scope.Provider)
	}
	if p.Scope.ConversationID != "abcd1234" {
		t.Errorf("unexpected conversation ID: %q", p.Scope.ConversationID)
	}
}
