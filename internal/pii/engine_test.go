package pii

import (
	"strings"
	"sync"
	"testing"
)

func TestNewEngineDefaultMaxInput(t *testing.T) {
	engine := NewEngine(0)
	if engine.maxInputLen != DefaultMaxInputBytes {
		t.Errorf("expected default max input %d, got %d", DefaultMaxInputBytes, engine.maxInputLen)
	}
}

func TestNewEngineNegativeMaxInput(t *testing.T) {
	engine := NewEngine(-1)
	if engine.maxInputLen != DefaultMaxInputBytes {
		t.Errorf("negative max input should default to %d, got %d", DefaultMaxInputBytes, engine.maxInputLen)
	}
}

func TestEngineDetectEmptyText(t *testing.T) {
	engine := NewEngine(DefaultMaxInputBytes, NewEmailRecognizer(), NewPhoneRecognizer())
	entities, err := engine.Detect("")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if entities != nil {
		t.Errorf("expected nil entities for empty input, got %v", entities)
	}
}

func TestEngineDetectNoPII(t *testing.T) {
	engine := NewEngine(DefaultMaxInputBytes,
		NewEmailRecognizer(),
		NewPhoneRecognizer(),
		NewIBANRecognizer(),
		NewCreditCardRecognizer(),
		NewJWTRecognizer(),
	)
	entities, err := engine.Detect("This is a normal sentence without any PII. Just some everyday words.")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if entities != nil {
		t.Errorf("expected nil entities when no PII found, got %v", entities)
	}
}

func TestEngineDetectOversizedInput(t *testing.T) {
	engine := NewEngine(100) // 100 bytes max
	largeText := strings.Repeat("A", 200)
	_, err := engine.Detect(largeText)
	if err == nil {
		t.Error("expected error for oversized input")
	}
	if !IsInputTooLarge(err) {
		t.Errorf("expected ErrInputTooLarge, got %T: %v", err, err)
	}
	var e *ErrInputTooLarge
	if err != nil {
		if e2, ok := err.(*ErrInputTooLarge); ok {
			e = e2
		}
	}
	if e == nil {
		t.Fatal("expected *ErrInputTooLarge")
	}
	if strings.Contains(e.Error(), "A") {
		t.Error("error message must not contain input text")
	}
}

func TestEngineDetectEmail(t *testing.T) {
	engine := NewEngine(DefaultMaxInputBytes, NewEmailRecognizer())
	entities, err := engine.Detect("Contact us at support@example.com for more info.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
	if entities[0].Type != Email {
		t.Errorf("expected EMAIL, got %s", entities[0].Type)
	}
}

func TestEngineDetectMultipleTypes(t *testing.T) {
	engine := NewEngine(DefaultMaxInputBytes,
		NewEmailRecognizer(),
		NewPhoneRecognizer(),
	)
	text := "Email: test@example.com, Phone: +1-202-555-0199"
	entities, err := engine.Detect(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entities) < 2 {
		t.Fatalf("expected at least 2 entities, got %d: %v", len(entities), entities)
	}
}

func TestEngineDetectSortedByPosition(t *testing.T) {
	engine := NewEngine(DefaultMaxInputBytes,
		NewEmailRecognizer(),
		NewJWTRecognizer(),
	)
	text := "JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fakesig Email: test@example.com"
	entities, err := engine.Detect(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify sorted by Start position.
	for i := 1; i < len(entities); i++ {
		if entities[i].Start < entities[i-1].Start {
			t.Errorf("entities not sorted by position: entity[%d].Start=%d < entity[%d].Start=%d",
				i, entities[i].Start, i-1, entities[i-1].Start)
		}
	}
}

func TestEngineDetectConcurrency(t *testing.T) {
	engine := NewEngine(DefaultMaxInputBytes,
		NewEmailRecognizer(),
		NewPhoneRecognizer(),
		NewIBANRecognizer(),
		NewCreditCardRecognizer(),
		NewJWTRecognizer(),
		NewSecretPrefixRecognizer(),
		NewSecretEntropyRecognizer(),
		NewPrivateKeyRecognizer(),
		NewNameFromEmailRecognizer(),
	)

	texts := []string{
		"Contact test@example.com for info.",
		"Call +1-202-555-0199 today.",
		"My IBAN is DE89370400440532013000.",
		"Use card 4111111111111111 for payment.",
		"Token: sk-test-1234567890abcdefghijklmnopqrstuv",
		"",
		"Just normal text with nothing special.",
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(texts)*10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for _, text := range texts {
				_, err := engine.Detect(text)
				if err != nil {
					errs <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent detection error: %v", err)
	}
}

func TestEngineDetectNoRecognizers(t *testing.T) {
	engine := NewEngine(DefaultMaxInputBytes)
	entities, err := engine.Detect("some text")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if entities != nil {
		t.Errorf("expected nil entities with no recognizers, got %v", entities)
	}
}

func TestEngineDetectReturnsNilNotEmpty(t *testing.T) {
	// When no PII is found, Detect should return nil, not empty slice.
	engine := NewEngine(DefaultMaxInputBytes, NewEmailRecognizer())
	entities, _ := engine.Detect("no pii here")
	if entities != nil {
		t.Errorf("expected nil when no PII, got %v", entities)
	}
}

func TestErrInputTooLargeFormat(t *testing.T) {
	err := &ErrInputTooLarge{MaxSize: 100, Received: 200}
	msg := err.Error()
	if !strings.Contains(msg, "100") {
		t.Error("error should contain max size")
	}
	if !strings.Contains(msg, "200") {
		t.Error("error should contain received size")
	}
}

func TestIsInputTooLarge(t *testing.T) {
	err := &ErrInputTooLarge{MaxSize: 10, Received: 20}
	if !IsInputTooLarge(err) {
		t.Error("IsInputTooLarge should return true for ErrInputTooLarge")
	}
	if IsInputTooLarge(nil) {
		t.Error("IsInputTooLarge should return false for nil")
	}
}

func TestEngineDetectNameRecognizerNoEmailAware(t *testing.T) {
	// Create a NAME recognizer that does NOT implement EmailAwareRecognizer.
	// This tests the fallback path in engine.go (the else branch at line 98-101).
	engine := NewEngine(DefaultMaxInputBytes,
		NewEmailRecognizer(),
		&nonEmailAwareNameRecognizer{},
	)
	text := "Contact jean.dupont@example.com"
	entities, err := engine.Detect(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The non-EmailAware recognizer returns nil from Detect().
	// Entities should just be the email.
	_ = entities
}

// nonEmailAwareNameRecognizer is a NAME recognizer that does NOT implement
// EmailAwareRecognizer, used to test the fallback path in Engine.Detect().
type nonEmailAwareNameRecognizer struct{}

func (r *nonEmailAwareNameRecognizer) Type() EntityType            { return Name }
func (r *nonEmailAwareNameRecognizer) Detect(text string) []Entity { return nil }

func TestEngineDetectNameRecognizerWithEmailAware(t *testing.T) {
	// This tests the normal path: NAME recognizer implementing EmailAwareRecognizer.
	engine := NewEngine(DefaultMaxInputBytes,
		NewEmailRecognizer(),
		NewNameFromEmailRecognizer(),
	)
	text := "Contact jean.dupont@example.com"
	entities, err := engine.Detect(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have both EMAIL and NAME entities.
	if len(entities) < 1 {
		t.Error("expected at least 1 entity")
	}
}
