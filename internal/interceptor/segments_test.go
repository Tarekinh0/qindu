package interceptor

import (
	"testing"
	"unicode/utf8"

	"github.com/Tarekinh0/qindu/internal/providers"
)

// TestReplaceSegments_ShorterToken verifies that replaceSegments correctly
// replaces PII with a token shorter than the original PII text.
func TestReplaceSegments_ShorterToken(t *testing.T) {
	// PII "john.doe@example.com" (24 bytes) → "<<EMAIL_1>>" (11 bytes)
	body := []byte(`{"email": "john.doe@example.com"}`)
	segments := []providers.TextSegment{
		{Start: 11, End: 31, Text: "<<EMAIL_1>>"},
	}

	result := replaceSegments(body, segments)

	expected := `{"email": "<<EMAIL_1>>"}`
	if string(result) != expected {
		t.Errorf("replaceSegments shorter token:\n  got: %q\n want: %q", string(result), expected)
	}
	if !utf8.Valid(result) {
		t.Error("result is not valid UTF-8")
	}
}

// TestReplaceSegments_LongerToken verifies replacement when the token is
// longer than the PII value.
func TestReplaceSegments_LongerToken(t *testing.T) {
	// PII "411" (3 bytes) → "<<CREDIT_CARD_123>>" (19 bytes)
	body := []byte(`{"cc": "411"}`)
	segments := []providers.TextSegment{
		{Start: 8, End: 11, Text: "<<CREDIT_CARD_123>>"},
	}

	result := replaceSegments(body, segments)

	expected := `{"cc": "<<CREDIT_CARD_123>>"}`
	if string(result) != expected {
		t.Errorf("replaceSegments longer token:\n  got: %q\n want: %q", string(result), expected)
	}
	if !utf8.Valid(result) {
		t.Error("result is not valid UTF-8")
	}
}

// TestReplaceSegments_AtStart verifies replacement when PII is at byte offset 0.
func TestReplaceSegments_AtStart(t *testing.T) {
	body := []byte(`john.doe@example.com is the email`)
	segments := []providers.TextSegment{
		{Start: 0, End: 20, Text: "<<EMAIL_1>>"},
	}

	result := replaceSegments(body, segments)

	expected := `<<EMAIL_1>> is the email`
	if string(result) != expected {
		t.Errorf("replaceSegments at start:\n  got: %q\n want: %q", string(result), expected)
	}
}

// TestReplaceSegments_AtEnd verifies replacement when PII is at the end of the body.
func TestReplaceSegments_AtEnd(t *testing.T) {
	body := []byte(`The email is john.doe@example.com`)
	segments := []providers.TextSegment{
		{Start: 13, End: 33, Text: "<<EMAIL_1>>"},
	}

	result := replaceSegments(body, segments)

	expected := `The email is <<EMAIL_1>>`
	if string(result) != expected {
		t.Errorf("replaceSegments at end:\n  got: %q\n want: %q", string(result), expected)
	}
}

// TestReplaceSegments_MultiplePII verifies replacing multiple PII occurrences
// in a single body.
func TestReplaceSegments_MultiplePII(t *testing.T) {
	body := []byte(`Name: Alice, Email: alice@example.com, Phone: +33123456789`)
	segments := []providers.TextSegment{
		{Start: 6, End: 11, Text: "<<NAME_1>>"},
		{Start: 20, End: 37, Text: "<<EMAIL_1>>"},
		{Start: 46, End: 58, Text: "<<PHONE_1>>"},
	}

	result := replaceSegments(body, segments)

	expected := `Name: <<NAME_1>>, Email: <<EMAIL_1>>, Phone: <<PHONE_1>>`
	if string(result) != expected {
		t.Errorf("replaceSegments multiple PII:\n  got: %q\n want: %q", string(result), expected)
	}
	if !utf8.Valid(result) {
		t.Error("result is not valid UTF-8")
	}
}

// TestReplaceSegments_InvalidBoundsStartNegative verifies that segments with
// negative Start are silently skipped.
func TestReplaceSegments_InvalidBoundsStartNegative(t *testing.T) {
	body := []byte(`hello world`)
	segments := []providers.TextSegment{
		{Start: -1, End: 5, Text: "<<BAD>>"},
	}

	result := replaceSegments(body, segments)

	// Body should be returned unchanged (invalid segment skipped).
	if string(result) != "hello world" {
		t.Errorf("replaceSegments invalid Start < 0:\n  got: %q\n want: %q", string(result), "hello world")
	}
}

// TestReplaceSegments_InvalidBoundsEndBeyondLen verifies that segments with
// End beyond body length are skipped.
func TestReplaceSegments_InvalidBoundsEndBeyondLen(t *testing.T) {
	body := []byte(`hello`)
	segments := []providers.TextSegment{
		{Start: 0, End: 10, Text: "<<BAD>>"},
	}

	result := replaceSegments(body, segments)

	if string(result) != "hello" {
		t.Errorf("replaceSegments invalid End > len(body):\n  got: %q\n want: %q", string(result), "hello")
	}
}

// TestReplaceSegments_NoSegments verifies that empty/nil segments return body unchanged.
func TestReplaceSegments_NoSegments(t *testing.T) {
	body := []byte(`hello world`)

	result := replaceSegments(body, nil)
	if string(result) != "hello world" {
		t.Errorf("replaceSegments nil segments changed body: %q", string(result))
	}

	result = replaceSegments(body, []providers.TextSegment{})
	if string(result) != "hello world" {
		t.Errorf("replaceSegments empty segments changed body: %q", string(result))
	}
}

// TestReplaceSegments_NoOpIdenticalText verifies segments with identical replacement
// text are treated as no-ops.
func TestReplaceSegments_NoOpIdenticalText(t *testing.T) {
	body := []byte(`hello`)
	segments := []providers.TextSegment{
		{Start: 0, End: 5, Text: "hello"},
	}

	result := replaceSegments(body, segments)
	if string(result) != "hello" {
		t.Errorf("replaceSegments identical text changed body: %q", string(result))
	}
}

// TestReplaceSegments_UTF8Output verifies result is always valid UTF-8,
// even with multibyte characters in the body.
func TestReplaceSegments_UTF8Output(t *testing.T) {
	body := []byte(`Prénom: Jean, Email: jean@example.com`)
	segments := []providers.TextSegment{
		{Start: 9, End: 13, Text: "<<NAME_1>>"},
		{Start: 22, End: 38, Text: "<<EMAIL_1>>"},
	}

	result := replaceSegments(body, segments)

	if !utf8.Valid(result) {
		t.Error("result is not valid UTF-8")
	}

	expected := `Prénom: <<NAME_1>>, Email: <<EMAIL_1>>`
	if string(result) != expected {
		t.Errorf("replaceSegments UTF-8:\n  got: %q\n want: %q", string(result), expected)
	}
}

// TestSortSegmentsDesc verifies the right-to-left sort helper.
func TestSortSegmentsDesc(t *testing.T) {
	segments := []providers.TextSegment{
		{Start: 10, End: 20, Text: "C"},
		{Start: 0, End: 5, Text: "A"},
		{Start: 30, End: 35, Text: "D"},
		{Start: 20, End: 25, Text: "B"},
	}

	sortSegmentsDesc(segments)

	if segments[0].Start != 30 {
		t.Errorf("first segment Start should be 30 (largest), got %d", segments[0].Start)
	}
	if segments[1].Start != 20 {
		t.Errorf("second segment Start should be 20, got %d", segments[1].Start)
	}
	if segments[2].Start != 10 {
		t.Errorf("third segment Start should be 10, got %d", segments[2].Start)
	}
	if segments[3].Start != 0 {
		t.Errorf("fourth segment Start should be 0, got %d", segments[3].Start)
	}
}
