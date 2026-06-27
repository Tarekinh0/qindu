package pii

import (
	"testing"
)

func TestPrivateKeyRecognizerType(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	if r.Type() != PrivateKey {
		t.Errorf("expected PRIVATE_KEY type, got %s", r.Type())
	}
}

func TestPrivateKeyRecognizerEmpty(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	entities := r.Detect("")
	if entities != nil {
		t.Errorf("expected nil for empty input, got %v", entities)
	}
}

func TestPrivateKeyRecognizerRSAPEM(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// Synthetic PEM block with clearly fake key material.
	input := `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS6RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
+5FUEXE2b3ZJwFPlCRFGSXtkZNf1TzZQW4UqUxlu
-----END RSA PRIVATE KEY-----`
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 PEM entity, got %d", len(entities))
	}
	e := entities[0]
	if e.Type != PrivateKey {
		t.Errorf("expected PRIVATE_KEY type, got %s", e.Type)
	}
	if e.Source != SourcePEMArmor {
		t.Errorf("expected pem_armor source, got %s", e.Source)
	}
	if e.Confidence < 0.94 {
		t.Errorf("valid PEM should have confidence >= 0.95, got %f", e.Confidence)
	}
}

func TestPrivateKeyRecognizerECPEM(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	input := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOMsjHSgMrOsqMVSFvjT0UFnAmAQMvMpIUNLWzURBYB2oAoGCCqGSM49
AwEHoUQDQgAEFbRciTBDZrRAfMqgS5ASxGyJeIR5rsDONQbffEHcviHBaiicNp4r
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
-----END EC PRIVATE KEY-----`
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 EC PEM entity, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerGenericPrivateKey(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	input := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCRjPLOqeBCFGNu
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCD
-----END PRIVATE KEY-----`
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 PRIVATE KEY entity, got %d", len(entities))
	}
	if entities[0].Confidence < 0.89 {
		t.Errorf("generic PRIVATE KEY should have 0.90 confidence, got %f", entities[0].Confidence)
	}
}

func TestPrivateKeyRecognizerOpenSSH(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	input := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA0fHkaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGho
-----END OPENSSH PRIVATE KEY-----`
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 OpenSSH entity, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerPGP(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	input := `-----BEGIN PGP PRIVATE KEY BLOCK-----
lQOYBGABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/
=eOPq
-----END PGP PRIVATE KEY BLOCK-----`
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 PGP entity, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerNoMatch(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	tests := []string{
		"not a key",
		"-----BEGIN CERTIFICATE-----\nABCDEFGH\n-----END CERTIFICATE-----", // Public cert, not private key.
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 0 {
			t.Errorf("expected 0 entities for %q, got %d", input, len(entities))
		}
	}
}

func TestPrivateKeyRecognizerShortBody(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// Body too short (< 40 base64 chars).
	input := `-----BEGIN RSA PRIVATE KEY-----
dG9vc2hvcnQ=
-----END RSA PRIVATE KEY-----`
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity even with short body, got %d", len(entities))
	}
	if entities[0].Confidence >= 0.71 {
		t.Errorf("short body should have low confidence (0.70), got %f", entities[0].Confidence)
	}
}

func TestPrivateKeyRecognizerSpanValidation(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	input := "Some text before\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----\nSome text after"
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
	e := entities[0]
	if e.Start >= e.End {
		t.Errorf("invalid span: [%d, %d)", e.Start, e.End)
	}
	if text := input[e.Start:e.End]; text != e.Value {
		t.Errorf("value mismatch: text[%d:%d]=%q, Value=%q", e.Start, e.End, text, e.Value)
	}
}

func TestPrivateKeyRecognizerEncryptedPKCS8(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	input := `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIUhNKLHuCObUCAggA
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
-----END ENCRYPTED PRIVATE KEY-----`
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 ENCRYPTED PRIVATE KEY entity, got %d", len(entities))
	}
}

func TestIsValidPEMBase64(t *testing.T) {
	if !isValidPEMBase64("dGhpcyBpcyBhIHRlc3Q=") {
		t.Error("valid base64 should return true")
	}
	if isValidPEMBase64("!!!invalid!!!") {
		t.Error("invalid base64 should return false")
	}
	if isValidPEMBase64("") {
		t.Error("empty string should return false")
	}
}

func TestPrivateKeyRecognizerInvalidBase64Body(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// PEM with invalid base64 in body.
	input := `-----BEGIN RSA PRIVATE KEY-----
!!!not-base64!!!
-----END RSA PRIVATE KEY-----`
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity even with invalid base64, got %d", len(entities))
	}
	// Should have lower confidence.
	if entities[0].Confidence >= 0.95 {
		t.Errorf("invalid base64 body should have low confidence, got %f", entities[0].Confidence)
	}
}

func TestPrivateKeyRecognizerNoEndMarker(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// BEGIN without matching END should not produce an entity.
	input := `-----BEGIN RSA PRIVATE KEY-----
dGhpcyBpcyBhIHRlc3Q=`
	entities := r.Detect(input)
	if len(entities) != 0 {
		t.Errorf("BEGIN without END should return 0 entities, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerUnknownHeaderType(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// A BEGIN header that is not a private key type.
	input := `-----BEGIN CERTIFICATE-----
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/
-----END CERTIFICATE-----`
	entities := r.Detect(input)
	if len(entities) != 0 {
		t.Errorf("non-private-key header should return 0 entities, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerBeginWithoutNewline(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// BEGIN header without a newline after it.
	input := "-----BEGIN PRIVATE KEY-----ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/\n-----END PRIVATE KEY-----"
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerCarriageReturn(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// Body with \r\n line endings.
	input := "-----BEGIN RSA PRIVATE KEY-----\r\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\r\n-----END RSA PRIVATE KEY-----"
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerBeginAtEndOfText(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// BEGIN line is at the end of text with no newline after it.
	input := "-----BEGIN RSA PRIVATE KEY-----"
	entities := r.Detect(input)
	// Without an END marker, should return nothing.
	if len(entities) != 0 {
		t.Errorf("BEGIN without END should return 0 entities, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerDSAPEM(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	input := `-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDRfHGohaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGho
aGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoa
-----END DSA PRIVATE KEY-----`
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 DSA PEM entity, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerBodyWithTrailingNewline(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// Body that ends with a newline before END marker.
	input := "-----BEGIN PRIVATE KEY-----\nABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/\n-----END PRIVATE KEY-----"
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
}

func TestPrivateKeyRecognizerNoNewlinesAtAll(t *testing.T) {
	r := NewPrivateKeyRecognizer()
	// PEM block with zero newline characters anywhere — BEGIN, body, END
	// all on one line. This triggers the beginLineEnd < 0 path.
	// The body is base64 without newlines, directly before the END marker.
	input := "-----BEGIN PRIVATE KEY-----ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/-----END PRIVATE KEY-----"
	entities := r.Detect(input)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity for no-newline PEM, got %d", len(entities))
	}
	e := entities[0]
	if e.Start != 0 {
		t.Errorf("expected start=0, got %d", e.Start)
	}
	if e.End != len(input) {
		t.Errorf("expected end=%d, got %d", len(input), e.End)
	}
	// With no newlines and body length ≥ 40 valid base64, confidence should be high.
	if e.Confidence < 0.85 {
		t.Errorf("expected high confidence, got %f", e.Confidence)
	}
}
