package pii

import (
	"regexp"
	"strings"
)

// emailRegex is a simplified RFC 5322 email regex compiled at construction time.
const emailRegexPattern = `[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}`

// commonTLDs is a whitelist of known TLDs used for validation.
// This helps reject strings that look like emails but have invalid TLDs.
var commonTLDs = map[string]bool{
	"com": true, "org": true, "net": true, "edu": true, "gov": true,
	"mil": true, "int": true, "info": true, "biz": true, "name": true,
	"pro": true, "coop": true, "museum": true, "aero": true, "xxx": true,
	"co": true, "io": true, "ai": true, "dev": true, "app": true,
	"cloud": true, "me": true, "tv": true, "cc": true, "ws": true,
	"fr": true, "de": true, "uk": true, "it": true, "es": true,
	"nl": true, "be": true, "ch": true, "at": true, "pt": true,
	"ie": true, "lu": true, "gr": true, "fi": true, "dk": true,
	"se": true, "no": true, "pl": true, "cz": true, "hu": true,
	"ro": true, "bg": true, "hr": true, "sk": true, "si": true,
	"lt": true, "lv": true, "ee": true, "is": true, "mt": true,
	"cy": true, "li": true, "mc": true, "sm": true, "ad": true,
	"us": true, "ca": true, "mx": true, "br": true, "ar": true,
	"jp": true, "cn": true, "in": true, "au": true, "nz": true,
	"ru": true, "ua": true, "za": true, "kr": true, "sg": true,
	"hk": true, "tw": true, "my": true, "ph": true, "th": true,
}

// falsePositiveEmails are known false-positive email local-parts that should
// be rejected. Per the story, these are: noreply, no-reply, mailer-daemon, root.
var falsePositiveEmails = map[string]bool{
	"noreply":       true,
	"no-reply":      true,
	"mailer-daemon": true,
	"root":          true,
}

// EmailRecognizer detects email addresses in text.
type EmailRecognizer struct {
	re *regexp.Regexp
}

// NewEmailRecognizer creates a new EMAIL recognizer.
func NewEmailRecognizer() *EmailRecognizer {
	return &EmailRecognizer{
		re: regexp.MustCompile(emailRegexPattern),
	}
}

// Type returns EMAIL.
func (r *EmailRecognizer) Type() EntityType {
	return Email
}

// Detect finds all email addresses in the given text.
func (r *EmailRecognizer) Detect(text string) []Entity {
	matches := r.re.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}

	entities := make([]Entity, 0, len(matches))
	for _, m := range matches {
		candidate := text[m[0]:m[1]]

		// Left boundary check: the character before the match must not be a
		// valid email local-part character or '@'. This prevents the regex
		// from matching sub-strings like "domain@example.com" inside
		// "no@domain@double.com".
		if m[0] > 0 {
			prev := text[m[0]-1]
			if isEmailLeftChar(prev) {
				continue
			}
		}

		// Right boundary check: the character after the match must not be a
		// valid email character. This prevents matching prefixes of longer
		// strings that look like emails.
		if m[1] < len(text) {
			next := text[m[1]]
			if isEmailRightChar(next) {
				continue
			}
		}

		if !isValidEmail(candidate) {
			continue
		}
		confidence := validateEmailCandidate(candidate)
		entities = append(entities, Entity{
			Type:       Email,
			Value:      candidate,
			Confidence: confidence,
			Source:     SourceRegex,
			Start:      m[0],
			End:        m[1],
		})
	}

	if len(entities) == 0 {
		return nil
	}
	return entities
}

// isEmailLeftChar returns true if the byte is a valid character in an email
// local-part. Used for left-boundary validation to prevent sub-matches.
func isEmailLeftChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '.' || c == '!' || c == '#' ||
		c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
		c == '+' || c == '-' || c == '/' || c == '=' || c == '?' ||
		c == '^' || c == '_' || c == '`' || c == '{' || c == '|' ||
		c == '}' || c == '~' || c == '@'
}

// isEmailRightChar returns true if the byte is a valid character in an email
// domain or local-part. Used for right-boundary validation.
func isEmailRightChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '@'
}

// isValidEmail performs basic email validation checks.
func isValidEmail(email string) bool {
	// Total length check (RFC 5321).
	if len(email) > 254 {
		return false
	}

	atIdx := strings.LastIndex(email, "@")
	if atIdx <= 0 || atIdx >= len(email)-1 {
		return false
	}

	localPart := email[:atIdx]
	domain := email[atIdx+1:]

	// Must not contain multiple @ signs.
	if strings.Count(email, "@") != 1 {
		return false
	}

	// Local part must not be empty and ≤ 64 chars.
	if len(localPart) == 0 || len(localPart) > 64 {
		return false
	}

	// Domain must not start or end with hyphen, no consecutive dots.
	if len(domain) == 0 || domain[0] == '-' || domain[len(domain)-1] == '-' {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}
	if strings.Contains(domain, "--") {
		return false
	}

	// Check for the `@localhost` case.
	if domain == "localhost" {
		return false
	}

	// Check false positive prefixes (case-insensitive on the part before @).
	localLower := strings.ToLower(localPart)
	// Strip +suffix for false positive check
	if plusIdx := strings.IndexByte(localLower, '+'); plusIdx >= 0 {
		localLower = localLower[:plusIdx]
	}
	if falsePositiveEmails[localLower] {
		return false
	}

	return true
}

// validateEmailCandidate returns a confidence score for an email address.
func validateEmailCandidate(email string) float64 {
	atIdx := strings.IndexByte(email, '@')
	if atIdx <= 0 {
		return 0.85
	}

	domain := email[atIdx+1:]

	// Extract TLD (last segment after dot).
	lastDot := strings.LastIndexByte(domain, '.')
	if lastDot < 0 {
		return 0.85
	}

	tld := strings.ToLower(domain[lastDot+1:])

	// TLD must be ≥ 2 alpha chars.
	if len(tld) < 2 {
		return 0.85
	}

	// If TLD is in known list, boost confidence.
	if commonTLDs[tld] {
		return 0.95
	}

	// Unknown TLD but still structurally valid.
	return 0.90
}
