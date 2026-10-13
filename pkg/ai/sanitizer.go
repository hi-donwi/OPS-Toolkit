package ai

import (
	"regexp"
)

var (
	// Redact bearer tokens
	reBearer = regexp.MustCompile(`(?i)(bearer\s+)[^\s"',;]+`)
	// Redact password parameters
	rePassword    = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key)["']?\s*[:=]\s*(?:"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^"'\s,;]+)`)
	reURLPassword = regexp.MustCompile(`(://[^:/@\s]+:)[^@\s]+(@)`)
	// Redact private keys
	rePrivKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	// Redact AWS access keys
	reAWS = regexp.MustCompile(`(AKIA[0-9A-Z]{16})`)
)

// SanitizeLog strips sensitive credentials, tokens, and private keys from raw log snippets before AI analysis.
func SanitizeLog(input string) string {
	if input == "" {
		return ""
	}

	sanitized := rePrivKey.ReplaceAllString(input, "[REDACTED_PRIVATE_KEY]")
	sanitized = reBearer.ReplaceAllString(sanitized, "${1}[REDACTED_TOKEN]")
	sanitized = rePassword.ReplaceAllString(sanitized, "${1}=[REDACTED_CREDENTIAL]")
	sanitized = reURLPassword.ReplaceAllString(sanitized, "${1}[REDACTED_CREDENTIAL]${2}")
	sanitized = reAWS.ReplaceAllString(sanitized, "[REDACTED_AWS_KEY]")

	return sanitized
}
