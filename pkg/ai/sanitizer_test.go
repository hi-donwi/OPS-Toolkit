package ai

import (
	"strings"
	"testing"
)

func TestSanitizeLog(t *testing.T) {
	input := `Error during authentication:
password="superSecretPassword123!"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz123456789
AWS_KEY: AKIAIOSFODNN7EXAMPLE`

	sanitized := SanitizeLog(input)

	if strings.Contains(sanitized, "superSecretPassword123!") {
		t.Errorf("Expected password to be redacted")
	}
	if strings.Contains(sanitized, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Errorf("Expected bearer token to be redacted")
	}
	if strings.Contains(sanitized, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Expected AWS key to be redacted")
	}
	if !strings.Contains(sanitized, "[REDACTED_") {
		t.Errorf("Expected sanitized output to contain redaction placeholders")
	}
}

func TestSanitizeLogRedactsPrivateKeys(t *testing.T) {
	input := `error loading key:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxu2n8Q0gK7v9Zx
qDfL0pW3nB8sT4vM6cR1yH2jK9dEwXa
-----END RSA PRIVATE KEY-----
done`

	got := SanitizeLog(input)

	if strings.Contains(got, "MIIEowIBAAKCAQEAxu2n8Q0gK7v9Zx") {
		t.Error("private key body must be redacted before leaving the host")
	}
	if !strings.Contains(got, "[REDACTED_PRIVATE_KEY]") {
		t.Errorf("expected a redaction placeholder, got: %s", got)
	}
	if !strings.Contains(got, "done") {
		t.Error("surrounding log context should survive redaction")
	}
}

func TestSanitizeLogHandlesEmptyInput(t *testing.T) {
	if got := SanitizeLog(""); got != "" {
		t.Errorf("SanitizeLog(\"\") = %q, want empty", got)
	}
}

func TestSanitizeLogPreservesOrdinaryText(t *testing.T) {
	// Over-redaction destroys the evidence the runbook is built from.
	input := "connection refused to 10.0.0.5:5432 after 3 retries"

	if got := SanitizeLog(input); got != input {
		t.Errorf("ordinary log text was altered:\n got: %s\nwant: %s", got, input)
	}
}

func TestSanitizeLogRedactsVariedCredentialForms(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		secret string
	}{
		{"api key with dash", `api-key: sk_live_abcdef123456`, "sk_live_abcdef123456"},
		{"token assignment", `token=ghp_aBcDeF1234567890xyz`, "ghp_aBcDeF1234567890xyz"},
		{"secret quoted", `secret: "hunter2-very-secret"`, "hunter2-very-secret"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeLog(tc.input); strings.Contains(got, tc.secret) {
				t.Errorf("secret leaked through sanitizer: %s", got)
			}
		})
	}
}

func TestSanitizeConnectionErrors(t *testing.T) {
	input := "mongodb://audit:synthetic-password@host password='alpha beta' bearer short-token"
	got := SanitizeLog(input)
	for _, secret := range []string{"synthetic-password", "alpha", "beta", "short-token"} {
		if strings.Contains(got, secret) {
			t.Errorf("connection error leaked %s: %s", secret, got)
		}
	}
}
