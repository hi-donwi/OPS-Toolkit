package security

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func TestAuditCertEndpointHandlesUnreachableTarget(t *testing.T) {
	findings, err := AuditCertEndpoint(context.Background(), "127.0.0.1:54321")
	if err != nil {
		t.Fatalf("an unreachable endpoint should produce a finding, not an error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a TLS handshake failure finding")
	}
	if findings[0].ID != "SEC-CRT-002" {
		t.Errorf("ID = %s, want SEC-CRT-002", findings[0].ID)
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want CRITICAL", findings[0].Severity)
	}
}

func TestAuditCertEndpointHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A cancelled context must not hang for the full dial timeout.
	start := time.Now()
	if _, err := AuditCertEndpoint(ctx, "example.com:443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("cancellation did not short-circuit the dial")
	}
}

func TestAuditCertEndpointAppendsDefaultPort(t *testing.T) {
	// A bare hostname means :443. Testing for any colon would misparse a
	// bracketless IPv6 literal.
	findings, err := AuditCertEndpoint(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(findings[0].Resource, ":443") {
		t.Errorf("resource = %q, want the default port appended", findings[0].Resource)
	}
}

func TestAuditExposedPortsDoesNotPanic(t *testing.T) {
	if findings := AuditExposedPorts(); findings == nil {
		t.Error("expected a non-nil slice")
	}
}

func TestAuditSSHConfigIsPlatformGuarded(t *testing.T) {
	// The parser reads a Linux path; on other platforms it must return cleanly
	// rather than reporting a missing file as a finding.
	if findings := AuditSSHConfig(); findings == nil {
		t.Error("expected a non-nil slice")
	}
}

// expiryFinding is the single scoring path shared by the remote and local
// certificate audits, so it is worth pinning each tier boundary.
func TestExpiryFindingTiers(t *testing.T) {
	tests := []struct {
		name         string
		daysFromNow  int
		wantSeverity model.Severity
	}{
		{"expired", -3, model.SeverityCritical},
		{"expires today", 0, model.SeverityCritical},
		{"inside the 7 day window", 5, model.SeverityCritical},
		{"on the 7 day boundary", 7, model.SeverityCritical},
		{"inside the 30 day window", 20, model.SeverityWarning},
		{"on the 30 day boundary", 30, model.SeverityWarning},
		{"comfortably valid", 90, model.SeverityPass},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotAfter: time.Now().Add(time.Duration(tc.daysFromNow)*24*time.Hour + time.Hour),
				Subject:  pkix.Name{CommonName: "example.com"},
				Issuer:   pkix.Name{CommonName: "Test CA"},
			}

			f := expiryFinding("tls:example.com:443", "example.com:443", cert, remoteRemedy)

			if f.Severity != tc.wantSeverity {
				t.Errorf("severity = %s, want %s (%d days out)", f.Severity, tc.wantSeverity, tc.daysFromNow)
			}
			if f.ID != "SEC-CRT-001" {
				t.Errorf("ID = %s, want SEC-CRT-001", f.ID)
			}
		})
	}
}

func TestExpiryFindingWordsExpiryInThePast(t *testing.T) {
	cert := &x509.Certificate{
		NotAfter: time.Now().Add(-10 * 24 * time.Hour),
		Subject:  pkix.Name{CommonName: "old.example.com"},
		Issuer:   pkix.Name{CommonName: "Test CA"},
	}

	f := expiryFinding("tls:old", "old.example.com", cert, remoteRemedy)

	// "expires in -10 days" is the kind of wording that makes an operator
	// distrust the whole report. (A plain dash check would false-positive on
	// the ISO date in the same sentence.)
	if strings.Contains(f.Symptom, "in -") || strings.Contains(f.Symptom, "-10 days") {
		t.Errorf("an expired certificate should read as 'expired N days ago', got: %s", f.Symptom)
	}
	if !strings.Contains(f.Symptom, "ago") {
		t.Errorf("symptom = %q, want it to say how long ago it expired", f.Symptom)
	}
}
