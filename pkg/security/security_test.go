package security

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
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

func TestParseProcNetListening(t *testing.T) {
	// Sample /proc/net/tcp fixture with port 5432 (0x1538) on 0.0.0.0,
	// port 9092 (0x2384) on 0.0.0.0, port 6379 (0x18EB) on 127.0.0.1 (0100007F),
	// and port 8080 (0x1F90) in TIME_WAIT (06).
	procNetTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:2384 00000000:0000 0A 00000000:00000000 00:00000000 00000000   1000        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   1000        0 12347 1 0000000000000000 100 0 0 10 0
   3: 00000000:1F90 00000000:0000 06 00000000:00000000 00:00000000 00000000   1000        0 12348 1 0000000000000000 100 0 0 10 0
`

	tests := []struct {
		name        string
		port        int
		wantExposed bool
		wantBind    string
	}{
		{"PostgreSQL 5432 exposed on all interfaces", 5432, true, "0.0.0.0 (all interfaces)"},
		{"Kafka 9092 exposed on all interfaces", 9092, true, "0.0.0.0 (all interfaces)"},
		{"Redis 6379 safe on loopback", 6379, false, ""},
		{"Non-listening state (TIME_WAIT)", 8080, false, ""},
		{"Unopened port 2375", 2375, false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exposed, bind := parseProcNetListening(strings.NewReader(procNetTCP), tc.port)
			if exposed != tc.wantExposed {
				t.Errorf("port %d exposed = %v, want %v", tc.port, exposed, tc.wantExposed)
			}
			if bind != tc.wantBind {
				t.Errorf("port %d bind = %q, want %q", tc.port, bind, tc.wantBind)
			}
		})
	}
}

func TestSSHDropInCanDisablePasswordAuthentication(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("Include sshd_config.d/*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config.d", "60-cloudimg-settings.conf"), []byte("PasswordAuthentication no\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, finding := range auditSSHConfigFile(filepath.Join(dir, "sshd_config")) {
		if finding.ID == "SEC-SSH-002" {
			t.Fatalf("readable drop-in disabling password authentication was ignored: %+v", finding)
		}
	}
}

func TestUnreadableEarlierDropInDoesNotHideLaterPasswordDisable(t *testing.T) {
	dir := t.TempDir()
	dropin := filepath.Join(dir, "sshd_config.d")
	if err := os.Mkdir(dropin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("Include sshd_config.d/*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropin, "50-cloud-init.conf"), []byte("PasswordAuthentication no\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropin, "60-cloudimg-settings.conf"), []byte("PasswordAuthentication no\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, finding := range auditSSHConfigFile(filepath.Join(dir, "sshd_config")) {
		if finding.ID == "SEC-SSH-002" {
			t.Fatalf("later readable drop-in was discarded after an unreadable file: %+v", finding)
		}
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

func TestExpiryFindingCACertificateSeverity(t *testing.T) {
	caCert := &x509.Certificate{
		NotAfter: time.Now().Add(-30 * 24 * time.Hour),
		Subject:  pkix.Name{CommonName: "Legacy Root CA"},
		Issuer:   pkix.Name{CommonName: "Legacy Root CA"},
		IsCA:     true,
	}

	f := expiryFinding("file:/etc/ssl/certs/legacy.pem", "legacy.pem", caCert, localRemedy)
	if f.Severity != model.SeverityWarning {
		t.Errorf("expired CA certificate severity = %s, want WARNING", f.Severity)
	}
	if !strings.Contains(f.Title, "Trust Store Root/CA Expired") {
		t.Errorf("title = %q, want it to mention Trust Store Root/CA Expired", f.Title)
	}
}
