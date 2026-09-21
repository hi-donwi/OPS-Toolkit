package security

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// CertInfo contains parsed SSL/TLS certificate metadata.
type CertInfo struct {
	Subject       string
	Issuer        string
	DNSNames      []string
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int
	IsExpired     bool
	Source        string
}

// AuditCertEndpoint connects to a remote TLS host:port (e.g. "google.com:443")
// and verifies certificate validity.
func AuditCertEndpoint(ctx context.Context, target string) ([]model.Finding, error) {
	// A bare hostname means the default HTTPS port. Checking for any colon
	// would misread a bracketless IPv6 literal, so only add the port when the
	// target does not already parse as host:port.
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: false},
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return []model.Finding{
			{
				ID:          "SEC-CRT-002",
				Title:       fmt.Sprintf("TLS Handshake Failed: %s", target),
				TargetType:  model.TargetSecurity,
				Category:    "Certificate Validity",
				Resource:    "tls:" + target,
				Severity:    model.SeverityCritical,
				Symptom:     fmt.Sprintf("Failed to establish TLS connection: %v", err),
				RootCause:   "Certificate is expired, self-signed without trust, hostname mismatch, or port not serving TLS.",
				RemedySteps: []string{"Renew SSL certificate with valid CA", "Ensure intermediate certificates are bundled"},
			},
		}, nil
	}
	conn := rawConn.(*tls.Conn)
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates presented by %s", target)
	}

	return []model.Finding{expiryFinding("tls:"+target, target, certs[0], remoteRemedy)}, nil
}

// expiryTier maps how much life a certificate has left onto a severity and the
// wording that goes with it. Keeping the tiers as data rather than as four
// near-identical if-branches means a threshold change is a one-line edit and the
// local and remote audits cannot drift apart.
var expiryTiers = []struct {
	// WithinDays is the upper bound of this tier; the first match wins.
	WithinDays int
	Severity   model.Severity
	Title      string
	RootCause  string
}{
	{
		WithinDays: 0,
		Severity:   model.SeverityCritical,
		Title:      "SSL/TLS Certificate Expired",
		RootCause:  "The certificate is past its notAfter date. Clients are already refusing the connection.",
	},
	{
		WithinDays: 7,
		Severity:   model.SeverityCritical,
		Title:      "SSL/TLS Certificate Expiring Within 7 Days",
		RootCause:  "Automated renewal (certbot, ACME, cert-manager) has not completed and the window is nearly closed.",
	},
	{
		WithinDays: 30,
		Severity:   model.SeverityWarning,
		Title:      "SSL/TLS Certificate Expiring Within 30 Days",
		RootCause:  "The renewal window is open. If auto-renewal is configured, it should have run by now.",
	},
}

// remedy step sets, kept separate because a file on disk and a live endpoint
// are fixed differently.
var (
	remoteRemedy = []string{
		"Check the renewal job's last run: journalctl -u certbot.timer -n 50",
		"For Kubernetes, inspect the issuing resources: kubectl get certificate,certificaterequest -A",
		"Renew and reload the terminating proxy once the new chain is in place",
	}
	localRemedy = []string{
		"Replace the certificate file with a renewed chain, including any intermediates",
		"Reload the service that reads it so the new chain is actually served",
	}
)

// expiryFinding scores one certificate's remaining validity.
func expiryFinding(resource, label string, cert *x509.Certificate, remedy []string) model.Finding {
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	expires := cert.NotAfter.Format("2006-01-02")

	for _, tier := range expiryTiers {
		if daysRemaining > tier.WithinDays {
			continue
		}

		symptom := fmt.Sprintf("Certificate for %s expires in %d days (%s). Subject: %s, issuer: %s.",
			label, daysRemaining, expires, cert.Subject.CommonName, cert.Issuer.CommonName)
		if daysRemaining < 0 {
			symptom = fmt.Sprintf("Certificate for %s expired %d days ago (%s). Subject: %s, issuer: %s.",
				label, -daysRemaining, expires, cert.Subject.CommonName, cert.Issuer.CommonName)
		}

		return model.Finding{
			ID:          "SEC-CRT-001",
			Title:       fmt.Sprintf("%s: %s", tier.Title, label),
			TargetType:  model.TargetSecurity,
			Category:    "Certificate Expiry",
			Resource:    resource,
			Severity:    tier.Severity,
			Symptom:     symptom,
			RootCause:   tier.RootCause,
			RemedySteps: remedy,
			Metadata: map[string]string{
				"days_remaining": strconv.Itoa(daysRemaining),
				"not_after":      expires,
				"issuer":         cert.Issuer.CommonName,
			},
		}
	}

	return model.Finding{
		ID:         "SEC-CRT-001",
		Title:      fmt.Sprintf("SSL/TLS Certificate Valid: %s", label),
		TargetType: model.TargetSecurity,
		Category:   "Certificate Health",
		Resource:   resource,
		Severity:   model.SeverityPass,
		Symptom: fmt.Sprintf("Valid for %d more days (expires %s, issuer: %s)",
			daysRemaining, expires, cert.Issuer.CommonName),
		Metadata: map[string]string{"days_remaining": strconv.Itoa(daysRemaining)},
	}
}

// AuditLocalCertPaths scans common SSL directory paths for expiring .crt or .pem certificates.
func AuditLocalCertPaths() []model.Finding {
	findings := make([]model.Finding, 0)
	certDirs := []string{
		"/etc/ssl/certs",
		"/etc/letsencrypt/live",
		"/etc/pki/tls/certs",
	}

	for _, dir := range certDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}

		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".crt") && !strings.HasSuffix(path, ".pem") {
				return nil
			}

			// Read and parse PEM
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			block, _ := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil
			}

			// Same scoring as the remote audit, so a certificate does not
			// report differently depending on how it was discovered. Only
			// actionable results are kept: /etc/ssl/certs holds hundreds of CA
			// bundle entries and a PASS for each would bury the real finding.
			f := expiryFinding("file:"+path, filepath.Base(path), cert, localRemedy)
			if f.Severity != model.SeverityPass {
				findings = append(findings, f)
			}

			return nil
		})
	}

	return findings
}
