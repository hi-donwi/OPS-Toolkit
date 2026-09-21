package analyzer

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// -----------------------------------------------------------------------------
// HOST-DNS-001 — resolver availability and latency
// -----------------------------------------------------------------------------

func (e *Engine) checkDNS(ctx context.Context) []model.Finding {
	probe := dnsProbeDomain()

	start := e.now()
	_, err := e.lookupHost(ctx, probe)
	duration := e.now().Sub(start)

	switch {
	case err != nil:
		return []model.Finding{{
			ID:         "HOST-DNS-001",
			Title:      "DNS Resolution Failed",
			TargetType: model.TargetHost,
			Category:   "Network Connectivity",
			Resource:   "dns:" + probe,
			Severity:   model.SeverityCritical,
			Symptom:    fmt.Sprintf("Host failed to resolve %s: %v", probe, err),
			RootCause:  "The nameservers in /etc/resolv.conf are unreachable, the local resolver is down, or egress UDP/53 is blocked.",
			RemedySteps: []string{
				"Inspect the configured nameservers: cat /etc/resolv.conf",
				"Check the local stub resolver: systemctl status systemd-resolved",
				"Override the probe target with OPSKIT_DNS_PROBE if this host is intentionally air-gapped",
			},
			QuickFixCmd: "systemctl restart systemd-resolved",
		}}
	case duration > dnsSlowThreshold:
		return []model.Finding{{
			ID:          "HOST-DNS-001",
			Title:       "High DNS Resolution Latency",
			TargetType:  model.TargetHost,
			Category:    "Network Latency",
			Resource:    "dns:" + probe,
			Severity:    model.SeverityWarning,
			Symptom:     fmt.Sprintf("DNS lookup took %v (threshold %v)", duration.Round(time.Millisecond), dnsSlowThreshold),
			RootCause:   "Nameserver timeout, network jitter, or a cold cache forcing full recursive resolution on every lookup.",
			RemedySteps: []string{"Verify primary nameserver responsiveness", "Enable local DNS caching (systemd-resolved or dnsmasq)"},
		}}
	default:
		return []model.Finding{{
			ID:         "HOST-DNS-001",
			Title:      "DNS Resolution Responsive",
			TargetType: model.TargetHost,
			Category:   "Network",
			Resource:   "dns:" + probe,
			Severity:   model.SeverityPass,
			Symptom:    fmt.Sprintf("Lookup of %s succeeded in %v", probe, duration.Round(time.Millisecond)),
		}}
	}
}

// dnsProbeDomain returns the name used to test resolution. Air-gapped and
// split-horizon estates must be able to point this at a name they can actually
// resolve, otherwise every run reports a false CRITICAL.
func dnsProbeDomain() string {
	if custom := strings.TrimSpace(os.Getenv("OPSKIT_DNS_PROBE")); custom != "" {
		return custom
	}
	return "google.com"
}

// -----------------------------------------------------------------------------
// HOST-SYS-001 — failed systemd units
// -----------------------------------------------------------------------------

// parseFailedUnits extracts unit names from `systemctl --failed --no-legend`.
func parseFailedUnits(output string) []string {
	units := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimPrefix(fields[0], "●") // some versions bullet the row
		name = strings.TrimSpace(name)
		if name == "" {
			if len(fields) < 2 {
				continue
			}
			name = fields[1]
		}
		if !strings.Contains(name, ".") {
			continue // not a unit name
		}
		units = append(units, name)
	}
	return units
}

func (e *Engine) checkSystemdUnits(ctx context.Context) []model.Finding {
	if runtime.GOOS != "linux" || !e.env.HasSystemd || !e.run.Available("systemctl") {
		return nil
	}

	out, err := e.run.Run(ctx, 10*time.Second, "systemctl", "--failed", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil
	}

	return evaluateFailedUnits(parseFailedUnits(string(out)))
}

func evaluateFailedUnits(units []string) []model.Finding {
	if len(units) == 0 {
		return []model.Finding{{
			ID:         "HOST-SYS-001",
			Title:      "All Systemd Services Active",
			TargetType: model.TargetHost,
			Category:   "Service Health",
			Resource:   "systemd:services",
			Severity:   model.SeverityPass,
			Symptom:    "No failed systemd units detected.",
		}}
	}

	findings := make([]model.Finding, 0, len(units))
	for _, unit := range units {
		findings = append(findings, model.Finding{
			ID:         "HOST-SYS-001",
			Title:      fmt.Sprintf("Systemd Service Failed: %s", unit),
			TargetType: model.TargetHost,
			Category:   "Service Degradation",
			Resource:   "systemd:" + unit,
			Severity:   model.SeverityCritical,
			Symptom:    fmt.Sprintf("Unit %s is in failed state.", unit),
			RootCause:  "The unit exited non-zero, exceeded its start limit, or a declared dependency never became ready.",
			RemedySteps: []string{
				fmt.Sprintf("Read the failure logs: journalctl -u %s -n 50 --no-pager", unit),
				fmt.Sprintf("Inspect the unit state and last exit code: systemctl status %s", unit),
			},
			QuickFixCmd: fmt.Sprintf("systemctl restart %s", unit),
		})
	}

	return findings
}
