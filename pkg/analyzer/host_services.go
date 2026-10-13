package analyzer

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
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

// -----------------------------------------------------------------------------
// HOST-CLK-001 — clock synchronization / NTP status
// -----------------------------------------------------------------------------

func parseTimedatectlSync(output string) (synced bool, found bool) {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "NTPSynchronized=") {
			val := strings.ToLower(strings.TrimPrefix(trimmed, "NTPSynchronized="))
			return val == "yes" || val == "1" || val == "true", true
		}
		if strings.Contains(trimmed, "System clock synchronized:") {
			val := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "System clock synchronized:")))
			return strings.HasPrefix(val, "yes"), true
		}
	}
	return false, false
}

func parseChronycTracking(output string) (synced bool, found bool) {
	hasLeapNormal := false
	hasValidStratum := false
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "leap status") {
			if strings.Contains(lower, "normal") {
				hasLeapNormal = true
			}
		}
		if strings.Contains(lower, "stratum") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				if s, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && s > 0 && s < 16 {
					hasValidStratum = true
				}
			}
		}
	}
	if hasLeapNormal && hasValidStratum {
		return true, true
	}
	if strings.Contains(strings.ToLower(output), "not synchronised") {
		return false, true
	}
	return false, false
}

func evaluateClockSync(synced bool, source string) []model.Finding {
	if synced {
		return []model.Finding{{
			ID:         "HOST-CLK-001",
			Title:      "Host Clock Synchronized",
			TargetType: model.TargetHost,
			Category:   "Time Synchronization",
			Resource:   "clock:" + source,
			Severity:   model.SeverityPass,
			Symptom:    fmt.Sprintf("System clock is synchronized with NTP (%s).", source),
		}}
	}

	return []model.Finding{{
		ID:          "HOST-CLK-001",
		Title:       "Host Clock Not Synchronized",
		TargetType:  model.TargetHost,
		Category:    "Time Synchronization",
		Resource:    "clock:" + source,
		Severity:    model.SeverityCritical,
		Symptom:     fmt.Sprintf("Host clock is not synchronized with NTP (%s). Time drift causes database consistency errors, transaction sequencing failures, and token expiration bugs.", source),
		RootCause:   "NTP synchronization daemon (systemd-timesyncd or chrony) is inactive, disabled, or failing upstream synchronization.",
		RemedySteps: []string{
			"Enable and start systemd-timesyncd: systemctl enable --now systemd-timesyncd",
			"Or install and verify chrony: apt-get install -y chrony && systemctl start chrony && chronyc tracking",
			"Check UDP port 123 outbound network reachability to NTP servers",
		},
		QuickFixCmd: "systemctl restart systemd-timesyncd",
	}}
}

func (e *Engine) checkClockSync(ctx context.Context) []model.Finding {
	if runtime.GOOS != "linux" {
		return nil
	}

	// 1. Try timedatectl
	if e.run.Available("timedatectl") {
		out, err := e.run.Run(ctx, 5*time.Second, "timedatectl", "show", "--property=NTPSynchronized")
		if err == nil {
			if synced, ok := parseTimedatectlSync(string(out)); ok {
				return evaluateClockSync(synced, "systemd-timesyncd")
			}
		}
		// Fallback to timedatectl status
		out, err = e.run.Run(ctx, 5*time.Second, "timedatectl", "status")
		if err == nil {
			if synced, ok := parseTimedatectlSync(string(out)); ok {
				return evaluateClockSync(synced, "timedatectl")
			}
		}
	}

	// 2. Try chronyc
	if e.run.Available("chronyc") {
		out, err := e.run.Run(ctx, 5*time.Second, "chronyc", "tracking")
		if err == nil {
			if synced, ok := parseChronycTracking(string(out)); ok {
				return evaluateClockSync(synced, "chrony")
			}
		}
	}

	return nil
}
