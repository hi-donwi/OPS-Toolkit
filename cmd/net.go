package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/detector"
	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/netdiag"
	"github.com/hi-donwi/OPS-Toolkit/pkg/report"
	"github.com/spf13/cobra"
)

// defaultNetTarget is a well-known anycast address that answers ICMP, used when
// the operator does not name one.
const defaultNetTarget = "1.1.1.1"

// slowResolverThreshold is the per-nameserver latency above which a resolver is
// reported as slow rather than healthy.
const slowResolverThreshold = 250 * time.Millisecond

var netCmd = &cobra.Command{
	Use:   "net [target-host/ip]",
	Short: "Diagnose network connectivity, DNS resolution benchmark, and Path MTU drop",
	Long: `net performs deep network diagnostics across three critical SRE dimensions:
1. Upstream DNS resolution benchmark across local resolv.conf and public resolvers.
2. TCP SYN-ACK connection latency to target endpoints.
3. Path MTU Discovery with Don't Fragment (DF) packets to detect Docker Swarm VXLAN (1450) or CNI packet drops.

Example:
  opskit net
  opskit net 1.1.1.1
  opskit net dns google.com
  opskit net mtu 10.0.0.1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target := defaultNetTarget
		if len(args) > 0 {
			target = args[0]
		}

		return runNetworkSuite(target)
	},
}

var netDNSCmd = &cobra.Command{
	Use:   "dns [domain]",
	Short: "Benchmark DNS resolution latency across nameservers",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := ""
		if len(args) > 0 {
			domain = args[0]
		} else if envDomain := strings.TrimSpace(os.Getenv("OPSKIT_DNS_PROBE")); envDomain != "" {
			domain = envDomain
		} else {
			domain = "google.com"
		}

		results := netdiag.BenchmarkDNS(domain)

		// --json is a global flag; a subcommand that quietly ignores it is
		// worse than one that never offered it.
		if JSONOutput {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"domain":  domain,
				"results": results,
			})
		}

		c := report.Colors(NoColor)
		fmt.Printf("Benchmarking DNS resolution for '%s'...\n\n", domain)
		fmt.Printf("%-24s %-12s %s\n", "NAMESERVER", "LATENCY", "STATUS")
		fmt.Println(strings.Repeat("-", 50))

		for _, r := range results {
			var status string
			switch {
			case !r.Success:
				status = c.Wrap(c.Red, "FAILED") + " (" + r.Error + ")"
			case r.Duration > slowResolverThreshold:
				status = c.Wrap(c.Yellow, "SLOW")
			default:
				status = c.Wrap(c.Green, "PASS")
			}
			fmt.Printf("%-24s %-12s %s\n", r.Nameserver, r.Duration.Round(time.Millisecond), status)
		}

		fmt.Println()
		return nil
	},
}

var netMTUCmd = &cobra.Command{
	Use:   "mtu [target-host/ip]",
	Short: "Probe Path MTU boundaries (1500, 1450 VXLAN, 1420 WireGuard, 1280)",
	RunE: func(cmd *cobra.Command, args []string) error {
		target := defaultNetTarget
		if len(args) > 0 {
			target = args[0]
		}

		// Without this baseline, a target that simply ignores ICMP reports as
		// four dropped packet sizes — indistinguishable from a real MTU fault.
		reachable := netdiag.PingReachable(target)
		results := netdiag.ProbeMTU(target)

		if JSONOutput {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"target":         target,
				"icmp_reachable": reachable,
				"results":        results,
			})
		}

		c := report.Colors(NoColor)
		fmt.Printf("Testing Path MTU against '%s' with the Don't Fragment bit...\n\n", target)
		fmt.Printf("%-10s %-15s %s\n", "MTU SIZE", "PAYLOAD BYTES", "RESULT")
		fmt.Println(strings.Repeat("-", 50))

		for _, r := range results {
			var status string
			switch {
			case r.Pass:
				status = c.Wrap(c.Green, "PASS (no fragmentation)")
			case !reachable:
				status = c.Wrap(c.Gray, "N/A (target does not answer ICMP)")
			default:
				status = c.Wrap(c.Red, "DROPPED / packet too large")
			}
			fmt.Printf("%-10d %-15d %s\n", r.TestedMTU, r.PayloadBytes, status)
		}

		fmt.Println()
		if !reachable {
			fmt.Println("Note: the target ignores ICMP echo, so no MTU conclusion can be drawn.")
			fmt.Println("      Probe a host that answers ping, or an overlay peer's internal IP.")
		}
		return nil
	},
}

func init() {
	netCmd.AddCommand(netDNSCmd)
	netCmd.AddCommand(netMTUCmd)
	RootCmd.AddCommand(netCmd)
}

func runNetworkSuite(target string) error {
	netRep := netdiag.RunNetworkAudit(target)
	env := detector.Detect()

	rep := &model.Report{
		Title:       fmt.Sprintf("Network Connectivity, DNS & MTU Audit (%s)", target),
		Timestamp:   netRep.Timestamp,
		Duration:    netRep.Duration.Round(time.Millisecond).String(),
		Environment: env,
		Findings:    netRep.Findings,
	}

	for _, f := range rep.Findings {
		switch f.Severity {
		case model.SeverityCritical:
			rep.Summary.Critical++
		case model.SeverityWarning:
			rep.Summary.Warning++
		case model.SeverityInfo:
			rep.Summary.Info++
		case model.SeverityPass:
			rep.Summary.Pass++
		}
	}

	if OutputFile != "" {
		_ = report.SaveToFile(OutputFile, rep)
		fmt.Printf("Report successfully saved to %s\n", OutputFile)
	}

	if JSONOutput {
		return report.PrintJSON(os.Stdout, rep)
	}

	// Print Summary Tables
	fmt.Printf("\n================================================================================\n")
	fmt.Printf("               OPSKIT NETWORK CONNECTIVITY & MTU DIAGNOSTICS                    \n")
	fmt.Printf("================================================================================\n")
	fmt.Printf("Target Host:       %s\n", target)
	if netRep.ICMPReachable && netRep.MaxSafeMTU > 0 {
		fmt.Printf("Max Safe Path MTU: %d bytes\n\n", netRep.MaxSafeMTU)
	} else {
		fmt.Printf("Max Safe Path MTU: unknown (target does not answer ICMP echo)\n\n")
	}

	fmt.Printf("--- DNS Resolution Latencies ---\n")
	for _, dns := range netRep.DNSResults {
		status := "PASS"
		if !dns.Success {
			status = "FAIL"
		}
		fmt.Printf("  • %-22s : %8s [%s]\n", dns.Nameserver, dns.Duration.Round(time.Millisecond), status)
	}

	fmt.Printf("\n--- Path MTU Boundaries ---\n")
	for _, mtu := range netRep.MTUResults {
		res := "PASS"
		if !mtu.Pass {
			res = "DROP"
			if !netRep.ICMPReachable {
				res = "N/A (ICMP filtered)"
			}
		}
		fmt.Printf("  • MTU %4d (Payload: %4d bytes) : [%s]\n", mtu.TestedMTU, mtu.PayloadBytes, res)
	}

	report.PrintConsole(os.Stdout, rep, NoColor)
	return nil
}
