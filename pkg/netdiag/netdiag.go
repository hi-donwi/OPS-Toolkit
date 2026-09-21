package netdiag

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// DNSCheckResult holds latency and status for a specific nameserver.
type DNSCheckResult struct {
	Nameserver string        `json:"nameserver"`
	Duration   time.Duration `json:"duration"`
	Success    bool          `json:"success"`
	Error      string        `json:"error,omitempty"`
}

// MTUCheckResult represents path MTU probe findings.
type MTUCheckResult struct {
	Target       string `json:"target"`
	TestedMTU    int    `json:"tested_mtu"`
	PayloadBytes int    `json:"payload_bytes"`
	Pass         bool   `json:"pass"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// TCPProbeResult holds latency metrics for a TCP handshake.
type TCPProbeResult struct {
	Target   string        `json:"target"`
	Port     int           `json:"port"`
	Duration time.Duration `json:"duration"`
	Success  bool          `json:"success"`
	Error    string        `json:"error,omitempty"`
}

// NetworkReport contains aggregated network diagnostic telemetry.
type NetworkReport struct {
	Target     string           `json:"target"`
	Timestamp  time.Time        `json:"timestamp"`
	DNSResults []DNSCheckResult `json:"dns_results"`
	MTUResults []MTUCheckResult `json:"mtu_results"`
	TCPResults []TCPProbeResult `json:"tcp_results"`
	MaxSafeMTU int              `json:"max_safe_mtu"`
	// ICMPReachable records whether the target answers a minimum-size ping at
	// all. Every MTU verdict is meaningless when it does not.
	ICMPReachable bool            `json:"icmp_reachable"`
	Duration      time.Duration   `json:"duration"`
	Findings      []model.Finding `json:"findings"`
}

// RunNetworkAudit executes comprehensive DNS, TCP, and MTU checks against target.
func RunNetworkAudit(target string) *NetworkReport {
	if target == "" {
		target = "1.1.1.1"
	}

	report := &NetworkReport{
		Target:     target,
		Timestamp:  time.Now(),
		DNSResults: make([]DNSCheckResult, 0),
		MTUResults: make([]MTUCheckResult, 0),
		TCPResults: make([]TCPProbeResult, 0),
		Findings:   make([]model.Finding, 0),
	}

	// 1. Benchmark DNS (pass "" to respect OPSKIT_DNS_PROBE if configured)
	report.DNSResults = BenchmarkDNS("")
	for _, dns := range report.DNSResults {
		if !dns.Success {
			report.Findings = append(report.Findings, model.Finding{
				ID:          "NET-DNS-FAIL",
				Title:       fmt.Sprintf("DNS Resolver Unreachable: %s", dns.Nameserver),
				TargetType:  model.TargetHost,
				Category:    "DNS Connectivity",
				Resource:    "dns:" + dns.Nameserver,
				Severity:    model.SeverityCritical,
				Symptom:     fmt.Sprintf("Query to nameserver %s timed out or failed: %s", dns.Nameserver, dns.Error),
				RootCause:   "Upstream DNS server offline or port 53 UDP traffic blocked by firewall/security group.",
				RemedySteps: []string{"Verify /etc/resolv.conf configuration", "Test DNS reachability using dig or nslookup"},
				QuickFixCmd: "systemctl restart systemd-resolved",
			})
		} else if dns.Duration > 300*time.Millisecond {
			report.Findings = append(report.Findings, model.Finding{
				ID:          "NET-DNS-LATENCY",
				Title:       fmt.Sprintf("High DNS Resolution Latency: %s", dns.Nameserver),
				TargetType:  model.TargetHost,
				Category:    "DNS Latency",
				Resource:    "dns:" + dns.Nameserver,
				Severity:    model.SeverityWarning,
				Symptom:     fmt.Sprintf("DNS lookup took %v (>300ms threshold).", dns.Duration),
				RootCause:   "Network congestion, distant nameserver, or lack of local DNS caching.",
				RemedySteps: []string{"Enable local DNS caching (dnsmasq or systemd-resolved)", "Switch to low-latency resolver (1.1.1.1 / 8.8.8.8)"},
			})
		}
	}

	// 2. Probe TCP Latency
	tcpProbe := ProbeTCPHandshake(target, 443, 3*time.Second)
	report.TCPResults = append(report.TCPResults, tcpProbe)
	if !tcpProbe.Success {
		report.Findings = append(report.Findings, model.Finding{
			ID:          "NET-TCP-CONNECT",
			Title:       fmt.Sprintf("TCP Handshake Failed: %s:%d", target, tcpProbe.Port),
			TargetType:  model.TargetHost,
			Category:    "Network Connectivity",
			Resource:    fmt.Sprintf("tcp:%s:%d", target, tcpProbe.Port),
			Severity:    model.SeverityWarning,
			Symptom:     fmt.Sprintf("Connection failed: %s", tcpProbe.Error),
			RootCause:   "Target host unreachable, port closed, or egress firewall dropping packets.",
			RemedySteps: []string{"Check network routing and security groups"},
		})
	}

	// 3. Probe MTU boundaries.
	//
	// A dropped large packet only means "MTU too small" if the target answers
	// small packets. Many hosts and clouds filter ICMP wholesale; without this
	// baseline every such target is reported as a critical VXLAN MTU fault.
	report.ICMPReachable = PingReachable(target)
	report.MTUResults = ProbeMTU(target)
	report.MaxSafeMTU = 0
	for _, m := range report.MTUResults {
		if m.Pass && m.TestedMTU > report.MaxSafeMTU {
			report.MaxSafeMTU = m.TestedMTU
		}
	}

	report.Findings = append(report.Findings, evaluateMTU(target, report.ICMPReachable, report.MTUResults)...)

	if len(report.Findings) == 0 {
		report.Findings = append(report.Findings, model.Finding{
			ID:         "NET-ALL-HEALTHY",
			Title:      "Network Connectivity, DNS & MTU Healthy",
			TargetType: model.TargetHost,
			Category:   "Network",
			Resource:   "network:overall",
			Severity:   model.SeverityPass,
			Symptom:    fmt.Sprintf("Max safe path MTU: %d bytes. DNS and TCP latency within normal parameters.", report.MaxSafeMTU),
		})
	}

	report.Duration = time.Since(report.Timestamp)
	return report
}

// evaluateMTU turns raw probe results into findings, gated on ICMP being usable
// as a measurement tool against this target in the first place.
func evaluateMTU(target string, reachable bool, results []MTUCheckResult) []model.Finding {
	if !reachable {
		return []model.Finding{{
			ID:         "NET-MTU-UNKNOWN",
			Title:      "Path MTU Could Not Be Measured",
			TargetType: model.TargetHost,
			Category:   "Overlay Network & MTU",
			Resource:   "mtu:" + target,
			Severity:   model.SeverityInfo,
			Symptom:    fmt.Sprintf("%s does not answer even a minimum-size ICMP echo, so packet-size probes carry no information.", target),
			RootCause:  "ICMP echo is filtered by the target, a firewall, or a cloud security group. This is a limitation of the probe, not a fault in the network path.",
			RemedySteps: []string{
				"Re-run against a host that answers ICMP: opskit net mtu <reachable-host>",
				"Inside a Swarm or Kubernetes overlay, probe another node's overlay IP rather than a public address",
			},
		}}
	}

	findings := make([]model.Finding, 0, 1)

	// Report the tightest failure only. If 1500 drops but 1450 passes the path
	// simply has a smaller-than-Ethernet MTU, which is normal on tunnels; the
	// actionable fault is when the overlay's own working size cannot pass.
	for _, m := range results {
		if m.Pass {
			continue
		}

		switch m.TestedMTU {
		case 1450:
			findings = append(findings, model.Finding{
				ID:         "SWM-MTU-001",
				Title:      "Docker Swarm VXLAN MTU (1450) Drop Detected",
				TargetType: model.TargetSwarm,
				Category:   "Overlay Network & MTU",
				Resource:   "mtu:1450",
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("1422-byte payloads with the Don't Fragment bit set are dropped on the path to %s.", target),
				RootCause:  "The underlay MTU cannot carry VXLAN's 50-byte encapsulation overhead. Large packets vanish silently: small requests succeed while large responses hang, which usually gets misdiagnosed as an application timeout.",
				RemedySteps: []string{
					"Lower the overlay MTU: docker network create --opt com.docker.network.driver.mtu=1400 <network>",
					"In compose, set driver_opts: com.docker.network.driver.mtu: 1400 on the overlay network",
					"Confirm the physical NIC MTU on every node: ip link show",
				},
				Metadata: map[string]string{"payload_bytes": strconv.Itoa(m.PayloadBytes)},
			})
		case 1280:
			findings = append(findings, model.Finding{
				ID:         "NET-MTU-001",
				Title:      "Path MTU Below IPv6 Minimum (1280)",
				TargetType: model.TargetHost,
				Category:   "Overlay Network & MTU",
				Resource:   "mtu:1280",
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("Even 1252-byte payloads are dropped on the path to %s.", target),
				RootCause:  "The path MTU is below the 1280-byte IPv6 minimum. Stacked encapsulation (VPN inside an overlay) is the usual cause, and it breaks TLS handshakes whose certificate chains exceed one segment.",
				RemedySteps: []string{
					"Identify and remove a layer of encapsulation on this path",
					"Clamp TCP MSS at the gateway: iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
				},
			})
		}
	}

	return findings
}

// BenchmarkDNS queries local resolv.conf nameservers and public resolvers concurrently.
func BenchmarkDNS(domain string) []DNSCheckResult {
	return BenchmarkDNSContext(context.Background(), domain)
}

// BenchmarkDNSContext queries nameservers concurrently under the provided context deadline.
func BenchmarkDNSContext(ctx context.Context, domain string) []DNSCheckResult {
	if domain == "" {
		if envDomain := strings.TrimSpace(os.Getenv("OPSKIT_DNS_PROBE")); envDomain != "" {
			domain = envDomain
		} else {
			domain = "google.com"
		}
	}

	resolvers := getNameservers()
	// Add Cloudflare and Google
	resolvers = append(resolvers, "1.1.1.1:53", "8.8.8.8:53")

	results := make([]DNSCheckResult, len(resolvers))
	var wg sync.WaitGroup

	for i, r := range resolvers {
		wg.Add(1)
		go func(idx int, ns string) {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
					return dialer.DialContext(dialCtx, "udp", ns)
				},
			}

			start := time.Now()
			probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err := resolver.LookupHost(probeCtx, domain)
			dur := time.Since(start)
			cancel()

			res := DNSCheckResult{
				Nameserver: ns,
				Duration:   dur,
				Success:    err == nil,
			}
			if err != nil {
				res.Error = err.Error()
			}
			results[idx] = res
		}(i, r)
	}
	wg.Wait()

	return results
}

// ProbeTCPHandshake measures TCP SYN-ACK latency to a specific target and port.
func ProbeTCPHandshake(target string, port int, timeout time.Duration) TCPProbeResult {
	addr := net.JoinHostPort(target, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	dur := time.Since(start)

	res := TCPProbeResult{
		Target:   target,
		Port:     port,
		Duration: dur,
		Success:  err == nil,
	}
	if err != nil {
		res.Error = err.Error()
	} else {
		conn.Close()
	}

	return res
}

// PingReachable reports whether target answers a minimum-size ICMP echo. It is
// the baseline every MTU verdict is interpreted against.
func PingReachable(target string) bool {
	res := testPingMTU(target, 0, 56)
	return res.Pass
}

// ProbeMTU checks path MTU across the boundary sizes that matter operationally,
// sending each with the Don't Fragment bit so an oversized packet is dropped
// rather than silently split.
//
// Payload sizes are the MTU minus 28 bytes: a 20-byte IPv4 header plus an
// 8-byte ICMP header.
func ProbeMTU(target string) []MTUCheckResult {
	testCases := []struct {
		MTU     int
		Payload int
	}{
		{1500, 1472}, // standard Ethernet
		{1450, 1422}, // Docker Swarm VXLAN overlay
		{1420, 1392}, // WireGuard / Calico IPIP
		{1280, 1252}, // IPv6 minimum
	}

	// Each probe waits out its own timeout, so running them serially costs the
	// sum of four timeouts on a filtered path. They are independent; run them
	// together and keep the result order stable.
	results := make([]MTUCheckResult, len(testCases))
	var wg sync.WaitGroup

	for i, tc := range testCases {
		wg.Add(1)
		go func(idx int, mtu, payload int) {
			defer wg.Done()
			results[idx] = testPingMTU(target, mtu, payload)
		}(i, tc.MTU, tc.Payload)
	}
	wg.Wait()

	return results
}

func testPingMTU(target string, mtu, payload int) MTUCheckResult {
	res := MTUCheckResult{
		Target:       target,
		TestedMTU:    mtu,
		PayloadBytes: payload,
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		// macOS: ping -D (Don't Fragment) -s <size> -c 1 -W 1000 <target>
		cmd = exec.Command("ping", "-D", "-s", fmt.Sprintf("%d", payload), "-c", "1", "-W", "1000", target)
	} else {
		// Linux: ping -M do (Don't Fragment) -s <size> -c 1 -W 1 <target>
		cmd = exec.Command("ping", "-M", "do", "-s", fmt.Sprintf("%d", payload), "-c", "1", "-W", "1", target)
	}

	out, err := cmd.CombinedOutput()
	if err == nil {
		res.Pass = true
	} else {
		res.Pass = false
		res.ErrorMessage = strings.TrimSpace(string(out))
		if res.ErrorMessage == "" {
			res.ErrorMessage = err.Error()
		}
	}

	return res
}

func getNameservers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return []string{"127.0.0.1:53"}
	}
	defer f.Close()

	var sb strings.Builder
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteString("\n")
	}

	return parseResolvConf(sb.String())
}

// parseResolvConf extracts nameserver addresses from a resolv.conf body,
// returning them as dialable host:port strings.
func parseResolvConf(content string) []string {
	resolvers := make([]string, 0, 3)

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// JoinHostPort brackets IPv6 literals. Appending ":53" by hand produces
		// an unusable address for every IPv6 nameserver, because the colon test
		// cannot tell a v6 literal from an address that already has a port.
		resolvers = append(resolvers, net.JoinHostPort(fields[1], "53"))
	}

	if len(resolvers) == 0 {
		resolvers = append(resolvers, "127.0.0.1:53")
	}
	return resolvers
}
