package security

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// AuditSSHConfig inspects sshd_config on Linux hosts for secure defaults.
func AuditSSHConfig() []model.Finding {
	findings := make([]model.Finding, 0)
	if runtime.GOOS != "linux" {
		return findings
	}
	return auditSSHConfigFile("/etc/ssh/sshd_config")
}

type sshSettings struct {
	permitRoot    string
	permitRootSet bool
	passwordAuth  string
	passwordSet   bool
	unreadable    bool
}

func auditSSHConfigFile(configPath string) []model.Finding {
	findings := make([]model.Finding, 0)
	settings := sshSettings{}
	if err := parseSSHFile(configPath, filepath.Dir(configPath), &settings, 0); err != nil && !settings.permitRootSet && !settings.passwordSet {
		return findings
	}

	permitRoot := "prohibit-password"
	if settings.permitRootSet {
		permitRoot = settings.permitRoot
	}
	passwordAuth := ""
	if settings.passwordSet {
		passwordAuth = settings.passwordAuth
	} else if !settings.unreadable {
		passwordAuth = "yes"
	}

	if permitRoot == "yes" {
		findings = append(findings, model.Finding{
			ID:          "SEC-SSH-001",
			Title:       "SSH Permits Direct Root Login",
			TargetType:  model.TargetSecurity,
			Category:    "Authentication & Access Control",
			Resource:    "file:/etc/ssh/sshd_config",
			Severity:    model.SeverityCritical,
			Symptom:     "Directive 'PermitRootLogin yes' is enabled.",
			RootCause:   "Direct root login over SSH allows brute-force attacks against the root account without audit trail.",
			RemedySteps: []string{"Set 'PermitRootLogin no' or 'prohibit-password' in /etc/ssh/sshd_config", "Reload sshd: systemctl reload sshd"},
			QuickFixCmd: "sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && systemctl reload sshd",
		})
	} else {
		findings = append(findings, model.Finding{
			ID:         "SEC-SSH-001",
			Title:      "SSH Root Login Protected",
			TargetType: model.TargetSecurity,
			Category:   "Access Control",
			Resource:   "file:/etc/ssh/sshd_config",
			Severity:   model.SeverityPass,
			Symptom:    fmt.Sprintf("PermitRootLogin is configured safely (%s).", permitRoot),
		})
	}

	if passwordAuth == "yes" {
		findings = append(findings, model.Finding{
			ID:          "SEC-SSH-002",
			Title:       "SSH Password Authentication Allowed",
			TargetType:  model.TargetSecurity,
			Category:    "Authentication Hardening",
			Resource:    "file:/etc/ssh/sshd_config",
			Severity:    model.SeverityWarning,
			Symptom:     "Password authentication is enabled instead of enforcing public key authentication only.",
			RootCause:   "Passwords are prone to brute-force credential stuffing attacks.",
			RemedySteps: []string{"Deploy SSH public keys for authorized engineers", "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"},
		})
	}

	return findings
}

func parseSSHFile(path, base string, settings *sshSettings, depth int) error {
	if depth > 8 {
		return fmt.Errorf("ssh config include depth exceeded")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "match" {
			break
		}
		if key == "include" {
			for _, pattern := range fields[1:] {
				if err := parseSSHInclude(pattern, base, settings, depth); err != nil {
					return err
				}
			}
			continue
		}
		val := strings.ToLower(fields[1])
		switch key {
		case "permitrootlogin":
			if !settings.permitRootSet {
				settings.permitRoot = val
				settings.permitRootSet = true
			}
		case "passwordauthentication":
			if !settings.passwordSet {
				settings.passwordAuth = val
				settings.passwordSet = true
			}
		}
	}
	return scanner.Err()
}

func parseSSHInclude(pattern, base string, settings *sshSettings, depth int) error {
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(base, pattern)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	sort.Strings(matches)
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			settings.unreadable = true
			continue
		}
		if info.IsDir() {
			continue
		}
		if err := parseSSHFile(match, base, settings, depth+1); err != nil {
			settings.unreadable = true
		}
	}
	return nil
}

// AuditExposedPorts probes whether unauthenticated or sensitive internal services are exposed on external interfaces.
func AuditExposedPorts() []model.Finding {
	findings := make([]model.Finding, 0)

	dangerousPorts := []struct {
		Port        int
		Service     string
		Description string
	}{
		{2375, "Docker Daemon (Unencrypted)", "Allows unauthenticated remote code execution on the host."},
		{5432, "PostgreSQL", "Exposed relational database server on external network interface."},
		{6379, "Redis", "Exposed in-memory key-value database without TLS."},
		{9092, "Apache Kafka", "Exposed message broker / event streaming log without network isolation."},
		{27017, "MongoDB", "Exposed document database."},
		{2379, "Etcd", "Kubernetes / clustering state store."},
		{11211, "Memcached", "Vulnerable to amplification DDoS and data extraction."},
	}

	for _, p := range dangerousPorts {
		if exposed, bindAddr := isPortExposedExternally(p.Port); exposed {
			findings = append(findings, model.Finding{
				ID:         "SEC-PRT-001",
				Title:      fmt.Sprintf("Sensitive Service Exposed Externally: %s (Port %d)", p.Service, p.Port),
				TargetType: model.TargetSecurity,
				Category:   "Network Exposure",
				Resource:   fmt.Sprintf("tcp:%d", p.Port),
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("Port %d is bound to %s and accepting connections. %s", p.Port, bindAddr, p.Description),
				RootCause:  "Service is bound to an external network interface without strict authentication or firewall isolation.",
				RemedySteps: []string{
					fmt.Sprintf("Reconfigure %s to bind strictly to localhost (127.0.0.1)", p.Service),
					"Enforce firewall rules (iptables/nftables/ufw/security groups) blocking external access",
				},
				Metadata: map[string]string{"bind_address": bindAddr},
			})
		}
	}

	return findings
}

func parseProcNetListening(r io.Reader, port int) (bool, string) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // skip header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// State 0A == TCP_LISTEN
		if fields[3] != "0A" {
			continue
		}
		addrParts := strings.Split(fields[1], ":")
		if len(addrParts) != 2 {
			continue
		}
		hexPort := addrParts[1]
		var parsedPort int64
		if _, err := fmt.Sscanf(hexPort, "%X", &parsedPort); err == nil && int(parsedPort) == port {
			hexIP := addrParts[0]
			// Check if bound to all interfaces
			if hexIP == "00000000" {
				return true, "0.0.0.0 (all interfaces)"
			}
			if hexIP == "00000000000000000000000000000000" {
				return true, ":: (all IPv6/IPv4 interfaces)"
			}
			// Check if NOT loopback (127.0.0.1 in hex is 0100007F)
			if hexIP != "0100007F" && hexIP != "00000000000000000000000001000000" {
				return true, "non-loopback IP"
			}
		}
	}
	return false, ""
}

func isPortExposedExternally(port int) (bool, string) {
	// 1. On Linux, inspect /proc/net/tcp and /proc/net/tcp6 for listening sockets (state 0A)
	if runtime.GOOS == "linux" {
		checkedProc := false
		for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			checkedProc = true
			exposed, bindAddr := parseProcNetListening(f, port)
			f.Close()
			if exposed {
				return true, bindAddr
			}
		}
		if checkedProc {
			return false, ""
		}
	}

	// 2. Fallback: Query non-loopback local interface IPs and dial them
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, ""
	}

	portStr := fmt.Sprintf("%d", port)
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		target := net.JoinHostPort(ipNet.IP.String(), portStr)
		conn, err := net.DialTimeout("tcp", target, 150*time.Millisecond)
		if err == nil {
			conn.Close()
			return true, ipNet.IP.String()
		}
	}

	return false, ""
}
