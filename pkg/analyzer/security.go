package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/security"
)

// sensitiveHostPaths are host directories whose exposure inside a container
// hands the container effective control of the host.
var sensitiveHostPaths = map[string]string{
	"/var/run/docker.sock":                "Grants root-equivalent control of the Docker daemon, and therefore of the host.",
	"/run/docker.sock":                    "Grants root-equivalent control of the Docker daemon, and therefore of the host.",
	"/":                                   "Exposes the entire host filesystem for read and write.",
	"/etc":                                "Exposes host credentials and system configuration.",
	"/var/run/containerd/containerd.sock": "Grants direct control of the container runtime.",
	"/var/lib/kubelet":                    "Exposes kubelet credentials and every mounted pod secret.",
}

// evaluateSecurity runs every SEC-* rule.
func (e *Engine) evaluateSecurity(ctx context.Context) []model.Finding {
	findings := make([]model.Finding, 0, 16)

	findings = append(findings, e.checkSensitiveFilePermissions()...)
	findings = append(findings, e.checkDockerSecurity(ctx)...)
	findings = append(findings, security.AuditSSHConfig()...)
	findings = append(findings, security.AuditLocalCertPaths()...)
	findings = append(findings, security.AuditExposedPorts()...)
	findings = append(findings, e.checkKubernetesSecurity(ctx)...)

	return findings
}

// -----------------------------------------------------------------------------
// SEC-FIL-001 — sensitive file permissions
// -----------------------------------------------------------------------------

// sensitiveFile pairs a path with the mode bits that must not be set on it.
type sensitiveFile struct {
	Path string
	// ForbiddenBits are permission bits that constitute a finding. /etc/shadow
	// must not be readable by group or other; /etc/passwd is world-readable by
	// design and only world-writability matters.
	ForbiddenBits os.FileMode
	Expected      string
}

var sensitiveFiles = []sensitiveFile{
	{Path: "/etc/shadow", ForbiddenBits: 0o077, Expected: "0640 or stricter"},
	{Path: "/etc/gshadow", ForbiddenBits: 0o077, Expected: "0640 or stricter"},
	{Path: "/etc/passwd", ForbiddenBits: 0o022, Expected: "0644"},
	{Path: "/etc/group", ForbiddenBits: 0o022, Expected: "0644"},
	{Path: "/etc/sudoers", ForbiddenBits: 0o077, Expected: "0440"},
	{Path: "/etc/ssh/sshd_config", ForbiddenBits: 0o077, Expected: "0600"},
}

func (e *Engine) checkSensitiveFilePermissions() []model.Finding {
	if runtime.GOOS != "linux" {
		return nil
	}

	findings := make([]model.Finding, 0, len(sensitiveFiles))

	for _, sf := range sensitiveFiles {
		info, err := os.Stat(sf.Path)
		if err != nil {
			continue // not every distro ships every file
		}

		mode := info.Mode().Perm()
		offending := mode & sf.ForbiddenBits
		if offending == 0 {
			findings = append(findings, model.Finding{
				ID:         "SEC-FIL-001",
				Title:      fmt.Sprintf("File Permissions Secure: %s", sf.Path),
				TargetType: model.TargetSecurity,
				Category:   "File Permissions",
				Resource:   "file:" + sf.Path,
				Severity:   model.SeverityPass,
				Symptom:    fmt.Sprintf("%s has safe permissions (%04o).", sf.Path, mode),
			})
			continue
		}

		// World-writable is materially worse than merely over-readable: it lets
		// an unprivileged user rewrite the file rather than only read it.
		severity := model.SeverityWarning
		if offending&0o002 != 0 {
			severity = model.SeverityCritical
		} else if sf.Path == "/etc/shadow" || sf.Path == "/etc/gshadow" {
			severity = model.SeverityCritical
		}

		findings = append(findings, model.Finding{
			ID:          "SEC-FIL-001",
			Title:       fmt.Sprintf("Insecure File Permissions: %s", sf.Path),
			TargetType:  model.TargetSecurity,
			Category:    "File Permissions",
			Resource:    "file:" + sf.Path,
			Severity:    severity,
			Symptom:     fmt.Sprintf("%s has mode %04o; expected %s.", sf.Path, mode, sf.Expected),
			RootCause:   "An overly permissive file mask lets unprivileged users read or modify system credential files.",
			RemedySteps: []string{fmt.Sprintf("Restore the expected mode: chmod %s %s", strings.Fields(sf.Expected)[0], sf.Path)},
			QuickFixCmd: fmt.Sprintf("chmod %s %s", strings.Fields(sf.Expected)[0], sf.Path),
			Metadata:    map[string]string{"mode": fmt.Sprintf("%04o", mode)},
		})
	}

	return findings
}

// -----------------------------------------------------------------------------
// SEC-DOC-001..003 — container isolation
// -----------------------------------------------------------------------------

// dockerSecurityProfile is the security-relevant slice of `docker inspect`.
type dockerSecurityProfile struct {
	Privileged bool
	User       string
	Mounts     []string
	CapAdd     []string
}

// parseDockerSecurityProfile parses the tab-separated inspect format used by
// checkDockerSecurity.
func parseDockerSecurityProfile(output string) dockerSecurityProfile {
	fields := strings.Split(strings.TrimSpace(output), "\t")
	profile := dockerSecurityProfile{}

	if len(fields) > 0 {
		profile.Privileged = strings.TrimSpace(fields[0]) == "true"
	}
	if len(fields) > 1 {
		profile.User = strings.TrimSpace(fields[1])
	}
	if len(fields) > 2 {
		for _, m := range strings.Split(fields[2], ",") {
			if m = strings.TrimSpace(m); m != "" {
				profile.Mounts = append(profile.Mounts, m)
			}
		}
	}
	if len(fields) > 3 {
		caps := strings.Trim(strings.TrimSpace(fields[3]), "[]")
		for _, c := range strings.Fields(caps) {
			profile.CapAdd = append(profile.CapAdd, c)
		}
	}

	return profile
}

func (e *Engine) checkDockerSecurity(ctx context.Context) []model.Finding {
	if !e.env.HasDocker || !e.run.Available("docker") {
		return nil
	}

	out, err := e.run.Run(ctx, 15*time.Second, "docker", "ps", "--format", "{{.ID}}\t{{.Names}}")
	if err != nil {
		return nil
	}

	findings := make([]model.Finding, 0)
	for _, c := range parseDockerPS(string(out)) {
		inspect, err := e.run.Run(ctx, 10*time.Second, "docker", "inspect", "--format",
			"{{.HostConfig.Privileged}}\t{{.Config.User}}\t{{range .Mounts}}{{.Source}},{{end}}\t{{.HostConfig.CapAdd}}", c.ID)
		if err != nil {
			continue
		}
		findings = append(findings, evaluateContainerSecurity(c, parseDockerSecurityProfile(string(inspect)))...)
	}

	return findings
}

// evaluateContainerSecurity scores one running container's isolation posture.
func evaluateContainerSecurity(c dockerPS, p dockerSecurityProfile) []model.Finding {
	findings := make([]model.Finding, 0)

	if p.Privileged {
		findings = append(findings, model.Finding{
			ID:         "SEC-DOC-001",
			Title:      fmt.Sprintf("Container Running with --privileged: %s", c.Name),
			TargetType: model.TargetSecurity,
			Category:   "Container Isolation",
			Resource:   "container:" + c.Name,
			Severity:   model.SeverityCritical,
			Symptom:    "Container holds all Linux capabilities and raw device access.",
			RootCause:  "The privileged flag disables the isolation boundary entirely. Any code execution inside this container is equivalent to root on the host.",
			RemedySteps: []string{
				"Remove --privileged and grant only the capabilities actually needed via --cap-add",
				"If device access is the reason, pass the specific device with --device instead",
			},
			Metadata: map[string]string{"container_id": c.ID},
		})
	}

	// SEC-DOC-002: an unset User means the image's default, which for most
	// images is root (UID 0).
	if p.User == "" || p.User == "0" || p.User == "root" || strings.HasPrefix(p.User, "0:") {
		findings = append(findings, model.Finding{
			ID:         "SEC-DOC-002",
			Title:      fmt.Sprintf("Container Running as Root: %s", c.Name),
			TargetType: model.TargetSecurity,
			Category:   "Least Privilege",
			Resource:   "container:" + c.Name,
			Severity:   model.SeverityWarning,
			Symptom:    "Container processes run as UID 0 inside the container.",
			RootCause:  "Without user namespace remapping, container root shares the host's UID 0. A container escape or a writable bind mount then acts with host root authority.",
			RemedySteps: []string{
				"Add a non-root USER to the image, or run with --user 1000:1000",
				"Enable userns-remap on the daemon if images cannot be changed",
			},
			Metadata: map[string]string{"container_id": c.ID, "user": p.User},
		})
	}

	for _, mount := range p.Mounts {
		explanation, sensitive := sensitiveHostPaths[mount]
		if !sensitive {
			continue
		}
		findings = append(findings, model.Finding{
			ID:          "SEC-DOC-003",
			Title:       fmt.Sprintf("Sensitive Host Path Mounted: %s → %s", mount, c.Name),
			TargetType:  model.TargetSecurity,
			Category:    "Host Escape Risk",
			Resource:    "container:" + c.Name,
			Severity:    model.SeverityCritical,
			Symptom:     fmt.Sprintf("Host path %s is mounted into the container.", mount),
			RootCause:   explanation,
			RemedySteps: []string{"Remove the mount, or replace it with a scoped API and a least-privilege token."},
			Metadata:    map[string]string{"container_id": c.ID, "mount": mount},
		})
	}

	return findings
}

// -----------------------------------------------------------------------------
// SEC-K8S-001 — Pod Security Standards violations
// -----------------------------------------------------------------------------

// systemNamespaces are exempt from the workload PSS rule: control-plane and CNI
// components legitimately need host access, and flagging them on every run
// trains operators to ignore the check.
var systemNamespaces = map[string]bool{
	"kube-system":        true,
	"kube-public":        true,
	"kube-node-lease":    true,
	"local-path-storage": true,
}

func (e *Engine) checkKubernetesSecurity(ctx context.Context) []model.Finding {
	if !e.env.HasKubernetes || !e.run.Available("kubectl") {
		return nil
	}

	findings := make([]model.Finding, 0)

	if raw, err := e.kubectlJSON(ctx, "pods", []string{"--all-namespaces"}); err == nil {
		var list podList
		if json.Unmarshal(raw, &list) == nil {
			findings = append(findings, evaluatePodSecurity(list.Items)...)
		}
	}

	if raw, err := e.run.Run(ctx, k8sTimeout, "kubectl", "get", "clusterroles", "-o", "json"); err == nil {
		var list clusterRoleList
		if json.Unmarshal(raw, &list) == nil {
			findings = append(findings, evaluateRBACWildcards(list.Items)...)
		}
	}

	return findings
}

// evaluatePodSecurity checks workloads against the restricted Pod Security
// Standard's highest-impact controls.
func evaluatePodSecurity(pods []pod) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, p := range pods {
		ns, name := p.Metadata.Namespace, p.Metadata.Name
		if systemNamespaces[ns] {
			continue
		}

		violations := make([]string, 0, 4)
		privilegedContainers := make([]string, 0)
		escalationContainers := make([]string, 0)

		if p.Spec.HostNetwork {
			violations = append(violations, "hostNetwork: true (shares the node's network namespace, bypassing NetworkPolicy)")
		}
		if p.Spec.HostPID {
			violations = append(violations, "hostPID: true (can see and signal every process on the node)")
		}

		for _, c := range p.Spec.Containers {
			sc := c.SecurityContext
			if sc == nil {
				escalationContainers = append(escalationContainers, c.Name)
				continue
			}
			if sc.Privileged != nil && *sc.Privileged {
				privilegedContainers = append(privilegedContainers, c.Name)
			}
			// allowPrivilegeEscalation defaults to true when unset, so an
			// absent field is itself the violation.
			if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				escalationContainers = append(escalationContainers, c.Name)
			}
		}

		if len(privilegedContainers) > 0 {
			violations = append(violations, "privileged containers: "+joinNames(privilegedContainers))
		}
		if len(escalationContainers) > 0 {
			violations = append(violations, "allowPrivilegeEscalation not disabled: "+joinNames(escalationContainers))
		}

		// Only privileged or host-namespace access is severe enough to page on;
		// a missing allowPrivilegeEscalation:false alone is a hardening gap.
		if len(violations) == 0 {
			continue
		}

		severity := model.SeverityWarning
		if len(privilegedContainers) > 0 || p.Spec.HostPID || p.Spec.HostNetwork {
			severity = model.SeverityCritical
		}

		findings = append(findings, model.Finding{
			ID:         "SEC-K8S-001",
			Title:      fmt.Sprintf("Pod Security Standards Violation: %s/%s", ns, name),
			TargetType: model.TargetSecurity,
			Category:   "Pod Security Standards",
			Resource:   fmt.Sprintf("pod/%s", name),
			Namespace:  ns,
			Severity:   severity,
			Symptom:    fmt.Sprintf("Pod violates the restricted Pod Security Standard: %s.", joinNames(violations)),
			RootCause:  "The workload runs with more privilege than it needs. Each violation widens the blast radius of a single compromised container from the pod to the node.",
			RemedySteps: []string{
				"Set securityContext.allowPrivilegeEscalation: false and runAsNonRoot: true on every container",
				"Drop hostNetwork and hostPID unless the workload is a node-level agent",
				fmt.Sprintf("Enforce the standard at the namespace level: kubectl label namespace %s pod-security.kubernetes.io/enforce=restricted", ns),
			},
		})
	}

	return findings
}

// -----------------------------------------------------------------------------
// SEC-K8S-002 — RBAC wildcard grants
// -----------------------------------------------------------------------------

type clusterRoleList struct {
	Items []clusterRole `json:"items"`
}

type clusterRole struct {
	Metadata objectMeta   `json:"metadata"`
	Rules    []policyRule `json:"rules"`
}

type policyRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

// builtinWildcardRoles ship with Kubernetes and are expected to hold wildcards.
// Reporting them would bury the one custom role that should not.
var builtinWildcardRoles = map[string]bool{
	"cluster-admin": true,
	"admin":         true,
	"edit":          true,
}

// evaluateRBACWildcards finds custom ClusterRoles granting unrestricted access.
func evaluateRBACWildcards(roles []clusterRole) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, r := range roles {
		name := r.Metadata.Name
		if builtinWildcardRoles[name] || strings.HasPrefix(name, "system:") {
			continue
		}

		for _, rule := range r.Rules {
			verbWildcard := contains(rule.Verbs, "*")
			resourceWildcard := contains(rule.Resources, "*")
			if !verbWildcard || !resourceWildcard {
				continue
			}

			findings = append(findings, model.Finding{
				ID:         "SEC-K8S-002",
				Title:      fmt.Sprintf("ClusterRole Grants Unrestricted Access: %s", name),
				TargetType: model.TargetSecurity,
				Category:   "RBAC & Authorization",
				Resource:   fmt.Sprintf("clusterrole/%s", name),
				Severity:   model.SeverityCritical,
				Symptom:    fmt.Sprintf("ClusterRole %q grants verbs %v on resources %v across apiGroups %v.", name, rule.Verbs, rule.Resources, rule.APIGroups),
				RootCause:  "A wildcard verb on a wildcard resource is cluster-admin by another name. Any subject bound to this role can read every secret and schedule privileged pods on any node.",
				RemedySteps: []string{
					fmt.Sprintf("List who holds this role: kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name==\"%s\")'", name),
					"Replace the wildcards with the specific verbs and resources the workload actually calls",
				},
				Metadata: map[string]string{"role": name},
			})
			break // one finding per role is enough
		}
	}

	return findings
}

// contains reports whether needle appears in haystack.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
