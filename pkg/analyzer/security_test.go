package analyzer

import (
	"encoding/json"
	"testing"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func TestParseDockerSecurityProfile(t *testing.T) {
	p := parseDockerSecurityProfile("true\t\t/var/run/docker.sock,/data,\t[SYS_ADMIN NET_ADMIN]")

	if !p.Privileged {
		t.Error("Privileged should be true")
	}
	if p.User != "" {
		t.Errorf("User = %q, want empty (image default)", p.User)
	}
	if len(p.Mounts) != 2 {
		t.Fatalf("mounts = %v, want 2 entries", p.Mounts)
	}
	if len(p.CapAdd) != 2 || p.CapAdd[0] != "SYS_ADMIN" {
		t.Errorf("CapAdd = %v", p.CapAdd)
	}
}

func TestEvaluateContainerSecurity(t *testing.T) {
	c := dockerPS{ID: "abc", Name: "agent"}
	findings := evaluateContainerSecurity(c, dockerSecurityProfile{
		Privileged: true,
		User:       "",
		Mounts:     []string{"/var/run/docker.sock", "/app/data"},
	})

	ids := map[string]model.Severity{}
	for _, f := range findings {
		ids[f.ID] = f.Severity
	}

	if ids["SEC-DOC-001"] != model.SeverityCritical {
		t.Error("privileged container must be SEC-DOC-001/CRITICAL")
	}
	// SPEC assigns SEC-DOC-002 to root execution and SEC-DOC-003 to sensitive
	// host mounts; an earlier build used SEC-DOC-002 for the socket mount.
	if ids["SEC-DOC-002"] != model.SeverityWarning {
		t.Error("root execution must be SEC-DOC-002/WARNING")
	}
	if ids["SEC-DOC-003"] != model.SeverityCritical {
		t.Error("docker.sock mount must be SEC-DOC-003/CRITICAL")
	}
	if len(findings) != 3 {
		t.Errorf("got %d findings; /app/data is not sensitive and must not be flagged", len(findings))
	}
}

func TestEvaluateContainerSecurityCleanContainer(t *testing.T) {
	findings := evaluateContainerSecurity(
		dockerPS{ID: "x", Name: "web"},
		dockerSecurityProfile{Privileged: false, User: "1000:1000", Mounts: []string{"/srv/www"}},
	)

	if len(findings) != 0 {
		t.Errorf("hardened container produced %d findings: %+v", len(findings), findings)
	}
}

func TestEvaluatePodSecurity(t *testing.T) {
	pods := decodePods(t, `{"items":[
	  {"metadata":{"namespace":"prod","name":"privileged-pod"},
	   "spec":{"containers":[{"name":"c","securityContext":{"privileged":true,"allowPrivilegeEscalation":true}}]}},
	  {"metadata":{"namespace":"prod","name":"hostnet-pod"},
	   "spec":{"hostNetwork":true,"containers":[{"name":"c","securityContext":{"allowPrivilegeEscalation":false}}]}},
	  {"metadata":{"namespace":"prod","name":"soft-pod"},
	   "spec":{"containers":[{"name":"c","securityContext":{"allowPrivilegeEscalation":true}}]}},
	  {"metadata":{"namespace":"prod","name":"hardened-pod"},
	   "spec":{"containers":[{"name":"c","securityContext":{"allowPrivilegeEscalation":false,"privileged":false}}]}},
	  {"metadata":{"namespace":"kube-system","name":"cni-agent"},
	   "spec":{"hostNetwork":true,"containers":[{"name":"c","securityContext":{"privileged":true}}]}}
	]}`)

	findings := evaluatePodSecurity(pods)

	byResource := map[string]model.Finding{}
	for _, f := range findings {
		byResource[f.Resource] = f
	}

	if _, ok := byResource["pod/hardened-pod"]; ok {
		t.Error("a compliant pod must produce no finding")
	}
	// Control-plane and CNI components legitimately need host access; flagging
	// them every run is what trains operators to ignore the check.
	if _, ok := byResource["pod/cni-agent"]; ok {
		t.Error("kube-system must be exempt from the workload PSS rule")
	}
	if byResource["pod/privileged-pod"].Severity != model.SeverityCritical {
		t.Error("a privileged container must be CRITICAL")
	}
	if byResource["pod/hostnet-pod"].Severity != model.SeverityCritical {
		t.Error("hostNetwork must be CRITICAL")
	}
	if byResource["pod/soft-pod"].Severity != model.SeverityWarning {
		t.Error("allowPrivilegeEscalation alone is a WARNING, not an outage")
	}
}

func TestEvaluatePodSecurityTreatsMissingContextAsViolation(t *testing.T) {
	// allowPrivilegeEscalation defaults to true, so an absent securityContext
	// is itself non-compliant.
	pods := decodePods(t, `{"items":[{
	  "metadata":{"namespace":"prod","name":"no-ctx"},
	  "spec":{"containers":[{"name":"c"}]}
	}]}`)

	findings := evaluatePodSecurity(pods)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != "SEC-K8S-001" {
		t.Errorf("ID = %s, want SEC-K8S-001", findings[0].ID)
	}
}

func TestEvaluateRBACWildcards(t *testing.T) {
	var list clusterRoleList
	raw := `{"items":[
	  {"metadata":{"name":"cluster-admin"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]},
	  {"metadata":{"name":"system:controller:foo"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]},
	  {"metadata":{"name":"my-app-god-mode"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]},
	  {"metadata":{"name":"reader"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]},
	  {"metadata":{"name":"partial"},"rules":[{"apiGroups":[""],"resources":["*"],"verbs":["get"]}]}
	]}`
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatalf("fixture did not decode: %v", err)
	}

	findings := evaluateRBACWildcards(list.Items)

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 — built-ins and system: roles are expected to hold wildcards", len(findings))
	}
	if findings[0].Metadata["role"] != "my-app-god-mode" {
		t.Errorf("flagged role = %q, want my-app-god-mode", findings[0].Metadata["role"])
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want CRITICAL", findings[0].Severity)
	}
}
