package analyzer

import (
	"strings"
	"testing"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func TestParseSwarmServicesAndReplicas(t *testing.T) {
	services := parseSwarmServices(
		"s1\tapi\treplicated\t0/3\tapi:1.0\n" +
			"s2\tweb\treplicated\t2/2\tweb:1.0\n" +
			"s3\tagent\tglobal\t5/5\tagent:1.0\n")

	if len(services) != 3 {
		t.Fatalf("parsed %d services, want 3", len(services))
	}

	running, desired, ok := services[0].ReplicaCounts()
	if !ok || running != 0 || desired != 3 {
		t.Errorf("api replicas = %d/%d (ok=%v), want 0/3", running, desired, ok)
	}

	running, desired, ok = services[2].ReplicaCounts()
	if !ok || running != 5 || desired != 5 {
		t.Errorf("global service replicas = %d/%d, want 5/5", running, desired)
	}
}

func TestReplicaCountsHandlesMalformedInput(t *testing.T) {
	// An empty replica column must not panic on Fields(...)[0].
	if _, _, ok := (swarmService{Replicas: ""}).ReplicaCounts(); ok {
		t.Error("empty replica column must not parse")
	}
	if _, _, ok := (swarmService{Replicas: "garbage"}).ReplicaCounts(); ok {
		t.Error("non-fraction replica column must not parse")
	}
}

func TestClassifyTaskFailure(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantSubstr string
	}{
		{
			"insufficient memory",
			"t1\tnode-2\tRunning\tRejected 2 minutes ago\t\"insufficient memory on node\"",
			"free memory",
		},
		{
			"constraint mismatch",
			"t2\t\tReady\tPending\t\"no suitable node (scheduling constraints not satisfied)\"",
			"Placement constraints",
		},
		{
			"image missing",
			"t3\tnode-1\tReady\tRejected\t\"No such image: api:9.9\"",
			"image tag does not exist",
		},
		{
			"port conflict",
			"t4\tnode-1\tReady\tRejected\t\"port 8080 is already in use\"",
			"published host port",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evidence, reason := classifyTaskFailure(tc.line)
			if evidence == "" {
				t.Fatal("expected evidence to be captured")
			}
			if !strings.Contains(reason, tc.wantSubstr) {
				t.Errorf("reason = %q, want it to mention %q", reason, tc.wantSubstr)
			}
		})
	}
}

func TestClassifyTaskFailureIgnoresHealthyTasks(t *testing.T) {
	evidence, reason := classifyTaskFailure("t1\tnode-1\tRunning\tRunning 2 hours ago\t")
	if evidence != "" || reason != "" {
		t.Errorf("healthy task produced evidence=%q reason=%q", evidence, reason)
	}
}

func TestEvaluateSwarmNodes(t *testing.T) {
	nodes := parseSwarmNodes(
		"n1\tmanager-1\tReady\tActive\tLeader\n" +
			"n2\tworker-1\tDown\tActive\t\n" +
			"n3\tworker-2\tReady\tDrain\t\n")

	findings := evaluateSwarmNodes(nodes)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (a healthy node produces none)", len(findings))
	}

	var sawDown, sawDrain bool
	for _, f := range findings {
		switch f.ID {
		case "SWM-NOD-001":
			sawDown = true
			if f.Severity != model.SeverityCritical {
				t.Error("an unreachable node must be CRITICAL")
			}
		case "SWM-NOD-002":
			sawDrain = true
			if f.Severity != model.SeverityInfo {
				t.Error("a drained node is INFO, not an outage")
			}
		}
	}
	if !sawDown || !sawDrain {
		t.Errorf("missing findings: down=%v drain=%v", sawDown, sawDrain)
	}
}

func TestBuildReplicaFindingCarriesCounts(t *testing.T) {
	svc := swarmService{Name: "api", Replicas: "1/3", Image: "api:1.0"}
	f := buildReplicaFinding(svc, 1, 3, "evidence line", "because reasons")

	if f.ID != "SWM-REP-001" || f.Severity != model.SeverityCritical {
		t.Errorf("got %s/%s", f.ID, f.Severity)
	}
	if f.Metadata["running"] != "1" || f.Metadata["desired"] != "3" {
		t.Errorf("metadata = %v", f.Metadata)
	}
	if f.RootCause != "because reasons" {
		t.Errorf("RootCause = %q, want the classified reason", f.RootCause)
	}
}
