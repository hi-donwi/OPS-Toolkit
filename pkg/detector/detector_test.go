package detector

import (
	"runtime"
	"testing"
)

func TestDetect(t *testing.T) {
	ctx := Detect()

	if ctx.OS == "" {
		t.Errorf("Expected OS to be populated, got empty string")
	}
	if ctx.Arch == "" {
		t.Errorf("Expected Arch to be populated, got empty string")
	}
	if len(ctx.ActiveTargets) == 0 {
		t.Errorf("Expected at least one active target, got 0")
	}
	if runtime.GOOS == "darwin" && ctx.HasSystemd {
		t.Errorf("HasSystemd should be false on macOS")
	}
}

func TestDockerInfoInactiveSwarmIsNotActive(t *testing.T) {
	inactive := `{"Swarm":{"NodeID":"","NodeAddr":"","LocalNodeState":"inactive","ControlAvailable":false}}`
	if dockerInfoSwarmActive(inactive) {
		t.Fatal("an inactive Swarm object must not be treated as an active swarm")
	}
	active := `{"Swarm":{"NodeID":"abc","LocalNodeState":"active","ControlAvailable":true}}`
	if !dockerInfoSwarmActive(active) {
		t.Fatal("LocalNodeState active must be treated as an active swarm")
	}
}

func TestDockerInfoRequiresValidScopedSwarmState(t *testing.T) {
	for _, test := range []struct {
		body string
		want bool
	}{
		{"{\n\"Swarm\": {\"LocalNodeState\":\t\"active\"}}", true},
		{`{"Labels":{"LocalNodeState":"active"},"Swarm":{"LocalNodeState":"inactive"}}`, false},
		{`{"Swarm":{"LocalNodeState":"active"`, false},
		{`{"Swarm":{"LocalNodeState":"pending"}}`, false},
	} {
		if got := dockerInfoSwarmActive(test.body); got != test.want {
			t.Errorf("membership for %q = %v, want %v", test.body, got, test.want)
		}
	}
}

func TestCandidateDockerSockets(t *testing.T) {
	candidates := candidateDockerSockets()
	if len(candidates) < 2 {
		t.Fatalf("expected at least 2 candidate sockets, got %d", len(candidates))
	}
	foundVarRun := false
	for _, c := range candidates {
		if c == "/var/run/docker.sock" {
			foundVarRun = true
			break
		}
	}
	if !foundVarRun {
		t.Errorf("expected /var/run/docker.sock in candidates: %v", candidates)
	}
}
