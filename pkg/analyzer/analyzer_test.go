package analyzer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/sysexec"
)

// newFixtureProc builds a minimal procfs tree so host rules can run without
// touching the real machine.
func newFixtureProc(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()

	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

// healthyEngine builds an Engine wired entirely to fixtures.
func healthyEngine(t *testing.T, opts ...Option) *Engine {
	t.Helper()

	procRoot := newFixtureProc(t, map[string]string{
		"meminfo": "MemTotal: 8000000 kB\nMemAvailable: 6000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
		"loadavg": "0.20 0.30 0.25 1/200 900\n",
		"mounts":  "/dev/sda1 / ext4 rw,relatime 0 0\n",
		"net/tcp": "  sl  local_address rem_address   st\n   0: 0100007F:1F90 00000000:0000 0A\n",
	})

	env := model.EnvironmentContext{
		OS:            "linux",
		Distro:        "Ubuntu 22.04 LTS",
		Arch:          "amd64",
		ActiveTargets: []model.TargetType{model.TargetHost},
	}

	base := []Option{
		WithProcRoot(procRoot),
		WithRunner(&sysexec.Fake{Missing: map[string]bool{"dmesg": true, "systemctl": true}}),
		WithStatfs(func(string) (fsUsage, error) {
			return fsUsage{BlockSize: 4096, Blocks: 1000000, BlocksFree: 600000, BlocksAvail: 600000,
				Inodes: 100000, InodesFree: 90000}, nil
		}),
		WithResolver(func(context.Context, string) ([]string, error) {
			return []string{"93.184.216.34"}, nil
		}),
	}

	return NewEngine(env, append(base, opts...)...)
}

func TestRunDiagnosticsHealthyHost(t *testing.T) {
	engine := healthyEngine(t)

	rep, err := engine.RunDiagnostics(context.Background(), model.TargetHost, "")
	if err != nil {
		t.Fatalf("RunDiagnostics: %v", err)
	}

	if len(rep.Findings) == 0 {
		t.Fatal("expected host rules to produce findings")
	}
	if rep.Summary.Critical != 0 {
		t.Errorf("a healthy fixture produced %d critical findings", rep.Summary.Critical)
	}
	if rep.Summary.Pass == 0 {
		t.Error("expected some PASS findings on a healthy host")
	}
	if rep.Duration == "" {
		t.Error("Duration should be measured, not left blank")
	}
}

func TestRunDiagnosticsSurfacesSaturation(t *testing.T) {
	engine := healthyEngine(t, WithStatfs(func(string) (fsUsage, error) {
		// 95% full with no reserved pool.
		return fsUsage{BlockSize: 4096, Blocks: 1000, BlocksFree: 50, BlocksAvail: 50,
			Inodes: 1000, InodesFree: 20}, nil
	}))

	rep, err := engine.RunDiagnostics(context.Background(), model.TargetHost, "")
	if err != nil {
		t.Fatalf("RunDiagnostics: %v", err)
	}

	var sawDisk, sawInode bool
	for _, f := range rep.Findings {
		if f.ID == "HOST-DSK-001" && f.Severity == model.SeverityCritical {
			sawDisk = true
		}
		if f.ID == "HOST-INO-001" && f.Severity == model.SeverityCritical {
			sawInode = true
		}
	}
	if !sawDisk {
		t.Error("expected a critical disk finding at 95% usage")
	}
	if !sawInode {
		t.Error("expected a critical inode finding at 98% usage")
	}
	if rep.Summary.Critical < 2 {
		t.Errorf("summary critical = %d, want at least 2", rep.Summary.Critical)
	}
}

func TestRunDiagnosticsSortsMostSevereFirst(t *testing.T) {
	engine := healthyEngine(t, WithStatfs(func(string) (fsUsage, error) {
		return fsUsage{BlockSize: 4096, Blocks: 1000, BlocksFree: 50, BlocksAvail: 50,
			Inodes: 1000, InodesFree: 900}, nil
	}))

	rep, err := engine.RunDiagnostics(context.Background(), model.TargetHost, "")
	if err != nil {
		t.Fatalf("RunDiagnostics: %v", err)
	}

	// An operator reads top-down; a PASS row above a CRITICAL row buries the
	// incident.
	lastRank := -1
	for _, f := range rep.Findings {
		rank := severityRank(f.Severity)
		if rank < lastRank {
			t.Fatalf("findings are not ordered by severity: %s (%s) came after a more severe entry", f.ID, f.Severity)
		}
		lastRank = rank
	}
	if rep.Findings[0].Severity != model.SeverityCritical {
		t.Errorf("first finding is %s, want CRITICAL", rep.Findings[0].Severity)
	}
}

func TestRunDiagnosticsHonoursCancellation(t *testing.T) {
	engine := healthyEngine(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := engine.RunDiagnostics(ctx, model.TargetHost, "")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled — a cancelled run must stop, not complete", err)
	}
}

func TestDNSRuleReportsFailure(t *testing.T) {
	engine := healthyEngine(t, WithResolver(func(context.Context, string) ([]string, error) {
		return nil, errors.New("no such host")
	}))

	rep, err := engine.RunDiagnostics(context.Background(), model.TargetHost, "")
	if err != nil {
		t.Fatalf("RunDiagnostics: %v", err)
	}

	for _, f := range rep.Findings {
		if f.ID == "HOST-DNS-001" {
			if f.Severity != model.SeverityCritical {
				t.Errorf("DNS failure severity = %s, want CRITICAL", f.Severity)
			}
			return
		}
	}
	t.Error("expected a HOST-DNS-001 finding")
}

func TestDNSProbeDomainIsOverridable(t *testing.T) {
	// An air-gapped host must be able to point the probe at a name it can
	// actually resolve, instead of reporting a false CRITICAL every run.
	t.Setenv("OPSKIT_DNS_PROBE", "internal.corp.example")

	if got := dnsProbeDomain(); got != "internal.corp.example" {
		t.Errorf("dnsProbeDomain() = %q, want the override", got)
	}
}

func TestDockerRulesSkippedWhenBinaryMissing(t *testing.T) {
	env := model.EnvironmentContext{HasDocker: true, ActiveTargets: []model.TargetType{model.TargetDocker}}
	engine := NewEngine(env, WithRunner(&sysexec.Fake{Missing: map[string]bool{"docker": true}}))

	rep, err := engine.RunDiagnostics(context.Background(), model.TargetDocker, "")
	if err != nil {
		t.Fatalf("RunDiagnostics: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("expected no findings when docker is absent, got %+v", rep.Findings)
	}
}

func TestDockerRulesEvaluateFakeOutput(t *testing.T) {
	fake := &sysexec.Fake{
		Outputs: map[string]string{
			"docker ps -a --filter status=exited": "c1\tapi\tExited (137) 2 minutes ago\tapi:1.0",
			"docker ps --filter health=unhealthy": "c2\tweb\tUp 2 hours (unhealthy)\tweb:1.0",
			"docker ps -a --format":               "c1\tapi",
			"docker inspect":                      "1\trunning\talways",
		},
	}

	env := model.EnvironmentContext{HasDocker: true, ActiveTargets: []model.TargetType{model.TargetDocker}}
	engine := NewEngine(env, WithRunner(fake))

	rep, err := engine.RunDiagnostics(context.Background(), model.TargetDocker, "")
	if err != nil {
		t.Fatalf("RunDiagnostics: %v", err)
	}

	ids := map[string]bool{}
	for _, f := range rep.Findings {
		ids[f.ID] = true
	}
	if !ids["DOC-EXT-137"] {
		t.Error("expected the OOMKilled container to be reported")
	}
	if !ids["DOC-HLT-001"] {
		t.Error("expected the unhealthy container to be reported")
	}
}

func TestSummarize(t *testing.T) {
	got := Summarize([]model.Finding{
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityWarning},
		{Severity: model.SeverityInfo},
		{Severity: model.SeverityPass},
		{Severity: model.SeverityPass},
	})

	want := model.Summary{Critical: 2, Warning: 1, Info: 1, Pass: 2}
	if got != want {
		t.Errorf("Summarize() = %+v, want %+v", got, want)
	}
}

func TestEngineUsesInjectedClock(t *testing.T) {
	fixed := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	engine := healthyEngine(t, WithClock(func() time.Time { return fixed }))

	rep, err := engine.RunDiagnostics(context.Background(), model.TargetHost, "")
	if err != nil {
		t.Fatalf("RunDiagnostics: %v", err)
	}
	if !rep.Timestamp.Equal(fixed) {
		t.Errorf("Timestamp = %v, want the injected clock value", rep.Timestamp)
	}
}

func TestProcRootFromEnv(t *testing.T) {
	if got := ProcRootFromEnv(); got != DefaultProcRoot {
		t.Errorf("ProcRootFromEnv() = %q, want %q by default", got, DefaultProcRoot)
	}

	// Inside a container "/proc" describes the container, not the node. The
	// DaemonSet bind-mounts the host's procfs and points the engine at it.
	t.Setenv("OPSKIT_PROC_ROOT", "/host/proc")
	if got := ProcRootFromEnv(); got != "/host/proc" {
		t.Errorf("ProcRootFromEnv() = %q, want the override", got)
	}
}

func TestNewEngineHonoursProcRootEnv(t *testing.T) {
	t.Setenv("OPSKIT_PROC_ROOT", "/host/proc")

	e := NewEngine(model.EnvironmentContext{})
	if e.procRoot != "/host/proc" {
		t.Errorf("engine procRoot = %q, want the environment override", e.procRoot)
	}
}
