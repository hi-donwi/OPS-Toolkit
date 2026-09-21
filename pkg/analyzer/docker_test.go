package analyzer

import (
	"testing"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func TestParseDockerPSToleratesShortRows(t *testing.T) {
	// A row missing its Image column must not panic. Indexing fields[3] behind
	// a `len(fields) < 3` guard crashes the whole diagnostic run on a row with
	// exactly three columns.
	rows := parseDockerPS("abc123\tapi\tExited (137) 2 minutes ago")

	if len(rows) != 1 {
		t.Fatalf("parsed %d rows, want 1", len(rows))
	}
	if rows[0].Image != "" {
		t.Errorf("Image = %q, want empty for a short row", rows[0].Image)
	}
	if rows[0].Status != "Exited (137) 2 minutes ago" {
		t.Errorf("Status = %q", rows[0].Status)
	}
}

func TestParseDockerPSSkipsBlankLines(t *testing.T) {
	rows := parseDockerPS("\n\nabc\tname\tUp 3 hours\timage:tag\n\n")
	if len(rows) != 1 {
		t.Fatalf("parsed %d rows, want 1", len(rows))
	}
}

func TestExitCodeFromStatus(t *testing.T) {
	tests := []struct {
		status string
		want   int
		ok     bool
	}{
		{"Exited (137) 2 minutes ago", 137, true},
		{"Exited (0) About an hour ago", 0, true},
		{"Exited (139) 5 seconds ago", 139, true},
		{"Up 3 hours (healthy)", 0, false},
		{"Restarting (1) 2 seconds ago", 0, false},
		{"Exited (abc) now", 0, false},
	}

	for _, tc := range tests {
		got, ok := exitCodeFromStatus(tc.status)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("exitCodeFromStatus(%q) = (%d, %v), want (%d, %v)", tc.status, got, ok, tc.want, tc.ok)
		}
	}
}

func TestEvaluateExitedContainers(t *testing.T) {
	rows := parseDockerPS(
		"c1\tapi\tExited (137) 2 minutes ago\tapi:1.0\n" +
			"c2\tworker\tExited (139) 1 minute ago\tworker:2.0\n" +
			"c3\tcron\tExited (127) 3 minutes ago\tcron:1.0\n" +
			"c4\tbatch\tExited (1) 4 minutes ago\tbatch:1.0\n" +
			"c5\tdone\tExited (0) 5 minutes ago\tdone:1.0\n")

	findings := evaluateExitedContainers(rows)

	// The cleanly-exited container must not be reported.
	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4 (exit code 0 is not a fault)", len(findings))
	}

	byID := map[string]model.Finding{}
	for _, f := range findings {
		byID[f.ID] = f
	}

	for _, want := range []string{"DOC-EXT-137", "DOC-EXT-139", "DOC-EXT-127", "DOC-EXT-ERR"} {
		if _, ok := byID[want]; !ok {
			t.Errorf("missing expected finding %s", want)
		}
	}
	if byID["DOC-EXT-137"].Severity != model.SeverityCritical {
		t.Error("OOMKilled must be CRITICAL")
	}
	if byID["DOC-EXT-ERR"].Severity != model.SeverityWarning {
		t.Error("a generic non-zero exit is a WARNING, not CRITICAL")
	}
	if byID["DOC-EXT-137"].Metadata["exit_code"] != "137" {
		t.Errorf("exit_code metadata = %q", byID["DOC-EXT-137"].Metadata["exit_code"])
	}
}

func TestEvaluateRestartLoop(t *testing.T) {
	c := dockerPS{ID: "abc", Name: "flaky"}

	if _, ok := evaluateRestartLoop(c, "3\trunning\talways"); ok {
		t.Error("3 restarts is below the threshold and must not fire")
	}

	finding, ok := evaluateRestartLoop(c, "42\trunning\talways")
	if !ok {
		t.Fatal("42 restarts must fire DOC-RES-001")
	}
	if finding.ID != "DOC-RES-001" || finding.Severity != model.SeverityCritical {
		t.Errorf("got %s/%s, want DOC-RES-001/CRITICAL", finding.ID, finding.Severity)
	}
	if finding.Metadata["restart_count"] != "42" {
		t.Errorf("restart_count = %q, want 42", finding.Metadata["restart_count"])
	}

	if _, ok := evaluateRestartLoop(c, "not-a-number\trunning"); ok {
		t.Error("unparseable restart count must not fire")
	}
}

func TestEvaluateUnhealthyContainers(t *testing.T) {
	findings := evaluateUnhealthyContainers(parseDockerPS("c1\tapi\tUp 2 hours (unhealthy)\tapi:1.0"))

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != "DOC-HLT-001" || findings[0].Severity != model.SeverityWarning {
		t.Errorf("got %s/%s, want DOC-HLT-001/WARNING", findings[0].ID, findings[0].Severity)
	}
}

func TestParseDockerSize(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
	}{
		{"0B", 0},
		{"512kB", 512_000},
		{"1.5GB", 1_500_000_000},
		{"2TB", 2_000_000_000_000},
		{"12.4GB", 12_400_000_000},
		{"", 0},
		{"garbage", 0},
	}

	for _, tc := range tests {
		if got := parseDockerSize(tc.in); got != tc.want {
			t.Errorf("parseDockerSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseDockerSystemDF(t *testing.T) {
	const sample = "Images\t12.4GB\t8.1GB (65%)\n" +
		"Containers\t1.2GB\t0.5GB (41%)\n" +
		"Local Volumes\t3GB\t3GB (100%)\n" +
		"Build Cache\t2GB\t2GB (100%)\n"

	usage := parseDockerSystemDF(sample)

	if usage.Images != 12_400_000_000 {
		t.Errorf("Images = %d", usage.Images)
	}
	if usage.Total() != 18_600_000_000 {
		t.Errorf("Total() = %d, want 18.6GB", usage.Total())
	}
	if usage.Reclaimable != 13_600_000_000 {
		t.Errorf("Reclaimable = %d, want 13.6GB", usage.Reclaimable)
	}
}

func TestEvaluateDockerDiskFootprint(t *testing.T) {
	usage := dockerDiskUsage{Images: 60_000_000_000, Reclaimable: 40_000_000_000}

	// 60GB of Docker on a 100GB filesystem is 60% — worth reporting.
	findings := evaluateDockerDiskFootprint(usage, 100_000_000_000)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != "DOC-DSK-001" {
		t.Errorf("ID = %s, want DOC-DSK-001", findings[0].ID)
	}

	// The same 60GB on a 1TB filesystem is 6% and unremarkable.
	if got := evaluateDockerDiskFootprint(usage, 1_000_000_000_000); len(got) != 0 {
		t.Errorf("got %d findings on a large filesystem, want 0", len(got))
	}
}

func TestEvaluateDockerDiskFootprintHandlesZeroes(t *testing.T) {
	if got := evaluateDockerDiskFootprint(dockerDiskUsage{}, 100); len(got) != 0 {
		t.Error("empty usage must produce no finding")
	}
	if got := evaluateDockerDiskFootprint(dockerDiskUsage{Images: 100}, 0); len(got) != 0 {
		t.Error("an unknown filesystem size must produce no finding, not a divide by zero")
	}
}
