package exporter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func sampleReport() *model.Report {
	return &model.Report{
		Timestamp: time.Unix(1_756_000_000, 0),
		Summary:   model.Summary{Critical: 1, Warning: 2, Info: 1, Pass: 10},
		Findings: []model.Finding{
			{ID: "HOST-DSK-001", TargetType: model.TargetHost, Severity: model.SeverityCritical, Resource: "filesystem:/"},
			{ID: "DOC-HLT-001", TargetType: model.TargetDocker, Severity: model.SeverityWarning, Resource: "container:api"},
			{ID: "K8S-POD-001", TargetType: model.TargetKubernetes, Severity: model.SeverityWarning, Resource: "pod/x", Namespace: "prod"},
			{ID: "SWM-NOD-002", TargetType: model.TargetSwarm, Severity: model.SeverityInfo, Resource: "node/n1"},
			{ID: "HOST-DNS-001", TargetType: model.TargetHost, Severity: model.SeverityPass, Resource: "dns:example"},
		},
	}
}

func render(t *testing.T, rep *model.Report) string {
	t.Helper()
	var buf bytes.Buffer
	writeMetrics(&buf, rep, 0, rep.Timestamp)
	return buf.String()
}

func TestWriteMetricsEmitsCoreSeries(t *testing.T) {
	out := render(t, sampleReport())

	for _, want := range []string{
		"opskit_up 1",
		"opskit_findings_total",
		"opskit_severity_count",
		"opskit_health_score",
		"opskit_last_evaluation_timestamp_seconds",
		"opskit_evaluation_errors_total",
		"opskit_finding_active",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing metric %q in output", want)
		}
	}

	// Every metric family needs its HELP and TYPE lines or Prometheus discards
	// the metadata.
	if strings.Count(out, "# HELP") != strings.Count(out, "# TYPE") {
		t.Error("HELP and TYPE lines are unbalanced")
	}
}

func TestWriteMetricsSeveritySummary(t *testing.T) {
	out := render(t, sampleReport())

	for _, want := range []string{
		`opskit_severity_count{severity="CRITICAL"} 1`,
		`opskit_severity_count{severity="WARNING"} 2`,
		`opskit_severity_count{severity="INFO"} 1`,
		`opskit_severity_count{severity="PASS"} 10`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing line: %s", want)
		}
	}
}

func TestWriteMetricsOmitsPassFromActiveFindings(t *testing.T) {
	out := render(t, sampleReport())

	// PASS rows would multiply series cardinality for no alerting value.
	if strings.Contains(out, `opskit_finding_active{id="HOST-DNS-001"`) {
		t.Error("PASS findings must not be emitted as active findings")
	}
	if !strings.Contains(out, `opskit_finding_active{id="HOST-DSK-001"`) {
		t.Error("critical findings must be emitted as active findings")
	}
}

func TestWriteMetricsIsDeterministic(t *testing.T) {
	// Ranging a map directly makes scrape output reorder between calls, which
	// breaks diffs and any golden comparison.
	rep := sampleReport()
	first := render(t, rep)

	for i := 0; i < 10; i++ {
		if got := render(t, rep); got != first {
			t.Fatal("metrics output is not stable across renders")
		}
	}
}

func TestWriteMetricsDeduplicatesIdenticalSeries(t *testing.T) {
	// Duplicate label sets make Prometheus reject the entire scrape.
	rep := &model.Report{
		Timestamp: time.Now(),
		Findings: []model.Finding{
			{ID: "SEC-FIL-001", TargetType: model.TargetSecurity, Severity: model.SeverityCritical, Resource: "file:/etc/shadow"},
			{ID: "SEC-FIL-001", TargetType: model.TargetSecurity, Severity: model.SeverityCritical, Resource: "file:/etc/shadow"},
		},
	}

	out := render(t, rep)
	if got := strings.Count(out, "opskit_finding_active{"); got != 1 {
		t.Errorf("emitted %d active-finding series, want 1 after de-duplication", got)
	}
}

func TestEscapeLabel(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{`plain`, `plain`},
		{`say "hi"`, `say \"hi\"`},
		{`C:\path`, `C:\\path`},
		{"two\nlines", `two\nlines`},
	}

	for _, tc := range tests {
		if got := escapeLabel(tc.in); got != tc.want {
			t.Errorf("escapeLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEscapeLabelKeepsExpositionParseable(t *testing.T) {
	// A quote inside a resource name (a container command, a mount path) would
	// otherwise terminate the label value and corrupt the whole scrape.
	rep := &model.Report{
		Timestamp: time.Now(),
		Findings: []model.Finding{{
			ID:         `weird"id`,
			TargetType: model.TargetHost,
			Severity:   model.SeverityCritical,
			Resource:   `container:sh -c "echo hi"`,
		}},
	}

	out := render(t, rep)
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "opskit_finding_active{") {
			continue
		}
		// A correctly escaped line has exactly one unescaped quote per label
		// delimiter; the raw two-quote sequence from the resource must be gone.
		if strings.Contains(line, `"echo hi"`) {
			t.Errorf("unescaped quotes leaked into exposition: %s", line)
		}
	}
}

func TestHealthScore(t *testing.T) {
	tests := []struct {
		name    string
		summary model.Summary
		want    int
	}{
		{"clean", model.Summary{Pass: 20}, 100},
		{"one warning", model.Summary{Warning: 1, Pass: 5}, 90},
		{"one critical", model.Summary{Critical: 1, Pass: 5}, 70},
		{"mixed", model.Summary{Critical: 1, Warning: 2, Pass: 5}, 50},
		{"clamped at zero", model.Summary{Critical: 10}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HealthScore(tc.summary); got != tc.want {
				t.Errorf("HealthScore(%+v) = %d, want %d", tc.summary, got, tc.want)
			}
		})
	}
}

func TestHandleMetricsBeforeFirstEvaluation(t *testing.T) {
	// A dashboard must be able to tell "starting up" from "collector gone".
	s := NewMetricsServer(9999, time.Minute)

	rec := httptest.NewRecorder()
	s.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "opskit_up 0") {
		t.Errorf("expected opskit_up 0 before the first evaluation, got:\n%s", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want the Prometheus text exposition type", ct)
	}
}
