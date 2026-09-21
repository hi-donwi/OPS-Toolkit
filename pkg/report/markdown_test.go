package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func TestGenerateMarkdown(t *testing.T) {
	rep := &model.Report{
		Title:     "Test SRE Report",
		Timestamp: time.Now(),
		Duration:  "15ms",
		Environment: model.EnvironmentContext{
			Distro: "Linux Ubuntu",
			Arch:   "amd64",
		},
		Summary: model.Summary{
			Critical: 1,
			Warning:  0,
			Pass:     5,
		},
		Findings: []model.Finding{
			{
				ID:          "K8S-OOM-001",
				Title:       "Test Pod Crash",
				Severity:    model.SeverityCritical,
				Resource:    "pod/test-worker",
				Category:    "Workload Crash",
				Symptom:     "CrashLoopBackOff detected",
				RootCause:   "Out of memory 137",
				RemedySteps: []string{"Increase limits"},
				QuickFixCmd: "kubectl set resources",
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateMarkdown(&buf, rep)
	if err != nil {
		t.Fatalf("GenerateMarkdown failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Test SRE Report") {
		t.Errorf("Expected markdown to contain report title")
	}
	if !strings.Contains(output, "K8S-OOM-001") {
		t.Errorf("Expected markdown to contain finding ID")
	}
	if !strings.Contains(output, "kubectl set resources") {
		t.Errorf("Expected markdown to contain quick fix command")
	}
}

func TestPrintConsoleNumbersOnlyPrintedFindings(t *testing.T) {
	// PASS rows are counted in the summary but not listed. Numbering by the
	// index into the full slice makes the visible list read #2, #4, #6.
	rep := &model.Report{
		Timestamp: time.Now(),
		Duration:  "10ms",
		Summary:   model.Summary{Critical: 3, Pass: 3},
		Findings: []model.Finding{
			{ID: "A", Title: "First", Severity: model.SeverityCritical, Resource: "r1"},
			{ID: "P1", Title: "Passed", Severity: model.SeverityPass, Resource: "p1"},
			{ID: "B", Title: "Second", Severity: model.SeverityCritical, Resource: "r2"},
			{ID: "P2", Title: "Passed", Severity: model.SeverityPass, Resource: "p2"},
			{ID: "C", Title: "Third", Severity: model.SeverityCritical, Resource: "r3"},
			{ID: "P3", Title: "Passed", Severity: model.SeverityPass, Resource: "p3"},
		},
	}

	var buf bytes.Buffer
	PrintConsole(&buf, rep, true)
	out := buf.String()

	for _, want := range []string{"#1: First", "#2: Second", "#3: Third"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected contiguous numbering %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Passed") {
		t.Error("PASS findings must not be listed in the detail section")
	}
	if !strings.Contains(out, "3 checks passed") {
		t.Error("PASS findings should still be summarised as a count")
	}
}

func TestPrintConsoleShowsRuleID(t *testing.T) {
	// The rule ID is what an operator passes to `opskit explain` and `--only`.
	rep := &model.Report{
		Timestamp: time.Now(),
		Summary:   model.Summary{Critical: 1},
		Findings: []model.Finding{
			{ID: "K8S-POD-002", Title: "OOMKilled", Severity: model.SeverityCritical, Resource: "pod/api"},
		},
	}

	var buf bytes.Buffer
	PrintConsole(&buf, rep, true)

	if !strings.Contains(buf.String(), "K8S-POD-002") {
		t.Error("console output should name the rule ID")
	}
}

func TestPrintConsoleNoColorEmitsNoANSI(t *testing.T) {
	rep := &model.Report{
		Timestamp: time.Now(),
		Summary:   model.Summary{Critical: 1},
		Findings: []model.Finding{
			{ID: "X", Title: "T", Severity: model.SeverityCritical, Resource: "r", QuickFixCmd: "true"},
		},
	}

	var buf bytes.Buffer
	PrintConsole(&buf, rep, true)

	if strings.Contains(buf.String(), "\033[") {
		t.Error("--no-color output must contain no ANSI escape sequences")
	}
}

func TestPrintJSONRoundTrips(t *testing.T) {
	rep := &model.Report{
		Title:     "T",
		Timestamp: time.Now(),
		Summary:   model.Summary{Critical: 1},
		Findings:  []model.Finding{{ID: "X", Severity: model.SeverityCritical}},
	}

	var buf bytes.Buffer
	if err := PrintJSON(&buf, rep); err != nil {
		t.Fatalf("PrintJSON: %v", err)
	}

	var decoded model.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("emitted JSON does not parse: %v", err)
	}
	if decoded.Summary.Critical != 1 || len(decoded.Findings) != 1 {
		t.Errorf("round-trip lost data: %+v", decoded)
	}
}

func TestSaveToFileChoosesFormatByExtension(t *testing.T) {
	rep := &model.Report{
		Title:     "T",
		Timestamp: time.Now(),
		Findings:  []model.Finding{{ID: "X", Title: "Broken", Severity: model.SeverityCritical}},
	}

	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "report.json")
	if err := SaveToFile(jsonPath, rep); err != nil {
		t.Fatalf("SaveToFile(json): %v", err)
	}
	data, _ := os.ReadFile(jsonPath)
	if !json.Valid(data) {
		t.Error(".json output is not valid JSON")
	}

	mdPath := filepath.Join(dir, "report.md")
	if err := SaveToFile(mdPath, rep); err != nil {
		t.Fatalf("SaveToFile(md): %v", err)
	}
	md, _ := os.ReadFile(mdPath)
	if !strings.HasPrefix(string(md), "#") {
		t.Error(".md output should start with a Markdown heading")
	}
}

func TestGenerateMarkdownOmitsPassDetail(t *testing.T) {
	rep := &model.Report{
		Title:     "T",
		Timestamp: time.Now(),
		Summary:   model.Summary{Pass: 2},
		Findings: []model.Finding{
			{ID: "P1", Title: "Fine", Severity: model.SeverityPass},
			{ID: "P2", Title: "Also fine", Severity: model.SeverityPass},
		},
	}

	var buf bytes.Buffer
	if err := GenerateMarkdown(&buf, rep); err != nil {
		t.Fatalf("GenerateMarkdown: %v", err)
	}

	if !strings.Contains(buf.String(), "No critical issues or warnings detected") {
		t.Error("an all-clear report should say so explicitly")
	}
}
