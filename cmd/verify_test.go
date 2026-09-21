package cmd

import (
	"strings"
	"testing"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func TestParseThreshold(t *testing.T) {
	tests := []struct {
		in      string
		want    model.Severity
		wantErr bool
	}{
		{"critical", model.SeverityCritical, false},
		{"CRITICAL", model.SeverityCritical, false},
		{" warning ", model.SeverityWarning, false},
		{"info", model.SeverityInfo, false},
		// An unrecognised value previously fell through to "critical", so a
		// typo silently weakened the gate it was meant to tighten.
		{"criticl", "", true},
		{"", "", true},
		{"none", "", true},
	}

	for _, tc := range tests {
		got, err := parseThreshold(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseThreshold(%q) should have failed", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseThreshold(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseThreshold(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestParseThresholdErrorNamesValidValues(t *testing.T) {
	_, err := parseThreshold("bogus")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"critical", "warning", "info"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should list %q as a valid value, got: %v", want, err)
		}
	}
}

func TestCountAtOrAbove(t *testing.T) {
	summary := model.Summary{Critical: 2, Warning: 3, Info: 4, Pass: 10}

	tests := []struct {
		threshold model.Severity
		want      int
	}{
		{model.SeverityCritical, 2},
		{model.SeverityWarning, 5},
		{model.SeverityInfo, 9},
	}

	for _, tc := range tests {
		if got := countAtOrAbove(summary, tc.threshold); got != tc.want {
			t.Errorf("countAtOrAbove(%s) = %d, want %d", tc.threshold, got, tc.want)
		}
	}
}

func TestCountAtOrAboveNeverCountsPass(t *testing.T) {
	if got := countAtOrAbove(model.Summary{Pass: 100}, model.SeverityInfo); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestParseTargetFilter(t *testing.T) {
	tests := []struct {
		in      string
		want    model.TargetType
		wantErr bool
	}{
		{"", model.TargetType(""), false},
		{"all", model.TargetType(""), false},
		{"host", model.TargetHost, false},
		{"HOST", model.TargetHost, false},
		{"docker", model.TargetDocker, false},
		{"swarm", model.TargetSwarm, false},
		{"k8s", model.TargetKubernetes, false},
		{"kubernetes", model.TargetKubernetes, false},
		{"sec", model.TargetSecurity, false},
		{"security", model.TargetSecurity, false},
		{"unknown", "", true},
		{"invalid", "", true},
	}

	for _, tc := range tests {
		got, err := parseTargetFilter(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseTargetFilter(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTargetFilter(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseTargetFilter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
