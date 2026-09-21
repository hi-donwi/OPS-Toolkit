package cmd

import (
	"strings"
	"testing"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/remediation"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		args []string
		want model.TargetType
	}{
		{nil, model.TargetType("")},
		{[]string{"host"}, model.TargetHost},
		{[]string{"docker"}, model.TargetDocker},
		{[]string{"swarm"}, model.TargetSwarm},
		{[]string{"k8s"}, model.TargetKubernetes},
		{[]string{"kubernetes"}, model.TargetKubernetes},
		{[]string{"SEC"}, model.TargetSecurity},
	}

	for _, tc := range tests {
		got, err := parseTarget(tc.args)
		if err != nil {
			t.Errorf("parseTarget(%v): %v", tc.args, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseTarget(%v) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestParseTargetRejectsUnknownValue(t *testing.T) {
	// An unrecognised target used to fall through to "scan everything", so a
	// typo widened the blast radius of `fix` instead of narrowing it.
	_, err := parseTarget([]string{"dcoker"})
	if err == nil {
		t.Fatal("expected an error for an unknown target")
	}
	if !strings.Contains(err.Error(), "dcoker") {
		t.Errorf("error should quote the offending value, got: %v", err)
	}
}

func TestParseRisk(t *testing.T) {
	tests := []struct {
		in      string
		want    remediation.Risk
		wantErr bool
	}{
		{"low", remediation.RiskLow, false},
		{"MEDIUM", remediation.RiskMedium, false},
		{"high", remediation.RiskHigh, false},
		{"", remediation.RiskHigh, false},
		{"extreme", "", true},
	}

	for _, tc := range tests {
		got, err := parseRisk(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseRisk(%q) should have failed", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseRisk(%q) = (%s, %v), want %s", tc.in, got, err, tc.want)
		}
	}
}

func TestFilterPlansByRiskCeiling(t *testing.T) {
	plans := []remediation.FixPlan{
		{FindingID: "A", Risk: remediation.RiskLow},
		{FindingID: "B", Risk: remediation.RiskMedium},
		{FindingID: "C", Risk: remediation.RiskHigh},
	}

	if got := filterPlans(plans, nil, remediation.RiskHigh); len(got) != 3 {
		t.Errorf("max-risk high kept %d plans, want 3", len(got))
	}
	if got := filterPlans(plans, nil, remediation.RiskMedium); len(got) != 2 {
		t.Errorf("max-risk medium kept %d plans, want 2", len(got))
	}

	low := filterPlans(plans, nil, remediation.RiskLow)
	if len(low) != 1 || low[0].FindingID != "A" {
		t.Errorf("max-risk low kept %+v, want only the low-risk plan", low)
	}
}

func TestFilterPlansByFindingID(t *testing.T) {
	plans := []remediation.FixPlan{
		{FindingID: "HOST-DSK-001", Risk: remediation.RiskLow},
		{FindingID: "DOC-EXT-137", Risk: remediation.RiskLow},
	}

	got := filterPlans(plans, []string{"host-dsk-001"}, remediation.RiskHigh)

	if len(got) != 1 || got[0].FindingID != "HOST-DSK-001" {
		t.Errorf("--only should match case-insensitively, got %+v", got)
	}
}

func TestFilterPlansCombinesBothFilters(t *testing.T) {
	plans := []remediation.FixPlan{
		{FindingID: "A", Risk: remediation.RiskHigh},
		{FindingID: "B", Risk: remediation.RiskLow},
	}

	// Named explicitly, but still above the risk ceiling: the ceiling wins.
	if got := filterPlans(plans, []string{"A"}, remediation.RiskLow); len(got) != 0 {
		t.Errorf("--max-risk must still apply to plans named by --only, got %+v", got)
	}
}

func TestFirstLinesTruncates(t *testing.T) {
	if got := firstLines("a\nb", 3); got != "a\n  b" {
		t.Errorf("short output should pass through, got %q", got)
	}

	got := firstLines("1\n2\n3\n4\n5", 3)
	if !strings.Contains(got, "2 more lines") {
		t.Errorf("long output should be truncated with a count, got %q", got)
	}
}
