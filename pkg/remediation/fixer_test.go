package remediation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func TestClassifyRisk(t *testing.T) {
	tests := []struct {
		command string
		want    Risk
	}{
		{"journalctl --vacuum-time=3d", RiskHigh},
		{"docker system prune -f", RiskHigh},
		{"find /tmp -type f -atime +7 -delete", RiskHigh},
		{"systemctl restart nginx", RiskMedium},
		{"kubectl rollout restart deployment -n prod", RiskMedium},
		{"chmod 0600 /etc/shadow", RiskMedium},
		{"docker start abc123", RiskLow},
		{"echo hello", RiskLow},
	}

	for _, tc := range tests {
		if got := ClassifyRisk(tc.command); got != tc.want {
			t.Errorf("ClassifyRisk(%q) = %s, want %s", tc.command, got, tc.want)
		}
	}
}

func TestPlanFixes(t *testing.T) {
	findings := []model.Finding{
		{ID: "SEC-FIL-001", Title: "Insecure File", Resource: "file:/etc/shadow",
			Severity: model.SeverityCritical, QuickFixCmd: "chmod 0600 /etc/shadow"},
		{ID: "HOST-DNS-001", Title: "DNS Healthy", Resource: "dns:example",
			Severity: model.SeverityPass, QuickFixCmd: "systemctl restart systemd-resolved"},
		{ID: "HOST-MEM-002", Title: "No fix available", Severity: model.SeverityWarning},
	}

	plans := PlanFixes(findings)

	if len(plans) != 1 {
		t.Fatalf("got %d plans, want 1", len(plans))
	}
	if plans[0].Command != "chmod 0600 /etc/shadow" {
		t.Errorf("command = %q", plans[0].Command)
	}
	if plans[0].Risk != RiskMedium {
		t.Errorf("risk = %s, want MEDIUM", plans[0].Risk)
	}
}

func TestPlanFixesSkipsPassFindings(t *testing.T) {
	// A PASS finding carrying a quick-fix command must never be executed:
	// nothing is wrong, and the command would restart a healthy service.
	plans := PlanFixes([]model.Finding{{
		ID: "HOST-DNS-001", Severity: model.SeverityPass,
		QuickFixCmd: "systemctl restart systemd-resolved",
	}})

	if len(plans) != 0 {
		t.Errorf("PASS findings must not produce fix plans, got %+v", plans)
	}
}

func TestPlanFixesDeduplicatesCommands(t *testing.T) {
	// Several saturated filesystems all suggest the same prune command.
	plans := PlanFixes([]model.Finding{
		{ID: "A", Severity: model.SeverityWarning, QuickFixCmd: "docker system prune -f"},
		{ID: "B", Severity: model.SeverityWarning, QuickFixCmd: "docker system prune -f"},
	})

	if len(plans) != 1 {
		t.Errorf("got %d plans, want 1 after de-duplication", len(plans))
	}
}

func TestExecuteFixDryRun(t *testing.T) {
	plan := FixPlan{FindingID: "X", Command: "rm -rf /important"}

	if err := ExecuteFix(context.Background(), &plan, true); err != nil {
		t.Fatalf("dry run returned an error: %v", err)
	}
	if plan.Executed {
		t.Error("dry run must not mark the plan executed")
	}
	if !strings.Contains(plan.Output, "would execute") {
		t.Errorf("Output = %q, want a dry-run description", plan.Output)
	}
}

func TestExecuteFixRunsCommand(t *testing.T) {
	plan := FixPlan{FindingID: "X", Command: "echo remediated"}

	if err := ExecuteFix(context.Background(), &plan, false); err != nil {
		t.Fatalf("ExecuteFix: %v", err)
	}
	if !plan.Executed || !plan.Success {
		t.Errorf("Executed=%v Success=%v, want both true", plan.Executed, plan.Success)
	}
	if plan.Output != "remediated" {
		t.Errorf("Output = %q", plan.Output)
	}
	if plan.Duration <= 0 {
		t.Error("Duration should be measured")
	}
}

func TestExecuteFixReportsFailure(t *testing.T) {
	plan := FixPlan{FindingID: "X", Command: "exit 7"}

	err := ExecuteFix(context.Background(), &plan, false)
	if err == nil {
		t.Fatal("expected an error for a non-zero exit")
	}
	if plan.Success {
		t.Error("a failed command must not be marked successful")
	}
	if plan.Error == "" {
		t.Error("Error should record why the fix failed")
	}
}

func TestExecuteFixRejectsEmptyCommand(t *testing.T) {
	plan := FixPlan{FindingID: "X", Command: "   "}
	if err := ExecuteFix(context.Background(), &plan, false); err == nil {
		t.Error("expected an error for an empty command")
	}
}

func TestExecuteFixHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	plan := FixPlan{FindingID: "X", Command: "sleep 10"}

	start := time.Now()
	if err := ExecuteFix(ctx, &plan, false); err == nil {
		t.Fatal("expected an error when the context expires")
	}
	if time.Since(start) > 3*time.Second {
		t.Error("cancellation did not interrupt the fix")
	}
}
