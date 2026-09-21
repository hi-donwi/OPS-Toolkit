// Package remediation turns findings into executable mitigation plans and runs
// them under explicit operator control.
package remediation

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// DefaultTimeout bounds a single remediation command.
const DefaultTimeout = 60 * time.Second

// Risk classifies how much damage a remediation command can do if it is wrong.
type Risk string

const (
	// RiskLow describes read-mostly or additive commands.
	RiskLow Risk = "LOW"
	// RiskMedium describes commands that restart or reconfigure a service,
	// causing a brief interruption.
	RiskMedium Risk = "MEDIUM"
	// RiskHigh describes commands that delete data or stop a service outright.
	RiskHigh Risk = "HIGH"
)

// FixPlan represents a proposed or applied remediation action.
type FixPlan struct {
	FindingID   string         `json:"finding_id"`
	Resource    string         `json:"resource"`
	Description string         `json:"description"`
	Command     string         `json:"command"`
	Risk        Risk           `json:"risk"`
	Severity    model.Severity `json:"severity"`
	Executed    bool           `json:"executed"`
	Success     bool           `json:"success"`
	Output      string         `json:"output,omitempty"`
	Error       string         `json:"error,omitempty"`
	Duration    time.Duration  `json:"duration"`
}

// destructiveVerbs mark commands that remove data or stop serving traffic.
// These are surfaced separately so an operator approving a batch is not asked to
// spot `rm -rf` in a wall of text.
var destructiveVerbs = []string{
	"rm ", "rm -", "delete", "prune", "vacuum", "truncate",
	"drop ", "mkfs", "dd ", "kill", "stop",
}

// disruptiveVerbs mark commands that interrupt a running service.
var disruptiveVerbs = []string{
	"restart", "reload", "rollout", "update", "chmod", "chown", "sed -i", "set ",
}

// ClassifyRisk grades a command by what it can destroy. It is a heuristic on the
// command text and is used to decide what needs a second look, never to decide
// that something is safe to run unattended.
func ClassifyRisk(command string) Risk {
	lower := strings.ToLower(command)

	for _, verb := range destructiveVerbs {
		if strings.Contains(lower, verb) {
			return RiskHigh
		}
	}
	for _, verb := range disruptiveVerbs {
		if strings.Contains(lower, verb) {
			return RiskMedium
		}
	}
	return RiskLow
}

// PlanFixes extracts executable remediation plans from diagnostic findings.
// Findings that merely passed carry no command and are skipped.
func PlanFixes(findings []model.Finding) []FixPlan {
	plans := make([]FixPlan, 0)
	seen := make(map[string]bool)

	for _, f := range findings {
		if f.QuickFixCmd == "" || f.Severity == model.SeverityPass {
			continue
		}

		// Several findings can suggest the same command (one `docker system
		// prune` per saturated filesystem). Running it repeatedly is wasted
		// work at best, so collapse duplicates.
		if seen[f.QuickFixCmd] {
			continue
		}
		seen[f.QuickFixCmd] = true

		plans = append(plans, FixPlan{
			FindingID:   f.ID,
			Resource:    f.Resource,
			Description: f.Title,
			Command:     f.QuickFixCmd,
			Risk:        ClassifyRisk(f.QuickFixCmd),
			Severity:    f.Severity,
		})
	}

	return plans
}

// ExecuteFix runs the remediation command, or describes it when dryRun is set.
//
// Commands are run through `sh -c` because the curated fixes use shell operators
// (pipes, &&). They originate from opskit's own rule set and from rule files the
// operator authored, so they are trusted input — but they are still gated behind
// an explicit confirmation in the CLI rather than run automatically.
func ExecuteFix(ctx context.Context, plan *FixPlan, dryRun bool) error {
	if strings.TrimSpace(plan.Command) == "" {
		return fmt.Errorf("fix plan for %s has an empty command", plan.FindingID)
	}

	if dryRun {
		plan.Executed = false
		plan.Output = "[DRY-RUN] would execute: " + plan.Command
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(ctx, "sh", "-c", plan.Command)
	prepareCommand(cmd)
	out, err := cmd.CombinedOutput()

	plan.Executed = true
	plan.Duration = time.Since(start)
	plan.Output = strings.TrimSpace(string(out))

	if ctx.Err() == context.DeadlineExceeded {
		plan.Success = false
		plan.Error = fmt.Sprintf("timed out after %s", DefaultTimeout)
		return fmt.Errorf("fix %s timed out after %s", plan.FindingID, DefaultTimeout)
	}
	if err != nil {
		plan.Success = false
		plan.Error = err.Error()
		return fmt.Errorf("fix %s failed: %w (output: %s)", plan.FindingID, err, plan.Output)
	}

	plan.Success = true
	return nil
}
