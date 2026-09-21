package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/analyzer"
	"github.com/hi-donwi/OPS-Toolkit/pkg/detector"
	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/remediation"
	"github.com/hi-donwi/OPS-Toolkit/pkg/report"
	"github.com/spf13/cobra"
)

var (
	fixDryRun      bool
	fixAutoApprove bool
	fixOnly        []string
	fixMaxRisk     string
)

var fixCmd = &cobra.Command{
	Use:   "fix [host|docker|swarm|k8s|sec]",
	Short: "Run automated or interactive incident remediation and quick-fixes",
	Long: `fix scans active deployments for known issues and executes the curated
remediation command attached to each finding.

--dry-run is the default. Nothing is executed until you either pass
--dry-run=false (which prompts for confirmation) or -y (which does not).

Every command is graded by risk before it runs:
  LOW     additive or read-mostly
  MEDIUM  restarts or reconfigures a service (brief interruption)
  HIGH    deletes data or stops a service outright

Use --max-risk to refuse anything above a chosen grade, and --only to run the
fixes for specific finding IDs.

Examples:
  opskit fix                                  # preview every proposed fix
  opskit fix --dry-run=false --max-risk medium
  opskit fix --only HOST-DSK-001 --dry-run=false
  opskit fix docker -y`,
	RunE: func(cmd *cobra.Command, args []string) error {
		maxRisk, err := parseRisk(fixMaxRisk)
		if err != nil {
			return err
		}

		ctx, cancel := CommandContext()
		defer cancel()

		env := detector.Detect()
		engine := analyzer.NewEngine(env)

		targetFilter, err := parseTarget(args)
		if err != nil {
			return err
		}

		rep, err := engine.RunDiagnostics(ctx, targetFilter, "")
		if err != nil {
			return fmt.Errorf("diagnostics error: %w", err)
		}

		plans := remediation.PlanFixes(rep.Findings)
		plans = filterPlans(plans, fixOnly, maxRisk)

		if len(plans) == 0 {
			fmt.Println("[OK] No actionable quick-fixes match the current filters. Nothing to do.")
			return nil
		}

		printPlans(plans)

		if fixDryRun && !fixAutoApprove {
			c := report.Colors(NoColor)
			fmt.Printf("\n%s\n", c.Wrap(c.Yellow, "DRY-RUN: nothing was executed."))
			fmt.Println("To apply these fixes: opskit fix --dry-run=false   (or add -y to skip the prompt)")
			return nil
		}

		if !fixAutoApprove && !confirm(len(plans)) {
			fmt.Println("Remediation aborted by operator.")
			return nil
		}

		return applyPlans(ctx, plans)
	},
}

// parseTarget maps the positional target argument to a TargetType.
func parseTarget(args []string) (model.TargetType, error) {
	if len(args) == 0 {
		return model.TargetType(""), nil
	}

	switch strings.ToLower(args[0]) {
	case "host":
		return model.TargetHost, nil
	case "docker":
		return model.TargetDocker, nil
	case "swarm":
		return model.TargetSwarm, nil
	case "k8s", "kubernetes":
		return model.TargetKubernetes, nil
	case "sec", "security":
		return model.TargetSecurity, nil
	default:
		// Previously an unrecognised target silently fell through to "scan
		// everything", so a typo widened the blast radius instead of narrowing it.
		return "", fmt.Errorf("unknown target %q: want host, docker, swarm, k8s, or sec", args[0])
	}
}

// parseRisk maps the --max-risk flag to a risk ceiling.
func parseRisk(value string) (remediation.Risk, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "LOW":
		return remediation.RiskLow, nil
	case "MEDIUM":
		return remediation.RiskMedium, nil
	case "HIGH", "":
		return remediation.RiskHigh, nil
	default:
		return "", fmt.Errorf("invalid --max-risk value %q: want 'low', 'medium', or 'high'", value)
	}
}

// riskRank orders risk grades for comparison.
func riskRank(r remediation.Risk) int {
	switch r {
	case remediation.RiskLow:
		return 0
	case remediation.RiskMedium:
		return 1
	default:
		return 2
	}
}

// filterPlans applies the --only and --max-risk filters.
func filterPlans(plans []remediation.FixPlan, only []string, maxRisk remediation.Risk) []remediation.FixPlan {
	wanted := make(map[string]bool, len(only))
	for _, id := range only {
		wanted[strings.ToUpper(strings.TrimSpace(id))] = true
	}

	filtered := make([]remediation.FixPlan, 0, len(plans))
	for _, p := range plans {
		if len(wanted) > 0 && !wanted[strings.ToUpper(p.FindingID)] {
			continue
		}
		if riskRank(p.Risk) > riskRank(maxRisk) {
			continue
		}
		filtered = append(filtered, p)
	}

	return filtered
}

// printPlans lists the proposed remediations with their risk grade.
func printPlans(plans []remediation.FixPlan) {
	c := report.Colors(NoColor)
	fmt.Printf("\nDiscovered %d actionable quick-fix(es):\n\n", len(plans))

	for i, p := range plans {
		fmt.Printf("[%d] %s %s (%s)\n", i+1, riskBadge(p.Risk), p.Description, p.Resource)
		fmt.Printf("    Rule:    %s\n", p.FindingID)
		fmt.Printf("    Command: %s\n\n", c.Wrap(c.Bold, p.Command))
	}
}

// riskBadge renders a coloured risk tag.
func riskBadge(r remediation.Risk) string {
	c := report.Colors(NoColor)
	label := "[" + string(r) + "]"

	switch r {
	case remediation.RiskHigh:
		return c.Wrap(c.Bold+c.Red, label)
	case remediation.RiskMedium:
		return c.Wrap(c.Bold+c.Yellow, label)
	default:
		return c.Wrap(c.Green, label)
	}
}

// confirm asks the operator to approve the batch. When stdin is not a terminal
// there is nobody to answer, so it refuses rather than blocking a CI job or, if
// stdin happens to be a pipe, treating stray input as approval.
func confirm(count int) bool {
	if !stdinIsTerminal() {
		fmt.Fprintln(os.Stderr, "Refusing to apply fixes: stdin is not a terminal. Pass -y to approve non-interactively.")
		return false
	}

	fmt.Printf("Apply all %d fix(es)? [y/N]: ", count)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return false
	}

	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return answer == "y" || answer == "yes"
}

// stdinIsTerminal reports whether stdin is an interactive terminal rather than a
// pipe or file. Avoids a dependency on x/term for a single check.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// applyPlans executes each plan, reporting a per-command result. It returns an
// error when any fix failed, so scripted callers see a non-zero exit.
func applyPlans(ctx context.Context, plans []remediation.FixPlan) error {
	c := report.Colors(NoColor)
	fmt.Println("\nApplying remediations...")

	failed := 0
	for i := range plans {
		p := &plans[i]
		fmt.Printf("Executing [%d/%d] %s... ", i+1, len(plans), p.Description)

		if err := remediation.ExecuteFix(ctx, p, false); err != nil {
			failed++
			fmt.Printf("%s\n", c.Wrap(c.Red, "FAILED"))
			fmt.Printf("  %v\n", err)
			continue
		}

		fmt.Printf("%s (%s)\n", c.Wrap(c.Green, "OK"), p.Duration.Round(time.Millisecond))
		if p.Output != "" {
			fmt.Printf("  %s\n", firstLines(p.Output, 3))
		}
	}

	fmt.Printf("\nRemediation complete: %d succeeded, %d failed.\n", len(plans)-failed, failed)
	if failed > 0 {
		return fmt.Errorf("%d of %d fixes failed", failed, len(plans))
	}
	return nil
}

// firstLines truncates command output so a chatty fix does not flood the screen.
func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n  ")
	}
	return strings.Join(lines[:n], "\n  ") + fmt.Sprintf("\n  … (%d more lines)", len(lines)-n)
}

func init() {
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", true, "Preview remediation actions without executing them")
	fixCmd.Flags().BoolVarP(&fixAutoApprove, "yes", "y", false, "Execute without an interactive confirmation prompt")
	fixCmd.Flags().StringSliceVar(&fixOnly, "only", nil, "Only apply fixes for these finding IDs (comma separated)")
	fixCmd.Flags().StringVar(&fixMaxRisk, "max-risk", "high", "Refuse fixes above this risk grade: low, medium, or high")
	RootCmd.AddCommand(fixCmd)
}
