package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/hi-donwi/OPS-Toolkit/pkg/analyzer"
	"github.com/hi-donwi/OPS-Toolkit/pkg/detector"
	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/report"
	"github.com/spf13/cobra"
)

var (
	verifyFailOn    string
	verifyNamespace string
	verifyTarget    string
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run CI/CD verification quality gate (returns non-zero exit code on failure)",
	Long: `verify is engineered for integration into automated CI/CD pipelines (GitHub Actions,
GitLab CI, Jenkins, ArgoCD hooks).

It executes health and security diagnostics and returns a non-zero exit code
if any finding meets or exceeds the specified failure threshold (--fail-on).

Exit codes:
  0  all findings are below the threshold
  1  the threshold was breached
  2  the diagnostic run itself failed (bad flag, cancelled, or timed out)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		threshold, err := parseThreshold(verifyFailOn)
		if err != nil {
			return err
		}

		targetFilter, err := parseTargetFilter(verifyTarget)
		if err != nil {
			return err
		}

		ctx, cancel := CommandContext()
		defer cancel()

		env := detector.Detect()
		engine := analyzer.NewEngine(env)

		rep, err := engine.RunDiagnostics(ctx, targetFilter, verifyNamespace)
		if err != nil {
			// A failed run is not a passing gate, but it is also not a policy
			// breach; exit 2 keeps the two outcomes distinguishable in CI.
			return &ExitError{Code: 2, Msg: fmt.Sprintf("Verification diagnostic error: %v", err)}
		}

		if OutputFile != "" {
			if err := report.SaveToFile(OutputFile, rep); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not write report to %s: %v\n", OutputFile, err)
			}
		}

		if JSONOutput {
			_ = report.PrintJSON(os.Stdout, rep)
		} else {
			report.PrintConsole(os.Stdout, rep, NoColor)
		}

		c := report.Colors(NoColor)
		breaches := countAtOrAbove(rep.Summary, threshold)

		if breaches > 0 {
			msg := fmt.Sprintf("\n%s Threshold '%s' breached by %d finding(s): %d critical, %d warning, %d info.",
				c.Wrap(c.Red, "[CI/CD GATE FAILED]"), threshold,
				breaches, rep.Summary.Critical, rep.Summary.Warning, rep.Summary.Info)
			return &ExitError{Code: 1, Msg: msg}
		}

		fmt.Printf("\n%s No finding at or above '%s'.\n",
			c.Wrap(c.Green, "[CI/CD GATE PASSED]"), threshold)
		return nil
	},
}

// parseTargetFilter validates --target.
func parseTargetFilter(value string) (model.TargetType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "all":
		return model.TargetType(""), nil
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
		return "", fmt.Errorf("invalid --target %q: want 'host', 'docker', 'swarm', 'k8s', 'sec'", value)
	}
}

// parseThreshold validates --fail-on. An unrecognised value previously fell
// through to "critical", so a typo silently weakened the gate it was meant to
// tighten.
func parseThreshold(value string) (model.Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return model.SeverityCritical, nil
	case "WARNING":
		return model.SeverityWarning, nil
	case "INFO":
		return model.SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid --fail-on value %q: want 'critical', 'warning', or 'info'", value)
	}
}

// countAtOrAbove counts findings at or above the threshold severity.
func countAtOrAbove(s model.Summary, threshold model.Severity) int {
	switch threshold {
	case model.SeverityInfo:
		return s.Critical + s.Warning + s.Info
	case model.SeverityWarning:
		return s.Critical + s.Warning
	default:
		return s.Critical
	}
}

func init() {
	verifyCmd.Flags().StringVar(&verifyFailOn, "fail-on", "critical", "Failure threshold severity: 'critical', 'warning', or 'info'")
	verifyCmd.Flags().StringVarP(&verifyNamespace, "namespace", "n", "", "Target Kubernetes namespace (if active)")
	verifyCmd.Flags().StringVarP(&verifyTarget, "target", "t", "", "Diagnostic target to verify: host, docker, swarm, k8s, sec (default: all)")
	RootCmd.AddCommand(verifyCmd)
}
