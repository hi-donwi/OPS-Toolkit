package cmd

import (
	"encoding/json"
	"fmt"
	"io"
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
	verifyReport    string
	verifyRules     []string
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run CI/CD verification quality gate (returns non-zero exit code on failure)",
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) > 0 {
			return &ExitError{Code: 2, Msg: "verify accepts no positional arguments; use --report FILE"}
		}
		return nil
	},
	Long: `verify is engineered for integration into automated CI/CD pipelines (GitHub Actions,
GitLab CI, Jenkins, ArgoCD hooks).

It executes health and security diagnostics and returns a non-zero exit code
if any finding meets or exceeds the specified failure threshold (--fail-on).

Use --report FILE (or - for stdin) to verify a saved JSON report without probing
the machine. --target and --namespace then require coverage rather than filter
the findings; --require-rule can require specific rule IDs in that scope.

Exit codes:
  0  all findings are below the threshold
  1  the threshold was breached
  2  the diagnostic run itself failed (bad flag, cancelled, or timed out)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		threshold, err := parseThreshold(verifyFailOn)
		if err != nil {
			return &ExitError{Code: 2, Msg: err.Error()}
		}

		targetFilter, err := parseTargetFilter(verifyTarget)
		if err != nil {
			return &ExitError{Code: 2, Msg: err.Error()}
		}

		var rep *model.Report
		if verifyReport != "" {
			input := cmd.InOrStdin()
			if verifyReport != "-" {
				file, err := os.Open(verifyReport)
				if err != nil {
					return &ExitError{Code: 2, Msg: fmt.Sprintf("Cannot open verification report: %v", err)}
				}
				defer file.Close()
				input = file
			}
			rep, err = readVerificationReport(input, targetFilter, verifyNamespace, verifyRules)
			if err != nil {
				return &ExitError{Code: 2, Msg: fmt.Sprintf("Invalid verification report: %v", err)}
			}
		} else {
			if len(verifyRules) > 0 {
				return &ExitError{Code: 2, Msg: "--require-rule requires --report"}
			}
			ctx, cancel := CommandContext()
			defer cancel()
			env := detector.Detect()
			engine := analyzer.NewEngine(env)
			rep, err = engine.RunDiagnostics(ctx, targetFilter, verifyNamespace)
			if err != nil {
				// An incomplete run is not a policy breach or a passing gate.
				return &ExitError{Code: 2, Msg: fmt.Sprintf("Verification diagnostic error: %v", err)}
			}
		}

		if OutputFile != "" {
			if err := report.SaveToFile(OutputFile, rep); err != nil {
				return &ExitError{Code: 2, Msg: fmt.Sprintf("Cannot save verification report: %v", err)}
			}
		}

		if JSONOutput {
			if err := report.PrintJSON(os.Stdout, rep); err != nil {
				return &ExitError{Code: 2, Msg: fmt.Sprintf("Cannot write verification report: %v", err)}
			}
		} else {
			report.PrintConsole(os.Stdout, rep, NoColor)
		}

		c := report.Colors(NoColor)
		if err := verifyCoverage(rep); err != nil {
			return err
		}
		breaches := countAtOrAbove(rep.Summary, threshold)

		if breaches > 0 {
			msg := fmt.Sprintf("\n%s Threshold '%s' breached by %d finding(s): %d critical, %d warning, %d info.",
				c.Wrap(c.Red, "[CI/CD GATE FAILED]"), threshold,
				breaches, rep.Summary.Critical, rep.Summary.Warning, rep.Summary.Info)
			return &ExitError{Code: 1, Msg: msg}
		}

		out := os.Stdout
		if JSONOutput {
			out = os.Stderr
		}
		fmt.Fprintf(out, "\n%s No finding at or above '%s'.\n",
			c.Wrap(c.Green, "[CI/CD GATE PASSED]"), threshold)
		return nil
	},
}

func verifyCoverage(rep *model.Report) error {
	if rep.ChecksExecuted == 0 || rep.CollectionErrors > 0 {
		return &ExitError{Code: 2, Msg: fmt.Sprintf("Verification incomplete: %d findings, %d collection errors", rep.ChecksExecuted, rep.CollectionErrors)}
	}
	return nil
}

func readVerificationReport(input io.Reader, target model.TargetType, namespace string, requiredRules []string) (*model.Report, error) {
	const maxBytes = 16 << 20
	data, err := io.ReadAll(io.LimitReader(input, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read JSON: %w", err)
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("report exceeds 16 MiB")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("cannot decode JSON: %w", err)
	}
	for _, name := range []string{"checks_executed", "collection_errors", "summary", "findings"} {
		if len(fields[name]) == 0 || strings.TrimSpace(string(fields[name])) == "null" {
			return nil, fmt.Errorf("missing report field %s", name)
		}
	}
	var rep model.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("invalid report fields: %w", err)
	}
	if rep.ChecksExecuted <= 0 || rep.CollectionErrors != 0 || rep.ChecksExecuted != len(rep.Findings) {
		return nil, fmt.Errorf("incomplete or inconsistent report coverage")
	}
	foundTarget, foundNamespace := target == "", namespace == ""
	rules := make(map[string]bool)
	for _, finding := range rep.Findings {
		if strings.TrimSpace(finding.ID) == "" || finding.Metadata["collection_error"] == "true" {
			return nil, fmt.Errorf("missing rule identity or failed collection")
		}
		switch finding.Severity {
		case model.SeverityCritical, model.SeverityWarning, model.SeverityInfo, model.SeverityPass:
		default:
			return nil, fmt.Errorf("unrecognized finding severity")
		}
		switch finding.TargetType {
		case model.TargetHost, model.TargetDocker, model.TargetSwarm, model.TargetKubernetes, model.TargetSecurity:
		default:
			return nil, fmt.Errorf("unrecognized finding target")
		}
		inTarget := target == "" || finding.TargetType == target
		inNamespace := namespace == "" || (finding.TargetType == model.TargetKubernetes && finding.Namespace == namespace)
		foundTarget = foundTarget || inTarget
		foundNamespace = foundNamespace || (inTarget && inNamespace)
		if inTarget && inNamespace {
			rules[finding.ID] = true
		}
	}
	if rep.Summary != analyzer.Summarize(rep.Findings) {
		return nil, fmt.Errorf("summary does not match findings")
	}
	if !foundTarget || !foundNamespace {
		return nil, fmt.Errorf("requested target or namespace has no coverage")
	}
	for _, rule := range requiredRules {
		if !rules[strings.TrimSpace(rule)] {
			return nil, fmt.Errorf("required rule has no coverage in the requested scope")
		}
	}
	return &rep, nil
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
	verifyCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &ExitError{Code: 2, Msg: err.Error()}
	})
	verifyCmd.Flags().StringVar(&verifyFailOn, "fail-on", "critical", "Failure threshold severity: 'critical', 'warning', or 'info'")
	verifyCmd.Flags().StringVarP(&verifyNamespace, "namespace", "n", "", "Target Kubernetes namespace (if active)")
	verifyCmd.Flags().StringVarP(&verifyTarget, "target", "t", "", "Diagnostic target to verify: host, docker, swarm, k8s, sec (default: all)")
	verifyCmd.Flags().StringVar(&verifyReport, "report", "", "Verify a saved JSON report without probes (file path or '-' for stdin; maximum 16 MiB)")
	verifyCmd.Flags().StringArrayVar(&verifyRules, "require-rule", nil, "Require this rule ID in the saved report's requested scope (repeatable; needs --report)")
	RootCmd.AddCommand(verifyCmd)
}
