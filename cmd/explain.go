package cmd

import (
	"fmt"
	"strings"

	"github.com/hi-donwi/OPS-Toolkit/pkg/ai"
	"github.com/hi-donwi/OPS-Toolkit/pkg/analyzer"
	"github.com/hi-donwi/OPS-Toolkit/pkg/detector"
	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:   "explain [finding-id]",
	Short: "AI Incident Copilot: Generate deep root-cause explanation and incident runbook",
	Long: `explain uses local Ollama or built-in SRE knowledge engines to generate
comprehensive, human-readable Incident Runbooks and Root-Cause Analyses (RCA)
for any detected diagnostic finding.

Example:
  opskit explain HOST-DSK-001
  opskit explain K8S-POD-001`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := CommandContext()
		defer cancel()

		env := detector.Detect()
		engine := analyzer.NewEngine(env)

		copilot := ai.NewCopilotClient()

		// If finding-id provided as argument, resolve it instantly from catalog
		if len(args) > 0 {
			targetID := strings.ToUpper(strings.TrimSpace(args[0]))
			if catalogFinding, ok := analyzer.GetCatalogFinding(targetID); ok {
				briefing, err := copilot.ExplainFinding(ctx, catalogFinding)
				if err != nil {
					return fmt.Errorf("error generating briefing for %s: %w", targetID, err)
				}
				fmt.Println(briefing)
				return nil
			}

			// If not in standard catalog, check active scan results
			rep, err := engine.RunDiagnostics(ctx, model.TargetType(""), "")
			if err != nil {
				return fmt.Errorf("diagnostics error: %w", err)
			}
			for _, f := range rep.Findings {
				if strings.ToUpper(f.ID) == targetID {
					briefing, err := copilot.ExplainFinding(ctx, f)
					if err != nil {
						return fmt.Errorf("error generating briefing for %s: %w", targetID, err)
					}
					fmt.Println(briefing)
					return nil
				}
			}

			// Fallback generic explanation
			genericFinding := model.Finding{
				ID:        targetID,
				Title:     fmt.Sprintf("Diagnostic Finding %s", targetID),
				Severity:  model.SeverityCritical,
				Resource:  "target/resource",
				Symptom:   "Observed anomaly matching rule " + targetID,
				RootCause: "Resource threshold breached, configuration error, or service failed.",
			}
			briefing, _ := copilot.ExplainFinding(ctx, genericFinding)
			fmt.Println(briefing)
			return nil
		}

		// If no argument provided, run full diagnostics and explain active issues
		rep, err := engine.RunDiagnostics(ctx, model.TargetType(""), "")
		if err != nil {
			return fmt.Errorf("diagnostics error: %w", err)
		}

		var matched []model.Finding
		for _, f := range rep.Findings {
			if f.Severity == model.SeverityPass {
				continue
			}
			matched = append(matched, f)
		}

		if len(matched) == 0 {
			fmt.Println("[OK] No active critical or warning findings to explain. System is healthy.")
			return nil
		}

		for _, f := range matched {
			briefing, err := copilot.ExplainFinding(ctx, f)
			if err != nil {
				fmt.Printf("Error generating briefing for %s: %v\n", f.ID, err)
				continue
			}
			fmt.Println(briefing)
			fmt.Println("--------------------------------------------------------------------------------")
		}

		return nil
	},
}

func init() {
	RootCmd.AddCommand(explainCmd)
}
