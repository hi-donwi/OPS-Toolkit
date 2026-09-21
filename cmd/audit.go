package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/analyzer"
	"github.com/hi-donwi/OPS-Toolkit/pkg/detector"
	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/report"
	"github.com/hi-donwi/OPS-Toolkit/pkg/security"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit [sec|certs]",
	Short: "Run security and hardening compliance audits",
	Long: `audit runs security checks against Linux Host files and permissions,
Docker container configurations (privileged flags, root execution, socket mounts),
and Kubernetes Pod Security Standards.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAudit(model.TargetSecurity)
	},
}

var auditSecCmd = &cobra.Command{
	Use:   "sec",
	Short: "Run comprehensive security posture audit (Host, Docker, K8s)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAudit(model.TargetSecurity)
	},
}

var auditCertsCmd = &cobra.Command{
	Use:   "certs [target-host:port]",
	Short: "Audit SSL/TLS certificate validity and expiration (local paths or remote endpoint)",
	Long: `certs scans local system certificate paths (/etc/ssl/certs, /etc/letsencrypt)
or connects directly to a specified remote TLS host (e.g. opskit audit certs google.com:443)
to check days remaining until expiration and certificate trust chains.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		start := time.Now()
		env := detector.Detect()

		rep := &model.Report{
			Title:       "SSL/TLS Certificate Validity & Expiration Audit",
			Timestamp:   start,
			Environment: env,
			Findings:    make([]model.Finding, 0),
		}

		if len(args) > 0 {
			ctx, cancel := CommandContext()
			defer cancel()

			target := args[0]
			findings, err := security.AuditCertEndpoint(ctx, target)
			if err != nil {
				return fmt.Errorf("certificate audit error for %s: %w", target, err)
			}
			rep.Findings = append(rep.Findings, findings...)
		} else {
			// Scan local certificate paths
			rep.Findings = append(rep.Findings, security.AuditLocalCertPaths()...)
			if len(rep.Findings) == 0 {
				rep.Findings = append(rep.Findings, model.Finding{
					ID:         "SEC-CRT-PASS",
					Title:      "Local Certificate Directories Scanned",
					TargetType: model.TargetSecurity,
					Category:   "Certificate Health",
					Resource:   "local:/etc/ssl/certs",
					Severity:   model.SeverityPass,
					Symptom:    "No expiring or invalid certificates found in standard system paths.",
				})
			}
		}

		// Calculate summary
		for _, f := range rep.Findings {
			switch f.Severity {
			case model.SeverityCritical:
				rep.Summary.Critical++
			case model.SeverityWarning:
				rep.Summary.Warning++
			case model.SeverityInfo:
				rep.Summary.Info++
			case model.SeverityPass:
				rep.Summary.Pass++
			}
		}

		rep.Duration = time.Since(start).Round(time.Millisecond).String()

		if OutputFile != "" {
			if err := report.SaveToFile(OutputFile, rep); err != nil {
				return fmt.Errorf("failed to save report to file: %w", err)
			}
			fmt.Printf("Report successfully saved to %s\n", OutputFile)
		}

		if JSONOutput {
			return report.PrintJSON(os.Stdout, rep)
		}

		report.PrintConsole(os.Stdout, rep, NoColor)
		return nil
	},
}

func init() {
	auditCmd.AddCommand(auditSecCmd)
	auditCmd.AddCommand(auditCertsCmd)
	RootCmd.AddCommand(auditCmd)
}

func runAudit(target model.TargetType) error {
	ctx, cancel := CommandContext()
	defer cancel()
	env := detector.Detect()
	engine := analyzer.NewEngine(env)

	rep, err := engine.RunDiagnostics(ctx, target, "")
	if err != nil {
		return fmt.Errorf("failed running security audit: %w", err)
	}

	rep.Title = "SRE Security Posture & Hardening Audit"

	if OutputFile != "" {
		if err := report.SaveToFile(OutputFile, rep); err != nil {
			return fmt.Errorf("failed to save report to file: %w", err)
		}
		fmt.Printf("Report successfully saved to %s\n", OutputFile)
	}

	if JSONOutput {
		return report.PrintJSON(os.Stdout, rep)
	}

	report.PrintConsole(os.Stdout, rep, NoColor)
	return nil
}
