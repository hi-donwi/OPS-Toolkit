package cmd

import (
	"fmt"
	"os"

	"github.com/hi-donwi/OPS-Toolkit/pkg/analyzer"
	"github.com/hi-donwi/OPS-Toolkit/pkg/detector"
	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/report"
	"github.com/spf13/cobra"
)

var (
	diagNamespace string
	diagShowPass  bool
)

var diagCmd = &cobra.Command{
	Use:   "diag [host|docker|swarm|k8s|sec]",
	Short: "Run automated health and crash diagnostics",
	Long: `diag probes your infrastructure, auto-detects active deployments (Host,
Docker, Swarm, Kubernetes, Security), and runs deep diagnostic rules to find root causes
for crashes, degraded performance, and resource exhaustion.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDiagnostics(model.TargetType(""))
	},
}

var diagHostCmd = &cobra.Command{
	Use:   "host",
	Short: "Diagnose Linux Host (CPU, Memory, Inodes, Systemd, Network, DNS)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDiagnostics(model.TargetHost)
	},
}

var diagDockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Diagnose Docker standalone containers, exit codes, and health status",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDiagnostics(model.TargetDocker)
	},
}

var diagSwarmCmd = &cobra.Command{
	Use:   "swarm",
	Short: "Diagnose Docker Swarm cluster, service replicas, and per-task container errors",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDiagnostics(model.TargetSwarm)
	},
}

var diagK8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Diagnose Kubernetes workloads, CrashLoops, OOMs, orphan services, and ingress",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDiagnostics(model.TargetKubernetes)
	},
}

var diagSecCmd = &cobra.Command{
	Use:     "sec",
	Aliases: []string{"security"},
	Short:   "Diagnose security risks (file permissions, exposed ports, Docker & K8s privilege, SSH)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDiagnostics(model.TargetSecurity)
	},
}

func init() {
	diagK8sCmd.Flags().StringVarP(&diagNamespace, "namespace", "n", "", "Target Kubernetes namespace (defaults to all namespaces)")
	diagCmd.Flags().StringVarP(&diagNamespace, "namespace", "n", "", "Target Kubernetes namespace (if K8s active)")
	diagCmd.PersistentFlags().BoolVar(&diagShowPass, "show-pass", false, "Display passed diagnostic checks in console output")

	diagCmd.AddCommand(diagHostCmd)
	diagCmd.AddCommand(diagDockerCmd)
	diagCmd.AddCommand(diagSwarmCmd)
	diagCmd.AddCommand(diagK8sCmd)
	diagCmd.AddCommand(diagSecCmd)

	RootCmd.AddCommand(diagCmd)
}

func runDiagnostics(targetFilter model.TargetType) error {
	ctx, cancel := CommandContext()
	defer cancel()

	// 1. Detect Environment
	env := detector.Detect()

	// 2. Initialize Analyzer Engine
	engine := analyzer.NewEngine(env)

	// 3. Execute Diagnostic Rules
	rep, err := engine.RunDiagnostics(ctx, targetFilter, diagNamespace)
	if err != nil {
		return fmt.Errorf("failed running diagnostics: %w", err)
	}

	// 4. Output Results
	if OutputFile != "" {
		if err := report.SaveToFile(OutputFile, rep); err != nil {
			return fmt.Errorf("failed to save report to file: %w", err)
		}
		fmt.Printf("Report successfully generated and saved to %s\n", OutputFile)
	}

	if JSONOutput {
		return report.PrintJSON(os.Stdout, rep)
	}

	report.PrintConsoleDetailed(os.Stdout, rep, NoColor, diagShowPass)
	return nil
}
