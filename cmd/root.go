package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	// Version info set via ldflags
	Version   = "0.1.0"
	GitCommit = "dev"
	BuildDate = "unknown"

	// Global flags
	JSONOutput bool
	NoColor    bool
	Verbose    bool
	OutputFile string
	Timeout    time.Duration
)

// CommandContext returns a context bound to the global --timeout and to
// SIGINT/SIGTERM, so a diagnostic run against a wedged API server or container
// runtime terminates instead of hanging the operator's shell.
func CommandContext() (context.Context, context.CancelFunc) {
	ctx, cancelSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if Timeout <= 0 {
		return ctx, cancelSignals
	}

	ctx, cancelTimeout := context.WithTimeout(ctx, Timeout)
	return ctx, func() {
		cancelTimeout()
		cancelSignals()
	}
}

// RootCmd represents the base command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "opskit",
	Short: "opskit — OPS Toolkit: Site Reliability Engineering Control & Diagnostics",
	Long: `opskit (OPS Toolkit) is an all-in-one SRE diagnostic and triage CLI tool designed for
Linux hosts, Docker standalone, Docker Swarm, and Kubernetes deployments.

It automatically inspects infrastructure health, identifies crashes (OOM, segfaults,
CrashLoopBackOff), performs root-cause analysis (RCA), and generates actionable
remediation guidance and security audits.`,
}

// ExitError carries an integer exit code for CI/CD gates and CLI exit statuses.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string {
	return e.Msg
}

func (e *ExitError) ExitCode() int {
	return e.Code
}

func Execute() {
	// Usage text is helpful for a bad flag, but noise when a diagnostic fails
	// at runtime; the error itself is what the operator needs to see.
	RootCmd.SilenceUsage = true
	RootCmd.SilenceErrors = true

	if err := RootCmd.Execute(); err != nil {
		if exitErr, ok := err.(interface{ ExitCode() int }); ok {
			if err.Error() != "" {
				fmt.Fprintln(os.Stderr, err.Error())
			}
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().BoolVar(&JSONOutput, "json", false, "Output diagnostic results in JSON format")
	RootCmd.PersistentFlags().BoolVar(&NoColor, "no-color", false, "Disable ANSI color output in terminal")
	RootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Enable verbose debug logs")
	RootCmd.PersistentFlags().StringVarP(&OutputFile, "output", "o", "", "Export diagnostic report to a file (.md for Markdown, .json for JSON)")
	RootCmd.PersistentFlags().DurationVar(&Timeout, "timeout", 2*time.Minute, "Overall deadline for a diagnostic run (0 disables)")
}
