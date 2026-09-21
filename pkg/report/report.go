package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// PrintConsole prints the diagnostic report to stdout with clean SRE formatting.
func PrintConsole(w io.Writer, rep *model.Report, noColor bool) {
	PrintConsoleDetailed(w, rep, noColor, false)
}

// PrintConsoleDetailed prints the diagnostic report to stdout with optional inclusion of PASS findings.
func PrintConsoleDetailed(w io.Writer, rep *model.Report, noColor bool, showPass bool) {
	c := Colors(noColor)
	reset, bold := c.Reset, c.Bold
	red, green, yellow, cyan, gray := c.Red, c.Green, c.Yellow, c.Cyan, c.Gray

	fmt.Fprintf(w, "\n%s================================================================================%s\n", bold, reset)
	fmt.Fprintf(w, "%s                OPS TOOLKIT (OPSKIT) DIAGNOSTIC & HEALTH REPORT%s\n", bold+cyan, reset)
	fmt.Fprintf(w, "%s================================================================================%s\n", bold, reset)

	fmt.Fprintf(w, "%sHost OS:%s      %s (%s, %s)\n", bold, reset, rep.Environment.Distro, rep.Environment.Kernel, rep.Environment.Arch)

	deployments := []string{"Host/Systemd"}
	if rep.Environment.HasDocker {
		deployments = append(deployments, "Docker")
	}
	if rep.Environment.IsDockerSwarm {
		deployments = append(deployments, "Docker Swarm")
	}
	if rep.Environment.HasKubernetes {
		deployments = append(deployments, "Kubernetes")
	}
	fmt.Fprintf(w, "%sDeployments:%s  %s\n", bold, reset, strings.Join(deployments, ", "))
	fmt.Fprintf(w, "%sDuration:%s     %s | %sTimestamp:%s %s\n", bold, reset, rep.Duration, bold, reset, rep.Timestamp.Format("2006-01-02 15:04:05 MST"))

	// Summary bar
	fmt.Fprintf(w, "%sSummary:%s      ", bold, reset)
	if rep.Summary.Critical > 0 {
		fmt.Fprintf(w, "%s%d CRITICAL%s, ", bold+red, rep.Summary.Critical, reset)
	} else {
		fmt.Fprintf(w, "0 CRITICAL, ")
	}
	if rep.Summary.Warning > 0 {
		fmt.Fprintf(w, "%s%d WARNING%s, ", bold+yellow, rep.Summary.Warning, reset)
	} else {
		fmt.Fprintf(w, "0 WARNING, ")
	}
	if rep.Summary.Info > 0 {
		fmt.Fprintf(w, "%s%d INFO%s, ", cyan, rep.Summary.Info, reset)
	}
	fmt.Fprintf(w, "%s%d PASS%s\n", green, rep.Summary.Pass, reset)
	fmt.Fprintf(w, "%s--------------------------------------------------------------------------------%s\n\n", gray, reset)

	if len(rep.Findings) == 0 {
		fmt.Fprintf(w, "%s[OK] All diagnostic checks completed. No anomalies found.%s\n\n", green, reset)
		return
	}

	// PASS findings are counted in the summary but only listed if showPass is true.
	// The counter tracks printed rows so the numbering stays contiguous.
	printed := 0
	for _, f := range rep.Findings {
		if f.Severity == model.SeverityPass && !showPass {
			continue
		}
		printed++

		var tag string
		switch f.Severity {
		case model.SeverityCritical:
			tag = fmt.Sprintf("%s[%s]%s", bold+red, f.Severity, reset)
		case model.SeverityWarning:
			tag = fmt.Sprintf("%s[%s]%s", bold+yellow, f.Severity, reset)
		case model.SeverityPass:
			tag = fmt.Sprintf("%s[%s]%s", bold+green, f.Severity, reset)
		default:
			tag = fmt.Sprintf("%s[%s]%s", cyan, f.Severity, reset)
		}

		fmt.Fprintf(w, "%s #%d: %s%s%s (%s)\n", tag, printed, bold, f.Title, reset, f.Resource)
		fmt.Fprintf(w, "  %sRule ID:%s     %s\n", gray, reset, f.ID)
		fmt.Fprintf(w, "  %sCategory:%s    %s\n", gray, reset, f.Category)
		fmt.Fprintf(w, "  %sSymptom:%s     %s\n", gray, reset, f.Symptom)
		if f.RootCause != "" {
			fmt.Fprintf(w, "  %sRoot Cause:%s  %s%s%s\n", gray, reset, bold, f.RootCause, reset)
		}

		if f.LogEvidence != "" {
			fmt.Fprintf(w, "  %sEvidence:%s    %s%s%s\n", gray, reset, red, f.LogEvidence, reset)
		}

		if len(f.RemedySteps) > 0 {
			fmt.Fprintf(w, "  %sRemediation:%s\n", bold+cyan, reset)
			for idx, step := range f.RemedySteps {
				fmt.Fprintf(w, "    %d. %s\n", idx+1, step)
			}
		}

		if f.QuickFixCmd != "" {
			fmt.Fprintf(w, "  %sQuick Fix:%s   %s%s%s\n", bold+green, reset, bold, f.QuickFixCmd, reset)
		}

		fmt.Fprintf(w, "\n")
	}

	// Print Passed count
	if rep.Summary.Pass > 0 && !showPass {
		fmt.Fprintf(w, "%s[OK] %d checks passed successfully.%s\n", green, rep.Summary.Pass, reset)
	}

	fmt.Fprintf(w, "%s================================================================================%s\n\n", bold, reset)
}

// PrintJSON writes the report formatted as indented JSON.
func PrintJSON(w io.Writer, rep *model.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(rep)
}
