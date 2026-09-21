package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// GenerateMarkdown creates an executive SRE diagnostic postmortem report in GitHub-flavored Markdown.
func GenerateMarkdown(w io.Writer, rep *model.Report) error {
	fmt.Fprintf(w, "# SRE Diagnostic & Health Report: %s\n\n", rep.Title)
	fmt.Fprintf(w, "**Generated**: `%s` | **Duration**: `%s`\n\n", rep.Timestamp.Format("2006-01-02 15:04:05 MST"), rep.Duration)

	// Environment section
	fmt.Fprintf(w, "## System & Deployment Environment\n\n")
	fmt.Fprintf(w, "| Attribute | Details |\n")
	fmt.Fprintf(w, "|---|---|\n")
	fmt.Fprintf(w, "| **Host OS** | `%s` (%s, %s) |\n", rep.Environment.Distro, rep.Environment.Kernel, rep.Environment.Arch)

	deployments := []string{"Host/Systemd"}
	if rep.Environment.HasDocker {
		deployments = append(deployments, "Docker Engine")
	}
	if rep.Environment.IsDockerSwarm {
		deployments = append(deployments, "Docker Swarm Cluster")
	}
	if rep.Environment.HasKubernetes {
		deployments = append(deployments, "Kubernetes Cluster")
	}
	fmt.Fprintf(w, "| **Active Deployments** | %s |\n\n", strings.Join(deployments, ", "))

	// Summary KPI
	fmt.Fprintf(w, "## Diagnostic Executive Summary\n\n")
	fmt.Fprintf(w, "| Metric | Count | Status |\n")
	fmt.Fprintf(w, "|---|---|---|\n")
	fmt.Fprintf(w, "| **Critical Issues** | **%d** | %s |\n", rep.Summary.Critical, statusBadge(rep.Summary.Critical, "[CRITICAL]", "[CLEAN]"))
	fmt.Fprintf(w, "| **Warnings** | **%d** | %s |\n", rep.Summary.Warning, statusBadge(rep.Summary.Warning, "[WARNING]", "[CLEAN]"))
	fmt.Fprintf(w, "| **Healthy Checks** | **%d** | [PASSED] |\n\n", rep.Summary.Pass)

	// Findings
	fmt.Fprintf(w, "## Detailed Root-Cause Analysis (RCA) & Remediation\n\n")

	hasActionable := false
	for _, f := range rep.Findings {
		if f.Severity == model.SeverityPass {
			continue
		}
		hasActionable = true

		fmt.Fprintf(w, "### [%s] %s: %s\n\n", f.Severity, f.ID, f.Title)
		fmt.Fprintf(w, "- **Rule ID**: `%s`\n", f.ID)
		fmt.Fprintf(w, "- **Resource**: `%s`\n", f.Resource)
		if f.Namespace != "" {
			fmt.Fprintf(w, "- **Namespace**: `%s`\n", f.Namespace)
		}
		fmt.Fprintf(w, "- **Category**: `%s`\n", f.Category)
		fmt.Fprintf(w, "- **Symptom**: %s\n", f.Symptom)
		fmt.Fprintf(w, "- **Root Cause**: **%s**\n", f.RootCause)

		if f.LogEvidence != "" {
			fmt.Fprintf(w, "\n```text\n%s\n```\n", f.LogEvidence)
		}

		if len(f.RemedySteps) > 0 {
			fmt.Fprintf(w, "\n**Remediation Steps**:\n")
			for idx, step := range f.RemedySteps {
				fmt.Fprintf(w, "%d. %s\n", idx+1, step)
			}
		}

		if f.QuickFixCmd != "" {
			fmt.Fprintf(w, "\n**Quick-Fix Command**:\n```bash\n%s\n```\n", f.QuickFixCmd)
		}

		fmt.Fprintf(w, "\n---\n\n")
	}

	if !hasActionable {
		fmt.Fprintf(w, "*No critical issues or warnings detected. All inspected infrastructure components are running within healthy operational parameters.*\n\n")
	}

	return nil
}

// SaveToFile exports the report to a specified file path based on file extension (.json or .md).
func SaveToFile(filePath string, rep *model.Report) error {
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create report file %s: %w", filePath, err)
	}
	defer f.Close()

	if strings.HasSuffix(strings.ToLower(filePath), ".json") {
		return PrintJSON(f, rep)
	}

	// Default to Markdown
	return GenerateMarkdown(f, rep)
}

func statusBadge(count int, badText, goodText string) string {
	if count > 0 {
		return badText
	}
	return goodText
}
