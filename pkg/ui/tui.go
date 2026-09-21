package ui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hi-donwi/OPS-Toolkit/pkg/ai"
	"github.com/hi-donwi/OPS-Toolkit/pkg/analyzer"
	"github.com/hi-donwi/OPS-Toolkit/pkg/detector"
	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/remediation"
)

// Styling tokens using Lipgloss
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#04B575")).
			MarginBottom(1)

	selectedItemStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.Color("#7D56F4")).
				Foreground(lipgloss.Color("#FAFAFA")).
				Background(lipgloss.Color("#353545")).
				PaddingLeft(1)

	normalItemStyle = lipgloss.NewStyle().
			PaddingLeft(2).
			Foreground(lipgloss.Color("#C3C3D0"))

	detailPaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	critBadge = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#FF3B30")).Padding(0, 1)
	warnBadge = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#000000")).Background(lipgloss.Color("#FFCC00")).Padding(0, 1)
	passBadge = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#34C759")).Padding(0, 1)
	infoBadge = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#007AFF")).Padding(0, 1)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8E8E93")).
			MarginTop(1)
)

// Async messages
type scanDoneMsg struct {
	report *model.Report
	err    error
}

type aiDoneMsg struct {
	runbook string
	err     error
}

type fixDoneMsg struct {
	command string
	err     error
}

// Model represents the Bubbletea UI state.
type Model struct {
	report       *model.Report
	cursor       int
	statusMsg    string
	width        int
	height       int
	aiRunbook    string
	pendingFix   *remediation.FixPlan
	loading      bool
	aiLoading    bool
	fixLoading   bool
	detailScroll int
	listScroll   int
}

// InitialModel initializes the TUI model in a loading state.
func InitialModel() Model {
	return Model{
		loading:   true,
		statusMsg: "Scanning infrastructure...",
		cursor:    0,
		width:     120,
		height:    30,
	}
}

func runScanCmd() tea.Cmd {
	return func() tea.Msg {
		env := detector.Detect()
		engine := analyzer.NewEngine(env)
		rep, err := engine.RunDiagnostics(context.Background(), model.TargetType(""), "")
		return scanDoneMsg{report: rep, err: err}
	}
}

func runAICmd(f model.Finding) tea.Cmd {
	return func() tea.Msg {
		copilot := ai.NewCopilotClient()
		runbook, err := copilot.ExplainFinding(context.Background(), f)
		return aiDoneMsg{runbook: runbook, err: err}
	}
}

func runFixCmd(plan *remediation.FixPlan) tea.Cmd {
	return func() tea.Msg {
		err := remediation.ExecuteFix(context.Background(), plan, false)
		return fixDoneMsg{command: plan.Command, err: err}
	}
}

func (m Model) Init() tea.Cmd {
	return runScanCmd()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case scanDoneMsg:
		m.loading = false
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("Scan failed: %v", msg.err)
		} else {
			m.report = msg.report
			m.statusMsg = "Scan completed. System state updated."
		}
		m.cursor = 0
		m.listScroll = 0
		m.detailScroll = 0
		m.aiRunbook = ""

	case aiDoneMsg:
		m.aiLoading = false
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("Copilot failed: %v", msg.err)
		} else {
			m.aiRunbook = msg.runbook
			m.statusMsg = "AI Runbook generated successfully."
		}

	case fixDoneMsg:
		m.fixLoading = false
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("Fix failed: %v", msg.err)
		} else {
			m.statusMsg = fmt.Sprintf("Applied successfully: %s", msg.command)
		}
		// Trigger rescan after fix
		m.loading = true
		return m, runScanCmd()

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.detailScroll = 0
				m.aiRunbook = ""
				if m.cursor < m.listScroll {
					m.listScroll = m.cursor
				}
			}

		case "down", "j":
			if m.report != nil && m.cursor < len(m.report.Findings)-1 {
				m.cursor++
				m.detailScroll = 0
				m.aiRunbook = ""
				visibleRows := m.visibleListRows()
				if m.cursor >= m.listScroll+visibleRows {
					m.listScroll = m.cursor - visibleRows + 1
				}
			}

		case "pgdown", "ctrl+d", "]":
			m.detailScroll += 5

		case "pgup", "ctrl+u", "[":
			if m.detailScroll > 0 {
				m.detailScroll -= 5
				if m.detailScroll < 0 {
					m.detailScroll = 0
				}
			}

		case "r":
			if !m.loading {
				m.loading = true
				m.statusMsg = "Scanning system in background..."
				return m, runScanCmd()
			}

		case "f":
			if m.report != nil && len(m.report.Findings) > m.cursor {
				cur := m.report.Findings[m.cursor]
				if cur.QuickFixCmd == "" {
					m.statusMsg = "No automated quick-fix available for this item."
					break
				}
				m.pendingFix = &remediation.FixPlan{
					FindingID:   cur.ID,
					Resource:    cur.Resource,
					Description: cur.Title,
					Command:     cur.QuickFixCmd,
					Risk:        remediation.ClassifyRisk(cur.QuickFixCmd),
					Severity:    cur.Severity,
				}
				m.statusMsg = fmt.Sprintf("Confirm [%s risk] %s  —  press [y] to run, [n] to cancel",
					m.pendingFix.Risk, m.pendingFix.Command)
			}

		case "y":
			if m.pendingFix != nil && !m.fixLoading {
				plan := m.pendingFix
				m.pendingFix = nil
				m.fixLoading = true
				m.statusMsg = fmt.Sprintf("Executing [%s risk] %s...", plan.Risk, plan.Command)
				return m, runFixCmd(plan)
			}

		case "n", "esc":
			if m.pendingFix != nil {
				m.pendingFix = nil
				m.statusMsg = "Quick-fix cancelled."
			}

		case "e":
			if m.report != nil && len(m.report.Findings) > m.cursor && !m.aiLoading {
				cur := m.report.Findings[m.cursor]
				m.aiLoading = true
				m.statusMsg = "Generating AI Runbook with Copilot..."
				return m, runAICmd(cur)
			}
		}
	}

	return m, nil
}

func (m Model) visibleListRows() int {
	h := m.height - 8
	if h < 5 {
		return 5
	}
	return h
}

func (m Model) View() string {
	var b strings.Builder

	// Title Bar
	b.WriteString(titleStyle.Render(" opskit — OPS Toolkit Operations Dashboard ") + "\n")

	if m.report == nil {
		if m.loading {
			b.WriteString(headerStyle.Render("Evaluating infrastructure health... please wait") + "\n\n")
		} else {
			b.WriteString(headerStyle.Render("No diagnostic report available.") + "\n\n")
		}
		if m.statusMsg != "" {
			b.WriteString("\033[33m" + m.statusMsg + "\033[0m\n")
		}
		b.WriteString(footerStyle.Render("\n[q] Quit\n"))
		return b.String()
	}

	b.WriteString(headerStyle.Render(fmt.Sprintf("Host: %s (%s) | Duration: %s | Critical: %d, Warning: %d, Pass: %d",
		m.report.Environment.Distro, m.report.Environment.Arch, m.report.Duration,
		m.report.Summary.Critical, m.report.Summary.Warning, m.report.Summary.Pass)) + "\n\n")

	// Dynamic split widths
	leftW := 42
	if m.width > 120 {
		leftW = m.width / 3
		if leftW > 50 {
			leftW = 50
		}
	}
	rightW := m.width - leftW - 6
	if rightW < 40 {
		rightW = 40
	}

	// Split View: Left list with scrolling
	visibleRows := m.visibleListRows()
	totalFindings := len(m.report.Findings)
	endIdx := m.listScroll + visibleRows
	if endIdx > totalFindings {
		endIdx = totalFindings
	}

	leftCol := strings.Builder{}
	for i := m.listScroll; i < endIdx; i++ {
		f := m.report.Findings[i]
		var badge string
		switch f.Severity {
		case model.SeverityCritical:
			badge = critBadge.Render("CRIT")
		case model.SeverityWarning:
			badge = warnBadge.Render("WARN")
		case model.SeverityPass:
			badge = passBadge.Render("PASS")
		default:
			badge = infoBadge.Render("INFO")
		}

		maxTitleLen := leftW - 18
		if maxTitleLen < 10 {
			maxTitleLen = 10
		}
		line := fmt.Sprintf("%s %-12s %s", badge, f.ID, truncate(f.Title, maxTitleLen))
		if i == m.cursor {
			leftCol.WriteString(selectedItemStyle.Width(leftW).Render(line) + "\n")
		} else {
			leftCol.WriteString(normalItemStyle.Width(leftW).Render(line) + "\n")
		}
	}

	// Right Pane: Detail View
	rightContent := strings.Builder{}
	if len(m.report.Findings) > m.cursor {
		cur := m.report.Findings[m.cursor]

		rightContent.WriteString(fmt.Sprintf("\033[1m%s\033[0m (%s)\n", cur.Title, cur.Resource))
		rightContent.WriteString(fmt.Sprintf("Category:    %s\n", cur.Category))
		rightContent.WriteString(fmt.Sprintf("Symptom:     %s\n", cur.Symptom))
		rightContent.WriteString(fmt.Sprintf("Root Cause:  \033[1m%s\033[0m\n\n", cur.RootCause))

		if cur.LogEvidence != "" {
			rightContent.WriteString(fmt.Sprintf("Evidence:\n  %s\n\n", cur.LogEvidence))
		}

		if len(cur.RemedySteps) > 0 {
			rightContent.WriteString("\033[1mRemediation Guidance:\033[0m\n")
			for idx, step := range cur.RemedySteps {
				rightContent.WriteString(fmt.Sprintf("  %d. %s\n", idx+1, step))
			}
			rightContent.WriteString("\n")
		}

		if cur.QuickFixCmd != "" {
			rightContent.WriteString(fmt.Sprintf("\033[32mQuick-Fix Command:\033[0m \033[1m%s\033[0m\n\n", cur.QuickFixCmd))
		}

		if m.aiLoading {
			rightContent.WriteString("\033[36mGenerating AI Incident Briefing with Copilot...\033[0m\n")
		} else if m.aiRunbook != "" {
			rightContent.WriteString("----------------------------------------\n")
			rightContent.WriteString(m.aiRunbook + "\n")
		}
	}

	// Apply detail viewport scrolling
	detailLines := strings.Split(rightContent.String(), "\n")
	visibleDetailLines := visibleRows
	if m.detailScroll > len(detailLines)-visibleDetailLines && len(detailLines) > visibleDetailLines {
		m.detailScroll = len(detailLines) - visibleDetailLines
	}
	if m.detailScroll < 0 {
		m.detailScroll = 0
	}
	detailEnd := m.detailScroll + visibleDetailLines
	if detailEnd > len(detailLines) {
		detailEnd = len(detailLines)
	}

	scrolledDetail := strings.Join(detailLines[m.detailScroll:detailEnd], "\n")

	// Layout two columns side by side
	splitView := lipgloss.JoinHorizontal(
		lipgloss.Top,
		lipgloss.NewStyle().Width(leftW).Render(leftCol.String()),
		detailPaneStyle.Width(rightW).Height(visibleRows).Render(scrolledDetail),
	)

	b.WriteString(splitView + "\n")

	// Status line & Hotkey footer
	if m.statusMsg != "" {
		b.WriteString("\n\033[33m" + m.statusMsg + "\033[0m")
	}

	if m.pendingFix != nil {
		b.WriteString(footerStyle.Render("\n[y] Confirm fix  |  [n] Cancel\n"))
	} else {
		b.WriteString(footerStyle.Render("\n[Up/Down/j/k] Navigate  |  [pgup/pgdn] Scroll  |  [r] Re-scan  |  [f] Quick-Fix  |  [e] AI Explain  |  [q] Quit\n"))
	}

	return b.String()
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		if maxLen > 3 {
			return s[:maxLen-3] + "..."
		}
		return s[:maxLen]
	}
	return s
}
