package cmd

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hi-donwi/OPS-Toolkit/pkg/ui"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch interactive full-screen terminal operations dashboard",
	Long: `tui opens a high-performance terminal UI (powered by Bubbletea and Lipgloss).
It displays active deployment nodes, real-time diagnostic alerts, detailed root-cause
cards, and interactive quick-fix hotkeys.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		p := tea.NewProgram(ui.InitialModel(), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("error running TUI: %w", err)
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(tuiCmd)
}
