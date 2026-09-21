package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell autocompletion script",
	Long: `To load completions:

Bash:
  $ source <(opskit completion bash)

Zsh:
  $ source <(opskit completion zsh)

Fish:
  $ opskit completion fish | source

Or use 'opskit completion install' to configure autocompletion permanently.`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return RootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return RootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return RootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return RootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return nil
	},
}

var completionInstallCmd = &cobra.Command{
	Use:   "install [bash|zsh|fish]",
	Short: "Automatically install shell autocompletion permanently into your shell profile",
	Long: `install detects your active shell (or accepts bash/zsh/fish as an argument)
and appends or registers the required autocompletion hooks in your configuration file (~/.zshrc, ~/.bashrc).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		shell := detectShell()
		if len(args) > 0 {
			shell = strings.ToLower(args[0])
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("unable to locate user home directory: %w", err)
		}

		switch shell {
		case "zsh":
			return installZsh(home)
		case "bash":
			return installBash(home)
		case "fish":
			return installFish(home)
		default:
			return fmt.Errorf("unsupported shell '%s'. Supported shells: zsh, bash, fish", shell)
		}
	},
}

func detectShell() string {
	shellEnv := os.Getenv("SHELL")
	if strings.Contains(shellEnv, "zsh") {
		return "zsh"
	}
	if strings.Contains(shellEnv, "bash") {
		return "bash"
	}
	if strings.Contains(shellEnv, "fish") {
		return "fish"
	}
	return "zsh" // default on modern macOS and Linux
}

func installZsh(home string) error {
	zshrc := filepath.Join(home, ".zshrc")
	hook := "\n# opskit shell autocompletion\neval \"$(opskit completion zsh)\"\n"

	// Check if already installed
	if content, err := os.ReadFile(zshrc); err == nil {
		if strings.Contains(string(content), "opskit completion zsh") {
			fmt.Printf("[OK] opskit autocompletion is already configured in %s\n", zshrc)
			return nil
		}
	}

	f, err := os.OpenFile(zshrc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", zshrc, err)
	}
	defer f.Close()

	if _, err := f.WriteString(hook); err != nil {
		return fmt.Errorf("failed to append hook to %s: %w", zshrc, err)
	}

	fmt.Printf("\033[32m[OK] Successfully installed zsh autocompletion to %s!\033[0m\n", zshrc)
	fmt.Println("To apply changes immediately, run:")
	fmt.Println("  source ~/.zshrc")
	return nil
}

func installBash(home string) error {
	bashrc := filepath.Join(home, ".bashrc")
	hook := "\n# opskit shell autocompletion\nsource <(opskit completion bash)\n"

	if content, err := os.ReadFile(bashrc); err == nil {
		if strings.Contains(string(content), "opskit completion bash") {
			fmt.Printf("[OK] opskit autocompletion is already configured in %s\n", bashrc)
			return nil
		}
	}

	f, err := os.OpenFile(bashrc, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", bashrc, err)
	}
	defer f.Close()

	if _, err := f.WriteString(hook); err != nil {
		return fmt.Errorf("failed to append hook to %s: %w", bashrc, err)
	}

	fmt.Printf("\033[32m[OK] Successfully installed bash autocompletion to %s!\033[0m\n", bashrc)
	fmt.Println("To apply changes immediately, run:")
	fmt.Println("  source ~/.bashrc")
	return nil
}

func installFish(home string) error {
	fishDir := filepath.Join(home, ".config", "fish", "completions")
	if err := os.MkdirAll(fishDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", fishDir, err)
	}

	fishFile := filepath.Join(fishDir, "opskit.fish")
	f, err := os.Create(fishFile)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", fishFile, err)
	}
	defer f.Close()

	if err := RootCmd.GenFishCompletion(f, true); err != nil {
		return fmt.Errorf("failed to generate fish completion: %w", err)
	}

	fmt.Printf("\033[32m[OK] Successfully installed fish autocompletion to %s!\033[0m\n", fishFile)
	return nil
}

func init() {
	completionCmd.AddCommand(completionInstallCmd)
	RootCmd.AddCommand(completionCmd)
}
