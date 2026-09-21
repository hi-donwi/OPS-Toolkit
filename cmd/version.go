package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print opskit version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("opskit version %s (commit: %s, built: %s, runtime: %s/%s)\n",
			Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
