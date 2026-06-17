package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("wormsign %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
		return nil
	},
}
