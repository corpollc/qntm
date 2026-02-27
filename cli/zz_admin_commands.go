package cli

import "github.com/spf13/cobra"

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Operator and development commands",
}

func init() {
	// Keep chat workflows at top-level and move operator surfaces under admin.
	rootCmd.RemoveCommand(gateCmd, registryCmd, unsafeCmd)
	adminCmd.AddCommand(gateCmd, registryCmd, unsafeCmd)
	rootCmd.AddCommand(adminCmd)
}
