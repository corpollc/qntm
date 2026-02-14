package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "qntm",
	Short: "qntm secure messaging protocol implementation",
	Long: `qntm implements the QSP v1.0 secure messaging protocol.
Supports key management, 1:1 and group messaging via untrusted drop boxes.`,
}

func Execute() error {
	return rootCmd.Execute()
}