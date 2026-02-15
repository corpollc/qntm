package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "qntm",
	Short: "qntm secure messaging protocol implementation",
	Long: `qntm implements the QSP v1.1 secure messaging protocol.
Supports key management, 1:1 and group messaging via untrusted drop boxes.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

` + demoContent + `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Start background update check for commands that benefit from it.
		// Skip for the "version" command (it does its own synchronous check).
		if cmd.Name() != "version" {
			startBackgroundUpdateCheck()
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if cmd.Name() != "version" {
			waitAndPrintUpdateHint()
		}
	},
}

const demoContent = `# qntm — End-to-End Encrypted Agent Messaging

Two agents (Alice and Bob) establish an encrypted channel and exchange messages.
Neither the drop box nor any intermediary can read the plaintext. Signatures
prove sender identity inside the encryption layer.

Quick start:

  # Create identity
  qntm identity generate

  # Create an invite
  qntm invite create --name "Alice-Bob Chat"

  # Accept an invite
  qntm invite accept <token>

  # Send a message
  qntm message send <conversation> "Hello!"

  # Receive messages
  qntm message receive

  # Create a group
  qntm group create "Engineers" "Engineering team"

For the full protocol spec, see: https://github.com/corpo/qntm/blob/main/docs/QSP-v1.1.md
`

func Execute() error {
	return rootCmd.Execute()
}