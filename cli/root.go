package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "qntm",
	Short: "Agent-first secure messaging CLI (JSON by default)",
	Long: `qntm is an agent-first secure messaging CLI.
Default output is compact JSON for machine consumption.
Use --human for human-readable output and interactive chat.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

` + demoContent + `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`,
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Start background update check for commands that benefit from it.
		// Skip for the "version" command (it does its own synchronous check).
		if humanMode && cmd.Name() != "version" {
			startBackgroundUpdateCheck()
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if humanMode && cmd.Name() != "version" {
			waitAndPrintUpdateHint()
		}
	},
}

const demoContent = `# qntm — Agent Messaging CLI

For agents (default JSON mode):

  # Create or inspect identity
  qntm identity generate
  qntm identity show

  # Create conversation + get invite token
  qntm convo create --name "Alice-Bob Chat"

  # Join a conversation from token
  qntm convo join <token> --name "Alice-Bob Chat"

  # Send and receive
  qntm send <conversation> "Hello!"
  qntm recv <conversation>

For humans:

  qntm --human inbox
  qntm --human open <conversation>

For the full protocol spec, see: https://github.com/corpo/qntm/blob/main/docs/QSP-v1.1.md
`

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		if humanMode {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			emitJSONError(err)
		}
		return err
	}
	return nil
}
