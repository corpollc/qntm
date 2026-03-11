// DEPRECATED: Go CLI moved to attic
//go:build ignore

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/gate"
)

var (
	gatewayHealthAddr string
	gatewayPollSecs   int
	gatewayConfigDir  string
	gatewayForce      bool
)

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	defaultGatewayDir := filepath.Join(homeDir, ".qntm-gateway")

	rootCmd.AddCommand(gatewayCmd)
	gatewayCmd.AddCommand(gatewayInitCmd)
	gatewayCmd.AddCommand(gatewayServeCmd)

	// Shared gateway config-dir flag (overrides the global --config-dir for gateway subcommands)
	gatewayCmd.PersistentFlags().StringVar(&gatewayConfigDir, "config-dir", defaultGatewayDir,
		"Gateway configuration directory")

	gatewayInitCmd.Flags().BoolVar(&gatewayForce, "force", false,
		"Overwrite existing identity if present")

	gatewayServeCmd.Flags().StringVar(&gatewayHealthAddr, "health-addr", "",
		"Address for HTTP health endpoint (e.g. :8081)")
	gatewayServeCmd.Flags().IntVar(&gatewayPollSecs, "poll-interval", 5,
		"Poll interval in seconds")
}

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Run a standalone qntm gateway",
	Long: `The gateway is a headless qntm conversation participant that polls its
dropbox for encrypted messages, processes gate.* protocol messages, and
executes authorized API requests when M-of-N signature thresholds are met.

Subcommands:
  init   Generate a gateway identity and config directory
  serve  Start the gateway polling loop

Quick start:
  qntm gateway init
  qntm gateway serve`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var gatewayInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a gateway identity and initialize config directory",
	Long: `Creates a new Ed25519 keypair for the gateway and sets up the config
directory structure at --config-dir (default: ~/.qntm-gateway/).

The command creates:
  identity.json       Gateway's Ed25519 keypair (CBOR, mode 0600)
  conversations.json  Empty conversation list
  vault/              Directory for credential encryption at rest

After init, share the printed public key and KID with conversation
creators so they can include the gateway in gate.promote messages.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := resolveGatewayConfigDir()

		var result *gate.InitResult
		var err error
		if gatewayForce {
			result, err = gate.InitGatewayForce(dir)
		} else {
			result, err = gate.InitGateway(dir)
		}
		if err != nil {
			return fmt.Errorf("gateway init failed: %w", err)
		}

		if humanMode {
			fmt.Printf("Gateway identity created:\n")
			fmt.Printf("  Config dir: %s\n", dir)
			fmt.Printf("  Key ID:     %s\n", result.KeyID)
			fmt.Printf("  Public Key: %s\n", result.PublicKey)
			fmt.Printf("  Vault dir:  %s\n", result.VaultDir)
			fmt.Println()
			fmt.Println("Share the Key ID and Public Key with conversation creators.")
			fmt.Println("Then join a conversation with: qntm --config-dir", dir, "invite accept <token>")
			return nil
		}

		return emitJSONSuccess("gateway.init", map[string]interface{}{
			"config_dir": dir,
			"key_id":     result.KeyID,
			"public_key": result.PublicKey,
			"vault_dir":  result.VaultDir,
			"identity":   result.IdentityPath,
		})
	},
}

var gatewayServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the gateway polling loop",
	Long: `Starts the gateway as a headless qntm conversation participant.

The gateway:
  1. Loads its Ed25519 identity from the config directory
  2. Loads its conversation list
  3. Polls all conversations for new encrypted messages
  4. Processes gate.promote, gate.secret, gate.config messages to build state
  5. Processes gate.request and gate.approval messages to check thresholds
  6. Executes authorized API requests when M-of-N thresholds are met
  7. Posts gate.executed messages back to conversations

Environment variables:
  GATE_VAULT_KEY  Base64-encoded AES-256 key for credential encryption at rest

Flags:
  --config-dir     Gateway config directory (default: ~/.qntm-gateway/)
  --poll-interval  Seconds between polls (default: 5)
  --health-addr    Address for HTTP health endpoint (e.g. :8081)

Graceful shutdown on SIGINT or SIGTERM.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := resolveGatewayConfigDir()

		// Override the global configDir so loadIdentity/loadConversations use
		// the gateway config directory.
		origConfigDir := configDir
		configDir = dir
		defer func() { configDir = origConfigDir }()

		// Load gateway identity
		gwIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load gateway identity from %s: %w\nRun 'qntm gateway init' to create one", dir, err)
		}

		// Load conversations
		conversations, err := loadConversations()
		if err != nil {
			return fmt.Errorf("failed to load conversations from %s: %w", dir, err)
		}

		if len(conversations) == 0 {
			return fmt.Errorf("no conversations found in %s\nThe gateway needs at least one conversation to poll.\nJoin one with: qntm --config-dir %s invite accept <token>", dir, dir)
		}

		// Create the gateway
		gw := gate.NewGateway(gwIdentity)
		gw.DropboxURL = dropboxURL
		gw.ConfigDir = dir
		gw.PollInterval = time.Duration(gatewayPollSecs) * time.Second

		if gatewayHealthAddr != "" {
			gw.HealthAddr = gatewayHealthAddr
		}

		// Configure vault
		if vaultKey := os.Getenv("GATE_VAULT_KEY"); vaultKey != "" {
			vault, err := gate.NewEnvVaultFromBase64(vaultKey)
			if err != nil {
				return fmt.Errorf("invalid GATE_VAULT_KEY: %w", err)
			}
			gw.Vault = vault
			fmt.Println("Vault: AES-256-GCM credential encryption enabled")
		}

		// Set storage provider
		gw.Storage = getStorageProvider()
		if _, ok := gw.Storage.(*dropbox.HTTPStorageProvider); ok {
			fmt.Printf("Dropbox: %s\n", gw.DropboxURL)
		}

		// Register all conversations
		for _, conv := range conversations {
			gw.RegisterConversation(conv)
			fmt.Printf("  Registered conversation %x\n", conv.ID[:4])
		}

		fmt.Printf("Gateway starting: %d conversation(s), poll every %ds, config %s\n",
			len(conversations), gatewayPollSecs, dir)
		if gatewayHealthAddr != "" {
			fmt.Printf("Health endpoint: %s/health\n", gatewayHealthAddr)
		}

		// Run until interrupted
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigCh
			fmt.Printf("\nReceived %v, shutting down gateway...\n", sig)
			cancel()
		}()

		return gw.Run(ctx)
	},
}

// resolveGatewayConfigDir returns the gateway config directory, preferring
// the gateway-specific flag over the global --config-dir.
func resolveGatewayConfigDir() string {
	return gatewayConfigDir
}
