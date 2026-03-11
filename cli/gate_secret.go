package cli

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/corpo/qntm/gate"
)

var (
	gateSecretConvFlag       string
	gateSecretServiceFlag    string
	gateSecretHeaderNameFlag string
	gateSecretHeaderTplFlag  string
	gateSecretValueFlag      string
	gateSecretGatewayPubkey  string
)

func init() {
	rootCmd.AddCommand(gateSecretCmd)
	gateSecretCmd.Flags().StringVarP(&gateSecretConvFlag, "conv", "c", "", "Conversation name, short ref, or hex ID")
	gateSecretCmd.Flags().StringVar(&gateSecretServiceFlag, "service", "", "Target service name (e.g. stripe, github)")
	gateSecretCmd.Flags().StringVar(&gateSecretHeaderNameFlag, "header-name", "Authorization", "HTTP header name for credential injection")
	gateSecretCmd.Flags().StringVar(&gateSecretHeaderTplFlag, "header-template", "Bearer {value}", "Header value template ({value} is replaced with the secret)")
	gateSecretCmd.Flags().StringVar(&gateSecretValueFlag, "value", "", "Secret value (omit to read from stdin)")
	gateSecretCmd.Flags().StringVar(&gateSecretGatewayPubkey, "gateway-pubkey", "", "Gateway's Ed25519 public key (hex-encoded, 64 hex chars)")
	gateSecretCmd.MarkFlagRequired("conv")
	gateSecretCmd.MarkFlagRequired("service")
	gateSecretCmd.MarkFlagRequired("gateway-pubkey")
}

var gateSecretCmd = &cobra.Command{
	Use:   "gate-secret",
	Short: "Provision a secret credential to a gate-enabled conversation",
	Long: `Encrypts a secret value to the gateway's public key (NaCl box) and sends
it as a gate.secret message. The gateway decrypts and stores the credential
for use when executing authorized API requests.

The secret is end-to-end encrypted: only the gateway can decrypt it.

The gateway's public key can be obtained from the gateway operator or from
the gateway's identity output (qntm id --json on the gateway).

Examples:
  qntm gate-secret -c my-group --service stripe --gateway-pubkey <hex> --value sk_test_abc123
  echo "sk_test_abc123" | qntm gate-secret -c my-group --service stripe --gateway-pubkey <hex>
  qntm gate-secret -c my-group --service github --header-template "token {value}" --gateway-pubkey <hex> --value ghp_xxx`,
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}

		conversation, convIDHex, err := resolveConversation(gateSecretConvFlag)
		if err != nil {
			return err
		}

		// Determine the secret value
		secretValue := gateSecretValueFlag
		if secretValue == "" {
			// Read from stdin
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) != 0 {
				fmt.Fprint(os.Stderr, "Enter secret value: ")
			}
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				secretValue = strings.TrimSpace(scanner.Text())
			}
			if secretValue == "" {
				return fmt.Errorf("secret value is required (use --value or pipe via stdin)")
			}
		}

		// Parse the gateway's public key
		gwPubBytes, err := hex.DecodeString(gateSecretGatewayPubkey)
		if err != nil {
			return fmt.Errorf("invalid gateway public key hex: %w", err)
		}
		if len(gwPubBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("gateway public key must be %d bytes (got %d)", ed25519.PublicKeySize, len(gwPubBytes))
		}
		gatewayPubKey := ed25519.PublicKey(gwPubBytes)

		secretID := uuid.New().String()

		payload, err := gate.BuildSecretPayload(
			ed25519.PrivateKey(currentIdentity.PrivateKey),
			ed25519.PublicKey(currentIdentity.PublicKey),
			gatewayPubKey,
			secretID,
			gateSecretServiceFlag,
			gateSecretHeaderNameFlag,
			gateSecretHeaderTplFlag,
			secretValue,
		)
		if err != nil {
			return fmt.Errorf("build secret payload: %w", err)
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal secret payload: %w", err)
		}

		if err := sendGateMessage(currentIdentity, conversation, string(gate.GateMessageSecret), body); err != nil {
			return err
		}

		gatewayKID := gate.KIDFromPublicKey(gatewayPubKey)
		fmt.Printf("Gate secret sent to %s\n", convIDHex)
		fmt.Printf("  Secret ID:  %s\n", secretID)
		fmt.Printf("  Service:    %s\n", gateSecretServiceFlag)
		fmt.Printf("  Header:     %s: %s\n", gateSecretHeaderNameFlag, gateSecretHeaderTplFlag)
		fmt.Printf("  Gateway:    %s\n", gatewayKID)
		fmt.Printf("  Encrypted:  yes (NaCl box to gateway pubkey)\n")
		return nil
	},
}
