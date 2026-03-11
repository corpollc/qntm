package cli

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/corpo/qntm/gate"
)

var (
	gatePromoteConvFlag      string
	gatePromoteOrgFlag       string
	gatePromoteThresholdFlag int
	gatePromoteGatewayKID    string

	gateConfigConvFlag      string
	gateConfigThresholdFlag int
)

func init() {
	rootCmd.AddCommand(gatePromoteCmd)
	gatePromoteCmd.Flags().StringVarP(&gatePromoteConvFlag, "conv", "c", "", "Conversation name, short ref, or hex ID")
	gatePromoteCmd.Flags().StringVarP(&gatePromoteOrgFlag, "org", "o", "", "Gate org ID")
	gatePromoteCmd.Flags().IntVar(&gatePromoteThresholdFlag, "threshold", 2, "Approval threshold (M-of-N)")
	gatePromoteCmd.Flags().StringVar(&gatePromoteGatewayKID, "gateway-kid", "", "KID of gateway participant (optional)")
	gatePromoteCmd.MarkFlagRequired("conv")
	gatePromoteCmd.MarkFlagRequired("org")

	rootCmd.AddCommand(gateConfigCmd)
	gateConfigCmd.Flags().StringVarP(&gateConfigConvFlag, "conv", "c", "", "Conversation name, short ref, or hex ID")
	gateConfigCmd.Flags().IntVar(&gateConfigThresholdFlag, "threshold", 2, "New approval threshold (M-of-N)")
	gateConfigCmd.MarkFlagRequired("conv")
	gateConfigCmd.MarkFlagRequired("threshold")
}

// gatePromoteCmd sends a gate.promote message to mark a conversation as gate-enabled.
var gatePromoteCmd = &cobra.Command{
	Use:   "gate-promote",
	Short: "Promote a conversation to gate-enabled",
	Long: `Sends a gate.promote message to the specified conversation, registering it
as gate-enabled with signers and threshold rules. The gateway will process this
message and begin accepting gate.request and gate.approval messages.

Example:
  qntm gate-promote -c my-group -o acme --threshold 2
  qntm gate-promote -c my-group -o acme --threshold 1 --gateway-kid <kid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}

		conversation, convIDHex, err := resolveConversation(gatePromoteConvFlag)
		if err != nil {
			return err
		}

		orgID := gatePromoteOrgFlag
		threshold := gatePromoteThresholdFlag
		if threshold < 1 {
			return fmt.Errorf("threshold must be at least 1")
		}

		// Build signers list. The sender (current identity) is always included.
		// Other participants are added by KID only (we don't have their public
		// keys locally; the gateway resolves pubkeys from its own conversation
		// state or from subsequent messages).
		selfKID := gate.KIDFromPublicKey(ed25519.PublicKey(currentIdentity.PublicKey))
		signers := []gate.Signer{
			{
				KID:       selfKID,
				PublicKey: ed25519.PublicKey(currentIdentity.PublicKey),
			},
		}

		n := len(signers)
		if threshold > n {
			fmt.Printf("Warning: threshold %d exceeds signer count %d\n", threshold, n)
		}

		// Build the promote payload
		payload := gate.PromotePayload{
			OrgID:   orgID,
			Signers: signers,
			Rules: []gate.ThresholdRule{
				{
					Service:  "*",
					Endpoint: "*",
					Verb:     "*",
					M:        threshold,
					N:        n,
				},
			},
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal promote payload: %w", err)
		}

		if err := sendGateMessage(currentIdentity, conversation, string(gate.GateMessagePromote), body); err != nil {
			return err
		}

		fmt.Printf("Gate promote sent to %s\n", convIDHex)
		fmt.Printf("  Org:        %s\n", orgID)
		fmt.Printf("  Threshold:  %d-of-%d\n", threshold, n)
		fmt.Printf("  Signers:    %d\n", n)
		for _, s := range signers {
			label := ""
			if s.KID == selfKID {
				label = " (self)"
			}
			fmt.Printf("    - %s%s\n", s.KID, label)
		}
		return nil
	},
}

// gateConfigCmd sends a gate.config message to update threshold rules.
var gateConfigCmd = &cobra.Command{
	Use:   "gate-config",
	Short: "Update gate threshold rules for a conversation",
	Long: `Sends a gate.config message to update the threshold rules on an already-promoted
conversation. The gateway will apply the new rules to subsequent requests.

Example:
  qntm gate-config -c my-group --threshold 3`,
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}

		conversation, convIDHex, err := resolveConversation(gateConfigConvFlag)
		if err != nil {
			return err
		}

		threshold := gateConfigThresholdFlag
		if threshold < 1 {
			return fmt.Errorf("threshold must be at least 1")
		}

		payload := gate.ConfigPayload{
			Rules: []gate.ThresholdRule{
				{
					Service:  "*",
					Endpoint: "*",
					Verb:     "*",
					M:        threshold,
					N:        0, // N is informational; gateway calculates from signers
				},
			},
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal config payload: %w", err)
		}

		if err := sendGateMessage(currentIdentity, conversation, string(gate.GateMessageConfig), body); err != nil {
			return err
		}

		fmt.Printf("Gate config sent to %s\n", convIDHex)
		fmt.Printf("  New threshold: %d\n", threshold)
		return nil
	},
}
