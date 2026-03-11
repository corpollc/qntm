package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/gate"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
)

var gateRunConvFlag string
var gateRunOrgFlag string
var gateChatURL string

func init() {
	// Top-level gate chat commands (not under admin)
	rootCmd.AddCommand(gateRunCmd)
	gateRunCmd.Flags().StringVarP(&gateRunConvFlag, "conv", "c", "", "Conversation name, short ref, or hex ID")
	gateRunCmd.Flags().StringVarP(&gateRunOrgFlag, "org", "o", "", "Gate org ID")
	gateRunCmd.Flags().StringVar(&gateChatURL, "gate-url", "http://localhost:8080", "Gate server URL")
	gateRunCmd.MarkFlagRequired("conv")
	gateRunCmd.MarkFlagRequired("org")

	rootCmd.AddCommand(gateApproveCmd)
	gateApproveCmd.Flags().StringVarP(&gateRunConvFlag, "conv", "c", "", "Conversation name, short ref, or hex ID")
	gateApproveCmd.Flags().StringVar(&gateChatURL, "gate-url", "http://localhost:8080", "Gate server URL for execution trigger")
	gateApproveCmd.MarkFlagRequired("conv")

	rootCmd.AddCommand(gatePendingCmd)
	gatePendingCmd.Flags().StringVarP(&gateRunConvFlag, "conv", "c", "", "Conversation name, short ref, or hex ID (optional)")
}

// gateRunCmd sends a gate.request message to a conversation.
var gateRunCmd = &cobra.Command{
	Use:   "gate-run <recipe>",
	Short: "Submit a gate authorization request to a conversation",
	Long: `Creates a signed gate.request message and sends it to the specified conversation.
The request includes the recipe details and your signature. Other signers in the
conversation can approve it with 'qntm gate-approve'.

Example:
  qntm gate-run jokes.dad -c my-group -o acme`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		recipeName := args[0]

		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}

		// Load recipe
		cat, err := gate.LoadStarterCatalog()
		if err != nil {
			return fmt.Errorf("load recipes: %w", err)
		}
		recipe, err := cat.GetRecipe(recipeName)
		if err != nil {
			return fmt.Errorf("unknown recipe: %w", err)
		}

		// Resolve conversation
		conversation, convIDHex, err := resolveConversation(gateRunConvFlag)
		if err != nil {
			return err
		}

		orgID := gateRunOrgFlag
		requestID := uuid.New().String()
		expiresAt := time.Now().Add(1 * time.Hour)

		kid := gate.KIDFromPublicKey(ed25519.PublicKey(currentIdentity.PublicKey))
		payloadHash := gate.ComputePayloadHash(nil)
		signable := &gate.GateSignable{
			OrgID:          orgID,
			RequestID:      requestID,
			Verb:           recipe.Verb,
			TargetEndpoint: recipe.Endpoint,
			TargetService:  recipe.Service,
			TargetURL:      recipe.TargetURL,
			ExpiresAtUnix:  expiresAt.Unix(),
			PayloadHash:    payloadHash,
		}
		sig, err := gate.SignRequest(ed25519.PrivateKey(currentIdentity.PrivateKey), signable)
		if err != nil {
			return fmt.Errorf("sign request: %w", err)
		}

		// Build gate.request message body
		gateMsg := gate.GateConversationMessage{
			Type:           gate.GateMessageRequest,
			OrgID:          orgID,
			RequestID:      requestID,
			Verb:           recipe.Verb,
			TargetEndpoint: recipe.Endpoint,
			TargetService:  recipe.Service,
			TargetURL:      recipe.TargetURL,
			ExpiresAt:      expiresAt,
			SignerKID:      kid,
			Signature:      base64.RawURLEncoding.EncodeToString(sig),
		}
		body, err := json.Marshal(gateMsg)
		if err != nil {
			return fmt.Errorf("marshal gate message: %w", err)
		}

		// Send as qntm message with body_type=gate.request
		if err := sendGateMessage(currentIdentity, conversation, string(gate.GateMessageRequest), body); err != nil {
			return err
		}

		// Also POST to gate server for execution tracking
		if gateChatURL != "" {
			if err := postToGateServer(orgID, body); err != nil {
				fmt.Fprintf(os.Stderr, "  Note: gate server POST failed: %v\n", err)
			}
		}

		fmt.Printf("Gate request submitted to %s\n", convIDHex)
		fmt.Printf("  Request ID: %s\n", requestID)
		fmt.Printf("  Recipe:     %s (%s %s)\n", recipeName, recipe.Verb, recipe.Endpoint)
		fmt.Printf("  Service:    %s\n", recipe.Service)
		fmt.Printf("  Org:        %s\n", orgID)
		fmt.Printf("  Signer:     %s\n", kid)
		fmt.Printf("  Expires:    %s\n", expiresAt.Format(time.RFC3339))
		return nil
	},
}

// gateApproveCmd approves a gate request by sending a gate.approval message.
var gateApproveCmd = &cobra.Command{
	Use:   "gate-approve <request-id>",
	Short: "Approve a gate request in a conversation",
	Long: `Finds the gate.request with the given ID in the conversation, signs an approval,
and sends a gate.approval message. If this approval meets the threshold, the client
optimistically triggers execution on the gate server (approach C).

Example:
  qntm gate-approve abc123 -c my-group`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		requestID := args[0]

		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}

		conversation, convIDHex, err := resolveConversation(gateRunConvFlag)
		if err != nil {
			return err
		}

		// Find the request in local chat archive
		reqMsg, err := findGateRequest(conversation, requestID)
		if err != nil {
			return fmt.Errorf("find request: %w", err)
		}

		kid := gate.KIDFromPublicKey(ed25519.PublicKey(currentIdentity.PublicKey))
		payloadHash := gate.ComputePayloadHash(reqMsg.Payload)
		signable := &gate.GateSignable{
			OrgID:          reqMsg.OrgID,
			RequestID:      requestID,
			Verb:           reqMsg.Verb,
			TargetEndpoint: reqMsg.TargetEndpoint,
			TargetService:  reqMsg.TargetService,
			TargetURL:      reqMsg.TargetURL,
			ExpiresAtUnix:  reqMsg.ExpiresAt.Unix(),
			PayloadHash:    payloadHash,
		}
		reqHash, err := gate.HashRequest(signable)
		if err != nil {
			return fmt.Errorf("hash request: %w", err)
		}
		appSig, err := gate.SignApproval(
			ed25519.PrivateKey(currentIdentity.PrivateKey),
			&gate.ApprovalSignable{OrgID: reqMsg.OrgID, RequestID: requestID, RequestHash: reqHash},
		)
		if err != nil {
			return fmt.Errorf("sign approval: %w", err)
		}

		// Build gate.approval message body
		approvalMsg := gate.GateConversationMessage{
			Type:      gate.GateMessageApproval,
			OrgID:     reqMsg.OrgID,
			RequestID: requestID,
			SignerKID: kid,
			Signature: base64.RawURLEncoding.EncodeToString(appSig),
		}
		body, err := json.Marshal(approvalMsg)
		if err != nil {
			return fmt.Errorf("marshal approval: %w", err)
		}

		// Send as qntm message with body_type=gate.approval
		if err := sendGateMessage(currentIdentity, conversation, string(gate.GateMessageApproval), body); err != nil {
			return err
		}

		fmt.Printf("Approval sent to %s\n", convIDHex)
		fmt.Printf("  Request ID: %s\n", requestID)
		fmt.Printf("  Signer:     %s\n", kid)

		// Approach C: POST approval to gate server (auto-triggers execution if threshold met)
		if gateChatURL != "" {
			fmt.Printf("  Posting to gate server %s...\n", gateChatURL)
			if err := postToGateServer(reqMsg.OrgID, body); err != nil {
				fmt.Fprintf(os.Stderr, "  Note: gate server POST failed: %v\n", err)
				// Fallback: try explicit execute
				if err := triggerGateExecution(reqMsg.OrgID, requestID); err != nil {
					fmt.Fprintf(os.Stderr, "  Note: execution trigger also failed: %v\n", err)
				}
			}
		}

		return nil
	},
}

// gatePendingCmd lists pending gate requests in conversations.
var gatePendingCmd = &cobra.Command{
	Use:   "gate-pending",
	Short: "List pending gate requests in conversations",
	Long: `Scans conversation history for gate.request messages that haven't been
executed or expired. Shows approval progress.

Example:
  qntm gate-pending -c my-group`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var conversations []*types.Conversation

		if gateRunConvFlag != "" {
			conv, _, err := resolveConversation(gateRunConvFlag)
			if err != nil {
				return err
			}
			conversations = []*types.Conversation{conv}
		} else {
			convs, err := loadConversations()
			if err != nil {
				return fmt.Errorf("load conversations: %w", err)
			}
			conversations = convs
		}

		dc := NewDisplayContext()
		found := 0

		for _, conv := range conversations {
			convIDHex := hex.EncodeToString(conv.ID[:])
			requests, approvals, executed := scanGateMessages(conv)

			for reqID, req := range requests {
				if _, done := executed[reqID]; done {
					continue
				}
				if req.ExpiresAt.Before(time.Now()) {
					continue
				}

				found++
				approvalCount := len(approvals[reqID])
				fmt.Printf("\n%s in %s\n", reqID, dc.FormatConvIDHex(convIDHex))
				fmt.Printf("  Recipe:     %s %s\n", req.Verb, req.TargetEndpoint)
				fmt.Printf("  Service:    %s\n", req.TargetService)
				fmt.Printf("  Org:        %s\n", req.OrgID)
				fmt.Printf("  Requester:  %s\n", req.SignerKID)
				fmt.Printf("  Approvals:  %d (incl. requester)\n", approvalCount+1)
				fmt.Printf("  Expires:    %s\n", req.ExpiresAt.Format(time.RFC3339))
			}
		}

		if found == 0 {
			fmt.Println("No pending gate requests")
		}
		return nil
	},
}

// --- helpers ---

func resolveConversation(input string) (*types.Conversation, string, error) {
	convIDHex, err := resolveConvID(input)
	if err != nil {
		return nil, "", fmt.Errorf("could not resolve conversation %q: %w", input, err)
	}
	convIDBytes, err := hex.DecodeString(convIDHex)
	if err != nil || len(convIDBytes) != 16 {
		return nil, "", fmt.Errorf("invalid conversation ID format")
	}
	var convID types.ConversationID
	copy(convID[:], convIDBytes)
	conv, err := findConversation(convID)
	if err != nil {
		return nil, "", fmt.Errorf("conversation not found: %w", err)
	}
	return conv, convIDHex, nil
}

func sendGateMessage(identity *types.Identity, conversation *types.Conversation, bodyType string, body []byte) error {
	messageMgr := message.NewManager()
	envelope, err := messageMgr.CreateMessage(
		identity,
		conversation,
		bodyType,
		body,
		nil,
		messageMgr.DefaultTTL(),
	)
	if err != nil {
		return fmt.Errorf("create message: %w", err)
	}

	storage := getStorageProvider()
	dropboxMgr := dropbox.NewManager(storage)
	if _, err := dropboxMgr.SendMessageWithSequence(envelope); err != nil {
		return fmt.Errorf("send message: %w", err)
	}

	// Archive locally
	bodyEncoded, bodyEncoding := encodeChatBody(body)
	if err := appendChatArchiveEntry(conversation, chatArchiveEntry{
		MessageID:    hex.EncodeToString(envelope.MsgID[:]),
		Direction:    "outgoing",
		SenderKIDHex: hex.EncodeToString(identity.KeyID[:]),
		BodyType:     bodyType,
		Body:         bodyEncoded,
		BodyEncoding: bodyEncoding,
		CreatedTS:    envelope.CreatedTS,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to store chat history: %v\n", err)
	}

	return nil
}

func findGateRequest(conversation *types.Conversation, requestID string) (*gate.GateConversationMessage, error) {
	entries, err := loadChatArchive(conversation)
	if err != nil {
		return nil, fmt.Errorf("load chat archive: %w", err)
	}

	for _, entry := range entries {
		if entry.BodyType != string(gate.GateMessageRequest) {
			continue
		}
		body := chatEntryBodyBytes(entry)
		var msg gate.GateConversationMessage
		if err := json.Unmarshal(body, &msg); err != nil {
			continue
		}
		if msg.RequestID == requestID {
			return &msg, nil
		}
	}

	return nil, fmt.Errorf("gate request %q not found in conversation history (try 'qntm recv' first)", requestID)
}

func scanGateMessages(conversation *types.Conversation) (
	requests map[string]*gate.GateConversationMessage,
	approvals map[string][]string, // requestID -> list of approver KIDs
	executed map[string]bool,
) {
	requests = make(map[string]*gate.GateConversationMessage)
	approvals = make(map[string][]string)
	executed = make(map[string]bool)

	entries, err := loadChatArchive(conversation)
	if err != nil {
		return
	}

	for _, entry := range entries {
		switch entry.BodyType {
		case string(gate.GateMessageRequest):
			body := chatEntryBodyBytes(entry)
			var msg gate.GateConversationMessage
			if json.Unmarshal(body, &msg) == nil {
				requests[msg.RequestID] = &msg
			}
		case string(gate.GateMessageApproval):
			body := chatEntryBodyBytes(entry)
			var msg gate.GateConversationMessage
			if json.Unmarshal(body, &msg) == nil {
				approvals[msg.RequestID] = append(approvals[msg.RequestID], msg.SignerKID)
			}
		case string(gate.GateMessageExecuted):
			body := chatEntryBodyBytes(entry)
			var msg gate.GateConversationMessage
			if json.Unmarshal(body, &msg) == nil {
				executed[msg.RequestID] = true
			}
		}
	}

	return
}

// chatEntryBodyBytes extracts the raw body bytes from a chat archive entry.
func chatEntryBodyBytes(entry chatArchiveEntry) []byte {
	if entry.BodyEncoding == "base64" {
		decoded, err := base64.RawStdEncoding.DecodeString(entry.Body)
		if err == nil {
			return decoded
		}
	}
	return []byte(entry.Body)
}

func postToGateServer(orgID string, body []byte) error {
	resp, err := http.Post(gateChatURL+fmt.Sprintf("/v1/orgs/%s/messages", orgID), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("gate server: %s (HTTP %d)", errResp["error"], resp.StatusCode)
	}

	var result gate.ExecuteResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if result.Status == gate.StatusExecuted {
			fmt.Printf("  Executed! HTTP %d\n", result.ExecutionResult.StatusCode)
		} else {
			fmt.Printf("  Gate status: %s (%d/%d signatures)\n", result.Status, result.SignatureCount, result.Threshold)
		}
	}
	return nil
}

func triggerGateExecution(orgID, requestID string) error {
	body, _ := json.Marshal(map[string]string{})
	resp, err := http.Post(gateChatURL+fmt.Sprintf("/v1/orgs/%s/execute/%s", orgID, requestID), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result gate.ExecuteResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if result.Status == gate.StatusExecuted {
		fmt.Printf("  Executed! Status: %d\n", result.ExecutionResult.StatusCode)
	} else {
		fmt.Printf("  Status: %s (%d/%d signatures)\n", result.Status, result.SignatureCount, result.Threshold)
	}
	return nil
}

// FormatGateMessage renders a gate message for CLI display.
func FormatGateMessage(bodyType string, body []byte) string {
	var msg gate.GateConversationMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return string(body)
	}

	switch gate.GateMessageType(bodyType) {
	case gate.GateMessagePromote:
		var payload gate.PromotePayload
		if err := json.Unmarshal(body, &payload); err == nil {
			return fmt.Sprintf("GATE PROMOTE org=%s signers=%d rules=%d",
				payload.OrgID, len(payload.Signers), len(payload.Rules))
		}
		return string(body)
	case gate.GateMessageConfig:
		var payload gate.ConfigPayload
		if err := json.Unmarshal(body, &payload); err == nil {
			ruleDesc := ""
			if len(payload.Rules) > 0 {
				ruleDesc = fmt.Sprintf(" (M=%d)", payload.Rules[0].M)
			}
			return fmt.Sprintf("GATE CONFIG rules=%d%s", len(payload.Rules), ruleDesc)
		}
		return string(body)
	case gate.GateMessageRequest:
		return fmt.Sprintf("GATE REQUEST %s\n    %s %s on %s (org: %s)\n    signer: %s  expires: %s",
			msg.RequestID,
			msg.Verb, msg.TargetEndpoint, msg.TargetService,
			msg.OrgID,
			msg.SignerKID,
			msg.ExpiresAt.Format("15:04"),
		)
	case gate.GateMessageApproval:
		return fmt.Sprintf("GATE APPROVAL for %s by %s",
			msg.RequestID, msg.SignerKID,
		)
	case gate.GateMessageExecuted:
		status := ""
		if msg.ExecutionStatusCode > 0 {
			status = fmt.Sprintf(" (HTTP %d)", msg.ExecutionStatusCode)
		}
		return fmt.Sprintf("GATE EXECUTED %s%s",
			msg.RequestID, status,
		)
	default:
		return string(body)
	}
}
