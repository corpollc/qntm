package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/corpo/qntm/gate"
)

var gateURL string
var gatePort int
var gateAdminToken string
var gateDevMode bool

func init() {
	// Gate parent command
	rootCmd.AddCommand(gateCmd)

	// Serve
	gateServeCmd.Flags().IntVar(&gatePort, "port", 8080, "Gate server port")
	gateServeCmd.Flags().StringVar(&gateAdminToken, "admin-token", "", "Admin bearer token for org/credential endpoints (env: QNTM_GATE_TOKEN)")
	gateServeCmd.Flags().BoolVar(&gateDevMode, "dev", false, "Development mode: allow running without admin token (WARNING: insecure)")
	gateCmd.AddCommand(gateServeCmd)

	// Echo
	echoPort := 9090
	gateEchoCmd.Flags().IntVar(&echoPort, "port", 9090, "Echo server port")
	gateCmd.AddCommand(gateEchoCmd)

	// Org
	gateCmd.AddCommand(gateOrgCmd)
	gateOrgCmd.AddCommand(gateOrgCreateCmd)

	// Credential
	gateCmd.AddCommand(gateCredCmd)
	gateCredCmd.AddCommand(gateCredAddCmd)

	// Request
	gateCmd.AddCommand(gateRequestCmd)
	gateRequestCmd.AddCommand(gateRequestSubmitCmd)
	gateRequestCmd.AddCommand(gateRequestApproveCmd)
	gateRequestCmd.AddCommand(gateRequestStatusCmd)

	// Execute
	gateCmd.AddCommand(gateExecuteCmd)

	// Persistent flag for gate URL
	gateCmd.PersistentFlags().StringVar(&gateURL, "gate-url", "http://localhost:8080", "Gate server URL")
}

var gateCmd = &cobra.Command{
	Use:           "gate",
	Short:         "qntm-gate multisig API gateway",
	Long:          "Stateless multisig authorization gateway. Authorization state lives in the qntm group conversation, not in server memory.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

var gateServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the gate server",
	RunE: func(cmd *cobra.Command, args []string) error {
		token := gateAdminToken
		if token == "" {
			token = os.Getenv("QNTM_GATE_TOKEN")
		}
		if token == "" && !gateDevMode {
			return fmt.Errorf("qntm gate serve requires --admin-token or QNTM_GATE_TOKEN\n  Use --dev to run without authentication (local testing only)")
		}
		var srv *gate.Server
		if token == "" {
			srv = gate.NewInsecureServerForTests()
		} else {
			secureSrv, err := gate.NewServer(token)
			if err != nil {
				return err
			}
			srv = secureSrv
		}
		addr := fmt.Sprintf(":%d", gatePort)
		if token != "" {
			fmt.Printf("qntm-gate server starting on %s (admin auth enabled, stateless)\n", addr)
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: running in --dev mode without admin token. Do NOT use in production.\n")
			fmt.Printf("qntm-gate server starting on %s (dev mode, no auth, stateless)\n", addr)
		}
		return http.ListenAndServe(addr, srv)
	},
}

var gateEchoCmd = &cobra.Command{
	Use:   "echo",
	Short: "Start the echo test server",
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			auth := r.Header.Get("Authorization")
			resp := map[string]interface{}{
				"method":      r.Method,
				"path":        r.URL.Path,
				"had_auth":    auth != "",
				"auth_header": auth,
			}
			if len(body) > 0 && json.Valid(body) {
				resp["body"] = json.RawMessage(body)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		addr := fmt.Sprintf(":%d", port)
		fmt.Printf("qntm echo server on %s\n", addr)
		return http.ListenAndServe(addr, mux)
	},
}

// --- Org commands ---

var gateOrgCmd = &cobra.Command{
	Use:   "org",
	Short: "Manage gate organizations",
}

var gateOrgCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an org (reads JSON from stdin)",
	Long:  `Reads JSON from stdin with fields: id, signers, rules. Signers need kid, public_key (base64url), label.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		return gatePost("/v1/orgs", body)
	},
}

// --- Credential commands ---

var gateCredCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage gate credentials",
}

var gateCredAddCmd = &cobra.Command{
	Use:   "add <org_id>",
	Short: "Add a credential (reads JSON from stdin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID := args[0]
		body, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		return gatePost(fmt.Sprintf("/v1/orgs/%s/credentials", orgID), body)
	},
}

// --- Request commands (post to conversation via gate server) ---

var gateRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Manage gate authorization requests",
}

var gateRequestSubmitCmd = &cobra.Command{
	Use:   "submit <org_id>",
	Short: "Submit a signed request to the gate conversation",
	Long: `Reads JSON from stdin: request_id, verb, target_endpoint, target_service, target_url, payload, expires_at (optional).
Signs with the current identity key. Posts as a gate.request message to the org's conversation.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID := args[0]

		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}

		var input struct {
			RequestID      string          `json:"request_id"`
			Verb           string          `json:"verb"`
			TargetEndpoint string          `json:"target_endpoint"`
			TargetService  string          `json:"target_service"`
			TargetURL      string          `json:"target_url"`
			Payload        json.RawMessage `json:"payload,omitempty"`
			ExpiresAt      *time.Time      `json:"expires_at,omitempty"`
		}
		if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}

		expiresAt := time.Now().Add(1 * time.Hour)
		if input.ExpiresAt != nil {
			expiresAt = *input.ExpiresAt
		}

		kid := gate.KIDFromPublicKey(currentIdentity.PublicKey)
		payloadHash := gate.ComputePayloadHash(input.Payload)
		signable := &gate.GateSignable{
			OrgID: orgID, RequestID: input.RequestID, Verb: input.Verb,
			TargetEndpoint: input.TargetEndpoint, TargetService: input.TargetService,
			TargetURL: input.TargetURL, ExpiresAtUnix: expiresAt.Unix(),
			PayloadHash: payloadHash,
		}
		sig, err := gate.SignRequest(ed25519.PrivateKey(currentIdentity.PrivateKey), signable)
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}

		// Post as a gate.request conversation message
		msg := map[string]interface{}{
			"type":            "gate.request",
			"request_id":      input.RequestID,
			"verb":            input.Verb,
			"target_endpoint": input.TargetEndpoint,
			"target_service":  input.TargetService,
			"target_url":      input.TargetURL,
			"payload":         input.Payload,
			"signer_kid":      kid,
			"signature":       base64.RawURLEncoding.EncodeToString(sig),
			"expires_at":      expiresAt,
		}

		body, _ := json.Marshal(msg)
		return gatePost(fmt.Sprintf("/v1/orgs/%s/messages", orgID), body)
	},
}

var gateRequestApproveCmd = &cobra.Command{
	Use:   "approve <org_id> <request_id>",
	Short: "Approve a request by posting to the gate conversation",
	Long: `Reads JSON from stdin: verb, target_endpoint, target_service, target_url, expires_at, payload.
These must match the original request. Signs approval and posts as a gate.approval message.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		orgID, requestID := args[0], args[1]

		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("load identity: %w", err)
		}

		var input struct {
			Verb           string          `json:"verb"`
			TargetEndpoint string          `json:"target_endpoint"`
			TargetService  string          `json:"target_service"`
			TargetURL      string          `json:"target_url"`
			ExpiresAt      *time.Time      `json:"expires_at"`
			Payload        json.RawMessage `json:"payload,omitempty"`
		}
		if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if input.TargetURL == "" {
			return fmt.Errorf("target_url is required for approval signing")
		}
		if input.ExpiresAt == nil {
			return fmt.Errorf("expires_at is required for approval signing")
		}

		kid := gate.KIDFromPublicKey(currentIdentity.PublicKey)
		payloadHash := gate.ComputePayloadHash(input.Payload)
		signable := &gate.GateSignable{
			OrgID: orgID, RequestID: requestID, Verb: input.Verb,
			TargetEndpoint: input.TargetEndpoint, TargetService: input.TargetService,
			TargetURL: input.TargetURL, ExpiresAtUnix: input.ExpiresAt.Unix(),
			PayloadHash: payloadHash,
		}
		reqHash, err := gate.HashRequest(signable)
		if err != nil {
			return fmt.Errorf("hash: %w", err)
		}
		appSig, err := gate.SignApproval(ed25519.PrivateKey(currentIdentity.PrivateKey),
			&gate.ApprovalSignable{OrgID: orgID, RequestID: requestID, RequestHash: reqHash})
		if err != nil {
			return fmt.Errorf("sign approval: %w", err)
		}

		// Post as a gate.approval conversation message
		msg := map[string]interface{}{
			"type":       "gate.approval",
			"request_id": requestID,
			"signer_kid": kid,
			"signature":  base64.RawURLEncoding.EncodeToString(appSig),
		}

		body, _ := json.Marshal(msg)
		return gatePost(fmt.Sprintf("/v1/orgs/%s/messages", orgID), body)
	},
}

var gateRequestStatusCmd = &cobra.Command{
	Use:   "status <org_id> <request_id>",
	Short: "Scan conversation for request status",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := http.Get(gateURL + fmt.Sprintf("/v1/orgs/%s/scan/%s", args[0], args[1]))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		var pretty bytes.Buffer
		if json.Indent(&pretty, data, "", "  ") == nil {
			fmt.Println(pretty.String())
		} else {
			fmt.Println(string(data))
		}
		return nil
	},
}

var gateExecuteCmd = &cobra.Command{
	Use:   "execute <org_id> <request_id>",
	Short: "Trigger execution check — scan conversation and execute if threshold met",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		body, _ := json.Marshal(map[string]string{})
		return gatePost(fmt.Sprintf("/v1/orgs/%s/execute/%s", args[0], args[1]), body)
	},
}

// --- Helpers ---

func gatePost(path string, body []byte) error {
	resp, err := http.Post(gateURL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	// Pretty print
	var pretty bytes.Buffer
	if json.Indent(&pretty, data, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(data))
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}
