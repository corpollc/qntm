package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/handle"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/naming"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
	"github.com/corpo/qntm/registry"
	"github.com/corpo/qntm/shortref"
)

var registryURL string

func init() {
	// Registry commands
	rootCmd.AddCommand(registryCmd)
	registryCmd.AddCommand(registryServeCmd)
	registryCmd.AddCommand(registryRegisterCmd)
	registryRegisterCmd.Flags().StringVar(&registryURL, "registry-url", "http://localhost:8420", "Registry server URL")

	// Handle commands
	rootCmd.AddCommand(handleCmd)
	handleCmd.AddCommand(handleRevealCmd)
	handleCmd.AddCommand(handleShowCmd)

	// Name commands
	rootCmd.AddCommand(nameCmd)
	nameCmd.AddCommand(nameSetCmd)
	nameCmd.AddCommand(nameListCmd)
	nameCmd.AddCommand(nameRemoveCmd)
	nameCmd.AddCommand(nameConvCmd)

	// Short ref command
	rootCmd.AddCommand(refCmd)
}

// --- Registry Commands ---

var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Handle registry operations",
}

var registryServeCmd = &cobra.Command{
	Use:   "serve [--addr :8420]",
	Short: "Start the handle registry server",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")
		if addr == "" {
			addr = ":8420"
		}
		dataDir := configDir + "/registry"
		store, err := registry.NewStore(dataDir)
		if err != nil {
			return fmt.Errorf("failed to init registry store: %w", err)
		}
		srv := registry.NewServer(store)
		fmt.Printf("Registry server listening on %s\n", addr)
		return http.ListenAndServe(addr, srv.Handler())
	},
}

func init() {
	registryServeCmd.Flags().String("addr", ":8420", "Listen address")
}

var registryRegisterCmd = &cobra.Command{
	Use:   "register <handle>",
	Short: "Register a handle with the registry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		chosenHandle := args[0]

		id, err := loadIdentity()
		if err != nil {
			return err
		}

		kidHex := hex.EncodeToString(id.KeyID[:])
		ikPKHex := hex.EncodeToString(id.PublicKey)

		// Sign "register:<kid>:<handle>"
		msg := []byte("register:" + kidHex + ":" + chosenHandle)
		sig := ed25519.Sign(id.PrivateKey, msg)

		reqBody, _ := json.Marshal(registry.RegisterRequest{
			KID:       kidHex,
			IKPK:      ikPKHex,
			Handle:    chosenHandle,
			Signature: hex.EncodeToString(sig),
		})

		resp, err := http.Post(registryURL+"/register", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			return fmt.Errorf("failed to contact registry: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			var errResp map[string]string
			json.NewDecoder(resp.Body).Decode(&errResp)
			return fmt.Errorf("registration failed: %s", errResp["error"])
		}

		var regResp registry.RegisterResponse
		json.NewDecoder(resp.Body).Decode(&regResp)

		// Store handle + salt locally
		handleStore, err := handle.NewStore(configDir)
		if err != nil {
			return err
		}
		if err := handleStore.SetMyHandle(chosenHandle, regResp.Salt); err != nil {
			return err
		}

		fmt.Printf("Handle registered: %s\n", chosenHandle)
		fmt.Printf("Salt (stored locally): %s...\n", regResp.Salt[:16])
		return nil
	},
}

// --- Handle Commands ---

var handleCmd = &cobra.Command{
	Use:   "handle",
	Short: "Manage encrypted handles",
}

var handleRevealCmd = &cobra.Command{
	Use:   "reveal <conversation-id>",
	Short: "Reveal your handle in a conversation",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		convIDHex, err := resolveConvID(args[0])
		if err != nil {
			return err
		}

		id, err := loadIdentity()
		if err != nil {
			return err
		}

		handleStore, err := handle.NewStore(configDir)
		if err != nil {
			return err
		}

		myHandle, mySaltHex := handleStore.GetMyHandle()
		if myHandle == "" {
			return fmt.Errorf("no handle registered (use 'qntm registry register <handle>' first)")
		}

		salt, err := hex.DecodeString(mySaltHex)
		if err != nil {
			return fmt.Errorf("corrupt salt: %w", err)
		}

		// Create handle_reveal payload
		payload := handle.RevealPayload{
			Handle:     myHandle,
			HandleSalt: salt,
		}
		body, err := cbor.MarshalCanonical(payload)
		if err != nil {
			return err
		}

		// Find conversation and send as a message
		convIDBytes, _ := hex.DecodeString(convIDHex)
		var convID types.ConversationID
		copy(convID[:], convIDBytes)
		conv, err := findConversation(convID)
		if err != nil {
			return err
		}

		// Create and send the message
		msgMgr := message.NewManager()
		envelope, err := msgMgr.CreateMessage(id, conv, "handle_reveal", body, nil, msgMgr.DefaultTTL())
		if err != nil {
			return err
		}

		storage := getStorageProvider()
		dropboxMgr := dropbox.NewManager(storage)
		if err := dropboxMgr.SendMessage(envelope); err != nil {
			return err
		}

		fmt.Printf("Handle revealed in conversation %s\n", convIDHex[:8]+"...")
		return nil
	},
}

var handleShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show your registered handle",
	RunE: func(cmd *cobra.Command, args []string) error {
		handleStore, err := handle.NewStore(configDir)
		if err != nil {
			return err
		}
		h, _ := handleStore.GetMyHandle()
		if h == "" {
			fmt.Println("No handle registered")
		} else {
			fmt.Printf("Handle: %s\n", h)
		}
		return nil
	},
}

// --- Name Commands ---

var nameCmd = &cobra.Command{
	Use:   "name",
	Short: "Manage local nicknames",
}

var nameSetCmd = &cobra.Command{
	Use:   "set <kid_or_short_ref> <local_name>",
	Short: "Assign a local nickname to an identity",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		kidHex, err := resolveKID(args[0])
		if err != nil {
			return err
		}
		localName := args[1]

		store, err := naming.NewStore(configDir)
		if err != nil {
			return err
		}
		if err := store.SetIdentityName(kidHex, localName); err != nil {
			return err
		}
		short := kidHex
		if len(short) > 8 {
			short = short[:8] + "..."
		}
		fmt.Printf("Named %s → %s\n", short, localName)
		return nil
	},
}

var nameListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all named identities and conversations",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := naming.NewStore(configDir)
		if err != nil {
			return err
		}

		ids := store.ListIdentities()
		convs := store.ListConversations()

		if len(ids) == 0 && len(convs) == 0 {
			fmt.Println("No names set")
			return nil
		}

		if len(ids) > 0 {
			fmt.Println("Identities:")
			for kid, name := range ids {
				short := kid
				if len(kid) > 8 {
					short = kid[:8] + "..."
				}
				fmt.Printf("  %s → %s\n", short, name)
			}
		}
		if len(convs) > 0 {
			fmt.Println("Conversations:")
			for cid, name := range convs {
				short := cid
				if len(cid) > 8 {
					short = cid[:8] + "..."
				}
				fmt.Printf("  %s → %s\n", short, name)
			}
		}
		return nil
	},
}

var nameRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a nickname",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := naming.NewStore(configDir)
		if err != nil {
			return err
		}
		if err := store.RemoveIdentityName(args[0]); err == nil {
			fmt.Printf("Removed identity name: %s\n", args[0])
			return nil
		}
		if err := store.RemoveConversationName(args[0]); err == nil {
			fmt.Printf("Removed conversation name: %s\n", args[0])
			return nil
		}
		return fmt.Errorf("name %q not found", args[0])
	},
}

var nameConvCmd = &cobra.Command{
	Use:   "conv <conv_id_or_short_ref> <local_name>",
	Short: "Assign a local name to a conversation",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		convIDHex, err := resolveConvID(args[0])
		if err != nil {
			return err
		}
		store, err := naming.NewStore(configDir)
		if err != nil {
			return err
		}
		if err := store.SetConversationName(convIDHex, args[1]); err != nil {
			return err
		}
		short := convIDHex
		if len(short) > 8 {
			short = short[:8] + "..."
		}
		fmt.Printf("Named conversation %s → %s\n", short, args[1])
		return nil
	},
}

// --- Short Ref Command ---

var refCmd = &cobra.Command{
	Use:   "ref <short_prefix>",
	Short: "Resolve a short reference to a full ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		trie := buildTrie()
		matches := trie.Resolve(args[0])
		switch len(matches) {
		case 0:
			return fmt.Errorf("no match for %q", args[0])
		case 1:
			fmt.Println(matches[0])
		default:
			fmt.Printf("Ambiguous prefix %q matches %d IDs:\n", args[0], len(matches))
			for _, m := range matches {
				fmt.Printf("  %s\n", m)
			}
		}
		return nil
	},
}

// --- Helpers ---

func buildTrie() *shortref.Trie {
	trie := shortref.New()
	convs, _ := loadConversations()
	for _, conv := range convs {
		trie.Insert(hex.EncodeToString(conv.ID[:]))
		for _, p := range conv.Participants {
			trie.Insert(hex.EncodeToString(p[:]))
		}
	}
	if id, err := loadIdentity(); err == nil {
		trie.Insert(hex.EncodeToString(id.KeyID[:]))
	}
	return trie
}

func resolveKID(input string) (string, error) {
	// Accept 32-char hex KIDs directly
	if len(input) == 32 {
		if _, err := hex.DecodeString(input); err == nil {
			return input, nil
		}
	}
	// Accept base64url-encoded KIDs (22 chars for 16-byte KID)
	if b, err := base64.RawURLEncoding.DecodeString(input); err == nil && len(b) == 16 {
		return hex.EncodeToString(b), nil
	}
	// Try name resolution
	store, err := naming.NewStore(configDir)
	if err == nil {
		if kid, ok := store.ResolveIdentityByName(input); ok {
			return kid, nil
		}
	}
	trie := buildTrie()
	return trie.ResolveExact(input)
}

func resolveConvID(input string) (string, error) {
	if len(input) == 32 {
		if _, err := hex.DecodeString(input); err == nil {
			return input, nil
		}
	}
	store, err := naming.NewStore(configDir)
	if err == nil {
		if cid, ok := store.ResolveConversationByName(input); ok {
			return cid, nil
		}
	}
	trie := buildTrie()
	return trie.ResolveExact(input)
}
