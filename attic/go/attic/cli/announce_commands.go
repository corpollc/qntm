// DEPRECATED: Go CLI moved to attic
//go:build ignore

package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/corpo/qntm/announce"
	"github.com/corpo/qntm/crypto"
	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
)

func init() {
	rootCmd.AddCommand(announceCmd)
	announceCmd.AddCommand(announceCreateCmd)
	announceCmd.AddCommand(announcePostCmd)
	announceCmd.AddCommand(announceSubscribeCmd)
	announceCmd.AddCommand(announceListCmd)
	announceCmd.AddCommand(announceDeleteCmd)

	announceSubscribeCmd.Flags().String("token", "", "Invite token from channel owner")
	announceSubscribeCmd.Flags().String("name", "", "Local name for this channel")
}

var announceCmd = &cobra.Command{
	Use:   "announce",
	Short: "Manage broadcast/announce channels",
	Long:  "Create, post to, subscribe to, and manage one-way announce channels.",
}

// --- Local storage for announce channel keys ---

type announceChannelStore struct {
	Channels map[string]*announceChannelEntry `json:"channels"` // keyed by conv_id hex
}

type announceChannelEntry struct {
	Name           string `json:"name"`
	ConvID         string `json:"conv_id"`
	MasterPrivate  string `json:"master_private,omitempty"`  // hex, only for owner
	MasterPublic   string `json:"master_public,omitempty"`   // hex, only for owner
	PostingPrivate string `json:"posting_private,omitempty"` // hex, only for owner
	PostingPublic  string `json:"posting_public,omitempty"`  // hex
	IsOwner        bool   `json:"is_owner"`
}

func getAnnounceStorePath() string {
	return filepath.Join(configDir, "announce_channels.json")
}

func loadAnnounceStore() *announceChannelStore {
	data, err := os.ReadFile(getAnnounceStorePath())
	if err != nil {
		return &announceChannelStore{Channels: make(map[string]*announceChannelEntry)}
	}
	var store announceChannelStore
	if err := json.Unmarshal(data, &store); err != nil {
		return &announceChannelStore{Channels: make(map[string]*announceChannelEntry)}
	}
	if store.Channels == nil {
		store.Channels = make(map[string]*announceChannelEntry)
	}
	return &store
}

func saveAnnounceStore(store *announceChannelStore) error {
	if err := ensureConfigDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getAnnounceStorePath(), data, 0600)
}

func resolveAnnounceChannel(nameOrID string) (*announceChannelEntry, error) {
	store := loadAnnounceStore()
	if entry, ok := store.Channels[nameOrID]; ok {
		return entry, nil
	}
	for _, entry := range store.Channels {
		if entry.Name == nameOrID {
			return entry, nil
		}
	}
	return nil, fmt.Errorf("announce channel %q not found", nameOrID)
}

// deriveAnnounceKeys derives conversation keys from an invite secret and convID.
func deriveAnnounceKeys(inviteSecret []byte, convID types.ConversationID) (types.ConversationKeys, error) {
	suite := crypto.NewQSP1Suite()
	rootKey, err := suite.DeriveRootKey(inviteSecret, convID[:], convID[:])
	if err != nil {
		return types.ConversationKeys{}, fmt.Errorf("derive root key: %w", err)
	}
	aeadKey, nonceKey, err := suite.DeriveConversationKeys(rootKey, convID[:])
	if err != nil {
		return types.ConversationKeys{}, fmt.Errorf("derive conversation keys: %w", err)
	}
	return types.ConversationKeys{Root: rootKey, AEADKey: aeadKey, NonceKey: nonceKey}, nil
}

// --- Commands ---

var announceCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new announce channel (generates master + posting keys)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		channelName := args[0]

		mgr := announce.NewManager()
		keys, err := mgr.GenerateChannelKeys()
		if err != nil {
			return fmt.Errorf("failed to generate channel keys: %w", err)
		}

		idMgr := identity.NewManager()
		convID, err := idMgr.GenerateConversationID()
		if err != nil {
			return fmt.Errorf("failed to generate conversation ID: %w", err)
		}
		convIDHex := hex.EncodeToString(convID[:])

		masterPKB64 := base64.RawURLEncoding.EncodeToString(keys.MasterPublic)
		postingPKB64 := base64.RawURLEncoding.EncodeToString(keys.PostingPublic)

		sig, err := mgr.SignRegister(keys.MasterPrivate, channelName, convIDHex, postingPKB64)
		if err != nil {
			return fmt.Errorf("failed to sign register: %w", err)
		}

		regReq := announce.RegisterRequest{
			Name:      channelName,
			ConvID:    convIDHex,
			MasterPK:  masterPKB64,
			PostingPK: postingPKB64,
			Sig:       sig,
		}
		regBody, err := json.Marshal(regReq)
		if err != nil {
			return fmt.Errorf("failed to encode register: %w", err)
		}

		storage := getStorageProvider()
		httpStorage, ok := storage.(*dropbox.HTTPStorageProvider)
		if !ok {
			return fmt.Errorf("announce channels require HTTP storage provider (set --dropbox-url)")
		}
		if err := httpStorage.AnnounceRegister(json.RawMessage(regBody)); err != nil {
			return fmt.Errorf("failed to register announce channel: %w", err)
		}

		// Generate invite secret for subscribers
		inviteSecret, err := idMgr.GenerateRandomBytes(32)
		if err != nil {
			return fmt.Errorf("failed to generate invite secret: %w", err)
		}

		convKeys, err := deriveAnnounceKeys(inviteSecret, convID)
		if err != nil {
			return err
		}

		conversation := &types.Conversation{
			ID:           convID,
			Name:         channelName,
			Type:         types.ConversationTypeAnnounce,
			Keys:         convKeys,
			CreatedAt:    time.Now(),
			CurrentEpoch: 0,
		}
		if err := saveConversation(conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}

		store := loadAnnounceStore()
		store.Channels[convIDHex] = &announceChannelEntry{
			Name:           channelName,
			ConvID:         convIDHex,
			MasterPrivate:  hex.EncodeToString(keys.MasterPrivate),
			MasterPublic:   hex.EncodeToString(keys.MasterPublic),
			PostingPrivate: hex.EncodeToString(keys.PostingPrivate),
			PostingPublic:  hex.EncodeToString(keys.PostingPublic),
			IsOwner:        true,
		}
		if err := saveAnnounceStore(store); err != nil {
			return fmt.Errorf("failed to save announce store: %w", err)
		}

		inviteTokenHex := hex.EncodeToString(inviteSecret)

		fmt.Printf("Created announce channel: %s\n", channelName)
		fmt.Printf("Conversation ID: %s\n", convIDHex)
		fmt.Printf("Master Key ID: %s\n", hex.EncodeToString(keys.MasterKID[:]))
		fmt.Println()
		fmt.Println("IMPORTANT: Back up your master key! It cannot be recovered.")
		fmt.Printf("Master private key: %s\n", hex.EncodeToString(keys.MasterPrivate))
		fmt.Println()
		fmt.Println("Share this subscribe command with readers:")
		fmt.Printf("  qntm announce subscribe %s --token %s --name %s\n", convIDHex, inviteTokenHex, channelName)

		return nil
	},
}

var announcePostCmd = &cobra.Command{
	Use:   "post <channel> <message>",
	Short: "Post a message to an announce channel (owner only)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		channelRef := args[0]
		messageText := args[1]

		entry, err := resolveAnnounceChannel(channelRef)
		if err != nil {
			return err
		}
		if !entry.IsOwner {
			return fmt.Errorf("you are not the owner of this announce channel")
		}

		postingPrivBytes, err := hex.DecodeString(entry.PostingPrivate)
		if err != nil {
			return fmt.Errorf("invalid posting private key: %w", err)
		}

		convIDBytes, err := hex.DecodeString(entry.ConvID)
		if err != nil || len(convIDBytes) != 16 {
			return fmt.Errorf("invalid conversation ID")
		}
		var convID types.ConversationID
		copy(convID[:], convIDBytes)

		conversation, err := findConversation(convID)
		if err != nil {
			return fmt.Errorf("conversation not found: %w", err)
		}

		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}

		messageMgr := message.NewManager()
		envelope, err := messageMgr.CreateMessage(
			currentIdentity,
			conversation,
			"text",
			[]byte(messageText),
			nil,
			messageMgr.DefaultTTL(),
		)
		if err != nil {
			return fmt.Errorf("failed to create message: %w", err)
		}

		envelopeData, err := messageMgr.SerializeEnvelope(envelope)
		if err != nil {
			return fmt.Errorf("failed to serialize envelope: %w", err)
		}
		envelopeB64 := base64.StdEncoding.EncodeToString(envelopeData)

		announceMgr := announce.NewManager()
		announceSig := announceMgr.SignEnvelope(postingPrivBytes, envelopeB64)

		storage := getStorageProvider()
		httpStorage, ok := storage.(*dropbox.HTTPStorageProvider)
		if !ok {
			return fmt.Errorf("announce channels require HTTP storage provider")
		}

		seq, err := httpStorage.StoreAnnounceEnvelope(convID, envelopeData, announceSig)
		if err != nil {
			return fmt.Errorf("failed to send announce message: %w", err)
		}

		dc := NewDisplayContext()
		fmt.Printf("Posted to %s (seq %d)\n", dc.FormatConvIDHex(entry.ConvID), seq)
		fmt.Printf("Message ID: %s\n", hex.EncodeToString(envelope.MsgID[:]))
		return nil
	},
}

var announceSubscribeCmd = &cobra.Command{
	Use:   "subscribe <conv-id> --token <invite-token> [--name <name>]",
	Short: "Subscribe to an announce channel",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		convIDHex := args[0]
		token, _ := cmd.Flags().GetString("token")
		name, _ := cmd.Flags().GetString("name")

		if token == "" {
			return fmt.Errorf("--token is required (provided by channel owner)")
		}

		convIDBytes, err := hex.DecodeString(convIDHex)
		if err != nil || len(convIDBytes) != 16 {
			return fmt.Errorf("invalid conversation ID")
		}
		var convID types.ConversationID
		copy(convID[:], convIDBytes)

		inviteSecret, err := hex.DecodeString(token)
		if err != nil || len(inviteSecret) != 32 {
			return fmt.Errorf("invalid invite token")
		}

		convKeys, err := deriveAnnounceKeys(inviteSecret, convID)
		if err != nil {
			return err
		}

		if name == "" {
			name = "announce-" + convIDHex[:8]
		}

		conversation := &types.Conversation{
			ID:           convID,
			Name:         name,
			Type:         types.ConversationTypeAnnounce,
			Keys:         convKeys,
			CreatedAt:    time.Now(),
			CurrentEpoch: 0,
		}

		if err := saveConversation(conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}

		store := loadAnnounceStore()
		store.Channels[convIDHex] = &announceChannelEntry{
			Name:    name,
			ConvID:  convIDHex,
			IsOwner: false,
		}
		if err := saveAnnounceStore(store); err != nil {
			return fmt.Errorf("failed to save announce store: %w", err)
		}

		fmt.Printf("Subscribed to announce channel: %s\n", name)
		fmt.Printf("Conversation ID: %s\n", convIDHex)
		fmt.Println("Use 'qntm message receive' to read announcements.")
		return nil
	},
}

var announceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List announce channels",
	RunE: func(cmd *cobra.Command, args []string) error {
		store := loadAnnounceStore()
		if len(store.Channels) == 0 {
			fmt.Println("No announce channels found")
			return nil
		}

		dc := NewDisplayContext()
		fmt.Printf("Announce channels (%d):\n", len(store.Channels))
		for _, entry := range store.Channels {
			role := "subscriber"
			if entry.IsOwner {
				role = "owner"
			}
			fmt.Printf("  %s  %s  (%s)\n", dc.FormatConvIDHex(entry.ConvID), entry.Name, role)
		}
		return nil
	},
}

var announceDeleteCmd = &cobra.Command{
	Use:   "delete <channel>",
	Short: "Delete an announce channel (owner only, requires master key)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		channelRef := args[0]

		entry, err := resolveAnnounceChannel(channelRef)
		if err != nil {
			return err
		}
		if !entry.IsOwner {
			return fmt.Errorf("you are not the owner of this announce channel")
		}
		if entry.MasterPrivate == "" {
			return fmt.Errorf("master key not available (was it backed up?)")
		}

		masterPrivBytes, err := hex.DecodeString(entry.MasterPrivate)
		if err != nil {
			return fmt.Errorf("invalid master private key: %w", err)
		}
		masterPKBytes, err := hex.DecodeString(entry.MasterPublic)
		if err != nil {
			return fmt.Errorf("invalid master public key: %w", err)
		}
		masterPKB64 := base64.RawURLEncoding.EncodeToString(masterPKBytes)

		mgr := announce.NewManager()
		sig, err := mgr.SignDelete(masterPrivBytes, entry.ConvID)
		if err != nil {
			return fmt.Errorf("failed to sign delete: %w", err)
		}

		delReq := announce.DeleteRequest{
			ConvID:   entry.ConvID,
			MasterPK: masterPKB64,
			Sig:      sig,
		}
		delBody, err := json.Marshal(delReq)
		if err != nil {
			return fmt.Errorf("failed to encode delete: %w", err)
		}

		storage := getStorageProvider()
		httpStorage, ok := storage.(*dropbox.HTTPStorageProvider)
		if !ok {
			return fmt.Errorf("announce channels require HTTP storage provider")
		}

		if err := httpStorage.AnnounceDelete(json.RawMessage(delBody)); err != nil {
			return fmt.Errorf("failed to delete announce channel: %w", err)
		}

		store := loadAnnounceStore()
		delete(store.Channels, entry.ConvID)
		if err := saveAnnounceStore(store); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to update local store: %v\n", err)
		}

		fmt.Printf("Deleted announce channel: %s\n", entry.Name)
		return nil
	},
}
