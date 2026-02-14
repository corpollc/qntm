package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/group"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
)

var (
	configDir      string
	identityFile   string
	storageDir     string
	unsafeMode     bool
	verboseMode    bool
)

func init() {
	// Get user home directory for default config
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	
	defaultConfigDir := filepath.Join(homeDir, ".qntm")
	
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", defaultConfigDir, "Configuration directory")
	rootCmd.PersistentFlags().StringVar(&identityFile, "identity", "", "Identity file path (default: config-dir/identity.json)")
	rootCmd.PersistentFlags().StringVar(&storageDir, "storage", "", "Storage directory (default: config-dir/storage)")
	rootCmd.PersistentFlags().BoolVar(&unsafeMode, "unsafe", false, "Enable unsafe development features")
	rootCmd.PersistentFlags().BoolVar(&verboseMode, "verbose", false, "Enable verbose output")
	
	// Identity commands
	rootCmd.AddCommand(identityCmd)
	identityCmd.AddCommand(identityGenerateCmd)
	identityCmd.AddCommand(identityShowCmd)
	identityCmd.AddCommand(identityImportCmd)
	identityCmd.AddCommand(identityExportCmd)
	
	// Invite commands
	rootCmd.AddCommand(inviteCmd)
	inviteCmd.AddCommand(inviteCreateCmd)
	inviteCmd.AddCommand(inviteAcceptCmd)
	inviteCmd.AddCommand(inviteListCmd)
	
	// Message commands
	rootCmd.AddCommand(messageCmd)
	messageCmd.AddCommand(messageSendCmd)
	messageCmd.AddCommand(messageReceiveCmd)
	messageCmd.AddCommand(messageListCmd)
	
	// Group commands
	rootCmd.AddCommand(groupCmd)
	groupCmd.AddCommand(groupCreateCmd)
	groupCmd.AddCommand(groupJoinCmd)
	groupCmd.AddCommand(groupAddCmd)
	groupCmd.AddCommand(groupRemoveCmd)
	groupCmd.AddCommand(groupListCmd)
	
	// Unsafe development commands
	rootCmd.AddCommand(unsafeCmd)
	unsafeCmd.AddCommand(unsafePresetCmd)
	unsafeCmd.AddCommand(unsafeTestCmd)
}

// Identity Commands
var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage identity keys",
	Long:  "Generate, import, export, and manage qntm identity keys.",
}

var identityGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		ensureConfigDir()
		
		identityMgr := identity.NewManager()
		newIdentity, err := identityMgr.GenerateIdentity()
		if err != nil {
			return fmt.Errorf("failed to generate identity: %w", err)
		}
		
		// Save identity
		if err := saveIdentity(newIdentity); err != nil {
			return fmt.Errorf("failed to save identity: %w", err)
		}
		
		fmt.Printf("Generated new identity:\n")
		fmt.Printf("Key ID: %s\n", identityMgr.KeyIDToString(newIdentity.KeyID))
		fmt.Printf("Public Key: %s\n", identityMgr.PublicKeyToString(newIdentity.PublicKey))
		fmt.Printf("Saved to: %s\n", getIdentityPath())
		
		return nil
	},
}

var identityShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}
		
		identityMgr := identity.NewManager()
		fmt.Printf("Current identity:\n")
		fmt.Printf("Key ID: %s\n", identityMgr.KeyIDToString(currentIdentity.KeyID))
		fmt.Printf("Public Key: %s\n", identityMgr.PublicKeyToString(currentIdentity.PublicKey))
		
		return nil
	},
}

var identityImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import identity from file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Implementation would import from file
		return fmt.Errorf("import not implemented yet")
	},
}

var identityExportCmd = &cobra.Command{
	Use:   "export <file>",
	Short: "Export identity to file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Implementation would export to file
		return fmt.Errorf("export not implemented yet")
	},
}

// Invite Commands
var inviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Manage conversation invites",
	Long:  "Create, accept, and manage conversation invites.",
}

var inviteCreateCmd = &cobra.Command{
	Use:   "create [--group] [--name <name>]",
	Short: "Create a new conversation invite",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}
		
		isGroup, _ := cmd.Flags().GetBool("group")
		name, _ := cmd.Flags().GetString("name")
		
		convType := types.ConversationTypeDirect
		if isGroup {
			convType = types.ConversationTypeGroup
		}
		
		inviteMgr := invite.NewManager()
		newInvite, err := inviteMgr.CreateInvite(currentIdentity, convType)
		if err != nil {
			return fmt.Errorf("failed to create invite: %w", err)
		}
		
		// Generate invite URL (using placeholder base URL)
		baseURL := "https://qntm.example.com/join"
		inviteURL, err := inviteMgr.InviteToURL(newInvite, baseURL)
		if err != nil {
			return fmt.Errorf("failed to generate invite URL: %w", err)
		}
		
		fmt.Printf("Created %s invite:\n", convType)
		if name != "" {
			fmt.Printf("Name: %s\n", name)
		}
		fmt.Printf("Conversation ID: %s\n", hex.EncodeToString(newInvite.ConvID[:]))
		fmt.Printf("Invite URL: %s\n", inviteURL)
		
		return nil
	},
}

func init() {
	inviteCreateCmd.Flags().Bool("group", false, "Create group invite")
	inviteCreateCmd.Flags().String("name", "", "Conversation name")
}

var inviteAcceptCmd = &cobra.Command{
	Use:   "accept <invite-url>",
	Short: "Accept a conversation invite",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}
		
		inviteURL := args[0]
		
		inviteMgr := invite.NewManager()
		receivedInvite, err := inviteMgr.InviteFromURL(inviteURL)
		if err != nil {
			return fmt.Errorf("failed to parse invite: %w", err)
		}
		
		// Derive keys and create conversation
		keys, err := inviteMgr.DeriveConversationKeys(receivedInvite)
		if err != nil {
			return fmt.Errorf("failed to derive keys: %w", err)
		}
		
		conversation, err := inviteMgr.CreateConversation(receivedInvite, keys)
		if err != nil {
			return fmt.Errorf("failed to create conversation: %w", err)
		}
		
		// Add ourselves to the conversation
		inviteMgr.AddParticipant(conversation, currentIdentity.PublicKey)
		
		// Save conversation
		if err := saveConversation(conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}
		
		fmt.Printf("Accepted %s invite:\n", conversation.Type)
		fmt.Printf("Conversation ID: %s\n", hex.EncodeToString(conversation.ID[:]))
		fmt.Printf("Participants: %d\n", len(conversation.Participants))
		
		return nil
	},
}

var inviteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List accepted invites/conversations",
	RunE: func(cmd *cobra.Command, args []string) error {
		conversations, err := loadConversations()
		if err != nil {
			return fmt.Errorf("failed to load conversations: %w", err)
		}
		
		if len(conversations) == 0 {
			fmt.Println("No conversations found")
			return nil
		}
		
		fmt.Printf("Conversations (%d):\n", len(conversations))
		for _, conv := range conversations {
			fmt.Printf("  %s (%s) - %d participants\n", 
				hex.EncodeToString(conv.ID[:]), 
				conv.Type, 
				len(conv.Participants))
		}
		
		return nil
	},
}

// Message Commands
var messageCmd = &cobra.Command{
	Use:   "message",
	Short: "Send and receive messages",
	Long:  "Send and receive encrypted messages in conversations.",
}

var messageSendCmd = &cobra.Command{
	Use:   "send <conversation-id> <message>",
	Short: "Send a message to a conversation",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}
		
		convIDHex := args[0]
		messageText := args[1]
		
		// Parse conversation ID
		convIDBytes, err := hex.DecodeString(convIDHex)
		if err != nil || len(convIDBytes) != 16 {
			return fmt.Errorf("invalid conversation ID format")
		}
		
		var convID types.ConversationID
		copy(convID[:], convIDBytes)
		
		// Find conversation
		conversation, err := findConversation(convID)
		if err != nil {
			return fmt.Errorf("conversation not found: %w", err)
		}
		
		// Create message
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
		
		// Send via storage
		storage := getStorageProvider()
		dropboxMgr := dropbox.NewManager(storage)
		if err := dropboxMgr.SendMessage(envelope); err != nil {
			return fmt.Errorf("failed to send message: %w", err)
		}
		
		fmt.Printf("Message sent to conversation %s\n", convIDHex)
		fmt.Printf("Message ID: %s\n", hex.EncodeToString(envelope.MsgID[:]))
		
		return nil
	},
}

var messageReceiveCmd = &cobra.Command{
	Use:   "receive [conversation-id]",
	Short: "Receive messages from conversations",
	RunE: func(cmd *cobra.Command, args []string) error {
		conversations, err := loadConversations()
		if err != nil {
			return fmt.Errorf("failed to load conversations: %w", err)
		}
		
		// Filter to specific conversation if provided
		if len(args) > 0 {
			convIDHex := args[0]
			convIDBytes, err := hex.DecodeString(convIDHex)
			if err != nil || len(convIDBytes) != 16 {
				return fmt.Errorf("invalid conversation ID format")
			}
			
			var convID types.ConversationID
			copy(convID[:], convIDBytes)
			
			conversation, err := findConversation(convID)
			if err != nil {
				return fmt.Errorf("conversation not found: %w", err)
			}
			
			conversations = []*types.Conversation{conversation}
		}
		
		storage := getStorageProvider()
		dropboxMgr := dropbox.NewManager(storage)
		
		totalMessages := 0
		allSeenMessages := loadSeenMessages()
		
		for _, conversation := range conversations {
			// Get seen messages for this conversation
			conversationSeenMessages := allSeenMessages[conversation.ID]
			if conversationSeenMessages == nil {
				conversationSeenMessages = make(map[types.MessageID]bool)
				allSeenMessages[conversation.ID] = conversationSeenMessages
			}
			
			messages, err := dropboxMgr.ReceiveMessages(conversation, conversationSeenMessages)
			if err != nil {
				fmt.Printf("Error receiving from conversation %s: %v\n", 
					hex.EncodeToString(conversation.ID[:]), err)
				continue
			}
			
			if len(messages) > 0 {
				fmt.Printf("\nConversation %s (%d new messages):\n", 
					hex.EncodeToString(conversation.ID[:]), len(messages))
				
				for _, msg := range messages {
					fmt.Printf("  [%s] %s: %s\n",
						hex.EncodeToString(msg.Inner.SenderKID[:8]), // First 8 bytes of sender
						msg.Inner.BodyType,
						string(msg.Inner.Body))
				}
			}
			
			totalMessages += len(messages)
		}
		
		if totalMessages == 0 {
			fmt.Println("No new messages")
		} else {
			fmt.Printf("\nReceived %d total messages\n", totalMessages)
		}
		
		// Save updated seen messages
		saveSeenMessages(allSeenMessages)
		
		return nil
	},
}

var messageListCmd = &cobra.Command{
	Use:   "list <conversation-id>",
	Short: "List messages in storage",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		convIDHex := args[0]
		convIDBytes, err := hex.DecodeString(convIDHex)
		if err != nil || len(convIDBytes) != 16 {
			return fmt.Errorf("invalid conversation ID format")
		}
		
		var convID types.ConversationID
		copy(convID[:], convIDBytes)
		
		storage := getStorageProvider()
		dropboxMgr := dropbox.NewManager(storage)
		
		stats, err := dropboxMgr.GetStorageStats(convID)
		if err != nil {
			return fmt.Errorf("failed to get storage stats: %w", err)
		}
		
		fmt.Printf("Conversation %s storage stats:\n", convIDHex)
		fmt.Printf("  Messages: %d\n", stats.MessageCount)
		fmt.Printf("  Expired: %d\n", stats.ExpiredCount)
		fmt.Printf("  Total size: %d bytes\n", stats.TotalSize)
		
		return nil
	},
}

// Group Commands
var groupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage group conversations",
	Long:  "Create and manage group conversations with multiple participants.",
}

var groupCreateCmd = &cobra.Command{
	Use:   "create <name> [description]",
	Short: "Create a new group",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}
		
		groupName := args[0]
		description := ""
		if len(args) > 1 {
			description = args[1]
		}
		
		storage := getStorageProvider()
		groupMgr := group.NewManager()
		
		// Create group with no founding members initially
		conversation, groupState, err := groupMgr.CreateGroup(
			currentIdentity,
			groupName,
			description,
			nil, // No founding members
			storage,
		)
		if err != nil {
			return fmt.Errorf("failed to create group: %w", err)
		}
		
		// Save conversation and group state
		if err := saveConversation(conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}
		
		if err := saveGroupState(conversation.ID, groupState); err != nil {
			return fmt.Errorf("failed to save group state: %w", err)
		}
		
		fmt.Printf("Created group '%s':\n", groupName)
		fmt.Printf("Conversation ID: %s\n", hex.EncodeToString(conversation.ID[:]))
		fmt.Printf("Members: %d\n", groupMgr.GetMemberCount(groupState))
		
		return nil
	},
}

var groupJoinCmd = &cobra.Command{
	Use:   "join <invite-url>",
	Short: "Join a group via invite",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// This is similar to invite accept but specifically for groups
		return inviteAcceptCmd.RunE(cmd, args)
	},
}

var groupAddCmd = &cobra.Command{
	Use:   "add <conversation-id> <public-key>",
	Short: "Add member to group",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}
		
		convIDHex := args[0]
		pubkeyStr := args[1]
		
		// Parse conversation ID
		convIDBytes, err := hex.DecodeString(convIDHex)
		if err != nil || len(convIDBytes) != 16 {
			return fmt.Errorf("invalid conversation ID format")
		}
		
		var convID types.ConversationID
		copy(convID[:], convIDBytes)
		
		// Parse public key
		identityMgr := identity.NewManager()
		newMemberPubkey, err := identityMgr.PublicKeyFromString(pubkeyStr)
		if err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
		
		// Find conversation and group state
		conversation, err := findConversation(convID)
		if err != nil {
			return fmt.Errorf("conversation not found: %w", err)
		}
		
		groupState, err := loadGroupState(convID)
		if err != nil {
			return fmt.Errorf("failed to load group state: %w", err)
		}
		
		storage := getStorageProvider()
		groupMgr := group.NewManager()
		
		// Add member
		err = groupMgr.AddMembers(
			currentIdentity,
			conversation,
			groupState,
			[]ed25519.PublicKey{newMemberPubkey},
			storage,
		)
		if err != nil {
			return fmt.Errorf("failed to add member: %w", err)
		}
		
		// Save updated group state
		if err := saveGroupState(convID, groupState); err != nil {
			return fmt.Errorf("failed to save group state: %w", err)
		}
		
		fmt.Printf("Added member to group %s\n", convIDHex)
		
		return nil
	},
}

var groupRemoveCmd = &cobra.Command{
	Use:   "remove <conversation-id> <key-id>",
	Short: "Remove member from group",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Implementation similar to group add
		return fmt.Errorf("group remove not implemented yet")
	},
}

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List group conversations",
	RunE: func(cmd *cobra.Command, args []string) error {
		conversations, err := loadConversations()
		if err != nil {
			return fmt.Errorf("failed to load conversations: %w", err)
		}
		
		groupConversations := make([]*types.Conversation, 0)
		for _, conv := range conversations {
			if conv.Type == types.ConversationTypeGroup {
				groupConversations = append(groupConversations, conv)
			}
		}
		
		if len(groupConversations) == 0 {
			fmt.Println("No group conversations found")
			return nil
		}
		
		fmt.Printf("Group conversations (%d):\n", len(groupConversations))
		for _, conv := range groupConversations {
			groupState, err := loadGroupState(conv.ID)
			if err != nil {
				fmt.Printf("  %s (failed to load group state)\n", 
					hex.EncodeToString(conv.ID[:]))
				continue
			}
			
			fmt.Printf("  %s: %s (%d members)\n", 
				hex.EncodeToString(conv.ID[:]), 
				groupState.GroupName,
				len(groupState.Members))
		}
		
		return nil
	},
}

// Unsafe Development Commands
var unsafeCmd = &cobra.Command{
	Use:   "unsafe",
	Short: "Unsafe development and testing commands",
	Long:  "Commands for development and testing. Use with caution!",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if !unsafeMode {
			return fmt.Errorf("unsafe commands require --unsafe flag")
		}
		return nil
	},
}

var unsafePresetCmd = &cobra.Command{
	Use:   "preset <name>",
	Short: "Apply unsafe development presets",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		presetName := args[0]
		
		switch presetName {
		case "unsafe_test_alice":
			return createTestIdentity("Alice")
		case "unsafe_test_bob":
			return createTestIdentity("Bob")
		case "unsafe_clear_all":
			return clearAllData()
		default:
			return fmt.Errorf("unknown preset: %s", presetName)
		}
	},
}

var unsafeTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Run unsafe development tests",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Running unsafe development tests...")
		
		// Test identity generation
		identityMgr := identity.NewManager()
		testIdentity, err := identityMgr.GenerateIdentity()
		if err != nil {
			return fmt.Errorf("identity test failed: %w", err)
		}
		
		fmt.Printf("✓ Identity generation test passed\n")
		fmt.Printf("  Test Key ID: %s\n", identityMgr.KeyIDToString(testIdentity.KeyID))
		
		// Test invite creation
		inviteMgr := invite.NewManager()
		testInvite, err := inviteMgr.CreateInvite(testIdentity, types.ConversationTypeDirect)
		if err != nil {
			return fmt.Errorf("invite test failed: %w", err)
		}
		
		fmt.Printf("✓ Invite creation test passed\n")
		fmt.Printf("  Test Conversation ID: %s\n", hex.EncodeToString(testInvite.ConvID[:]))
		
		// Test message creation
		keys, err := inviteMgr.DeriveConversationKeys(testInvite)
		if err != nil {
			return fmt.Errorf("key derivation test failed: %w", err)
		}
		
		conversation, err := inviteMgr.CreateConversation(testInvite, keys)
		if err != nil {
			return fmt.Errorf("conversation test failed: %w", err)
		}
		
		messageMgr := message.NewManager()
		testEnvelope, err := messageMgr.CreateMessage(
			testIdentity,
			conversation,
			"text",
			[]byte("Test message"),
			nil,
			3600,
		)
		if err != nil {
			return fmt.Errorf("message test failed: %w", err)
		}
		
		fmt.Printf("✓ Message creation test passed\n")
		fmt.Printf("  Test Message ID: %s\n", hex.EncodeToString(testEnvelope.MsgID[:]))
		
		fmt.Println("All unsafe development tests passed!")
		
		return nil
	},
}