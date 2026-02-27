package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/group"
	"github.com/corpo/qntm/handle"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

var (
	configDir    string
	identityFile string
	storageDir   string
	dropboxURL   string
	unsafeMode   bool
	verboseMode  bool
	humanMode    bool
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
	rootCmd.PersistentFlags().StringVar(&storageDir, "storage", "", "Storage directory for local provider (e.g. local:/path)")
	rootCmd.PersistentFlags().StringVar(&dropboxURL, "dropbox-url", "", "HTTP drop box endpoint (default: https://inbox.qntm.corpo.llc)")
	rootCmd.PersistentFlags().BoolVar(&unsafeMode, "unsafe", false, "Enable unsafe development features")
	rootCmd.PersistentFlags().BoolVar(&verboseMode, "verbose", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&humanMode, "human", false, "Use human-readable output and interactive UX")

	// Identity commands
	rootCmd.AddCommand(identityCmd)
	identityCmd.AddCommand(identityGenerateCmd)
	identityCmd.AddCommand(identityShowCmd)
	// identity import/export tracked by qntm-ty5

	// Invite commands
	rootCmd.AddCommand(inviteCmd)
	inviteCmd.AddCommand(inviteCreateCmd)
	inviteCmd.AddCommand(inviteAcceptCmd)
	inviteAcceptCmd.Flags().String("name", "", "Name for this conversation")
	inviteCmd.AddCommand(inviteListCmd)

	// Top-level accept alias: "qntm accept <token>" → "qntm invite accept <token>"
	acceptCmd.Flags().String("name", "", "Name for this conversation")
	rootCmd.AddCommand(acceptCmd)

	// Message commands
	rootCmd.AddCommand(messageCmd)
	messageCmd.AddCommand(messageSendCmd)
	messageCmd.AddCommand(messageReceiveCmd)
	messageCmd.AddCommand(messageListCmd)
	messageCmd.AddCommand(messageHistoryCmd)
	messageCmd.Flags().BoolP("all", "a", false, "Receive messages across all inboxes")
	messageCmd.Flags().BoolP("list", "l", false, "List message inbox stats across all conversations")

	// Group commands
	rootCmd.AddCommand(groupCmd)
	groupCmd.AddCommand(groupCreateCmd)
	groupCmd.AddCommand(groupJoinCmd)
	groupCmd.AddCommand(groupAddCmd)
	groupCmd.AddCommand(groupRemoveCmd)
	groupCmd.AddCommand(groupRekeyCmd)
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

		keyID := identityMgr.KeyIDToString(newIdentity.KeyID)
		publicKey := identityMgr.PublicKeyToString(newIdentity.PublicKey)

		if humanMode {
			fmt.Printf("Generated new identity:\n")
			fmt.Printf("Key ID: %s\n", keyID)
			fmt.Printf("Public Key: %s\n", publicKey)
			fmt.Printf("Saved to: %s\n", getIdentityPath())
			return nil
		}

		return emitJSONSuccess("identity.generate", map[string]interface{}{
			"key_id":       keyID,
			"public_key":   publicKey,
			"identity":     getIdentityPath(),
			"spec_version": "QSP-v1.1",
		})
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
		dc := NewDisplayContext()
		kidHex := hex.EncodeToString(currentIdentity.KeyID[:])
		displayKID := dc.FormatKIDHex(kidHex, "")
		publicKey := identityMgr.PublicKeyToString(currentIdentity.PublicKey)

		if humanMode {
			fmt.Printf("Current identity:\n")
			fmt.Printf("Key ID: %s\n", displayKID)
			fmt.Printf("Public Key: %s\n", publicKey)
			return nil
		}

		return emitJSONSuccess("identity.show", map[string]interface{}{
			"key_id":     displayKID,
			"public_key": publicKey,
		})
	},
}

// Invite Commands
var inviteCmd = &cobra.Command{
	Use:   "invite [name]",
	Short: "Manage conversation invites",
	Long:  "Create, accept, and manage conversation invites.\n\nIf a name is given as a positional argument, creates an invite with that name.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 {
			// Route "qntm invite <name>" to "qntm invite create --name <name>"
			inviteCreateCmd.Flags().Set("name", args[0])
			return inviteCreateCmd.RunE(inviteCreateCmd, nil)
		}
		return cmd.Help()
	},
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

		// Encode invite data as base64 token (no URL wrapping — there's no
		// real endpoint yet). Users can construct join URLs once a dropbox is deployed.
		inviteToken, err := inviteMgr.InviteToToken(newInvite)
		if err != nil {
			return fmt.Errorf("failed to encode invite: %w", err)
		}

		fmt.Printf("Created %s invite:\n", convType)
		if name != "" {
			fmt.Printf("Name: %s\n", name)
		}
		fmt.Printf("Conversation ID: %s\n", hex.EncodeToString(newInvite.ConvID[:]))
		fmt.Printf("Invite Token: %s\n", inviteToken)
		fmt.Println()
		fmt.Println("Tell your recipient to run:")
		fmt.Printf("  uvx qntm invite accept %s\n", inviteToken)

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

		// Set conversation name if provided
		name, _ := cmd.Flags().GetString("name")
		if name != "" {
			conversation.Name = name
		}

		// Save conversation
		if err := saveConversation(conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}

		fmt.Printf("Accepted %s invite:\n", conversation.Type)
		fmt.Printf("Conversation ID: %s\n", hex.EncodeToString(conversation.ID[:]))
		if name != "" {
			fmt.Printf("Name: %s\n", name)
		}
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

		dc := NewDisplayContext()
		fmt.Printf("Conversations (%d):\n", len(conversations))
		for _, conv := range conversations {
			fmt.Printf("  %s (%s) - %d participants\n",
				dc.FormatConvID(conv.ID),
				conv.Type,
				len(conv.Participants))
		}

		return nil
	},
}

var acceptCmd = &cobra.Command{
	Use:   "accept <invite-token>",
	Short: "Accept a conversation invite (alias for 'invite accept')",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		if name != "" {
			inviteAcceptCmd.Flags().Set("name", name)
		}
		return inviteAcceptCmd.RunE(inviteAcceptCmd, args)
	},
}

// Message Commands
var messageCmd = &cobra.Command{
	Use:     "message [conversation]",
	Aliases: []string{"messages"},
	Short:   "Send and receive messages",
	Long:    "Send and receive encrypted messages in conversations.",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		all, _ := cmd.Flags().GetBool("all")
		list, _ := cmd.Flags().GetBool("list")

		if all && list {
			return fmt.Errorf("cannot use --all and --list together")
		}

		if list {
			return messageListCmd.RunE(messageListCmd, args)
		}

		if all {
			if len(args) > 0 {
				return fmt.Errorf("--all does not accept a conversation argument")
			}
			return messageReceiveCmd.RunE(messageReceiveCmd, nil)
		}

		if len(args) == 1 {
			return messageReceiveCmd.RunE(messageReceiveCmd, args)
		}

		return cmd.Help()
	},
}

var messageSendCmd = &cobra.Command{
	Use:   "send <conversation> <message>",
	Short: "Send a message to a conversation (accepts name, short ref, or hex ID)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}

		convIDHex, err := resolveConvID(args[0])
		if err != nil {
			return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
		}
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

		dc := NewDisplayContext()
		fmt.Printf("Message sent to %s\n", dc.FormatConvIDHex(convIDHex))
		fmt.Printf("Message ID: %s\n", hex.EncodeToString(envelope.MsgID[:]))

		// Persist outgoing chat history locally (encrypted at rest).
		body, encoding := encodeChatBody([]byte(messageText))
		if err := appendChatArchiveEntry(conversation, chatArchiveEntry{
			MessageID:    hex.EncodeToString(envelope.MsgID[:]),
			Direction:    "outgoing",
			SenderKIDHex: hex.EncodeToString(currentIdentity.KeyID[:]),
			BodyType:     "text",
			Body:         body,
			BodyEncoding: encoding,
			CreatedTS:    envelope.CreatedTS,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to store outgoing chat history: %v\n", err)
		}

		return nil
	},
}

var messageReceiveCmd = &cobra.Command{
	Use:   "receive [conversation]",
	Short: "Receive messages (accepts name, short ref, or hex ID)",
	RunE: func(cmd *cobra.Command, args []string) error {
		conversations, err := loadConversations()
		if err != nil {
			return fmt.Errorf("failed to load conversations: %w", err)
		}

		// Filter to specific conversation if provided
		if len(args) > 0 {
			convIDHex, err := resolveConvID(args[0])
			if err != nil {
				return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
			}
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
		dc := NewDisplayContext()
		groupMgr := group.NewManager()
		receiverIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}
		handleStore := dc.Handles
		if handleStore == nil {
			handleStore, _ = handle.NewStore(configDir)
			dc.Handles = handleStore
		}

		totalMessages := 0
		allSeenMessages := loadSeenMessages()

		for _, conversation := range conversations {
			convIDHex := hex.EncodeToString(conversation.ID[:])
			var groupState *group.GroupState
			groupStateLoaded := false
			groupStateDirty := false

			// Get seen messages for this conversation
			conversationSeenMessages := allSeenMessages[conversation.ID]
			if conversationSeenMessages == nil {
				conversationSeenMessages = make(map[types.MessageID]bool)
				allSeenMessages[conversation.ID] = conversationSeenMessages
			}

			messages, err := dropboxMgr.ReceiveMessages(receiverIdentity, conversation, conversationSeenMessages)
			if err != nil {
				fmt.Printf("Error receiving from %s: %v\n",
					dc.FormatConvIDHex(convIDHex), err)
				continue
			}

			if len(messages) > 0 {
				fmt.Printf("\n%s (%d new messages):\n",
					dc.FormatConvIDHex(convIDHex), len(messages))

				for _, msg := range messages {
					bodyDisplay := string(msg.Inner.Body)
					switch msg.Inner.BodyType {
					case "group_genesis", "group_add", "group_remove":
						if conversation.Type == types.ConversationTypeGroup {
							if !groupStateLoaded {
								loadedState, err := loadGroupState(conversation.ID)
								if err != nil {
									loadedState = &group.GroupState{
										Members: make(map[types.KeyID]*group.GroupMemberInfo),
										Admins:  make(map[types.KeyID]bool),
									}
								}
								groupState = loadedState
								groupStateLoaded = true
							}
							if err := groupMgr.ProcessGroupMessage(msg, groupState); err != nil {
								bodyDisplay = fmt.Sprintf("group update failed: %v", err)
							} else {
								groupStateDirty = true
								switch msg.Inner.BodyType {
								case "group_genesis":
									bodyDisplay = "group state initialized"
								case "group_add":
									bodyDisplay = "group members updated"
								case "group_remove":
									bodyDisplay = "group members removed"
								}
							}
						}
					case "group_rekey":
						if conversation.Type == types.ConversationTypeGroup {
							newGroupKey, newEpoch, err := groupMgr.ProcessRekeyMessage(msg, conversation, receiverIdentity)
							if err != nil {
								bodyDisplay = fmt.Sprintf("group rekey not applied: %v", err)
								break
							}
							if err := groupMgr.ApplyRekey(conversation, newGroupKey, newEpoch); err != nil {
								bodyDisplay = fmt.Sprintf("group rekey apply failed: %v", err)
								break
							}
							if err := saveConversation(conversation); err != nil {
								bodyDisplay = fmt.Sprintf("applied group rekey to epoch %d (save failed: %v)", newEpoch, err)
							} else {
								bodyDisplay = fmt.Sprintf("applied group rekey to epoch %d", newEpoch)
							}
						}
					case "handle_reveal":
						if handleStore != nil {
							var reveal handle.RevealPayload
							if err := cbor.UnmarshalCanonical(msg.Inner.Body, &reveal); err != nil {
								bodyDisplay = fmt.Sprintf("invalid handle reveal payload: %v", err)
								break
							}
							senderKIDHex := hex.EncodeToString(msg.Inner.SenderKID[:])
							expectedCommitmentHex := handleStore.GetCommitment(senderKIDHex)
							if expectedCommitmentHex == "" {
								bodyDisplay = "handle reveal skipped: no cached commitment"
								break
							}
							if err := handle.VerifyReveal(reveal.Handle, msg.Inner.SenderIKPK, reveal.HandleSalt, expectedCommitmentHex); err != nil {
								bodyDisplay = fmt.Sprintf("handle reveal rejected: %v", err)
								break
							}
							if err := handleStore.StoreReveal(convIDHex, senderKIDHex, reveal.Handle); err != nil {
								bodyDisplay = fmt.Sprintf("verified handle @%s (store failed: %v)", reveal.Handle, err)
								break
							}
							bodyDisplay = fmt.Sprintf("verified handle reveal @%s", reveal.Handle)
						}
					}

					senderDisplay := dc.FormatKID(msg.Inner.SenderKID, convIDHex)
					fmt.Printf("  [%s] %s: %s\n",
						senderDisplay,
						msg.Inner.BodyType,
						bodyDisplay)

					bodyEncoded, bodyEncoding := encodeChatBody(msg.Inner.Body)
					if err := appendChatArchiveEntry(conversation, chatArchiveEntry{
						MessageID:    hex.EncodeToString(msg.Envelope.MsgID[:]),
						Direction:    "incoming",
						SenderKIDHex: hex.EncodeToString(msg.Inner.SenderKID[:]),
						BodyType:     msg.Inner.BodyType,
						Body:         bodyEncoded,
						BodyEncoding: bodyEncoding,
						CreatedTS:    msg.Envelope.CreatedTS,
					}); err != nil {
						fmt.Fprintf(os.Stderr, "warning: failed to store incoming chat history: %v\n", err)
					}
				}

				if groupStateDirty {
					if err := saveGroupState(conversation.ID, groupState); err != nil {
						fmt.Printf("  Warning: failed to save group state for %s: %v\n",
							dc.FormatConvIDHex(convIDHex), err)
					}
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
	Use:   "list [conversation]",
	Short: "List message storage stats (all inboxes by default)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		storage := getStorageProvider()
		dropboxMgr := dropbox.NewManager(storage)
		dc := NewDisplayContext()
		allSeenMessages := loadSeenMessages()

		// Show aggregate inbox stats when no specific conversation is requested.
		if len(args) == 0 {
			conversations, err := loadConversations()
			if err != nil {
				return fmt.Errorf("failed to load conversations: %w", err)
			}

			if len(conversations) == 0 {
				fmt.Println("No conversations found")
				return nil
			}

			totalMessages := 0
			totalExpired := 0
			totalSize := 0
			totalUnread := 0

			fmt.Printf("Inboxes (%d):\n", len(conversations))
			for _, conversation := range conversations {
				convIDHex := hex.EncodeToString(conversation.ID[:])
				stats, err := dropboxMgr.GetStorageStats(conversation.ID)
				if err != nil {
					fmt.Printf("\n%s inbox stats: failed to load (%v)\n",
						dc.FormatConvIDHex(convIDHex), err)
					continue
				}
				unread, err := dropboxMgr.CountUnreadMessages(conversation.ID, allSeenMessages[conversation.ID])
				if err != nil {
					fmt.Printf("  Warning: unread count unavailable (%v)\n", err)
				}

				fmt.Printf("\n%s inbox stats:\n", dc.FormatConvIDHex(convIDHex))
				fmt.Printf("  Type: %s\n", conversation.Type)
				fmt.Printf("  Messages: %d\n", stats.MessageCount)
				fmt.Printf("  Unread: %d\n", unread)
				fmt.Printf("  Expired: %d\n", stats.ExpiredCount)
				fmt.Printf("  Total size: %d bytes\n", stats.TotalSize)

				totalMessages += stats.MessageCount
				totalUnread += unread
				totalExpired += stats.ExpiredCount
				totalSize += stats.TotalSize
			}

			fmt.Printf("\nTotal across inboxes:\n")
			fmt.Printf("  Messages: %d\n", totalMessages)
			fmt.Printf("  Unread: %d\n", totalUnread)
			fmt.Printf("  Expired: %d\n", totalExpired)
			fmt.Printf("  Total size: %d bytes\n", totalSize)
			return nil
		}

		convIDHex, err := resolveConvID(args[0])
		if err != nil {
			return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
		}
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

		stats, err := dropboxMgr.GetStorageStats(convID)
		if err != nil {
			return fmt.Errorf("failed to get storage stats: %w", err)
		}
		unread, err := dropboxMgr.CountUnreadMessages(convID, allSeenMessages[convID])
		if err != nil {
			return fmt.Errorf("failed to get unread count: %w", err)
		}

		fmt.Printf("%s storage stats:\n", dc.FormatConvIDHex(convIDHex))
		fmt.Printf("  Type: %s\n", conversation.Type)
		fmt.Printf("  Messages: %d\n", stats.MessageCount)
		fmt.Printf("  Unread: %d\n", unread)
		fmt.Printf("  Expired: %d\n", stats.ExpiredCount)
		fmt.Printf("  Total size: %d bytes\n", stats.TotalSize)

		return nil
	},
}

var messageHistoryCmd = &cobra.Command{
	Use:   "history [conversation]",
	Short: "Show local encrypted chat history (all conversations by default)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")

		conversations, err := loadConversations()
		if err != nil {
			return fmt.Errorf("failed to load conversations: %w", err)
		}

		if len(conversations) == 0 {
			fmt.Println("No conversations found")
			return nil
		}

		if len(args) == 1 {
			convIDHex, err := resolveConvID(args[0])
			if err != nil {
				return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
			}
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

		dc := NewDisplayContext()
		totalPrinted := 0

		for _, conversation := range conversations {
			entries, err := loadChatArchive(conversation)
			convIDHex := hex.EncodeToString(conversation.ID[:])
			if err != nil {
				fmt.Printf("\n%s history: failed to load (%v)\n", dc.FormatConvIDHex(convIDHex), err)
				continue
			}
			if len(entries) == 0 {
				continue
			}

			start := 0
			if limit > 0 && len(entries) > limit {
				start = len(entries) - limit
			}

			fmt.Printf("\n%s history (%d):\n", dc.FormatConvIDHex(convIDHex), len(entries))
			for _, entry := range entries[start:] {
				ts := time.Unix(entry.CreatedTS, 0).UTC().Format(time.RFC3339)
				fmt.Printf("  [%s] %s %s: %s\n",
					ts,
					entry.Direction,
					entry.BodyType,
					decodeChatBody(entry),
				)
				totalPrinted++
			}
		}

		if totalPrinted == 0 {
			fmt.Println("No local chat history yet")
		}

		return nil
	},
}

func init() {
	messageHistoryCmd.Flags().IntP("limit", "n", 50, "Maximum entries to show per conversation (0 = all)")
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

		dc := NewDisplayContext()
		fmt.Printf("Created group '%s':\n", groupName)
		fmt.Printf("Conversation ID: %s\n", dc.FormatConvID(conversation.ID))
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
	Use:   "add <conversation> <public-key>",
	Short: "Add member to group (accepts name, short ref, or hex ID for conversation)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}

		convIDHex, err := resolveConvID(args[0])
		if err != nil {
			return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
		}
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

		// Add member with rekey
		err = groupMgr.AddMembersWithRekey(
			currentIdentity,
			conversation,
			groupState,
			[]ed25519.PublicKey{newMemberPubkey},
			storage,
		)
		if err != nil {
			return fmt.Errorf("failed to add member: %w", err)
		}

		// Save updated state
		if err := saveConversation(conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}
		if err := saveGroupState(convID, groupState); err != nil {
			return fmt.Errorf("failed to save group state: %w", err)
		}

		dc := NewDisplayContext()
		fmt.Printf("Added member to %s\n", dc.FormatConvIDHex(convIDHex))
		fmt.Printf("Group rekeyed to epoch %d\n", conversation.CurrentEpoch)

		return nil
	},
}

var groupRemoveCmd = &cobra.Command{
	Use:   "remove <conversation> <key-id>",
	Short: "Remove member from group (accepts name, short ref, or hex ID)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}

		convIDHex, err := resolveConvID(args[0])
		if err != nil {
			return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
		}
		kidHex, err := resolveKID(args[1])
		if err != nil {
			return fmt.Errorf("could not resolve member %q: %w", args[1], err)
		}

		// Parse conversation ID
		convIDBytes, err := hex.DecodeString(convIDHex)
		if err != nil || len(convIDBytes) != 16 {
			return fmt.Errorf("invalid conversation ID format")
		}

		var convID types.ConversationID
		copy(convID[:], convIDBytes)

		// Parse key ID from resolved hex
		kidBytes, err := hex.DecodeString(kidHex)
		if err != nil || len(kidBytes) != 16 {
			return fmt.Errorf("invalid key ID format")
		}
		var memberKID types.KeyID
		copy(memberKID[:], kidBytes)

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

		// Remove with rekey
		err = groupMgr.RemoveMembersWithRekey(
			currentIdentity,
			conversation,
			groupState,
			[]types.KeyID{memberKID},
			"removed by admin",
			storage,
		)
		if err != nil {
			return fmt.Errorf("failed to remove member: %w", err)
		}

		// Save updated state
		if err := saveConversation(conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}
		if err := saveGroupState(convID, groupState); err != nil {
			return fmt.Errorf("failed to save group state: %w", err)
		}

		dc := NewDisplayContext()
		fmt.Printf("Removed %s from %s\n", dc.FormatKIDHex(kidHex, convIDHex), dc.FormatConvIDHex(convIDHex))
		fmt.Printf("Group rekeyed to epoch %d\n", conversation.CurrentEpoch)

		return nil
	},
}

var groupRekeyCmd = &cobra.Command{
	Use:   "rekey <conversation>",
	Short: "Manually trigger a group rekey (accepts name, short ref, or hex ID)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}

		convIDHex, err := resolveConvID(args[0])
		if err != nil {
			return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
		}

		// Parse conversation ID
		convIDBytes, err := hex.DecodeString(convIDHex)
		if err != nil || len(convIDBytes) != 16 {
			return fmt.Errorf("invalid conversation ID format")
		}

		var convID types.ConversationID
		copy(convID[:], convIDBytes)

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

		// Build full member list
		var allMembers []group.RekeyMemberInfo
		for kid, member := range groupState.Members {
			allMembers = append(allMembers, group.RekeyMemberInfo{
				KeyID:     kid,
				PublicKey: member.PublicKey,
			})
			_ = kid
		}

		// Create rekey
		_, newGroupKey, err := groupMgr.CreateRekey(
			currentIdentity,
			conversation,
			groupState,
			allMembers,
			storage,
		)
		if err != nil {
			return fmt.Errorf("failed to create rekey: %w", err)
		}

		// Apply locally
		if err := groupMgr.ApplyRekey(conversation, newGroupKey, conversation.CurrentEpoch+1); err != nil {
			return fmt.Errorf("failed to apply rekey: %w", err)
		}

		// Save updated state
		if err := saveConversation(conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}

		dc := NewDisplayContext()
		fmt.Printf("%s rekeyed to epoch %d\n", dc.FormatConvIDHex(convIDHex), conversation.CurrentEpoch)

		return nil
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

		dc := NewDisplayContext()
		fmt.Printf("Group conversations (%d):\n", len(groupConversations))
		for _, conv := range groupConversations {
			groupState, err := loadGroupState(conv.ID)
			if err != nil {
				fmt.Printf("  %s (failed to load group state)\n",
					dc.FormatConvID(conv.ID))
				continue
			}

			convIDHex := hex.EncodeToString(conv.ID[:])
			fmt.Printf("  %s: %s (%d members)\n",
				dc.FormatConvIDHex(convIDHex),
				groupState.GroupName,
				len(groupState.Members))

			// Show members with names
			if verboseMode {
				for kid := range groupState.Members {
					fmt.Printf("    - %s\n", dc.FormatKID(kid, convIDHex))
				}
			}
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
