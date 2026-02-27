package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/group"
	"github.com/corpo/qntm/handle"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/naming"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

func init() {
	// Agent-first command tree.
	rootCmd.AddCommand(convoCmd)
	convoCmd.AddCommand(convoCreateCmd)
	convoCmd.AddCommand(convoJoinCmd)
	convoCmd.AddCommand(convoListCmd)
	convoCmd.AddCommand(convoNameCmd)

	rootCmd.AddCommand(inboxCmd)
	rootCmd.AddCommand(sendCmd)
	rootCmd.AddCommand(recvCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(openCmd)

	// Keep legacy commands available but hidden while internal command reorg lands.
	hideLegacyChatCommands()
}

func hideLegacyChatCommands() {
	acceptCmd.Hidden = true
	chatCmd.Hidden = true
	groupCmd.Hidden = true
	handleCmd.Hidden = true
	inviteCmd.Hidden = true
	messageCmd.Hidden = true
	nameCmd.Hidden = true
	refCmd.Hidden = true
}

var convoCmd = &cobra.Command{
	Use:   "convo",
	Short: "Manage conversations",
}

var convoCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a conversation invite token",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}

		isGroup, _ := cmd.Flags().GetBool("group")
		name, _ := cmd.Flags().GetString("name")
		selfJoin, _ := cmd.Flags().GetBool("self-join")

		convType := types.ConversationTypeDirect
		if isGroup {
			convType = types.ConversationTypeGroup
		}

		inviteMgr := invite.NewManager()
		newInvite, err := inviteMgr.CreateInvite(currentIdentity, convType)
		if err != nil {
			return fmt.Errorf("failed to create invite: %w", err)
		}

		inviteToken, err := inviteMgr.InviteToToken(newInvite)
		if err != nil {
			return fmt.Errorf("failed to encode invite: %w", err)
		}

		convIDHex := hex.EncodeToString(newInvite.ConvID[:])
		if selfJoin {
			keys, err := inviteMgr.DeriveConversationKeys(newInvite)
			if err != nil {
				return fmt.Errorf("failed to derive keys for self-join: %w", err)
			}

			conversation, err := inviteMgr.CreateConversation(newInvite, keys)
			if err != nil {
				return fmt.Errorf("failed to create local conversation for self-join: %w", err)
			}
			inviteMgr.AddParticipant(conversation, currentIdentity.PublicKey)
			if name != "" {
				conversation.Name = name
			}
			if err := saveConversation(conversation); err != nil {
				return fmt.Errorf("failed to save self-joined conversation: %w", err)
			}
		}

		if humanMode {
			fmt.Printf("Created %s conversation invite\n", convType)
			fmt.Printf("Conversation ID: %s\n", convIDHex)
			if name != "" {
				fmt.Printf("Name: %s\n", name)
			}
			fmt.Printf("Invite Token: %s\n", inviteToken)
			if selfJoin {
				fmt.Println("Self-joined: yes")
			}
			return nil
		}

		return emitJSONSuccess("convo.create", map[string]interface{}{
			"conversation_id": convIDHex,
			"type":            convType,
			"name":            name,
			"invite_token":    inviteToken,
			"self_joined":     selfJoin,
		})
	},
}

var convoJoinCmd = &cobra.Command{
	Use:   "join <invite-token>",
	Short: "Join a conversation from an invite token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}

		inviteToken := args[0]
		name, _ := cmd.Flags().GetString("name")

		inviteMgr := invite.NewManager()
		receivedInvite, err := inviteMgr.InviteFromURL(inviteToken)
		if err != nil {
			return fmt.Errorf("failed to parse invite: %w", err)
		}

		keys, err := inviteMgr.DeriveConversationKeys(receivedInvite)
		if err != nil {
			return fmt.Errorf("failed to derive keys: %w", err)
		}

		conversation, err := inviteMgr.CreateConversation(receivedInvite, keys)
		if err != nil {
			return fmt.Errorf("failed to create conversation: %w", err)
		}
		inviteMgr.AddParticipant(conversation, currentIdentity.PublicKey)
		if name != "" {
			conversation.Name = name
		}

		if err := saveConversation(conversation); err != nil {
			return fmt.Errorf("failed to save conversation: %w", err)
		}

		convIDHex := hex.EncodeToString(conversation.ID[:])
		if humanMode {
			fmt.Printf("Joined %s conversation\n", conversation.Type)
			fmt.Printf("Conversation ID: %s\n", convIDHex)
			if name != "" {
				fmt.Printf("Name: %s\n", name)
			}
			return nil
		}

		return emitJSONSuccess("convo.join", map[string]interface{}{
			"conversation_id": convIDHex,
			"type":            conversation.Type,
			"name":            name,
			"participants":    len(conversation.Participants),
		})
	},
}

var convoListCmd = &cobra.Command{
	Use:   "list",
	Short: "List conversations",
	RunE: func(cmd *cobra.Command, args []string) error {
		refresh, _ := cmd.Flags().GetBool("refresh")
		if humanMode && !cmd.Flags().Changed("refresh") {
			refresh = true
		}

		summaries, totalUnread, unreadFresh, err := collectConversationSummaries(refresh)
		if err != nil {
			return err
		}

		if humanMode {
			if len(summaries) == 0 {
				fmt.Println("No conversations found")
				return nil
			}
			fmt.Printf("Conversations (%d):\n", len(summaries))
			for _, item := range summaries {
				unreadValue := "?"
				if unreadFresh {
					unreadValue = fmt.Sprintf("%d", item["unread"])
				}
				fmt.Printf("  %s (%s) unread=%s participants=%d\n",
					item["label"],
					item["type"],
					unreadValue,
					item["participants"],
				)
			}
			return nil
		}

		return emitJSONSuccess("convo.list", map[string]interface{}{
			"conversations": summaries,
			"total_unread":  totalUnread,
			"unread_fresh":  unreadFresh,
		})
	},
}

var convoNameCmd = &cobra.Command{
	Use:   "name <conversation> <local-name>",
	Short: "Assign a local conversation name",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		convIDHex, err := resolveConvID(args[0])
		if err != nil {
			return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
		}

		localName := args[1]
		store, err := naming.NewStore(configDir)
		if err != nil {
			return err
		}
		if err := store.SetConversationName(convIDHex, localName); err != nil {
			return err
		}

		if convID, err := parseConversationIDHex(convIDHex); err == nil {
			if conversation, err := findConversation(convID); err == nil {
				conversation.Name = localName
				_ = saveConversation(conversation)
			}
		}

		if humanMode {
			fmt.Printf("Named conversation %s -> %s\n", convIDHex, localName)
			return nil
		}

		return emitJSONSuccess("convo.name", map[string]interface{}{
			"conversation_id": convIDHex,
			"name":            localName,
		})
	},
}

func init() {
	convoCreateCmd.Flags().Bool("group", false, "Create a group conversation invite")
	convoCreateCmd.Flags().String("name", "", "Conversation name")
	convoCreateCmd.Flags().Bool("self-join", true, "Add yourself to the newly created conversation")
	convoJoinCmd.Flags().String("name", "", "Conversation name override")
	convoListCmd.Flags().Bool("refresh", false, "Fetch fresh unread counts from remote storage")
}

var inboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "Show inbox conversation summary",
	RunE: func(cmd *cobra.Command, args []string) error {
		refresh, _ := cmd.Flags().GetBool("refresh")
		if humanMode && !cmd.Flags().Changed("refresh") {
			refresh = true
		}

		summaries, totalUnread, unreadFresh, err := collectConversationSummaries(refresh)
		if err != nil {
			return err
		}

		if humanMode {
			if len(summaries) == 0 {
				fmt.Println("Inbox is empty")
				return nil
			}
			unreadTitle := "unknown"
			if unreadFresh {
				unreadTitle = fmt.Sprintf("%d", totalUnread)
			}
			fmt.Printf("Inbox (%d conversations, %s unread):\n", len(summaries), unreadTitle)
			for _, item := range summaries {
				unreadValue := "?"
				if unreadFresh {
					unreadValue = fmt.Sprintf("%d", item["unread"])
				}
				fmt.Printf("  %s unread=%s\n", item["label"], unreadValue)
			}
			return nil
		}

		return emitJSONSuccess("inbox", map[string]interface{}{
			"conversations": summaries,
			"total_unread":  totalUnread,
			"unread_fresh":  unreadFresh,
		})
	},
}

func init() {
	inboxCmd.Flags().Bool("refresh", false, "Fetch fresh unread counts from remote storage")
}

var sendCmd = &cobra.Command{
	Use:   "send <conversation> <message>",
	Short: "Send a text message",
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

		convID, err := parseConversationIDHex(convIDHex)
		if err != nil {
			return err
		}
		conversation, err := findConversation(convID)
		if err != nil {
			return fmt.Errorf("conversation not found: %w", err)
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

		storage := getStorageProvider()
		dropboxMgr := dropbox.NewManager(storage)
		seq, err := dropboxMgr.SendMessageWithSequence(envelope)
		if err != nil {
			return fmt.Errorf("failed to send message: %w", err)
		}

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

		messageID := hex.EncodeToString(envelope.MsgID[:])
		if humanMode {
			dc := NewDisplayContext()
			fmt.Printf("Message sent to %s\n", dc.FormatConvIDHex(convIDHex))
			fmt.Printf("Message ID: %s\n", messageID)
			return nil
		}

		return emitJSONSuccess("send", map[string]interface{}{
			"conversation_id": convIDHex,
			"message_id":      messageID,
			"sequence":        seq,
			"body_type":       "text",
			"body":            messageText,
			"created_ts":      envelope.CreatedTS,
		})
	},
}

var recvCmd = &cobra.Command{
	Use:   "recv [conversation]",
	Short: "Receive messages",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		conversations, err := loadConversations()
		if err != nil {
			return fmt.Errorf("failed to load conversations: %w", err)
		}

		if len(args) == 1 {
			convIDHex, err := resolveConvID(args[0])
			if err != nil {
				return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
			}
			convID, err := parseConversationIDHex(convIDHex)
			if err != nil {
				return err
			}
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
		sequenceCursors := loadSequenceCursors()
		jsonMessages := make([]map[string]interface{}, 0)

		for _, conversation := range conversations {
			convIDHex := hex.EncodeToString(conversation.ID[:])
			var groupState *group.GroupState
			groupStateLoaded := false
			groupStateDirty := false

			fromSeq := sequenceCursors[conversation.ID]
			messages, upToSeq, err := dropboxMgr.ReceiveMessagesFromSequence(receiverIdentity, conversation, fromSeq, 200)
			if err != nil {
				if humanMode {
					fmt.Printf("Error receiving from %s: %v\n", dc.FormatConvIDHex(convIDHex), err)
					continue
				}
				return fmt.Errorf("receive failed for %s: %w", convIDHex, err)
			}
			sequenceCursors[conversation.ID] = upToSeq

			if humanMode && len(messages) > 0 {
				fmt.Printf("\n%s (%d new messages):\n", dc.FormatConvIDHex(convIDHex), len(messages))
			}

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
				if humanMode {
					ts := time.Unix(msg.Envelope.CreatedTS, 0).Local().Format("15:04")
					fmt.Printf("  [%s] %s: %s\n", ts, senderDisplay, bodyDisplay)
				}

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

				msgRecord := map[string]interface{}{
					"conversation_id": convIDHex,
					"message_id":      hex.EncodeToString(msg.Envelope.MsgID[:]),
					"created_ts":      msg.Envelope.CreatedTS,
					"sender_kid":      hex.EncodeToString(msg.Inner.SenderKID[:]),
					"sender":          senderDisplay,
					"body_type":       msg.Inner.BodyType,
				}
				if bodyEncoding == "utf8" {
					msgRecord["unsafe_body"] = bodyEncoded
				} else {
					msgRecord["unsafe_body_b64"] = bodyEncoded
				}
				jsonMessages = append(jsonMessages, msgRecord)
			}

			if groupStateDirty {
				if err := saveGroupState(conversation.ID, groupState); err != nil && humanMode {
					fmt.Printf("  Warning: failed to save group state for %s: %v\n", dc.FormatConvIDHex(convIDHex), err)
				}
			}

			totalMessages += len(messages)
		}

		if err := saveSequenceCursors(sequenceCursors); err != nil && humanMode {
			fmt.Fprintf(os.Stderr, "warning: failed to persist sequence cursors: %v\n", err)
		}

		if humanMode {
			if totalMessages == 0 {
				fmt.Println("No new messages")
			} else {
				fmt.Printf("\nReceived %d total messages\n", totalMessages)
			}
			return nil
		}

		return emitJSONSuccess("recv", map[string]interface{}{
			"received": totalMessages,
			"messages": jsonMessages,
		})
	},
}

var historyCmd = &cobra.Command{
	Use:   "history [conversation]",
	Short: "Show local message history",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")
		conversations, err := loadConversations()
		if err != nil {
			return fmt.Errorf("failed to load conversations: %w", err)
		}
		if len(conversations) == 0 {
			if humanMode {
				fmt.Println("No conversations found")
				return nil
			}
			return emitJSONSuccess("history", map[string]interface{}{
				"entries": []map[string]interface{}{},
			})
		}

		if len(args) == 1 {
			convIDHex, err := resolveConvID(args[0])
			if err != nil {
				return fmt.Errorf("could not resolve conversation %q: %w", args[0], err)
			}
			convID, err := parseConversationIDHex(convIDHex)
			if err != nil {
				return err
			}
			conversation, err := findConversation(convID)
			if err != nil {
				return fmt.Errorf("conversation not found: %w", err)
			}
			conversations = []*types.Conversation{conversation}
		}

		dc := NewDisplayContext()
		entriesOut := make([]map[string]interface{}, 0)
		totalPrinted := 0

		for _, conversation := range conversations {
			entries, err := loadChatArchive(conversation)
			convIDHex := hex.EncodeToString(conversation.ID[:])
			if err != nil {
				if humanMode {
					fmt.Printf("\n%s history: failed to load (%v)\n", dc.FormatConvIDHex(convIDHex), err)
					continue
				}
				return fmt.Errorf("failed to load history for %s: %w", convIDHex, err)
			}
			if len(entries) == 0 {
				continue
			}

			start := 0
			if limit > 0 && len(entries) > limit {
				start = len(entries) - limit
			}

			if humanMode {
				fmt.Printf("\n%s history (%d):\n", dc.FormatConvIDHex(convIDHex), len(entries))
			}
			for _, entry := range entries[start:] {
				if humanMode {
					ts := time.Unix(entry.CreatedTS, 0).UTC().Format(time.RFC3339)
					fmt.Printf("  [%s] %s %s: %s\n", ts, entry.Direction, entry.BodyType, decodeChatBody(entry))
				}

				item := map[string]interface{}{
					"conversation_id": convIDHex,
					"message_id":      entry.MessageID,
					"direction":       entry.Direction,
					"body_type":       entry.BodyType,
					"created_ts":      entry.CreatedTS,
				}
				if entry.Direction == "incoming" {
					if entry.BodyEncoding == "utf8" {
						item["unsafe_body"] = entry.Body
					} else {
						item["unsafe_body_b64"] = entry.Body
					}
				} else {
					if entry.BodyEncoding == "utf8" {
						item["body"] = entry.Body
					} else {
						item["body_b64"] = entry.Body
					}
				}
				entriesOut = append(entriesOut, item)
				totalPrinted++
			}
		}

		if humanMode {
			if totalPrinted == 0 {
				fmt.Println("No local chat history yet")
			}
			return nil
		}

		return emitJSONSuccess("history", map[string]interface{}{
			"entries": entriesOut,
		})
	},
}

func init() {
	historyCmd.Flags().IntP("limit", "n", 50, "Maximum entries to show per conversation (0 = all)")
}

var openCmd = &cobra.Command{
	Use:   "open <conversation>",
	Short: "Open interactive chat (human mode)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !humanMode {
			return fmt.Errorf("open is human-interactive; use --human open <conversation> or use recv/send for agent mode")
		}

		pollIntervalSec, _ := cmd.Flags().GetInt("poll")
		historyLimit, _ := cmd.Flags().GetInt("history")
		_ = chatCmd.Flags().Set("poll", strconv.Itoa(pollIntervalSec))
		_ = chatCmd.Flags().Set("history", strconv.Itoa(historyLimit))
		return chatCmd.RunE(chatCmd, args)
	},
}

func init() {
	openCmd.Flags().IntP("poll", "p", 2, "Poll interval in seconds")
	openCmd.Flags().IntP("history", "n", 20, "Number of local history entries to show on startup")
}

func parseConversationIDHex(convIDHex string) (types.ConversationID, error) {
	convIDBytes, err := hex.DecodeString(convIDHex)
	if err != nil || len(convIDBytes) != 16 {
		return types.ConversationID{}, fmt.Errorf("invalid conversation ID format")
	}

	var convID types.ConversationID
	copy(convID[:], convIDBytes)
	return convID, nil
}

func collectConversationSummaries(refreshUnread bool) ([]map[string]interface{}, int, bool, error) {
	_ = refreshUnread
	conversations, err := loadConversations()
	if err != nil {
		return nil, 0, false, fmt.Errorf("failed to load conversations: %w", err)
	}

	dc := NewDisplayContext()

	summaries := make([]map[string]interface{}, 0, len(conversations))

	for _, conversation := range conversations {
		convIDHex := hex.EncodeToString(conversation.ID[:])

		name := conversation.Name
		if store, err := naming.NewStore(configDir); err == nil {
			if localName := store.GetConversationName(convIDHex); localName != "" {
				name = localName
			}
		}

		summaries = append(summaries, map[string]interface{}{
			"id":           convIDHex,
			"label":        dc.FormatConvIDHex(convIDHex),
			"name":         name,
			"type":         conversation.Type,
			"participants": len(conversation.Participants),
			"unread":       nil,
		})
	}

	return summaries, 0, false, nil
}
