package cli

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/types"
)

func init() {
	rootCmd.AddCommand(chatCmd)
	chatCmd.Flags().IntP("poll", "p", 2, "Poll interval in seconds")
	chatCmd.Flags().IntP("history", "n", 20, "Number of local history entries to show on startup")
}

var chatCmd = &cobra.Command{
	Use:   "chat <conversation>",
	Short: "Compact interactive chat mode",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pollIntervalSec, _ := cmd.Flags().GetInt("poll")
		historyLimit, _ := cmd.Flags().GetInt("history")
		if pollIntervalSec < 1 {
			pollIntervalSec = 1
		}
		if historyLimit < 0 {
			historyLimit = 0
		}

		currentIdentity, err := loadIdentity()
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
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

		dc := NewDisplayContext()
		storage := getStorageProvider()
		dropboxMgr := dropbox.NewManager(storage)
		messageMgr := message.NewManager()

		allSeenMessages := loadSeenMessages()
		conversationSeenMessages := allSeenMessages[convID]
		if conversationSeenMessages == nil {
			conversationSeenMessages = make(map[types.MessageID]bool)
			allSeenMessages[convID] = conversationSeenMessages
		}

		fmt.Printf("Chat mode for %s\n", dc.FormatConvIDHex(convIDHex))
		fmt.Println("Commands: /help, /poll, /history, /quit")

		if historyLimit > 0 {
			printRecentLocalHistory(conversation, dc, convIDHex, historyLimit)
		}

		pollInbox := func() error {
			messages, err := dropboxMgr.ReceiveMessages(currentIdentity, conversation, conversationSeenMessages)
			if err != nil {
				return err
			}
			if len(messages) == 0 {
				return nil
			}

			for _, msg := range messages {
				ts := time.Unix(msg.Envelope.CreatedTS, 0).Local().Format("15:04")
				senderDisplay := dc.FormatKID(msg.Inner.SenderKID, convIDHex)
				bodyDisplay := string(msg.Inner.Body)
				fmt.Printf("\n[%s] %s: %s\n", ts, senderDisplay, bodyDisplay)

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

			saveSeenMessages(allSeenMessages)
			return nil
		}

		if err := pollInbox(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: initial poll failed: %v\n", err)
		}

		inputCh := make(chan string)
		errCh := make(chan error, 1)
		go readInputLines(inputCh, errCh)

		ticker := time.NewTicker(time.Duration(pollIntervalSec) * time.Second)
		defer ticker.Stop()

		fmt.Print("chat> ")
		for {
			select {
			case <-ticker.C:
				if err := pollInbox(); err != nil {
					fmt.Fprintf(os.Stderr, "\nwarning: poll failed: %v\n", err)
					fmt.Print("chat> ")
				}
			case err := <-errCh:
				saveSeenMessages(allSeenMessages)
				if err != nil {
					return err
				}
				return nil
			case line, ok := <-inputCh:
				if !ok {
					saveSeenMessages(allSeenMessages)
					return nil
				}

				line = strings.TrimSpace(line)
				if line == "" {
					fmt.Print("chat> ")
					continue
				}

				if strings.HasPrefix(line, "/") {
					switch strings.ToLower(line) {
					case "/help":
						fmt.Println("Commands: /help, /poll, /history, /quit")
					case "/poll":
						if err := pollInbox(); err != nil {
							fmt.Fprintf(os.Stderr, "warning: poll failed: %v\n", err)
						}
					case "/history":
						printRecentLocalHistory(conversation, dc, convIDHex, 30)
					case "/quit", "/exit":
						saveSeenMessages(allSeenMessages)
						return nil
					default:
						fmt.Printf("unknown command: %s\n", line)
					}
					fmt.Print("chat> ")
					continue
				}

				envelope, err := messageMgr.CreateMessage(
					currentIdentity,
					conversation,
					"text",
					[]byte(line),
					nil,
					messageMgr.DefaultTTL(),
				)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to create message: %v\n", err)
					fmt.Print("chat> ")
					continue
				}

				if err := dropboxMgr.SendMessage(envelope); err != nil {
					fmt.Fprintf(os.Stderr, "failed to send message: %v\n", err)
					fmt.Print("chat> ")
					continue
				}

				body, encoding := encodeChatBody([]byte(line))
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

				ts := time.Unix(envelope.CreatedTS, 0).Local().Format("15:04")
				fmt.Printf("[%s] you: %s\n", ts, line)
				fmt.Print("chat> ")
			}
		}
	},
}

func readInputLines(out chan<- string, errCh chan<- error) {
	defer close(out)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		out <- scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		errCh <- err
		return
	}
	errCh <- nil
}

func printRecentLocalHistory(conversation *types.Conversation, dc *DisplayContext, convIDHex string, limit int) {
	entries, err := loadChatArchive(conversation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load local history: %v\n", err)
		return
	}
	if len(entries) == 0 {
		return
	}

	start := 0
	if limit > 0 && len(entries) > limit {
		start = len(entries) - limit
	}

	fmt.Printf("Recent local history for %s:\n", dc.FormatConvIDHex(convIDHex))
	for _, entry := range entries[start:] {
		sender := "you"
		if entry.Direction == "incoming" {
			sender = entry.SenderKIDHex
			if len(entry.SenderKIDHex) == 32 {
				if kidBytes, err := hex.DecodeString(entry.SenderKIDHex); err == nil {
					var kid types.KeyID
					copy(kid[:], kidBytes)
					sender = dc.FormatKID(kid, convIDHex)
				}
			}
		}
		ts := time.Unix(entry.CreatedTS, 0).Local().Format("15:04")
		fmt.Printf("  [%s] %s: %s\n", ts, sender, decodeChatBody(entry))
	}
}
