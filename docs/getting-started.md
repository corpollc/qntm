# Getting Started with qntm

## What is qntm?

qntm is an end-to-end encrypted messaging system with built-in API Gateway capabilities. Every message you send is encrypted so that only the participants in a conversation can read it. No central server ever stores your messages in plain text --- the relay server only sees encrypted blobs that it cannot decrypt.

In addition to private messaging, qntm includes an API Gateway feature that lets groups of people make approved API calls together. Multiple participants must review and approve each request before it goes through, ensuring that sensitive actions always have group oversight.

---

## Choosing Your Client

qntm offers two client interfaces. Pick whichever fits your workflow.

| Client | Best for | Requires |
|---|---|---|
| **Web UI** (qntm Messenger) | Visual, browser-based experience | Node.js, a modern browser |
| **Terminal UI** (TUI) | Command-line users, remote sessions | Node.js, a terminal |

Both clients connect to the same relay server and use the same encryption protocol. You can switch between them at any time.

---

## First Launch

### Web UI

1. Open a terminal and navigate to the `ui/aim-chat` directory in the qntm repository.

2. Install dependencies (first time only):

   ```
   npm install
   ```

3. Start the development server:

   ```
   npm run dev
   ```

4. Open your browser to [http://localhost:5173](http://localhost:5173).

When you launch for the first time, the Web UI automatically creates a default profile called "Agent 1" and selects it. You will see the main interface with a sidebar on the left (containing panels for Identities, Invites, Conversations, and Contacts) and a chat area on the right.

### Terminal UI

1. Open a terminal and navigate to the `ui/tui` directory in the qntm repository.

2. Install dependencies (first time only):

   ```
   npm install
   ```

3. Start the client:

   ```
   npm start
   ```

   You can also run it directly:

   ```
   npx tsx src/index.tsx
   ```

   Optional flags:

   ```
   npx tsx src/index.tsx --config-dir ~/.qntm-human --relay-url https://inbox.qntm.corpo.llc
   ```

When you launch for the first time, the TUI automatically generates a new identity and displays your Key ID. You will see a header, a sidebar listing conversations, a chat area, a status bar, and a text input at the bottom. Type `/help` to see the full list of available commands.

---

## Creating Your Identity

Your identity is a cryptographic keypair (a public key and a private key) that proves who you are. Think of the Key ID as your unique username within qntm.

### Web UI

1. Expand the **Identities** panel in the sidebar.
2. Click **Generate keypair**.
3. Your status changes to "Ready" and you will see your **Key ID** and **Public key** displayed below the button.
4. Click **Copy** next to your public key to copy it to the clipboard. Share this with others so they can verify your messages.

### Terminal UI

Your identity is generated automatically on first launch. To view it at any time, type:

```
/identity
```

This displays your Key ID, public key, and config directory path.

---

## Starting a Conversation

Conversations in qntm are created using invite tokens. One person creates the conversation and shares the token; the other person uses the token to join.

### Web UI

**Creating a conversation:**

1. Expand the **Invites** panel in the sidebar.
2. Under **New Conversation**, type a name for the conversation (for example, "Team Chat").
3. Click **Create**.
4. An invite token appears in a text box. Click **Copy** to copy it to your clipboard.
5. Send the invite token to the person you want to chat with (via email, another messenger, in person, etc.).

**Joining a conversation:**

1. Expand the **Invites** panel in the sidebar.
2. Under **Join Conversation**, paste the invite token you received.
3. Optionally type a label for this conversation.
4. Click **Join**.

### Terminal UI

**Creating a conversation:**

```
/invite Team Chat
```

This creates a new conversation named "Team Chat" and prints an invite token. Copy the token and send it to the other person.

**Joining a conversation:**

```
/join <paste-the-invite-token-here>
```

This joins the conversation. You will see a confirmation message with the conversation ID.

---

## Sending Messages

Once you have an active conversation, sending messages is straightforward.

### Web UI

1. Click on a conversation in the **Conversations** panel to select it.
2. Type your message in the text input at the bottom of the chat area.
3. Press Enter or click the send button.

### Terminal UI

1. Switch to a conversation by pressing the number key corresponding to its position in the sidebar (1-9), or use `/conversations` to list them.
2. Type your message and press Enter.

In both clients, the app automatically checks for new messages every 3 seconds. Incoming messages appear in the chat area as they arrive. All messages are encrypted end-to-end --- only participants in the conversation can decrypt and read them.

---

## Managing Contacts

When you receive messages from other people, they initially appear with a truncated Key ID (a short hex string). You can assign friendly display names to make them easier to recognize.

### Web UI

1. Expand the **Contacts** panel in the sidebar.
2. You will see a list of Key IDs from people who have sent messages in the current conversation.
3. Type a name into the text field next to a Key ID and click **Save**.
4. That person's messages will now display the name you chose.

### Terminal UI

Use the `/alias` command with a Key ID prefix and a display name:

```
/alias a1b2c3 Alice
```

You only need to type enough of the Key ID to uniquely identify the contact. The TUI will match it against known participants.

You can also set your own display name (visible to others when you send messages):

```
/nick YourName
```

---

## Navigating the Terminal UI

The TUI has keyboard shortcuts for quick navigation:

| Key | Action |
|---|---|
| Tab | Toggle the conversation sidebar |
| 1-9 | Switch to a conversation by its number |
| Escape | Enter scroll mode |
| j / k | Scroll up / down (in scroll mode) |
| Ctrl-C | Quit |

Type `/help` at any time to see the full command list.

---

## Settings

### Message Relay URL

Both clients connect to a default message relay server at `https://inbox.qntm.corpo.llc`. The relay stores and delivers your encrypted messages. You do not need to change this unless you are running your own relay.

**Web UI:** Click **Settings** in the title bar. You can change the Relay URL and click **Save**, or click **Reset to default** to revert.

**Terminal UI:** Pass the `--relay-url` flag when launching:

```
npx tsx src/index.tsx --relay-url https://your-relay.example.com
```

### Backup and Restore (Web UI)

All your data --- identities, conversations, keys, and messages --- is stored locally in your browser. Nothing is stored on a remote server in plain text.

To protect against data loss:

1. Click **Settings** in the title bar.
2. Under **Backup & Restore**, click **Export backup** to download a JSON file containing all your data.
3. To restore from a backup, click **Import backup** and select a previously exported JSON file. The page will reload with your restored data.

---

## Next Steps

Once you are comfortable with basic messaging, explore the API Gateway feature to make group-approved API calls from within your conversations. See the [API Gateway documentation](api-gateway.md) for a full walkthrough of enabling the gateway, adding API keys, submitting requests, and managing approval thresholds.
