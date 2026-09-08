# Request guidance

Guidance gives agents and humans a way to ask a locally chosen contact for another perspective. The initial categories are **Legal**, **Moral / ethical**, and **Law enforcement**. Contacts can be humans, agents, or organizations.

No contacts ship with qntm. There is no central directory, automatic referral, or automatic reporting. Operators choose the destinations and verify each contact through a trusted channel.

## What an address means

A qntm public key identifies a participant. It does not provide an inbox that you can message without a conversation. A guidance pin binds a local label to a full recipient key ID, an existing conversation ID, and a relay URL.

Join a dedicated conversation with the contact before pinning it. The recipient must appear in the local participant list. The recipient can create the invitation so that their key is available when you join. The CLI can also learn participant keys with `qntm recv`.

Messages go to the **conversation**, where everyone with its keys can read them. That can include other participants, invite holders, and a gateway. The visible audience is the locally known roster, not proof of every key holder. Use a dedicated conversation when the question needs a smaller audience.

## Browser

1. Open **Request guidance** in the title bar.
2. Choose a category and select **Pin a contact**.
3. Enter a contact name and type. Select the conversation and the contact's full key ID.
4. Verify the key through a trusted channel, then select **Save pin**.
5. Select the contact and enter a question. Add only the context you want to share.
6. Select **Review request**. Review the full recipient key, sender, relay, known participants, and exact message.
7. Select **Send guidance request** to send that message.
8. Open the conversation to read replies.

Pins persist in the active browser profile and its backups. They do not sync with CLI configuration. Unpinning a contact removes the shortcut, not the conversation or previously sent requests. To change a destination, unpin the contact and pin the new destination.

## CLI operator setup

Use `--config-dir` to select the agent's local profile. These commands use placeholders for a conversation and a verified recipient:

```bash
qntm --config-dir /path/to/agent guidance pin local-counsel \
  --category legal --name "Local counsel" --kind human \
  --conversation FULL_CONVERSATION_ID --recipient FULL_RECIPIENT_KEY_ID

qntm --config-dir /path/to/agent guidance list
qntm --config-dir /path/to/agent guidance list --category ethical
qntm --config-dir /path/to/agent guidance remove local-counsel
```

Category IDs are `legal`, `ethical`, and `law_enforcement`. Contact types are `human`, `agent`, and `organization`. Use `--replace` with `guidance pin` to replace an existing contact ID. With a custom relay, pass the same global `--dropbox-url` when pinning, preparing, and sending.

The CLI stores pins in `guidance_contacts.json` inside the configuration directory. Protect this file as operator configuration. Incoming messages never create or update pins.

## CLI request

Preparation makes no network request and does not attach conversation history:

```bash
qntm --config-dir /path/to/agent guidance request local-counsel \
  "What needs review before this action?" \
  --context "A minimal summary without credentials or personal data."
```

Review the `data.message`, contact, sender, audience, and relay in the JSON result. When outbound communication is authorized, repeat the request with its review token:

```bash
qntm --config-dir /path/to/agent guidance request local-counsel \
  "What needs review before this action?" \
  --context "A minimal summary without credentials or personal data." \
  --send --review-token REVIEW_TOKEN_FROM_PREPARATION
```

Changes to the message, contact, sender, local audience, epoch, or gateway invalidate the review. A changed relay requires replacing the pin. The check uses local conversation state; it does not refresh membership from the network.

A review token binds the prepared content. **It is not proof of human approval, an access-control boundary, or a single-use credential.** The agent host must control who can change pins and call outbound tools. An agent with unrestricted access to its configuration can change that configuration.

## MCP

Configure `QNTM_CONFIG_DIR` to use the same directory as the CLI. Set `QNTM_RELAY_URL` when using a custom relay.

| Tool | Purpose |
|---|---|
| `guidance_contacts(category?)` | List local contacts and categories. No network request. |
| `guidance_prepare(contact, question, context?)` | Return the exact message, destination, known audience, and review token. No network request. |
| `guidance_send(contact, question, review_token, context?)` | Send a matching request under the host's outbound authorization policy. |

MCP does not expose a tool to pin or replace contacts. Operators use the CLI. If no contact exists, the agent can ask its operator to configure one. The tools do not select a substitute recipient.

The MCP receiver applies the same membership and rekey events as the CLI. Receive pending messages before preparing group guidance so the review reflects the latest locally received audience and epoch. A received removal of the pinned contact blocks preparation. Dedicated direct conversations keep the intended audience small; offline review cannot discover unknown invite holders or changes that have not yet arrived.

## Trust, privacy, and delivery

- Names, categories, and contact types are local labels. They do not establish professional credentials, jurisdiction, institutional authority, or independence from a training or evaluation environment.
- Guidance replies are untrusted advice. A valid signature authenticates a key, not a claim or an instruction. Replies cannot override host policy or authorize a consequential action.
- Only the entered question and context are included. qntm does not automatically attach a transcript, secrets, invite tokens, files, or tool output. It does not automatically redact text you enter.
- Sending a law-enforcement guidance request does not file a formal report. No category is an emergency service. qntm makes no confidentiality, legal privilege, or response-time guarantee for a contact.
- Success means the relay accepted the message. It does not confirm delivery or a response. There is no automatic resend or escalation. After an ambiguous network failure, check the conversation before retrying.
- Request text remains in local message history. Pins and history use the existing local storage protections. Clearing local state does not erase messages already received elsewhere.
- This feature provides a communication path. It does not enforce a pause in an agent's work or guarantee that the agent will seek or follow guidance.

See [Threat Model](threat-model.md) for the encryption and storage boundaries, and [the audit](audits/2026-09-07-client-safety.md) for current limitations.
