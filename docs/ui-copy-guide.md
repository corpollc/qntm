# UI Copy Style Guide

Reference for all user-facing text across the qntm web UI and TUI.

## Voice and Tone

Write like a knowledgeable colleague: direct, helpful, technically precise but approachable. Not corporate ("We're delighted to inform you..."), not cute ("Oopsie!"). State what happened and what to do next.

## Terminology Reference

Use the canonical term on the left. Avoid the terms on the right.

| Use                  | Not                                      |
|----------------------|------------------------------------------|
| conversation         | chat, channel, room                      |
| profile              | account (for the user's local profile)   |
| keypair              | identity, keys, crypto identity          |
| API Gateway          | gate, gateway (alone)                    |
| API template         | recipe                                   |
| required approvals   | threshold                                |
| API keys             | secrets, credentials                     |
| message relay        | dropbox                                  |
| Key ID               | KID                                      |
| invite token         | invite link, invite code                 |

When referring to a user's cryptographic key material, say "keypair." When referring to who someone is on the platform, say "profile."

## Button Labels

- Start with a verb: "Generate keypair", "Join conversation", "Submit API request".
- Use sentence case: "Add API key" not "Add API Key".
- No trailing period.
- Prefer specific verbs over generic ones: "Generate keypair" not "Create". "Join" not "Accept".
- Keep labels short (2-4 words).

**Examples from the codebase:**
- `Generate keypair` -- good
- `Enable API Gateway` -- good
- `Add API key` -- good
- `Copy` -- acceptable for icon-adjacent actions
- `Submit API request` -- good

## Error Messages

Start with what went wrong, then suggest what to do.

Good:
> Failed to send message. Check your connection and try again.

> Keypair generation failed. Make sure your profile is selected and try again.

Bad:
> Error.

> Something went wrong!

No bare error codes. If a code is relevant, include it after the human-readable message: "Connection refused (ECONNREFUSED). Is the relay server running?"

## Success Messages

Brief confirmation of what happened. No fanfare.

Good:
> Keypair generated

> Conversation created

> Public key copied to clipboard

Bad:
> Your new keypair has been successfully generated!

> Congratulations, you've created a conversation!

Use past tense ("generated", "copied", "joined") rather than present ("generating", "copying").

## Empty States

State what is empty, then guide the user to the next action.

Good:
> No conversations yet. Create one above or join with an invite token.

> No API keys configured. Add one to make authenticated API calls.

Bad:
> Nothing here.

> It's lonely in here!

## Tooltips

One sentence maximum. Answer "what is this?" -- not "how does this work?"

Good:
> Your unique identifier on the network.

> Pre-configured API call patterns with endpoints, methods, and parameters.

> Credentials stored securely and used automatically when API calls execute.

Bad:
> This is the Key ID, which is a unique identifier that gets generated when you create a keypair. You can share it with others so they know who you are. To create one, go to the Identity panel and click Generate keypair.

## Placeholder Text

Suggest what to type. Be specific to the field.

Good:
> Name your conversation

> Paste an invite token

> e.g. stripe, github

Bad:
> Enter value here

> Type something...

> Input

## Confirmation Dialogs

Title states the action as a question: "Replace keypair?"

Body explains the consequence: "This will generate a new keypair and replace your current one. Your existing Key ID will no longer be valid. This cannot be undone."

Confirm button matches the action: "Replace keypair" (not "OK" or "Yes").

## Formatting Rules

- **Sentence case** for labels and buttons ("Required approvals", not "Required Approvals"). Exception: proper nouns ("API Gateway", "Key ID").
- **Periods** on descriptions and hints. No periods on button labels.
- **No exclamation marks** unless something is genuinely exciting (almost never).
- **No emoji** in UI text.
- **Use numerals** for counts: "2 of 3 signers", not "two of three signers".
- **Oxford comma** when listing: "endpoints, methods, and parameters."

## TUI Command Help Text

- `brief`: imperative phrase, no period. "Create a new conversation", "Show your identity info".
- `description`: one to two sentences. Start with what the command does, then usage syntax. End with a period.
- `usage`: show required args in `<angle brackets>`, optional args in `[square brackets]`.
