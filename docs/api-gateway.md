# API Gateway

The API Gateway is a qntm feature that lets a group of people make approved API calls together. No single person can make an API call alone --- multiple participants must review and approve each request before it goes through. This prevents unauthorized API usage and ensures that sensitive actions (like charging a credit card or deploying code) always have group oversight.

Think of it like a safe-deposit box that requires two keys to open: one key is not enough.


## Key Concepts

**API Gateway** -- The feature itself. When you enable the API Gateway on a conversation, that conversation becomes a shared control plane for making API calls. All messages --- requests, approvals, results --- appear in the conversation so everyone can see what is happening.

**Signers** -- The conversation participants who can submit and approve API requests. When you enable the API Gateway, every participant in the conversation automatically becomes a signer. Each signer has a cryptographic identity (a keypair) that proves who they are.

**Required Approvals** -- The number of signers who must approve a request before it executes. You set this when you enable the API Gateway. For example, if you set required approvals to 2, then at least two different signers must approve a request before the API call is made.

**Threshold Rules** -- Fine-grained controls that let you set different approval requirements for different kinds of API calls. For example, you might require only 1 approval for read-only requests but 3 approvals for requests that modify data.

**API Templates** -- Pre-configured API call patterns that define an endpoint, HTTP method, and parameters. Templates make it easy to submit requests without manually entering URLs and headers. qntm ships with a starter catalog of templates, and you can add your own.

**API Keys** -- Credentials (such as API tokens or passwords) stored securely for use with API calls. When you add an API key, it is encrypted so that only the gateway can read it. The key is automatically injected into outgoing requests when they execute --- no signer ever sees the raw key in the conversation.


## How It Works

Here is the step-by-step flow for making a group-approved API call:

1. **Enable the API Gateway.** A conversation admin enables the gateway on a conversation and sets the number of required approvals. All current participants become signers. A confirmation message appears in the chat.

2. **Add API Keys (if needed).** If the target API requires authentication, a signer provisions an API key. The key is encrypted to the gateway and stored securely. Only the gateway can decrypt it.

3. **Select an API Template and fill in parameters.** Open the API Gateway panel and choose a template from the dropdown. If the template has parameters (for example, an item ID or search query), fill them in. You will see a live preview of the resolved URL before submitting.

4. **Submit the request.** Click "Submit API request." Your request appears as a message in the conversation so everyone can see exactly what API call is being proposed. Submitting the request counts as your approval, so you do not need to approve your own request separately.

5. **Other participants review and approve.** Each signer sees the request in their chat with full details --- the HTTP method, URL, any parameters, and an expiration time. They can click "Approve" (in the web UI) or use the `/approve` command (in the TUI) to add their approval.

6. **The API call executes automatically.** Once enough approvals are collected (meeting the required approval threshold), the gateway automatically:
   - Decrypts the API key for the target service.
   - Injects the key into the outgoing HTTP request header.
   - Makes the API call.
   - Posts the result back to the conversation.

7. **The response appears in chat.** Everyone in the conversation sees the API response, including the HTTP status code and response body. If the call failed, the error is visible to the whole group.

If a request is not approved before its expiration time, it expires and can no longer be approved or executed.


## Setting Up

### Hosted gateway and self-hosting

The hosted AIM UI defaults the **Gateway server** field to `https://gateway.qntm.corpo.llc`. Local development still defaults to `http://localhost:8080`, and you can always replace the field with your own compatible deployment.

If you want to operate your own trust boundary, qntm ships the full Cloudflare Worker source in `gateway-worker/`. See [Gateway Deployment](gateway-deploy.md) for the hosted deployment runbook, required Cloudflare secrets, and self-hosting notes.

### Web UI

1. Open a conversation that has at least two participants.
2. Click the **API Gateway** button in the chat header. This opens the API Gateway panel on the right side of the screen.
3. If the gateway is not yet enabled, you will see an "API Gateway Inactive" banner and an "Enable API Gateway" section.
4. Set the **Required approvals** number. This is how many different signers must approve each request. A good starting point is 2.
5. Click **Enable API Gateway**.
6. A confirmation message appears in the conversation showing the gateway is active, listing all signers and the approval threshold.

### TUI (Terminal Interface)

In the TUI, gate messages are rendered as formatted cards in the conversation view:

- **API Request cards** show the HTTP method, URL, service, arguments, and expiration time. If the request is incoming and not expired, you will see instructions to press `a` to approve or use the `/approve` command followed by the request ID.
- **Approval cards** show which signer approved which request.
- **Executed cards** show the HTTP status code after the gateway makes the call.
- **Response cards** show the API response body.


## Adding API Keys

API keys let the gateway authenticate with external services on your behalf. The key is encrypted end-to-end --- only the gateway can decrypt it.

### Web UI

1. With the API Gateway panel open, scroll to the **API Keys** section (visible only after the gateway is enabled).
2. Enter the **Service** name. This must match the service name used by your API templates (for example, `stripe`, `github`, or `hackernews`).
3. Enter the **Header name** --- the HTTP header where the credential should be injected. The default is `Authorization`.
4. Enter the **Header template** --- the format for the header value. Use `{value}` as a placeholder for the actual key. For example: `Bearer {value}`.
5. Enter the **API key value** itself.
6. Click **Add API Key**.

The key is immediately encrypted and sent to the gateway. It never appears in plaintext in the conversation.

### Key Expiration

API keys can have a time-to-live (TTL). After the TTL expires, the gateway will refuse to use the key and log an expiration notice. A signer must provision a new key to resume making API calls for that service.

### Revoking Keys

Keys can be revoked by service name or by secret ID. Once revoked, the gateway deletes the key from memory and will no longer use it for any requests.


## API Templates

Templates are pre-configured API call patterns that make it easy to submit requests without manually entering URLs. Each template specifies:

- **Name** -- A human-readable identifier (for example, `hn.top-stories` or `httpbin.echo`).
- **Service** -- Which API service the template targets.
- **HTTP Method** -- GET, POST, PUT, PATCH, or DELETE.
- **Endpoint** -- The URL path, which can include `{parameter}` placeholders.
- **Suggested threshold** -- A recommended number of required approvals for this type of call.
- **Parameters** -- Path parameters, query parameters, or body fields that you fill in before submitting.

### Built-in Templates

qntm includes a starter catalog with templates for several public APIs:

| Template | Service | Method | Description |
|---|---|---|---|
| `hn.top-stories` | Hacker News | GET | Get top story IDs |
| `hn.get-item` | Hacker News | GET | Get a story or comment by ID |
| `httpbin.echo` | httpbin | POST | Echo POST data (good for testing) |
| `httpbin.headers` | httpbin | GET | Return request headers (shows injected auth) |
| `jokes.dad` | icanhazdadjoke | GET | Get a random dad joke |
| `trivia.random` | Open Trivia DB | GET | Get a random trivia question |
| `dogs.random` | Dog CEO | GET | Get a random dog image URL |
| `dogs.breed` | Dog CEO | GET | Get a random image of a specific breed |
| `leet.translate` | Fun Server | POST | Translate text to l33tsp34k |
| `ascii.artify` | Fun Server | POST | Convert text to ASCII art |

These are useful for testing and learning how the gateway works before connecting it to production APIs.


## Threshold Rules

Threshold rules give you fine-grained control over how many approvals are required for different types of API calls. Each rule matches on three dimensions:

- **Service** -- The target API service (or `*` for any service).
- **Endpoint** -- The target endpoint path (or `*` for any endpoint).
- **Verb** -- The HTTP method (or `*` for any method).

Rules are matched from most specific to least specific:

1. Exact service + exact endpoint + exact verb (most specific)
2. Exact service + exact verb
3. Exact service only
4. Wildcard (`*` for all three --- the default fallback)

**Example configuration:**

- `service=stripe, endpoint=/v1/charges, verb=POST, M=3` -- Creating a Stripe charge requires 3 approvals.
- `service=stripe, endpoint=*, verb=GET, M=1` -- Reading Stripe data requires only 1 approval.
- `service=*, endpoint=*, verb=*, M=2` -- Everything else requires 2 approvals.


## Security Model

The API Gateway is designed around a core principle: **no single person should be able to make an API call unilaterally.** Here is how the system enforces that:

### Cryptographic Signatures

Every request and every approval is cryptographically signed with the signer's Ed25519 private key. The gateway verifies each signature before counting it toward the threshold. This means:

- No one can forge an approval on someone else's behalf.
- No one can tamper with a request after it has been submitted.
- The gateway can prove exactly who approved what.

### API Key Protection

API keys are protected at multiple layers:

- **In transit:** When a signer provisions an API key, it is encrypted using NaCl public-key encryption (X25519-XSalsa20-Poly1305) to the gateway's public key. Only the gateway's private key can decrypt it.
- **At rest:** The gateway can encrypt stored keys using AES-256-GCM with a master key (the Vault). Even if the gateway's storage is compromised, the keys remain encrypted.
- **In use:** The decrypted key is held in memory only long enough to inject it into the outgoing HTTP request header. It is then scrubbed from memory.
- **Never exposed:** API keys never appear in conversation messages. Signers send encrypted blobs; the gateway decrypts internally.

### Replay Protection

Each request has a unique ID. The gateway rejects duplicate request IDs, preventing replay attacks where someone tries to re-execute a previously approved request.

### Expiration

Every API request has an expiration time. If the request is not fully approved before it expires, it cannot be executed. This prevents old, forgotten requests from being approved much later when circumstances may have changed.

### Membership Controls

In a gateway-enabled conversation, adding or removing signers requires a proposal-and-approval flow. Direct membership changes are blocked. All existing signers must unanimously approve membership changes, preventing a single compromised account from adding a colluding signer.


## Common Use Cases

### Team approval for production deployments

A DevOps team sets up a gateway-enabled conversation connected to their CI/CD API. Deploying to production requires 2 out of 3 team members to approve. This prevents accidental or unauthorized deployments while keeping the process fast.

### Shared access to a payment API

A finance team connects the gateway to their payment processor (Stripe, Square, etc.). Creating charges or issuing refunds requires approval from two authorized team members. Read-only queries (checking balances, listing transactions) require only one approval. The API key is stored in the gateway so no individual team member needs direct access to production credentials.

### Multi-party authorization for sensitive data

A compliance team uses the gateway to query customer data APIs. Every data access request is logged in the conversation with full details of who requested it, who approved it, and what data was returned. The conversation becomes a built-in audit trail.

### Agent-governed organizations

DAOs or agent-governed LLCs use the gateway to interact with real-world APIs (banks, HR platforms, government registries). Threshold authorization ensures that automated agents cannot act alone --- human oversight is always required for sensitive operations.
