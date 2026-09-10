# CLI reference

Generated from the Python CLI parser. Regenerate with `python scripts/generate_cli_reference.py` in an environment with the qntm dependencies installed. CI checks for drift.

Global options precede the command. One-shot commands return JSON; `recv --watch` streams JSONL. See [receive hooks](receive-hooks.md), [guidance](guidance.md), and [gateway invitations](gateway-invitations.md) for complete workflows.

## `qntm`

```text
usage: qntm [-h] [--config-dir CONFIG_DIR] [--dropbox-url DROPBOX_URL] [--human]
            [--verbose] [-v]
            {guidance,identity,convo,send,recv,inbox,history,contact,group,announce,gate-run,gate-approve,gate-disapprove,gate-pending,gate-promote,gate-secret,gov,name,ref,version}
            ...

qntm - agent-first secure messaging CLI

positional arguments:
  {guidance,identity,convo,send,recv,inbox,history,contact,group,announce,gate-run,gate-approve,gate-disapprove,gate-pending,gate-promote,gate-secret,gov,name,ref,version}
    guidance            Ask locally pinned contacts for legal, ethical, or law-
                        enforcement guidance
    identity            Manage identity keys
    convo               Manage conversations
    send                Send a text message
    recv                Receive messages
    inbox               Show inbox summary
    history             Show message history
    contact             Manage locally pinned contact addresses
    group               Manage group conversations
    announce            Manage announce channels
    gate-run            Submit a gate authorization request
    gate-approve        Approve a gate request
    gate-disapprove     Deny a gate request
    gate-pending        List pending gate requests
    gate-promote        Promote conversation to gate-enabled
    gate-secret         Provision a secret to gate conversation
    gov                 Govern gateway policy and membership
    name                Manage local nicknames
    ref                 Resolve a short prefix to a full ID
    version             Print version

options:
  -h, --help            show this help message and exit
  --config-dir CONFIG_DIR
                        Configuration directory (default: ~/.qntm)
  --dropbox-url DROPBOX_URL
                        HTTP drop box endpoint (default: https://inbox.qntm.corpo.llc)
  --human               Reserved compatibility option; output remains JSON
  --verbose             Enable verbose output
  -v, --version         Print version

quick start:
  qntm identity generate                  create a new identity
  qntm convo create --name mygroup        start a conversation, get an invite token
  qntm convo join <token>                 accept an invite token
  qntm send <conv> "hello"                send a message (conv = id or prefix)
  qntm recv <conv>                        receive new messages
  qntm recv <conv> --watch                stream messages and optional local hooks
  qntm guidance list                      find locally pinned guidance contacts

claude code channel:
  claude plugin marketplace add corpollc/qntm
  claude plugin install channel@qntm
  claude --dangerously-load-development-channels plugin:channel@qntm
```

## `qntm guidance`

```text
usage: qntm guidance [-h] {list,pin,remove,request} ...

positional arguments:
  {list,pin,remove,request}
    list                List local contacts and categories; no network request
    pin                 Operator setup: pin a verified key and existing conversation
                        locally
    remove              Remove a local pin
    request             Prepare an exact message and audience for review; sends only
                        with --send and --review-token

options:
  -h, --help            show this help message and exit
```

## `qntm guidance list`

```text
usage: qntm guidance list [-h] [--category {legal,ethical,law_enforcement}]

options:
  -h, --help            show this help message and exit
  --category {legal,ethical,law_enforcement}
```

## `qntm guidance pin`

```text
usage: qntm guidance pin [-h] --category {legal,ethical,law_enforcement} --name NAME
                         [--kind {human,agent,organization}] --conversation
                         CONVERSATION --recipient RECIPIENT [--replace]
                         contact

positional arguments:
  contact               Stable local contact ID

options:
  -h, --help            show this help message and exit
  --category {legal,ethical,law_enforcement}
  --name NAME           Local contact label
  --kind {human,agent,organization}
  --conversation CONVERSATION
                        Full conversation ID
  --recipient RECIPIENT
                        Full recipient key ID (32 hex characters)
  --replace             Replace an existing pin with this ID
```

## `qntm guidance remove`

```text
usage: qntm guidance remove [-h] contact

positional arguments:
  contact

options:
  -h, --help  show this help message and exit
```

## `qntm guidance request`

```text
usage: qntm guidance request [-h] [--context CONTEXT] [--send]
                             [--review-token REVIEW_TOKEN]
                             contact question

positional arguments:
  contact               Pinned contact ID
  question

options:
  -h, --help            show this help message and exit
  --context CONTEXT     Optional context; no transcript is added automatically
  --send                Send the reviewed request under the host's authorization
                        policy
  --review-token REVIEW_TOKEN
                        Token from the matching prepared request
```

## `qntm identity`

```text
usage: qntm identity [-h] {generate,show} ...

positional arguments:
  {generate,show}
    generate       Generate new identity keypair
    show           Show current identity

options:
  -h, --help       show this help message and exit
```

## `qntm identity generate`

```text
usage: qntm identity generate [-h]

options:
  -h, --help  show this help message and exit
```

## `qntm identity show`

```text
usage: qntm identity show [-h]

options:
  -h, --help  show this help message and exit
```

## `qntm convo`

```text
usage: qntm convo [-h] {create,join,invite,list,name} ...

positional arguments:
  {create,join,invite,list,name}
    create              Create conversation and invite
    join                Join conversation from invite token
    invite              Get token and fragment link for existing conversation
    list                List conversations
    name                Set a local name for a conversation

options:
  -h, --help            show this help message and exit
```

## `qntm convo create`

```text
usage: qntm convo create [-h] [--name NAME] [--group] [--no-self-join]

options:
  -h, --help      show this help message and exit
  --name NAME     Conversation name
  --group         Create group conversation
  --no-self-join  Don't self-join
```

## `qntm convo join`

```text
usage: qntm convo join [-h] [--name NAME] token

positional arguments:
  token        Invite token

options:
  -h, --help   show this help message and exit
  --name NAME  Conversation name
```

## `qntm convo invite`

```text
usage: qntm convo invite [-h] conv

positional arguments:
  conv        Conversation ID or prefix

options:
  -h, --help  show this help message and exit
```

## `qntm convo list`

```text
usage: qntm convo list [-h]

options:
  -h, --help  show this help message and exit
```

## `qntm convo name`

```text
usage: qntm convo name [-h] conversation local_name

positional arguments:
  conversation  Conversation ID or prefix
  local_name    Local nickname

options:
  -h, --help    show this help message and exit
```

## `qntm send`

```text
usage: qntm send [-h] conversation message

positional arguments:
  conversation  Conversation ID or prefix
  message       Message text

options:
  -h, --help    show this help message and exit
```

## `qntm recv`

```text
usage: qntm recv [-h] [--watch] [--webhook URL] [--on-receive COMMAND]
                 [--hook-timeout SECONDS] [--include-self]
                 conversation

positional arguments:
  conversation          Conversation ID or prefix

options:
  -h, --help            show this help message and exit
  --watch               Keep the WebSocket open; emit one JSON line per message
  --webhook URL         POST receive events to this HTTP(S) URL (repeatable; requires
                        --watch)
  --on-receive COMMAND  Run an adapter with event JSON on stdin, without a shell
                        (repeatable; requires --watch)
  --hook-timeout SECONDS
                        Timeout for each hook attempt (default: 10 seconds)
  --include-self        Also deliver your own messages to hooks (stdout always
                        includes them)
```

## `qntm inbox`

```text
usage: qntm inbox [-h]

options:
  -h, --help  show this help message and exit
```

## `qntm history`

```text
usage: qntm history [-h] conversation

positional arguments:
  conversation  Conversation ID or prefix

options:
  -h, --help    show this help message and exit
```

## `qntm contact`

```text
usage: qntm contact [-h] {add,list,remove} ...

positional arguments:
  {add,list,remove}
    add              Pin a full public key under a contact name
    list             List local contact names and public keys
    remove           Remove a local contact without changing group membership

options:
  -h, --help         show this help message and exit
```

## `qntm contact add`

```text
usage: qntm contact add [-h] name public_key

positional arguments:
  name
  public_key  Full Ed25519 public key (hex or base64url)

options:
  -h, --help  show this help message and exit
```

## `qntm contact list`

```text
usage: qntm contact list [-h]

options:
  -h, --help  show this help message and exit
```

## `qntm contact remove`

```text
usage: qntm contact remove [-h] name

positional arguments:
  name

options:
  -h, --help  show this help message and exit
```

## `qntm group`

```text
usage: qntm group [-h] {create,join,add,remove,rekey,retry,refresh,link,list} ...

positional arguments:
  {create,join,add,remove,rekey,retry,refresh,link,list}
    create              Create a new group
    join                Open a group link or legacy invite
    add                 Add a contact, rotate keys and deliver their encrypted welcome
    remove              Remove member from group
    rekey               Rekey group (new epoch)
    retry               Resume the saved group operation using its exact encrypted
                        messages
    refresh             Resend current keys to an existing member without changing
                        membership
    link                Show a public group locator link containing no group keys
    list                List group conversations

options:
  -h, --help            show this help message and exit
```

## `qntm group create`

```text
usage: qntm group create [-h] [--description DESCRIPTION] name

positional arguments:
  name                  Group name

options:
  -h, --help            show this help message and exit
  --description DESCRIPTION
                        Group description
```

## `qntm group join`

```text
usage: qntm group join [-h] [--name NAME] token

positional arguments:
  token        Public group link for this identity, or a legacy invite token

options:
  -h, --help   show this help message and exit
  --name NAME  Group name
```

## `qntm group add`

```text
usage: qntm group add [-h] conversation public_key

positional arguments:
  conversation  Conversation ID or prefix
  public_key    Local contact name or full public key (base64url or hex)

options:
  -h, --help    show this help message and exit
```

## `qntm group remove`

```text
usage: qntm group remove [-h] [--reason REASON] conversation key_id

positional arguments:
  conversation     Conversation ID or prefix
  key_id           Local contact name or member key ID (hex)

options:
  -h, --help       show this help message and exit
  --reason REASON  Removal reason
```

## `qntm group rekey`

```text
usage: qntm group rekey [-h] conversation

positional arguments:
  conversation  Conversation ID or prefix

options:
  -h, --help    show this help message and exit
```

## `qntm group retry`

```text
usage: qntm group retry [-h] conversation

positional arguments:
  conversation  Conversation ID or prefix

options:
  -h, --help    show this help message and exit
```

## `qntm group refresh`

```text
usage: qntm group refresh [-h] conversation contact

positional arguments:
  conversation  Conversation ID or prefix
  contact       Local contact name or full public key

options:
  -h, --help    show this help message and exit
```

## `qntm group link`

```text
usage: qntm group link [-h] conversation

positional arguments:
  conversation  Conversation ID or prefix

options:
  -h, --help    show this help message and exit
```

## `qntm group list`

```text
usage: qntm group list [-h]

options:
  -h, --help  show this help message and exit
```

## `qntm announce`

```text
usage: qntm announce [-h] {create,post,subscribe,list,delete} ...

positional arguments:
  {create,post,subscribe,list,delete}
    create              Create a new announce channel
    post                Post a message to a channel
    subscribe           Subscribe to a channel
    list                List announce channels
    delete              Delete an announce channel

options:
  -h, --help            show this help message and exit
```

## `qntm announce create`

```text
usage: qntm announce create [-h] name

positional arguments:
  name        Channel name

options:
  -h, --help  show this help message and exit
```

## `qntm announce post`

```text
usage: qntm announce post [-h] channel message

positional arguments:
  channel     Channel name or conv ID
  message     Message text

options:
  -h, --help  show this help message and exit
```

## `qntm announce subscribe`

```text
usage: qntm announce subscribe [-h] --token TOKEN [--name NAME] conv_id

positional arguments:
  conv_id        Conversation ID (hex)

options:
  -h, --help     show this help message and exit
  --token TOKEN  Invite token from owner
  --name NAME    Local name for this channel
```

## `qntm announce list`

```text
usage: qntm announce list [-h]

options:
  -h, --help  show this help message and exit
```

## `qntm announce delete`

```text
usage: qntm announce delete [-h] channel

positional arguments:
  channel     Channel name or conv ID

options:
  -h, --help  show this help message and exit
```

## `qntm gate-run`

```text
usage: qntm gate-run [-h] -c CONVERSATION [--arg KEY=VALUE] recipe

positional arguments:
  recipe                Recipe name (e.g. jokes.dad, hn.get-item)

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
  --arg KEY=VALUE       Recipe argument (repeatable)
```

## `qntm gate-approve`

```text
usage: qntm gate-approve [-h] -c CONVERSATION request_id

positional arguments:
  request_id            Request ID to approve

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
```

## `qntm gate-disapprove`

```text
usage: qntm gate-disapprove [-h] -c CONVERSATION request_id

positional arguments:
  request_id            Request ID to deny

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
```

## `qntm gate-pending`

```text
usage: qntm gate-pending [-h] [-c CONVERSATION]

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix (optional, scans all if omitted)
```

## `qntm gate-promote`

```text
usage: qntm gate-promote [-h] -c CONVERSATION --threshold THRESHOLD --gateway-url
                         GATEWAY_URL

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
  --threshold THRESHOLD
                        Approval threshold (M-of-N)
  --gateway-url GATEWAY_URL
                        Gateway server URL; any participant may invite it
```

## `qntm gate-secret`

```text
usage: qntm gate-secret [-h] -c CONVERSATION --service SERVICE --gateway-pubkey
                        GATEWAY_PUBKEY [--value VALUE] [--header-name HEADER_NAME]
                        [--header-template HEADER_TEMPLATE] [--ttl TTL]

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
  --service SERVICE     Target service name (e.g. stripe, github)
  --gateway-pubkey GATEWAY_PUBKEY
                        Gateway Ed25519 public key (base64url; legacy 64-char hex
                        still accepted)
  --value VALUE         Secret value (omit to read from stdin)
  --header-name HEADER_NAME
                        HTTP header name (default: Authorization)
  --header-template HEADER_TEMPLATE
                        Header value template (default: 'Bearer {value}')
  --ttl TTL             Secret TTL in seconds (0 = no expiry, default: 0)
```

## `qntm gov`

```text
usage: qntm gov [-h] {propose-floor,propose-add,propose-remove,approve,disapprove} ...

positional arguments:
  {propose-floor,propose-add,propose-remove,approve,disapprove}
    propose-floor       Propose a threshold floor change
    propose-add         Propose adding a member
    propose-remove      Propose removing a member
    approve             Approve a governance proposal
    disapprove          Reject a governance proposal

options:
  -h, --help            show this help message and exit
```

## `qntm gov propose-floor`

```text
usage: qntm gov propose-floor [-h] -c CONVERSATION --floor FLOOR
                              [--required-approvals REQUIRED_APPROVALS]
                              [--expires-in EXPIRES_IN]

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
  --floor FLOOR         New approval floor
  --required-approvals REQUIRED_APPROVALS
                        Approvals required for this proposal (defaults to current
                        governance quorum)
  --expires-in EXPIRES_IN
                        Proposal expiry in seconds (default: 3600)
```

## `qntm gov propose-add`

```text
usage: qntm gov propose-add [-h] -c CONVERSATION
                            [--required-approvals REQUIRED_APPROVALS]
                            [--expires-in EXPIRES_IN]
                            public_key

positional arguments:
  public_key            Member public key (base64url or hex)

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
  --required-approvals REQUIRED_APPROVALS
                        Approvals required for this proposal (defaults to current
                        governance quorum)
  --expires-in EXPIRES_IN
                        Proposal expiry in seconds (default: 3600)
```

## `qntm gov propose-remove`

```text
usage: qntm gov propose-remove [-h] -c CONVERSATION
                               [--required-approvals REQUIRED_APPROVALS]
                               [--expires-in EXPIRES_IN]
                               key_id

positional arguments:
  key_id                Member key ID (base64url or hex)

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
  --required-approvals REQUIRED_APPROVALS
                        Approvals required for this proposal (defaults to remaining-
                        member governance quorum)
  --expires-in EXPIRES_IN
                        Proposal expiry in seconds (default: 3600)
```

## `qntm gov approve`

```text
usage: qntm gov approve [-h] -c CONVERSATION proposal_id

positional arguments:
  proposal_id           Proposal ID to approve

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
```

## `qntm gov disapprove`

```text
usage: qntm gov disapprove [-h] -c CONVERSATION proposal_id

positional arguments:
  proposal_id           Proposal ID to reject

options:
  -h, --help            show this help message and exit
  -c CONVERSATION, --conversation CONVERSATION
                        Conversation ID or prefix
```

## `qntm name`

```text
usage: qntm name [-h] {set,list,remove} ...

positional arguments:
  {set,list,remove}
    set              Assign a local name to an identity (by KID)
    list             List all local names
    remove           Remove a local name

options:
  -h, --help         show this help message and exit
```

## `qntm name set`

```text
usage: qntm name set [-h] kid_or_ref local_name

positional arguments:
  kid_or_ref  Key ID (hex) or short prefix
  local_name  Local nickname

options:
  -h, --help  show this help message and exit
```

## `qntm name list`

```text
usage: qntm name list [-h]

options:
  -h, --help  show this help message and exit
```

## `qntm name remove`

```text
usage: qntm name remove [-h] name

positional arguments:
  name        Name to remove

options:
  -h, --help  show this help message and exit
```

## `qntm ref`

```text
usage: qntm ref [-h] short_prefix

positional arguments:
  short_prefix  Short hex prefix

options:
  -h, --help    show this help message and exit
```

## `qntm version`

```text
usage: qntm version [-h]

options:
  -h, --help  show this help message and exit
```
