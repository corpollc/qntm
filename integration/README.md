# Relay runtime acceptance

`npm run test:relay` runs the relay checks. The real relay suite builds the
Worker with `wrangler deploy --dry-run`, then serves that bundle through a direct
Miniflare/workerd listener. Wrangler reads the deployed configuration and
converts its bindings, compatibility settings and SQLite migrations; the test
supplies local variables and an isolated persistence directory. No remote
Worker is deployed.

The direct listener avoids Wrangler's additional development ProxyWorker and
its [five-second HTTP keep-alive race](https://github.com/cloudflare/workers-sdk/issues/14641).
That race reproduced the CI `HTTP 500: Error: Network connection lost` without
reaching the relay's error handler or assigning the failed POST a sequence.
The fixture does not retry POSTs. The idle-boundary regression checks every
response, then replays exact bytes and sequence numbers to detect missing or
duplicate delivery. Native WebSockets, contact welcomes, Python/TypeScript
journeys, process restart and real retention alarms run against this listener.

To investigate the upstream proxy with the same regression, run from this
directory after installing the repository's test dependencies:

```sh
QNTM_RELAY_DEV_PROXY=1 WRANGLER_LOG=debug npx vitest run relay-worker.test.ts --testNamePattern='idle-connection boundary'
```

The proxy failure depends on host timing; an individual passing control run
does not establish that it is fixed. Other client journeys which explicitly
start `wrangler dev` still exercise that development proxy.

Runtime output, Wrangler's internal log, test timing and idle-boundary responses
are written under `integration/test-results/qntm-relay-acceptance-*`. On failure,
the stopped fixture's runtime storage is retained too. This contains synthetic
test envelopes and relay metadata; it excludes the CLI identity profiles,
Wrangler registry and credentials. CI uploads this directory on failure.
Idle-boundary diagnostics retain the underlying fetch error, Node/Undici version
and complete relay replay before asserting success, so an ambiguous response can
be compared with stored delivery. Each POST is also attributed, through Node's
undici diagnostics channels, to the socket that carried it: whether that socket
was reused, its idle time since the previous completed response, when response
headers and trailers arrived, and connection opens and closes, together with
event-loop stalls in the test process (`idle-boundary-transport.json`). A
failed POST can then be classified as a stale reused socket, a slow relay or a
client-side stall from timestamps rather than by inference. Native callback diagnostics distinguish the
injected application failure from transport errors and record callback attempts,
successful delivery, the client's close() calls and the close events undici
reported. The reported code can be 1006 on Node's bundled undici even though
the relay echoed 4000: the relay compresses frames, undici inflates them
asynchronously, and a Close echo still queued behind that inflate when the TCP
connection ends is never parsed (local wire captures; CI only observed the
1006). The native test therefore asserts the close() call, which proves the
client's invocation and not wire bytes. The relay's close handshake itself is
checked by a separate raw TCP WebSocket test that requests no extensions,
sends a masked Close and parses the exact Close code, reason and FIN the relay
returns, recorded in `raw-close-handshake.json`.
