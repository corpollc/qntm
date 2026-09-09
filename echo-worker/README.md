# Public echo bot

The README demo is a shared public conversation. A Cloudflare cron runs once a minute, reads signed native QSP text messages from the relay, and posts encrypted replies. Use `qntm recv CONVERSATION --watch` to wait for the reply. The public invite is unsuitable for private content.

The Worker handles at most ten replies per conversation per tick and resumes deferred input using per-envelope relay sequences. Encrypted response bytes are cached in KV for seven days so an interrupted delivery can reuse the same message ID. Cursor writes occur once per tick. KV is eventually consistent, so this demonstration is not an exactly-once delivery service.

Only `/healthz` is exposed over HTTP. Public `/trigger` and `/replay` diagnostics were removed because they could disclose conversation content; plaintext is not logged. Unsigned legacy bridge envelopes and non-text control messages are not echoed.

Configuration is in `wrangler.toml`. Existing identity and conversation secrets must be preserved across deployments. Tagged releases deploy through `deploy-echo.yml` after the complete release gate. Local cron tests use Wrangler's development-only `/__scheduled` route; that route is not part of the production Worker.

Run `cd integration && npm run test:readme` from the repository root. It includes a real local echo Worker and relay round trip, authenticated replies, deferred batches, failed-send recovery, self-message suppression, and diagnostic route rejection. After production deployment, repeat the public README example and confirm the exact marker returns under the bot's signature.
