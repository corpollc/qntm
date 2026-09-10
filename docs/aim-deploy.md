# AIM browser deployment and recovery

The browser is a static Cloudflare Pages application. Its deployment is independent of Python/npm publication, relay storage and the charter VM. Use [the release procedure](deployment-checklist.md) when shipping all surfaces together.

## Project and credentials

| Setting | Value or source |
| --- | --- |
| Pages project | `qntm-aim` |
| Production branch in the upload command | `main` |
| Public browser | `https://chat.corpo.llc` |
| Additional public browser address | `https://web.qntm.corpo.llc` |
| Pages production address | `https://qntm-aim.pages.dev` |
| Source and output | `ui/aim-chat/` and `ui/aim-chat/dist/` |
| Cloudflare account | GitHub repository secret `CLOUDFLARE_ACCOUNT_ID`; use the account that owns `qntm-aim` |
| Upload credential | GitHub repository secret `CLOUDFLARE_API_TOKEN` |
| Workflow | [Deploy AIM UI](../.github/workflows/deploy-aim.yml) |

The upload token needs **Account → Cloudflare Pages → Edit** for that account. Cloudflare documents where to find the account ID and configure the two GitHub secrets in its [Direct Upload CI guide](https://developers.cloudflare.com/pages/how-to/use-direct-upload-with-continuous-integration/). Keep credential values in the secret store; none belong in the static build. The browser does not need the gateway vault key or metrics-read token.

As of September 10, 2026 UTC, all three production addresses above serve the same application. Both custom domains are attached to `qntm-aim` and have proxied CNAME records pointing to `qntm-aim.pages.dev`. Uploading assets alone does not configure DNS or attach a new hostname. Account-side Git integration/build settings require a separate audit; the behavior below describes the checked-in GitHub workflows.

## Custom domains and existing profiles

The additional `web.qntm.corpo.llc` address does not redirect existing users from `chat.corpo.llc`. Browser identities, conversation keys and history belong to each origin's local storage; opening another address starts with separate storage. Keep using the address where your profile lives. To move intentionally, export a password-encrypted backup there, import it at the new address, review the replacement preview and verify your conversations before removing the original profile. The Pages server does not copy or synchronize profiles between addresses.

Add a hostname through **Workers & Pages → qntm-aim → Custom domains** before changing DNS. Cloudflare creates the CNAME for a zone in the same account and provisions its certificate. Follow the [Pages custom-domain guide](https://developers.cloudflare.com/pages/configuration/custom-domains/); do not treat DNS resolution alone as successful TLS activation.

At activation on September 10, 2026, `web.qntm.corpo.llc` returned verified HTTPS 200 from the operator Mac and the exe.dev monitor host. HTML, JavaScript and CSS hashes matched the existing production addresses. HTTP redirected to HTTPS; HTML required revalidation and versioned JS/CSS responses on the custom domains used a four-hour cache lifetime. The served certificate was from Let's Encrypt YE1, covered the exact hostname and expired December 8, 2026. These are observed deployment properties, not permanent provider guarantees.

The [external monitor](relay-monitoring.md#external-checks) checks both browser hostnames every minute and has HTTPS-failure and certificate-expiry rules. These probes request only the public root page; they do not open profiles or replace the browser messaging check below. Outbound paging recipients still require configuration.

If issuance or renewal fails, inspect the actual issuer, challenge status and CAA records at the hostname and its ancestors. `qntm.corpo.llc` points to GitHub Pages, whose CAA policy permits Let's Encrypt but excludes Google Trust Services. No additional CAA record was needed for this Pages certificate. A future issuer change may require explicit authorization; see the [relay TLS incident and checks](relay-operations.md#certificate-authority-authorization) and Cloudflare's CAA guidance in the custom-domain guide. Avoid repeatedly detaching and reattaching a domain while validation is pending.

## Deploy a tested commit

Pushing `main` runs CI. A version tag triggers the coordinated release; AIM waits for the successful release gate on that exact tag and commit. For a browser update between package releases:

```sh
gh workflow run deploy-aim.yml --ref BRANCH_OR_TAG
gh run list --workflow deploy-aim.yml --limit 5
gh run view RUN_ID --json headSha,status,conclusion,jobs
```

Replace the placeholders with the reviewed ref and returned run ID. Check `headSha` against the intended commit. The manual workflow runs the complete reusable CI suite before uploading. The deployment job must also succeed; a green test job alone does not establish that the browser changed.

**Every manual invocation of this workflow deploys to production**, including an invocation against a feature branch. The selected ref determines the source; the upload always uses `--branch=main`. Production uploads are serialized and do not cancel an active deployment. If more than one is queued, inspect their refs before leaving them to run.

The build installs locked dependencies with `npm ci`, builds `client` first, then builds `ui/aim-chat`. Vite uses `/` as its base and the application uses hash routing. The workflow uploads only `dist/`, including the checked-in response-header configuration copied into the build. Its upload command is:

```sh
wrangler pages deploy dist --project-name=qntm-aim --branch=main --commit-hash=COMMIT_SHA --commit-dirty=true
```

The command runs from `ui/aim-chat` inside the gated workflow. `--commit-dirty=true` marks the deployment's working tree as dirty; the checkout and recorded commit identify the tested source. Use the workflow instead of a local production upload that bypasses its gate. A browser-only deployment leaves package versions unchanged, so the version displayed by the UI is not sufficient to identify a hotfix.

## Preview behavior

The repository does not create Pages previews for pull requests or ordinary branch pushes. Use the local development/preview commands in the [browser README](../ui/aim-chat/README.md). A manual production workflow is not a preview mechanism.

Cloudflare supports separate preview deployments, but those are not configured by this workflow. Provider previews are public unless access controls are added; an unlisted address is not protection for conversation keys. If a preview is created separately, use a disposable browser profile and synthetic conversations. See [Cloudflare preview behavior](https://developers.cloudflare.com/pages/configuration/preview-deployments/) and the [metadata inventory](metadata-privacy.md).

## Verify production

1. Record the GitHub run URL, successful deployment, source SHA and Pages deployment URL. Compare the live HTML and referenced JavaScript/CSS with the build from that commit; check all three production addresses over verified HTTPS.
2. Inspect response headers, including the content-security policy, against `ui/aim-chat/public/_headers`. An HTTP 200 alone does not verify that the expected application or policy is served.
3. In a disposable browser profile, exercise the changed feature and an encrypted round trip with a separate CLI or TypeScript identity. For invite changes, confirm the copied link uses a fragment, review the join, reload and verify receive/replay. Keep real invite secrets out of screenshots, URLs supplied to HTTP tools and logs.
4. Check the browser console and the [relay dashboard](relay-monitoring.md). The external relay probe verifies transport; it does not exercise the deployed browser bundle.

## Roll back

Choose a previously verified production deployment whose browser storage format and security behavior remain compatible. In Cloudflare, open **Workers & Pages → qntm-aim → Deployments**, find that deployment's actions menu and choose **Rollback to this deployment**. Confirm the source/deployment identity, then repeat the production verification above. Cloudflare permits rollback to successful production deployments; previews are not rollback targets. [Cloudflare rollback guide](https://developers.cloudflare.com/pages/configuration/rollbacks/).

Alternatively, dispatch `deploy-aim.yml` against a previous compatible ref that contains the manual workflow and let its complete gate run. Do not move an existing release tag. Rolling back static assets does not restore browser storage, revoke exposed invites, change gateway/relay data or downgrade published packages. Avoid restoring the old query-based invite emitter when addressing an unrelated regression; prefer a compatible fix forward.
