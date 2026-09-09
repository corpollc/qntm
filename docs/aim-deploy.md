# AIM browser deployment and recovery

The browser is a static Cloudflare Pages application. Its deployment is independent of Python/npm publication, relay storage and the charter VM. Use [the release procedure](deployment-checklist.md) when shipping all surfaces together.

## Project and credentials

| Setting | Value or source |
| --- | --- |
| Pages project | `qntm-aim` |
| Production branch in the upload command | `main` |
| Public browser | `https://chat.corpo.llc` |
| Pages production address | `https://qntm-aim.pages.dev` |
| Source and output | `ui/aim-chat/` and `ui/aim-chat/dist/` |
| Cloudflare account | GitHub repository secret `CLOUDFLARE_ACCOUNT_ID`; use the account that owns `qntm-aim` |
| Upload credential | GitHub repository secret `CLOUDFLARE_API_TOKEN` |
| Workflow | [Deploy AIM UI](../.github/workflows/deploy-aim.yml) |

The upload token needs **Account → Cloudflare Pages → Edit** for that account. Cloudflare documents where to find the account ID and configure the two GitHub secrets in its [Direct Upload CI guide](https://developers.cloudflare.com/pages/how-to/use-direct-upload-with-continuous-integration/). Keep credential values in the secret store; none belong in the static build. The browser does not need the gateway vault key or metrics-read token.

As of September 9, 2026, the two production addresses above serve the application. `web.qntm.corpo.llc` remains a separate, unfinished custom-domain cutover. Uploading assets does not configure DNS or attach that hostname. Account-side Git integration/build settings require a separate audit; the behavior below describes the checked-in GitHub workflows.

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

The command runs from `ui/aim-chat` inside the gated workflow. `--commit-dirty=true` permits generated build output; the checkout and recorded commit still identify the tested source. Use the workflow instead of a local production upload that bypasses its gate. A browser-only deployment leaves package versions unchanged, so the version displayed by the UI is not sufficient to identify a hotfix.

## Preview behavior

The repository does not create Pages previews for pull requests or ordinary branch pushes. Use the local development/preview commands in the [browser README](../ui/aim-chat/README.md). A manual production workflow is not a preview mechanism.

Cloudflare supports separate preview deployments, but those are not configured by this workflow. Provider previews are public unless access controls are added; an unlisted address is not protection for conversation keys. If a preview is created separately, use a disposable browser profile and synthetic conversations. See [Cloudflare preview behavior](https://developers.cloudflare.com/pages/configuration/preview-deployments/) and the [metadata inventory](metadata-privacy.md).

## Verify production

1. Record the GitHub run URL, successful deployment, source SHA and Pages deployment URL. Compare the live HTML and referenced JavaScript/CSS with the build from that commit; check both production addresses over verified HTTPS.
2. Inspect response headers, including the content-security policy, against `ui/aim-chat/public/_headers`. An HTTP 200 alone does not verify that the expected application or policy is served.
3. In a disposable browser profile, exercise the changed feature and an encrypted round trip with a separate CLI or TypeScript identity. For invite changes, confirm the copied link uses a fragment, review the join, reload and verify receive/replay. Keep real invite secrets out of screenshots, URLs supplied to HTTP tools and logs.
4. Check the browser console and the [relay dashboard](relay-monitoring.md). The external relay probe verifies transport; it does not exercise the deployed browser bundle.

## Roll back

Choose a previously verified production deployment whose browser storage format and security behavior remain compatible. In Cloudflare, open **Workers & Pages → qntm-aim → Deployments**, find that deployment's actions menu and choose **Rollback to this deployment**. Confirm the source/deployment identity, then repeat the production verification above. Cloudflare permits rollback to successful production deployments; previews are not rollback targets. [Cloudflare rollback guide](https://developers.cloudflare.com/pages/configuration/rollbacks/).

Alternatively, dispatch `deploy-aim.yml` against a previous compatible ref that contains the manual workflow and let its complete gate run. Do not move an existing release tag. Rolling back static assets does not restore browser storage, revoke exposed invites, change gateway/relay data or downgrade published packages. Avoid restoring the old query-based invite emitter when addressing an unrelated regression; prefer a compatible fix forward.
