# Autonomy Configuration — qntm
# The Founder checks this before any external action.
# Peter/Pepper can update this file to change permissions.
# Last updated: 2026-03-21

## Code
- branch: ALLOWED
- merge-to-main: ALLOWED — merge freely, deploy when ready
- force-push: DENIED
- delete-branch: ALLOWED — after merge
- release/tag: REQUIRES_APPROVAL

## Infrastructure
- cloudflare-workers-dev: ALLOWED
- cloudflare-workers-deploy: ALLOWED — deploy fixes and updates freely
- cloudflare-kv: ALLOWED (read/write)
- localhost/devserver: ALLOWED
- service-signups-free-tier: ALLOWED — store all creds with Pepper

## External Services — Sandboxes
- any-test-environment: ALLOWED

## External Services — Live/Production
- any-vendor-live-paid: DENIED

## Package Publishing
- npm-publish: REQUIRES_APPROVAL
- pypi-publish: REQUIRES_APPROVAL

## Communications
- qntm-to-pepper: ALLOWED (once available)
- github-issues-prs: ALLOWED
- whatsapp-direct-to-peter: DENIED — go through Pepper
- email-send: DENIED
- any-public-post: DENIED

## Permission Levels
- ALLOWED = do it, log it in FOUNDER-STATE.md
- REQUIRES_APPROVAL = write to Blockers in state file, Pepper will relay
- DENIED = never do this, period
