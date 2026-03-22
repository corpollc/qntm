# Releasing

Published artifacts:

- npm: `@corpollc/qntm` from `client/`
- PyPI: `qntm` from `python-dist/`

For the full hosted deploy sequence across workers, UI, npm, and PyPI, use [Deployment Checklist](deployment-checklist.md). This file only covers package release mechanics.

## Prerequisites

- GitHub Actions must be configured as a trusted publisher for the npm package `@corpollc/qntm`.
- GitHub Actions must be configured as a trusted publisher for the PyPI project `qntm`.
- Release tags use the form `vX.Y.Z`.

## Local preflight

```bash
python3 scripts/set_release_version.py 0.4.2
cd client && npm test && npm run build && npm pack --dry-run
cd python-dist && uv run python -m pytest && uv build
cd ui/aim-chat && npm test && npm run build
cd ui/tui && npm run build
```

## Publish flow

1. Run `python3 scripts/set_release_version.py X.Y.Z`.
2. Commit the version bump.
3. Push `main`.
4. Create and push tag `vX.Y.Z`.
5. GitHub Actions publishes `@corpollc/qntm`, publishes `qntm`, and creates the GitHub release.

## Notes

- The version updater keeps `client/package.json`, `client/package-lock.json`, the file-linked UI lockfiles, `python-dist/pyproject.toml`, and `python-dist/src/qntm/__init__.py` aligned.
- The npm package name remains `@corpollc/qntm`; do not switch scopes unless the `qntm` org is actually available.
