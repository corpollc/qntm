# Releasing

Published artifacts:

- npm: `@qntm/client` from `client/`
- PyPI: `qntm` from `python-dist/`

## Prerequisites

- GitHub Actions must be configured as a trusted publisher for the npm package `@qntm/client`.
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
5. GitHub Actions publishes `@qntm/client`, publishes `qntm`, and creates the GitHub release.

## Notes

- The version updater keeps `client/package.json`, `client/package-lock.json`, the file-linked UI lockfiles, `python-dist/pyproject.toml`, and `python-dist/src/qntm/__init__.py` aligned.
- If `@corpollc/qntm` still exists on npm, deprecate it after the first `@qntm/client` release so consumers do not pick up the old package name.
