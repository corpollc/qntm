# Spec-First Workflow

`docs/QSP-v*.md` is the source of truth for protocol behavior. Client code follows the spec, not the other way around.

## Rules

1. If wire behavior, crypto derivation, message validation, or transport semantics change, update or add the versioned spec in `docs/` first.
2. Keep `SPEC_VERSION` aligned across:
   - `client/src/constants.ts`
   - `client/package.json` (`qntmSpecVersion`)
   - `python-dist/src/qntm/constants.py`
   - `python-dist/pyproject.toml` (`[tool.qntm].spec-version`)
3. Regenerate shared vectors after any spec-affecting change:

```bash
go run ./crosstest/generate_vectors.go > client/tests/vectors.json
```

4. Update both client suites that consume the shared vectors:
   - `client/tests/cross-client.test.ts`
   - `python-dist/tests/test_cross_client.py`
5. Only after the spec and vectors are updated should client implementation changes land.

## Versioning Guidance

- `SPEC_VERSION` is the human-readable spec label, for example `QSP-v1.1`.
- `PROTOCOL_VERSION` is the numeric wire field embedded in invites and envelopes.
- A spec change may update `SPEC_VERSION` without changing `PROTOCOL_VERSION` if the wire format is still compatible.
- A wire-incompatible change must update both the versioned spec document and `PROTOCOL_VERSION`.

## Minimum Verification

```bash
cd client && npm test
cd python-dist && uv run python -m pytest
```

If vectors changed, both suites must pass in the same commit as the spec update.
