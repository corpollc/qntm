#!/usr/bin/env bash
set -euo pipefail

# Cross-compile qntm Go binary for all supported platforms.
# Usage: ./scripts/build-binaries.sh [version]
#   version defaults to "dev"

VERSION="${1:-dev}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$SCRIPT_DIR/../src/qntm/bin"

mkdir -p "$OUT_DIR"

PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

LDFLAGS="-s -w -X main.version=${VERSION}"

for platform in "${PLATFORMS[@]}"; do
    GOOS="${platform%/*}"
    GOARCH="${platform#*/}"
    output="qntm-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        output="${output}.exe"
    fi

    echo "Building ${output}..."
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
        go build -ldflags "$LDFLAGS" -o "$OUT_DIR/$output" "$PROJECT_ROOT/cmd/qntm/"
done

echo "Done. Binaries in $OUT_DIR:"
ls -lh "$OUT_DIR"/qntm-*
