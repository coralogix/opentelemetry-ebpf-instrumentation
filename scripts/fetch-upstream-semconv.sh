#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Pre-fetch the upstream OpenTelemetry semantic-conventions registry into
# `schemas/obi/.deps/` so weaver doesn't have to clone it on every container
# start. Without this, weaver's `live-check` resolves the dependency declared
# in `schemas/obi/manifest.yaml` over the network, which can take 30-60 s on
# a cold CI runner and trips the otelcol→weaver healthcheck dependency.
#
# The GenAI conventions (`gen_ai.*`, `mcp.*`, `openai.*`) live in the separate
# semantic-conventions-genai registry, which has no tagged releases. Weaver
# does not resolve a dependency's own dependencies, so when the manifest's
# `registry_path` carries a `-genai-<sha>` suffix, that registry's model is
# merged into the upstream model in place of the deprecated GenAI stubs and
# OBI depends on the merged registry.
#
# Both pins are parsed out of `manifest.yaml` so there's a single source of
# truth.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/schemas/obi/manifest.yaml"
DEPS_DIR="$REPO_ROOT/schemas/obi/.deps"

VERSION=$(grep -oE '(upstream-v|@v)[0-9]+\.[0-9]+\.[0-9]+' "$MANIFEST" \
  | head -1 \
  | sed -E 's|.*v||')
if [ -z "$VERSION" ]; then
  echo "fetch-upstream-semconv: could not extract version from $MANIFEST" >&2
  exit 1
fi

GENAI_REF=$(grep -oE "upstream-v${VERSION//./\\.}-genai-[0-9a-f]{7,40}" "$MANIFEST" \
  | head -1 \
  | sed -E 's|.*-genai-||' || true)

NAME="upstream-v$VERSION"
if [ -n "$GENAI_REF" ]; then
  NAME="$NAME-genai-$GENAI_REF"
fi
TARGET="$DEPS_DIR/$NAME"
if [ -d "$TARGET/model" ]; then
  exit 0
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

fetch() {
  curl -fsSL \
    --connect-timeout 15 \
    --retry 5 \
    --retry-delay 2 \
    --retry-all-errors \
    --retry-max-time 180 \
    -o "$1" \
    "$2"
}

echo "fetch-upstream-semconv: fetching v$VERSION into $TARGET/model"
fetch "$TMPDIR/semconv.tar.gz" \
  "https://github.com/open-telemetry/semantic-conventions/archive/refs/tags/v${VERSION}.tar.gz"
tar -xzf "$TMPDIR/semconv.tar.gz" -C "$TMPDIR" --strip-components=1 "semantic-conventions-${VERSION}/model"

if [ -n "$GENAI_REF" ]; then
  echo "fetch-upstream-semconv: merging semantic-conventions-genai@$GENAI_REF"
  mkdir -p "$TMPDIR/genai"
  fetch "$TMPDIR/genai.tar.gz" \
    "https://github.com/open-telemetry/semantic-conventions-genai/archive/${GENAI_REF}.tar.gz"
  tar -xzf "$TMPDIR/genai.tar.gz" -C "$TMPDIR/genai" --strip-components=1
  rm -rf "$TMPDIR/model/gen-ai" "$TMPDIR/model/mcp" "$TMPDIR/model/openai"
  for dir in "$TMPDIR/genai/model"/*/; do
    cp -R "${dir%/}" "$TMPDIR/model/"
  done
fi

rm -rf "${DEPS_DIR:?}"/upstream-v*
mkdir -p "$TARGET"
mv "$TMPDIR/model" "$TARGET/model"
