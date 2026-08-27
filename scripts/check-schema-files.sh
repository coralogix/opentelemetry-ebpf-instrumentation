#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Validate the published OBI telemetry schema files and their consistency with
# the emitted schema_url constant and the weaver registry manifest.
#
# With <oci-bin> and <schemas-image> also:
#   - validates each file with the OpenTelemetry reference schema validator. That
#     validator hardcodes `opentelemetry.io` as the expected schema_url host, so
#     it runs against a copy whose host is substituted; the structure (file
#     format and versions/transformations) is what is being checked.
#   - verifies an already-published version still matches the served copy, since
#     schema files are immutable once published.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA_DIR="${1:-$ROOT/site/schemas/obi}"
OCI_BIN="${2:-}"
SCHEMAS_IMAGE="${3:-}"
BASE_URL="https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi"
SCHEMA_VERSION_FILE="$ROOT/pkg/export/attributes/names/schema_version.go"
MANIFEST="$ROOT/schemas/obi/manifest.yaml"

fail() {
	echo "check-schema-files: $1" >&2
	exit 1
}

url_version() { grep -oE 'schemas/obi/[0-9]+\.[0-9]+\.[0-9]+' "$1" | head -1 | sed 's#.*/##'; }

shopt -s nullglob
count=0
for file in "$SCHEMA_DIR"/*; do
	version="$(basename "$file")"

	echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
		|| fail "$file: name is not a MAJOR.MINOR.PATCH version"

	format="$(grep -E '^file_format:' "$file" | head -1 | sed 's/^file_format:[[:space:]]*//')"
	[ "$format" = "1.1.0" ] || fail "$file: file_format must be 1.1.0 (got '${format:-<missing>}')"

	url="$(grep -E '^schema_url:' "$file" | head -1 | sed 's/^schema_url:[[:space:]]*//')"
	expected="$BASE_URL/$version"
	[ "$url" = "$expected" ] || fail "$file: schema_url '$url' does not match served URL '$expected'"

	grep -Eq "^  $version:" "$file" \
		|| fail "$file: versions: block does not contain an entry for $version"

	count=$((count + 1))
done

[ "$count" -gt 0 ] || fail "no schema files found under $SCHEMA_DIR"

# Release-driven consistency: the emitted schema_url and the manifest must name
# the versions.yaml version, and that version must be published (so it resolves).
version="$(awk '/^  obi:/{o=1} o&&/version:/{v=$2; sub(/^v/,"",v); print v; exit}' "$ROOT/versions.yaml")"
emitted="$(url_version "$SCHEMA_VERSION_FILE")"
manifest_v="$(url_version "$MANIFEST")"

[ -n "$version" ] || fail "could not read the obi version from versions.yaml"
[ -f "$SCHEMA_DIR/$version" ] || fail "versions.yaml is $version but site/schemas/obi/$version is not published (would 404)"
[ "$emitted" = "$version" ] || fail "OBISchemaURL ($emitted) does not match the versions.yaml version ($version)"
[ "$manifest_v" = "$version" ] || fail "manifest schema_url ($manifest_v) does not match the versions.yaml version ($version)"

# Structural validation with the reference validator, when available.
if [ -n "$OCI_BIN" ] && [ -n "$SCHEMAS_IMAGE" ]; then
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	for file in "$SCHEMA_DIR"/*; do
		v="$(basename "$file")"
		sed "s|$BASE_URL/|https://opentelemetry.io/schemas/|" "$file" > "$work/$v"
	done
	if ! out=$("$OCI_BIN" run --rm -v "$work:/schemas:ro,z" "$SCHEMAS_IMAGE" \
			--file "/schemas/$version" --version="$version" 2>&1); then
		echo "check-schema-files: reference validator failed to run:" >&2
		printf '%s\n' "$out" >&2
		exit 1
	fi
	if printf '%s' "$out" | grep -qi "not valid"; then
		echo "check-schema-files: $version is not a valid telemetry schema:" >&2
		printf '%s\n' "$out" >&2
		exit 1
	fi
fi

# Published files are immutable: a version already served must not have changed.
for file in "$SCHEMA_DIR"/*; do
	v="$(basename "$file")"
	served=$(mktemp)
	if curl -fsS --max-time 20 "$BASE_URL/$v" -o "$served" 2>/dev/null; then
		if ! diff -q "$served" "$file" >/dev/null; then
			rm -f "$served"
			echo "check-schema-files: $v differs from the published copy at $BASE_URL/$v;" >&2
			echo "schema files are immutable once published - add a new version instead" >&2
			exit 1
		fi
	fi
	rm -f "$served"
done

echo "check-schema-files: OK ($count published, schema_url = $version)"
