#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Generate the telemetry-coverage denominator from the OBI registry under
# `schemas/obi/`: every signal the registry declares and, for each, the
# attributes it declares with their requirement level.
#
# This is a pure function of the registry and its upstream pin — nothing here
# reads emitted telemetry. `cmd/obi-weaver-coverage` intersects the model with
# the `observed` sections of the archived live-check reports.
#
# The registry is mounted at `/obi-registry` and passed as an absolute path.
# weaver prunes a dot-prefixed registry root as a hidden directory, so a
# relative `--registry .` resolves to an empty registry and every signal
# silently disappears from the denominator. The working directory is the
# registry root because the manifest's `registry_path` for the pre-fetched
# upstream copy resolves relative to the working directory.
#
# Usage: weaver-coverage-model.sh <oci-bin> <weaver-image> <registry-host-path> <out-dir>
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $(basename "$0") <oci-bin> <weaver-image> <registry-host-path> <out-dir>" >&2
  exit 2
fi

OCI_BIN="$1"
WEAVER_IMAGE="$2"
REGISTRY_PATH="$3"
OUT_DIR="$4"

mkdir -p "$OUT_DIR"
OUT_ABS="$(cd "$OUT_DIR" && pwd)"

$OCI_BIN run --rm \
  -v "${REGISTRY_PATH}:/obi-registry:ro" \
  -v "${OUT_ABS}:/out" \
  -w /obi-registry \
  "$WEAVER_IMAGE" registry generate \
    --registry /obi-registry \
    --v2=true \
    --templates /obi-registry/.coverage_templates \
    coverage-model /out

MODEL="$OUT_ABS/coverage-model.json"
if [ ! -s "$MODEL" ]; then
  echo "weaver-coverage-model: $MODEL was not produced" >&2
  exit 1
fi

# A registry that resolved to nothing still produces well-formed but empty
# sections, which would read downstream as "everything is covered" rather than
# as a broken run. Fail here instead.
spans=$(jq '.spans | length' "$MODEL")
metrics=$(jq '.metrics | length' "$MODEL")
if [ "$spans" -eq 0 ] && [ "$metrics" -eq 0 ]; then
  echo "weaver-coverage-model: $MODEL declares no spans and no metrics" >&2
  exit 1
fi

echo "weaver-coverage-model: $spans span types, $metrics metrics -> $MODEL"
