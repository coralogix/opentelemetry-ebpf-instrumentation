#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# Emit the telemetry-coverage denominator straight from the OBI registry: the
# metric names and attributes the schema resolves to WITHOUT
# --include-unreferenced, i.e. exactly what OBI declares plus what it `ref`s
# from upstream. This is OBI's OTLP contract, and it is the single source of
# truth the coverage gate measures against (see weaver-coverage-aggregate.sh).
#
# Prometheus-only signals still declared in the schema for documentation
# (obi.bpf.*, obi.otel.*, … — imetrics has no OTLP reporter) never reach
# weaver, so they are dropped here: coverage is an OTLP question.
#
# Usage: weaver-schema-denominator.sh <oci-bin> <weaver-image> <registry-host-path> <out-json>
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $(basename "$0") <oci-bin> <weaver-image> <registry-host-path> <out-json>" >&2
  exit 2
fi

OCI_BIN="$1"
WEAVER_IMAGE="$2"
REGISTRY_PATH="$3"
OUT_JSON="$4"

# Metric names that OBI emits over Prometheus only (never OTLP), so weaver never
# observes them and they must not be part of the OTLP coverage denominator.
# Matched as a prefix set; the OTLP obi.* signals are obi.network.* / obi.stat.*.
PROM_ONLY_RE='^obi\.(bpf|ebpf|otel|kube|avoided|instrumentation|instrumented|internal)\.'

resolved=$($OCI_BIN run --rm \
  -v "${REGISTRY_PATH}:/obi-registry:ro" \
  -w /obi-registry \
  "$WEAVER_IMAGE" registry resolve \
    --registry /obi-registry \
    --format json 2>/dev/null) || true

if ! printf '%s' "$resolved" | jq empty >/dev/null 2>&1; then
  echo "weaver registry resolve did not produce parseable JSON" >&2
  exit 1
fi

printf '%s' "$resolved" | jq --arg prom "$PROM_ONLY_RE" '
  (.groups // .registry.groups // []) as $g
  | {
      metric_names: (
        [ $g[] | select(.type == "metric") | .metric_name ]
        | map(select(test($prom) | not))
        | unique
      ),
      metric_attributes: (
        [ $g[] | .attributes[]? | .name // .id // .ref ]
        | map(select(. != null))
        | unique
      )
    }
' > "$OUT_JSON"

echo "schema denominator: $(jq -r '.metric_names|length' "$OUT_JSON") metrics, $(jq -r '.metric_attributes|length' "$OUT_JSON") attributes -> $OUT_JSON"
