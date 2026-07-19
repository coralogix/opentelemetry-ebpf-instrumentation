#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Guards the integration-compose layout against bloat regrowth. Each suite
# owns one docker-compose-*.yml with only its unique services; the obi
# service and the shared infrastructure (otelcol, prometheus, jaeger, weaver)
# are defined once in Go (docker.NewOBI / docker.NewServices in
# internal/test/integration/components/docker/compose.go) and merged in via
# docker.NewStack.

set -euo pipefail

DIR="internal/test/integration"
# bespoke standalone stacks that intentionally carry their own obi + infra
ALLOW_FULL_STACK=(
    docker-compose-error-test.yml
    docker-compose-otlp-uds.yml
)

fail=0

for f in "${DIR}"/compose-*.yml; do
    [ -e "$f" ] || continue
    echo "lint-compose-layout: shared layer file '$(basename "$f")' reintroduced — obi and infra live in Go (docker.NewOBI / docker.NewServices)" >&2
    fail=1
done

for f in "${DIR}"/docker-compose*.yml; do
    b=$(basename "$f")
    ok=0
    for a in "${ALLOW_FULL_STACK[@]}"; do [ "$b" = "$a" ] && ok=1; done
    [ "$ok" = 1 ] && continue
    if grep -qE '^  (obi|otelcol|prometheus|jaeger|weaver):' "$f"; then
        echo "lint-compose-layout: '$b' declares obi or standard infra — configure them from Go (docker.NewOBI / docker.NewServices variants)" >&2
        fail=1
    fi
done

exit $fail
