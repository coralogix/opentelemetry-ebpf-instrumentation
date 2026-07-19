#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Guards the integration-compose layout against bloat regrowth. Suites are
# defined in Go (docker.StdStack / docker.StdOBI in
# internal/test/integration/components/docker/compose.go); a compose-suite-*.yml
# overlay holds only the suite's extra services. In particular:
#  - no new standalone docker-compose-*.yml (the allowlist holds the
#    historical exceptions)
#  - no shared-layer files (compose-base/-infra/-frag-*/-family-*): base obi
#    and infra come from Go, not yml layering
#  - no infra service (otelcol/prometheus/jaeger/weaver) re-declared in
#    overlays: use docker.StdServices() variants in Go instead
#  - no obi service re-declared in overlays: docker.OBI models every field,
#    including custom image/build

set -euo pipefail

DIR="internal/test/integration"
ALLOW_STANDALONE=(
    docker-compose-error-test.yml
    docker-compose-otlp-uds.yml
)

fail=0

for f in "${DIR}"/docker-compose*.yml; do
    b=$(basename "$f")
    ok=0
    for a in "${ALLOW_STANDALONE[@]}"; do [ "$b" = "$a" ] && ok=1; done
    if [ "$ok" = 0 ]; then
        echo "lint-compose-layout: new standalone compose file '$b' — define the suite in Go over docker.StdStack instead" >&2
        fail=1
    fi
done

for f in "${DIR}"/compose-base.yml "${DIR}"/compose-infra.yml "${DIR}"/compose-frag-*.yml "${DIR}"/compose-family-*.yml; do
    [ -e "$f" ] || continue
    echo "lint-compose-layout: shared layer file '$(basename "$f")' reintroduced — base obi and infra live in Go (docker.StdOBI / docker.StdServices)" >&2
    fail=1
done

for f in "${DIR}"/compose-suite-*.yml; do
    b=$(basename "$f")
    if grep -qE '^  (otelcol|prometheus|jaeger|weaver):' "$f"; then
        echo "lint-compose-layout: '$b' re-declares standard infra — customize via docker.StdServices() variants in Go" >&2
        fail=1
    fi
    if grep -q '^  obi:' "$f"; then
        echo "lint-compose-layout: '$b' re-declares the obi service — configure obi from Go via docker.OBI" >&2
        fail=1
    fi
done

exit $fail
