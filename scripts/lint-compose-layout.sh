#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Guards the layered integration-compose layout against bloat regrowth:
#  - no new standalone docker-compose-*.yml (suites layer over compose-base.yml;
#    the allowlist holds the historical exceptions)
#  - no obi service re-declared in suite/family overlays beyond the known
#    residual stubs (obi is configured from Go via docker.OBI)

set -euo pipefail

DIR="internal/test/integration"
ALLOW_STANDALONE=(
    docker-compose-aerospike.yml
    docker-compose-error-test.yml
    docker-compose-otlp-uds.yml
)
# suites whose obi stub carries keys the docker.OBI struct does not model
# (custom image/build, entrypoint, cgroup, networks, container_name, working_dir)
ALLOW_OBI_STUB=(
    compose-base.yml
    compose-suite-elasticsearch.yml
    compose-suite-java-dist.yml
    compose-suite-java-kafka-400-lb.yml
    compose-suite-java-kafka-400-tls.yml
    compose-suite-java-kafka-400.yml
    compose-suite-java-vthreads.yml
    compose-suite-nodejs-dist.yml
    compose-suite-php-fpm.yml
    compose-suite-php-fpm-sock.yml
)

fail=0

for f in "${DIR}"/docker-compose*.yml; do
    b=$(basename "$f")
    ok=0
    for a in "${ALLOW_STANDALONE[@]}"; do [ "$b" = "$a" ] && ok=1; done
    if [ "$ok" = 0 ]; then
        echo "lint-compose-layout: new standalone compose file '$b' — layer a compose-suite-*.yml over compose-base.yml instead" >&2
        fail=1
    fi
done

for f in "${DIR}"/compose-*.yml; do
    b=$(basename "$f")
    grep -q '^  obi:' "$f" || continue
    ok=0
    for a in "${ALLOW_OBI_STUB[@]}"; do [ "$b" = "$a" ] && ok=1; done
    if [ "$ok" = 0 ]; then
        echo "lint-compose-layout: '$b' re-declares the obi service — configure obi from Go via docker.OBI" >&2
        fail=1
    fi
done

exit $fail
