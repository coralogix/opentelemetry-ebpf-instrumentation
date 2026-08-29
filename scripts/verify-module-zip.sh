#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# verify-module-zip.sh is the release gate that prevents publishing a Go module
# zip that does not compile. It lays out a file:// GOPROXY from the dist module
# assets (obi-<version>.module.{zip,mod,info}), creates a throwaway consumer
# module that imports the OBI collector entrypoint package, then resolves and
# builds the module through that proxy. A non-zero exit means the module zip is
# not consumable and must not be published.
set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

PROGNAME="$(basename "$0")"
readonly PROGNAME

DEFAULT_RELEASE_DIR="./dist"
readonly DEFAULT_RELEASE_DIR

MODULE_PATH="go.opentelemetry.io/obi"
readonly MODULE_PATH

# Collector entrypoint package imported by the throwaway consumer. The OBI
# module exposes its OpenTelemetry Collector factory at this import path
# (collector/factory.go declares `package collector // import
# "go.opentelemetry.io/obi/collector"`).
CONSUMER_IMPORT="go.opentelemetry.io/obi/collector"
readonly CONSUMER_IMPORT

usage() {
  cat <<EOF
Usage: $PROGNAME --release-version <version> [--release-dir <dir>] [--skip-build] [--help|-h]

Verifies that the Go module proxy assets in <dir> resolve and build through a
file:// GOPROXY laid out from those assets.

Options:
  --release-version  Module version to verify (e.g. v1.2.3). Required.
  --release-dir      Directory holding the module assets (default: ./dist)
  --skip-build       Resolve the module (go get) but skip the cross-compile build.
                     Useful where generated BPF code is absent and the build
                     cannot succeed; verifies only the proxy/resolution mechanics.
  -h, --help         Show this help message.
EOF
}

log_info() { printf '%s\n' "$1"; }
log_error() { printf 'ERROR: %s\n' "$1" >&2; }
die() { log_error "$1"; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

RELEASE_VERSION=""
RELEASE_DIR="$DEFAULT_RELEASE_DIR"
SKIP_BUILD="0"

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --release-version)
        shift; [[ $# -gt 0 ]] || die "missing value for --release-version"
        RELEASE_VERSION="$1" ;;
      --release-dir)
        shift; [[ $# -gt 0 ]] || die "missing value for --release-dir"
        RELEASE_DIR="$1" ;;
      --skip-build)
        SKIP_BUILD="1" ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        die "unknown argument: $1" ;;
    esac
    shift
  done
  [[ -n "$RELEASE_VERSION" ]] || die "--release-version is required"
}

main() {
  parse_args "$@"

  require_cmd go
  require_cmd mktemp

  local version="$RELEASE_VERSION"
  local dist_dir
  dist_dir="$(cd "$RELEASE_DIR" && pwd)" || die "release dir not found: $RELEASE_DIR"

  local zip_src="$dist_dir/obi-${version}.module.zip"
  local mod_src="$dist_dir/obi-${version}.module.mod"
  local info_src="$dist_dir/obi-${version}.module.info"

  for f in "$zip_src" "$mod_src" "$info_src"; do
    [[ -f "$f" ]] || die "missing module asset: $f"
  done

  local work_dir
  work_dir="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand work_dir now, at trap-setup time.
  trap "rm -rf '$work_dir'" EXIT

  # Lay out a file:// module proxy:
  #   <proxy>/go.opentelemetry.io/obi/@v/{list,<ver>.info,<ver>.mod,<ver>.zip}
  local proxy_dir="$work_dir/proxy"
  local mod_dir="$proxy_dir/${MODULE_PATH}/@v"
  mkdir -p "$mod_dir"
  printf '%s\n' "$version" > "$mod_dir/list"
  cp "$info_src" "$mod_dir/${version}.info"
  cp "$mod_src" "$mod_dir/${version}.mod"
  cp "$zip_src" "$mod_dir/${version}.zip"

  log_info "### Laid out file:// proxy at $proxy_dir"

  # Derive the go directive from the OBI module's go.mod so the throwaway
  # consumer requires at least the same Go version. Otherwise `go get` triggers a
  # toolchain switch (downloading golang.org/toolchain) which the file:// proxy
  # cannot serve. GOTOOLCHAIN=local (set below) additionally pins the running
  # toolchain so the gate uses exactly the toolchain the release was built with.
  local go_directive
  go_directive="$(awk '/^go [0-9]/ {print $2; exit}' "$mod_src")"
  [[ -n "$go_directive" ]] || die "could not read go directive from $mod_src"

  # Throwaway consumer module importing the collector entrypoint.
  local consumer_dir="$work_dir/consumer"
  mkdir -p "$consumer_dir"
  cat > "$consumer_dir/go.mod" <<EOF
module obi-modzip-consumer

go ${go_directive}
EOF
  cat > "$consumer_dir/main.go" <<EOF
package main

import _ "${CONSUMER_IMPORT}"

func main() {}
EOF

  # Resolve and build through the file:// proxy, falling back to the public
  # proxy for transitive dependencies. The OBI module zip is built locally and
  # is not recorded in sum.golang.org, so its checksum-db lookup must be skipped.
  # GONOSUMDB is set as specified; GONOSUMCHECK is its legacy spelling and is set
  # to the same scope. Both are scoped to the OBI module only, so the global sum
  # database stays enabled for transitive dependencies (and any auto-selected Go
  # toolchain).
  #
  # We deliberately do NOT set GOPRIVATE: GOPRIVATE forces direct VCS access for
  # matching modules, bypassing GOPROXY entirely, which would defeat the file://
  # proxy under test (go would attempt to fetch the tag from git and fail with
  # "unknown revision"). GONOSUMDB skips only the checksum-db lookup, which is
  # what we need here.
  #
  # GOFLAGS=-mod=mod lets `go get` populate the throwaway module's go.sum.
  local goproxy="file://${proxy_dir},https://proxy.golang.org"
  export GOPROXY="$goproxy"
  export GONOSUMDB="$MODULE_PATH"
  export GONOSUMCHECK="$MODULE_PATH"
  export GOFLAGS="-mod=mod"
  # Pin to the toolchain provided by the environment (CI installs it from
  # go.mod via actions/setup-go). Avoid a surprise toolchain download masking
  # the gate result; allow override for local runs where the matching toolchain
  # is not installed.
  export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

  log_info "### Resolving ${MODULE_PATH}@${version} via ${goproxy}"
  (
    cd "$consumer_dir"
    go get "${MODULE_PATH}@${version}"
  ) || die "go get ${MODULE_PATH}@${version} failed"

  if [[ "$SKIP_BUILD" == "1" ]]; then
    log_info "### --skip-build set: resolution succeeded, skipping cross-compile build"
    log_info "### Module zip verification PASSED (resolution only)"
    return 0
  fi

  log_info "### Building consumer (GOOS=linux CGO_ENABLED=0 go build ./...)"
  (
    cd "$consumer_dir"
    GOOS=linux CGO_ENABLED=0 go build ./...
  ) || die "consumer build against ${MODULE_PATH}@${version} failed"

  log_info "### Module zip verification PASSED"
}

main "$@"
