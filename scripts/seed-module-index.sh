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
# seed-module-index.sh is a one-time, maintainer-run helper that seeds the Go
# module proxy version index (the "module-index" utility release) with the full
# history of existing v* semver tags.
#
# Going forward, .github/workflows/module_index.yml appends each newly published
# release tag automatically; this script only bootstraps the initial list.
#
# Seeding the full tag history is correct: pre-cutover versions (those without a
# published module zip asset) resolve through proxy.golang.org passthrough on the
# vanity redirector, so listing them keeps `go list -m -versions` complete.
#
# Requires: git, gh (authenticated with contents:write on the repository).
set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

PROGNAME="$(basename "$0")"
readonly PROGNAME

INDEX_RELEASE="module-index"
readonly INDEX_RELEASE

usage() {
  cat <<EOF
Usage: $PROGNAME [--dry-run] [--help|-h]

Seeds the '${INDEX_RELEASE}' utility release's list.txt with all existing v*
semver tags. Run once by a maintainer with an authenticated gh CLI.

Options:
  --dry-run   Build and print list.txt but do not create/update the release.
  -h, --help  Show this help message.
EOF
}

log_info() { printf '%s\n' "$1"; }
die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

main() {
  local dry_run="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) dry_run="1" ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done

  require_cmd git
  require_cmd sort
  [[ "$dry_run" == "1" ]] || require_cmd gh

  local work_dir
  work_dir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$work_dir'" EXIT
  local list_file="${work_dir}/list.txt"

  # List all v[0-9]* tags, semver-sorted and unique.
  git tag --list 'v[0-9]*' | sort -V -u > "${list_file}"

  if [[ ! -s "${list_file}" ]]; then
    die "no v* tags found; nothing to seed"
  fi

  log_info "### Module index will contain $(wc -l < "${list_file}" | tr -d ' ') versions:"
  cat "${list_file}"

  if [[ "$dry_run" == "1" ]]; then
    log_info "### --dry-run set: not touching the ${INDEX_RELEASE} release"
    exit 0
  fi

  if gh release view "${INDEX_RELEASE}" >/dev/null 2>&1; then
    log_info "### Updating existing ${INDEX_RELEASE} release"
  else
    log_info "### Creating ${INDEX_RELEASE} utility release"
    gh release create "${INDEX_RELEASE}" \
      --notes "Utility release holding the Go module proxy version index. Do not delete." \
      --latest=false
  fi

  gh release upload "${INDEX_RELEASE}" "${list_file}" --clobber
  log_info "### Seeded ${INDEX_RELEASE} list.txt"
}

main "$@"
