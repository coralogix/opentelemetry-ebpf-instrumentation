#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Aggregate per-suite weaver live-check reports (produced in isolation by each
# integration shard) into a single telemetry-coverage verdict: every metric
# name and metric attribute OBI can emit (the code-derived surface in
# --intended) must have been observed by at least one weaver run across the
# whole matrix.
#
# Each weaver report carries, under .statistics, the seen_registry_* and
# seen_non_registry_* maps (name -> observation count). The union of every
# key with count > 0, across all reports, is the observed set. Coverage is
# then observed vs intended; anything intended but never observed fails the
# gate unless it is listed in --allowlist.
#
# Usage:
#   weaver-coverage-aggregate.sh --in <dir-of-reports> --intended <file> \
#     [--allowlist <file>] [--out-md <file>] [--out-json <file>] [--no-fail]
#
# --in is searched recursively for weaver-report-*.json (the per-suite reports
# archived by the integration harness under testoutput/ and uploaded per shard).

set -euo pipefail

IN_DIR=""
INTENDED=""
ALLOWLIST=""
OUT_MD=""
OUT_JSON=""
FAIL_ON_GAP=1

while [ $# -gt 0 ]; do
  case "$1" in
    --in) IN_DIR="$2"; shift 2 ;;
    --intended) INTENDED="$2"; shift 2 ;;
    --allowlist) ALLOWLIST="$2"; shift 2 ;;
    --out-md) OUT_MD="$2"; shift 2 ;;
    --out-json) OUT_JSON="$2"; shift 2 ;;
    --no-fail) FAIL_ON_GAP=0; shift ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

IN_DIR="${IN_DIR:-./all-reports}"
OUT_MD="${OUT_MD:-/tmp/weaver-coverage-aggregate.md}"

if [ -z "$INTENDED" ] || [ ! -f "$INTENDED" ]; then
  echo "--intended <intended-telemetry.json> is required" >&2
  exit 2
fi

: > "$OUT_MD"
emit() {
  printf '%s\n' "$1" >> "$OUT_MD"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

mapfile -t reports < <(find "$IN_DIR" -type f -name 'weaver-report-*.json' 2>/dev/null | sort)

emit "## Weaver telemetry coverage"
emit ""

if [ ${#reports[@]} -eq 0 ]; then
  emit "_No weaver reports (\`weaver-report-*.json\`) found under \`$IN_DIR\`._"
  if [ -n "$OUT_JSON" ]; then
    printf '{"reports":0,"gaps":{"metric_names":[],"metric_attributes":[]}}\n' > "$OUT_JSON"
  fi
  # Absence of reports is not a coverage failure by itself: a matrix that
  # produced none (weaver disabled, all shards skipped) has nothing to gate.
  exit 0
fi

# allowlist entries (one name per line, '#' comments allowed) are removed from
# the intended denominator: telemetry OBI can emit but that no suite in this
# matrix can trigger (no GPU, no such runtime, etc.).
allow_json="[]"
if [ -n "$ALLOWLIST" ] && [ -f "$ALLOWLIST" ]; then
  allow_json=$({ grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST" || true; } | jq -R . | jq -s 'map(select(length > 0))')
fi

# observed = union over every report of keys whose count > 0, across both the
# registry and non-registry seen maps (OBI-own signals classify as
# non_registry, so both buckets must be unioned).
observed=$(jq -s '
  {
    metrics: [ .[]
      | .statistics as $s
      | (($s.seen_registry_metrics // {}) + ($s.seen_non_registry_metrics // {}))
      | to_entries[] | select(.value > 0) | .key ] | unique,
    attributes: [ .[]
      | .statistics as $s
      | (($s.seen_registry_attributes // {}) + ($s.seen_non_registry_attributes // {}))
      | to_entries[] | select(.value > 0) | .key ] | unique
  }
' "${reports[@]}")

result=$(jq -n \
  --argjson observed "$observed" \
  --slurpfile intended "$INTENDED" \
  --argjson allow "$allow_json" '
  ($intended[0]) as $want
  | ($allow | map(select(. != ""))) as $allow
  | {
      reports: 0,
      metric_names: {
        intended: ($want.metric_names | length),
        allowlisted: [ $want.metric_names[] | select(. as $n | $allow | index($n)) ],
        covered: [ $want.metric_names[] | select(. as $n | ($allow | index($n)) | not) | select(. as $n | $observed.metrics | index($n)) ],
        gaps: [ $want.metric_names[] | select(. as $n | ($allow | index($n)) | not) | select(. as $n | ($observed.metrics | index($n)) | not) ]
      },
      metric_attributes: {
        intended: ($want.metric_attributes | length),
        allowlisted: [ $want.metric_attributes[] | select(. as $n | $allow | index($n)) ],
        covered: [ $want.metric_attributes[] | select(. as $n | ($allow | index($n)) | not) | select(. as $n | $observed.attributes | index($n)) ],
        gaps: [ $want.metric_attributes[] | select(. as $n | ($allow | index($n)) | not) | select(. as $n | ($observed.attributes | index($n)) | not) ]
      }
    }
')
result=$(jq --argjson n "${#reports[@]}" '.reports = $n' <<< "$result")

pct() { # covered, gated-total
  if [ "$2" -eq 0 ]; then echo "100.0"; else awk "BEGIN{printf \"%.1f\", $1/$2*100}"; fi
}

mn_cov=$(jq -r '.metric_names.covered|length' <<< "$result")
mn_gap=$(jq -r '.metric_names.gaps|length' <<< "$result")
mn_allow=$(jq -r '.metric_names.allowlisted|length' <<< "$result")
mn_gated=$((mn_cov + mn_gap))
ma_cov=$(jq -r '.metric_attributes.covered|length' <<< "$result")
ma_gap=$(jq -r '.metric_attributes.gaps|length' <<< "$result")
ma_allow=$(jq -r '.metric_attributes.allowlisted|length' <<< "$result")
ma_gated=$((ma_cov + ma_gap))

emit "_Union of \`seen_*\` maps across ${#reports[@]} per-suite weaver report(s). A row is covered when at least one suite emitted it._"
emit ""
emit "| surface | covered | gated | coverage | allowlisted |"
emit "| --- | ---: | ---: | ---: | ---: |"
emit "| metric names | $mn_cov | $mn_gated | $(pct "$mn_cov" "$mn_gated")% | $mn_allow |"
emit "| metric attributes | $ma_cov | $ma_gated | $(pct "$ma_cov" "$ma_gated")% | $ma_allow |"
emit ""

emit_gaps() {
  local label="$1" path="$2" count="$3"
  if [ "$count" -eq 0 ]; then
    emit "**$label:** all covered ✅"
    emit ""
    return
  fi
  emit "**$label — $count never observed ❌**"
  emit ""
  while IFS= read -r name; do emit "- \`$name\`"; done < <(jq -r "${path}[]" <<< "$result")
  emit ""
}

emit_gaps "Uncovered metric names" ".metric_names.gaps" "$mn_gap"
emit_gaps "Uncovered metric attributes" ".metric_attributes.gaps" "$ma_gap"

if [ -n "$OUT_JSON" ]; then
  printf '%s\n' "$result" > "$OUT_JSON"
fi

total_gap=$((mn_gap + ma_gap))
if [ "$total_gap" -gt 0 ] && [ "$FAIL_ON_GAP" -eq 1 ]; then
  echo "weaver telemetry coverage: $total_gap intended item(s) never observed" >&2
  exit 1
fi
