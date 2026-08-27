# Emits the `versions:` body for a new OBI telemetry schema version from the
# renames declared in the registry, as `weaver registry resolve` output.
#
# Renames come from `deprecated: {reason: renamed, renamed_to: ...}` in the
# registry, which is the same source `weaver registry diff` reads. Diff itself
# cannot be used here: it aborts on the duplicate-attribute diagnostics from
# OBI's `x.obi.*` override groups (see scripts/lint-schema-filter.jq and
# https://github.com/open-telemetry/weaver/issues/1578), emitting nothing.
#
# Resolution merges the upstream registry, so groups are restricted to OBI's own
# by provenance; matching on group id would miss OBI metrics whose ids carry no
# `obi` marker (spanmetrics, service-graph, target.info).
#
# $known is the newline-separated list of `old: new` pairs already recorded in
# earlier schema versions; those must not be repeated in a new version block.
def is_obi: ((.lineage.provenance.schema_url // "") | test("opentelemetry-ebpf-instrumentation"));
def renamed: select(.deprecated.reason == "renamed") | select((.deprecated.renamed_to // "") != "");
def known: ($known | split("\n") | map(select(length > 0)));
def fresh: select((("\(.old): \(.new)") | IN(known[])) | not);

def metric_renames:
  [.groups[] | select(.type == "metric") | select(is_obi) | renamed
   | {old: .metric_name, new: .deprecated.renamed_to}]
  | map(fresh) | sort_by(.old) | unique_by(.old);

def attribute_renames:
  [.groups[] | select(.type == "attribute_group") | select(is_obi) | .attributes[]?
   | renamed | {old: .name, new: .deprecated.renamed_to}]
  | map(fresh) | sort_by(.old) | unique_by(.old);

(metric_renames) as $metrics
| (attribute_renames) as $attributes
| if (($metrics | length) == 0 and ($attributes | length) == 0 ) then ""
  else
    (if ($attributes | length) > 0 then
      ["    all:", "      changes:", "        - rename_attributes:", "            attribute_map:"]
      + ($attributes | map("              \(.old): \(.new)"))
     else [] end)
    + (if ($metrics | length) > 0 then
      ["    metrics:", "      changes:", "        - rename_metrics:"]
      + ($metrics | map("            \(.old): \(.new)"))
     else [] end)
    | join("\n")
  end
