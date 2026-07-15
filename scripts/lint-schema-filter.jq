# Filters `weaver registry check` JSON diagnostics down to the ones that must
# fail `make lint-schema`, removing only the single expected finding:
#
# The `definition/2` "not yet stable" diagnostic for schemas/obi/groups/dns.yaml.
# That file uses the v2 `metric_refinements` mechanism to relax
# `dns.question.name` on the upstream `dns.lookup.duration` metric from
# `required` to `opt_in` (see the header comment in dns.yaml for why). weaver
# (v0.24.2) resolves `definition/2` files fine but emits a non-fatal warning
# that the format is not yet stable; `--future` (which we pass so that other
# pending warnings — e.g. missing examples on string attributes — fail at PR
# time) promotes that warning to an error. We drop just this one expected
# diagnostic so the rest of `--future`'s strictness still applies.
#
# This mirrors how open-telemetry/semantic-conventions-genai consumes the same
# released weaver image for its own `definition/2` files. When weaver
# stabilizes the v2 file format (tracked in
# https://github.com/open-telemetry/weaver/issues/1483) this filter — and the
# NOTE in groups/dns.yaml — can be dropped.
#
# Any other diagnostic — including a `definition/2` unstable warning for a file
# other than groups/dns.yaml, or a differently-shaped error — is kept and fails
# the lint. Covered by scripts/lint_schema_filter_test.go.
map(select(
  (
    (.error.FailToResolveDefinition?.UnstableFileFormat? // null) as $unstable
    | $unstable != null
      and $unstable.file_format == "definition/2"
      and ($unstable.provenance | endswith("groups/dns.yaml"))
  ) | not
))
