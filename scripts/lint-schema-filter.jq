# Filters `weaver registry check` JSON diagnostics down to the ones that must
# fail `make lint-schema`, removing only the expected findings below. Weaver
# has no first-class override mechanism between a registry and its
# dependencies yet, nor a CLI flag to suppress the duplicate checks, while
# `registry live-check` resolves each duplicate in the local group's favor.
# Tracked in https://github.com/open-telemetry/weaver/issues/1578; when
# weaver defines override semantics this filter (and the override groups
# documented in schemas/obi/README.md) can be dropped.
#
# 1. DuplicateAttributeId for the attribute overrides in
#    `schemas/obi/groups/` (see schemas/obi/README.md): each re-declares an
#    upstream attribute (from group `registry.<ns>`, under the distinct group
#    id `x.obi.<ns>`) — either an enum extended with the values OBI
#    intentionally emits, or an open-ended enum re-typed as string. These
#    change the attribute's type/members, which weaver's v2 refinements cannot
#    express, so they use the v1 `extends`-style wholesale override.
#
# 2. The `definition/2` "not yet stable" diagnostic for
#    `schemas/obi/groups/dns.yaml`. Unlike the attribute overrides, the dns
#    override only relaxes `dns.question.name` from required to opt_in — a
#    requirement-level change that the v2 `metric_refinements` mechanism CAN
#    express, so dns.yaml uses it instead of an `extends` re-declaration (no
#    DuplicateMetricName results). weaver (v0.24.2) resolves `definition/2`
#    files fine but emits a non-fatal "not yet stable" warning; `--future`
#    (which we pass so other pending warnings — e.g. missing examples on
#    string attributes — fail at PR time) promotes it to an error, so we drop
#    just this one expected diagnostic. This mirrors how
#    open-telemetry/semantic-conventions-genai consumes the same released
#    weaver image for its own `definition/2` files. When weaver stabilizes the
#    v2 file format (https://github.com/open-telemetry/weaver/issues/1483) this
#    clause and the NOTE in groups/dns.yaml can be dropped.
#
# Any other diagnostic — including duplicates for other metrics/attributes, the
# expected ones with unexpected provenances/groups, or a `definition/2` warning
# for a file other than groups/dns.yaml — is kept and fails the lint. Covered
# by scripts/lint_schema_filter_test.go.
map(select(
  (
    (
      (.error.DuplicateAttributeId? // null) as $dup
      | $dup != null
        and ($dup.attribute_id
             | IN("messaging.system", "gen_ai.provider.name", "gen_ai.operation.name",
                  "openai.api.type", "telemetry.sdk.language", "db.system.name",
                  "rpc.system.name", "error.type"))
        and ((($dup.group_ids // []) | sort) as $groups
             | ($groups | length) == 2
               and ($groups[0] | startswith("registry."))
               and $groups[1] == ("x.obi." + ($groups[0] | ltrimstr("registry."))))
    )
    or
    (
      (.error.FailToResolveDefinition?.UnstableFileFormat? // null) as $unstable
      | $unstable != null
        and $unstable.file_format == "definition/2"
        and ($unstable.provenance | endswith("groups/dns.yaml"))
    )
  ) | not
))
