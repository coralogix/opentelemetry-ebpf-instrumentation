# OBI semantic-convention registry

This registry (see `manifest.yaml`) extends the upstream OpenTelemetry
semantic-conventions registry with the signals and attributes OBI emits in
addition to — or as overrides of — the standard semconv set. Together with the
upstream dependency it forms the complete contract of what OBI emits

## Overriding an upstream definition

Weaver (v0.24.x) has **no precedence or merge semantics** between a local
group and the groups a dependency contributes to the resolved registry
(`--include-unreferenced`, which OBI needs). When the same attribute id or
signal name is declared by more than one group, live-check silently resolves
the duplicate in favor of the group whose id sorts **last lexicographically** —
including the upstream `span.*` / `metric.*` groups that `ref` an attribute
and therefore carry an embedded copy of its upstream definition. Tracked
upstream in <https://github.com/open-telemetry/weaver/issues/1578>.

Until weaver defines local-wins override semantics, every override in
`groups/` must follow these rules:

1. **Group id**: use the `x.obi.<namespace>` prefix so the override sorts
   after every upstream group id (`registry.*`, `span.*`, `metric.*`, …) and
   wins the resolution. Do not rename an override to something that sorts
   earlier, and do not reuse an upstream group id (a same-id redefinition
   loses the tie to the dependency AND trips `DuplicateGroupId` in
   `registry check`).
2. **Replacement, not merge**: an override REPLACES the upstream attribute
   definition wholesale. An enum override must therefore carry the FULL
   upstream member list plus OBI's extensions; when bumping the semconv
   dependency, re-sync the upstream members verbatim from
   `.deps/upstream-<version>/model/<ns>/registry.yaml`. A missing member
   resurfaces as an `undefined_enum_variant` failure in the weaver-validated
   suites, so drift is caught, not silent.
3. **Expected lint duplicates**: `weaver registry check` flags each override
   as a `DuplicateAttributeId` (or `DuplicateMetricName`) error even though
   live-check resolves it. Each expected duplicate is allowlisted — tightly,
   by attribute id and group pair — in `scripts/lint-schema-filter.jq`
   (covered by `scripts/lint_schema_filter_test.go`). Anything else still
   fails `make lint-schema`.

`groups/dns.yaml` is the one exception to the `extends` pattern above. Its
override only relaxes `dns.question.name` from `required` to `opt_in` on the
upstream `dns.lookup.duration` metric — a requirement-level change, which is
exactly what weaver's v2 `metric_refinements` mechanism (`file_format:
definition/2`) is for. A refinement targets the base metric via `ref:` and
inherits its `name`, so it does NOT re-declare the metric and does NOT trip
`DuplicateMetricName`; the `x.obi.*` group-id / lint-allowlist dance is
unnecessary there. The `extends` style is still required for the attribute
overrides above because they change the attribute's **type or enum members**
(re-typing to `string`, or extending the member list), which v2 refinements
cannot express — refinements can only override brief/note/examples/
requirement_level/stability/deprecated, not `type`. The one cost is that
weaver (v0.24.x) still marks `definition/2` as "not yet stable" (a non-fatal
warning that `--future` promotes to an error), so that single diagnostic for
`dns.yaml` is allowlisted in `scripts/lint-schema-filter.jq`. Track
stabilization of the v2 format in
<https://github.com/open-telemetry/weaver/issues/1483>; if refinements later
gain type/enum overriding, the `extends` overrides here can migrate to it too.

## Two override styles

- **Closed enum, extended**: the upstream value space is enumerable and OBI
  intentionally emits extra members (e.g. `messaging.system` gains
  `amqp`/`mqtt`/`nats`, `db.system.name` gains `aerospike`). The override
  re-declares the enum with upstream members + OBI's, so weaver still flags
  any value outside the combined list — bug values like an empty string or
  `unknown` are deliberately NOT declared and keep failing the suites.
- **Open-ended value space, re-typed as string**: upstream declares an enum,
  but the real value space is unbounded by design — domain-specific error
  codes (`error.type`) or provider/MCP operation vocabularies
  (`gen_ai.operation.name`). Enumerating these is impossible, so the override
  re-types the attribute as a plain `string` with examples. Weaver then
  validates presence/type but not membership. For these attributes the
  emitters must still omit the attribute instead of sending an empty value;
  that guarantee lives in the emitter unit tests
  (`pkg/appolly/app/request/span_getters_test.go`,
  `pkg/export/otel/traces_test.go`), not in weaver.

Values OBI merely passes through from user configuration (e.g.
`deployment.environment.name` from a workload's `OTEL_RESOURCE_ATTRIBUTES`)
are NOT overridden: the integration tests must configure values that satisfy
the upstream conventions instead.
