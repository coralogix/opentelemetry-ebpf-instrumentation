# Telemetry Registry & Semantic-Convention Validation

OBI validates that every attribute and metric it emits is declared in a
semantic-convention registry — either upstream OpenTelemetry semconv or OBI's
own registry under [`schemas/obi/`](../schemas/obi). This document explains the
two validation layers, how to add new telemetry so it passes them, and the
telemetry that is intentionally *not* validated (documented exceptions).

## Two validation layers

The layers are complementary: neither alone is sufficient.

### 1. Weaver live-check (integration tests) — full signals, real values

Most integration suites under `internal/test/integration/` tap OBI's OTLP
stream into an [OpenTelemetry weaver](https://github.com/open-telemetry/weaver)
`registry live-check` container (`otel/weaver`). Weaver compares the *actual
emitted telemetry* against the registry and reports advice. The shared
parsing/assertion logic lives in
`internal/test/integration/components/weaver/weavercheck/`; suites invoke it via
`runWeaverValidation(t)` (enforce) or `runWeaverValidationObserve(t)` (observe).

Enforce mode fails the test on any **`violation`**-level advice, and — because
weaver classifies "attribute under a known namespace but declared nowhere" only
as `information` — also on the **`extends_namespace`** finding type (see
`actionableAdviceTypes` in `weavercheck.go`).

What this layer validates well: attribute→signal association, value **types**,
**units**, **enum membership** (e.g. `rpc.system=onc_rpc`), and registry-level
lint. Its limitation: **it only sees attributes a running test actually
exercises.** An optional, error-path, or feature-gated attribute that no suite
triggers is never sent to weaver, so it can stay undeclared unnoticed.

### 2. Deterministic static check — completeness, independent of runtime

`TestEmittedMetricAttributesAreDeclared`
(`pkg/export/attributes/registry_coverage_test.go`) closes that gap for **metric
attributes**. It enumerates every attribute the metric attribute-selection
registry (`getDefinitions()`) can emit — with **all** `AttrGroups` enabled, so
runtime feature flags don't hide anything — and asserts each is declared in
`schemas/obi/` or the pinned upstream semconv model. It needs no Docker and runs
in normal unit-test CI.

Scope: metric attributes only. Span-only attributes and metric *names* are still
covered by the live-check layer.

A handful of `getDefinitions()` entries are internal selector placeholders that
`span_getters.go` remaps to a real semconv key before emission (e.g.
`gen_ai.token.type_output` → `gen_ai.token.type` value `output`); these are
listed in `internalSelectorNames` and excluded.

## Adding new telemetry

1. **Prefer upstream semconv.** If a suitable attribute/metric already exists in
   the pinned semconv version, emit that name — no registry change needed.
2. **Otherwise declare it in `schemas/obi/`.** Add the attribute to the
   appropriate group under `schemas/obi/groups/` (e.g. `traces.yaml` for
   OBI-specific span/metric attributes) with an accurate `type`, `stability`,
   `brief`, and — for anything expected to move upstream later — a `note`
   pointing at the tracking semconv issue/PR.
3. **Bump the pinned semconv version in lockstep.** The Go `semconv` import and
   `schemas/obi/manifest.yaml` must match; `TestSemconvVersionMatchesManifest`
   guards this.
4. **Make sure a test exercises it** (so the live-check layer validates its
   type/enum/association), and confirm `TestEmittedMetricAttributesAreDeclared`
   still passes (so the completeness layer is satisfied).

If the semconv version is bumped, re-run `make fetch-upstream-semconv` so the
local `schemas/obi/.deps/upstream-*/model` cache the static check reads is
current.

## Documented exceptions

Telemetry that is intentionally outside weaver live-check validation:

- **GPU / CUDA spans and metrics.** No GPU is available in CI, so no suite can
  exercise the CUDA emission paths through weaver. The CUDA-specific attributes
  (e.g. `cuda.memcpy.kind`) are declared in `schemas/obi/groups/traces.yaml`, but
  their end-to-end emission is not live-check validated. Accepted limitation.
- **Prometheus-only metric variants.** OBI exposes some self-telemetry only via
  its Prometheus self-scrape endpoint (e.g. `obi_bpf_probe_executions_total`).
  The Prometheus path is not routed to weaver; validation targets the OTLP
  variant of each signal instead.
- **Collector-shaped signals in dashboards.** OBI-native span metrics
  (`traces_span_metrics_*`) and service-graph metrics
  (`traces_service_graph_*`) deliberately mirror the collector-contrib
  `spanmetrics`/`servicegraph` connector output so the same dashboards consume
  both; the names/labels are matched to those connectors rather than to a
  freestanding OBI convention (see `schemas/obi/groups/spanmetrics.yaml` and
  `service_graph.yaml`).
