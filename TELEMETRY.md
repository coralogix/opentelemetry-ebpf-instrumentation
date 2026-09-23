# Telemetry contract

This document defines which telemetry emitted by OpenTelemetry eBPF Instrumentation (OBI) is covered by the compatibility rules for emitted telemetry in [VERSIONING.md](./VERSIONING.md#emitted-telemetry). Those rules apply from `v1.0` on.

## Source of truth

Everything OBI emits is declared in its semantic-convention registry under [schemas/obi/](./schemas/obi/), and each span group, metric and attribute there carries a stability. The [telemetry reference](./site/docs/README.md) is generated from that registry and shows the stability of every signal and attribute.

This document does not list signals. What is covered is decided by the stability declared in the registry.

## What is covered

Telemetry declared `stable` is covered. For a stable signal, OBI guarantees:

- for a metric: its name, instrument, unit and the meaning of its value
- for a span: its span kind and the operation it represents
- for each stable attribute on the signal: its key, type and meaning

Attribute presence is guaranteed under the default configuration:

- a `required` attribute is always present
- a `conditionally_required` attribute is present whenever its declared condition holds
- a `recommended` or `opt_in` attribute may be added, removed or change default between minor releases

Changing the attribute set through `attributes.select` or other configuration is outside the guarantee: the contract describes the default output.

## What is not covered

Telemetry declared `release_candidate` or `development` is not covered, and neither is anything the registry does not declare. It may change in a minor release. Such changes are listed in the release notes, and renames are recorded as transformations in the published [telemetry schema](./devdocs/telemetry-schema.md) so consumers can translate between versions.

## Exporters

The OTLP output is the contract.

The Prometheus exporter is covered only through the OTLP definition: metric names are derived from the OTLP name, unit and instrument with the same translation a collector applies when re-exporting OBI's OTLP metrics in Prometheus format, and label names are the attribute keys with `.` replaced by `_`. A change that keeps the OTLP definition and this derivation is not a breaking change. Output specific to the Prometheus exporter is not covered.

## Observed values

OBI derives telemetry from what it observes in the kernel and on the wire, not from the application's own instrumentation. Improving what OBI can observe, such as matching more routes, recognizing more responses or parsing more protocol versions, can change attribute values and whether a conditional attribute is present. That is not a breaking change as long as keys, types and meaning are preserved.
