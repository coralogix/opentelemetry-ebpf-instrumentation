# k8s-cache Configuration Reference

Configuration reference for the OpenTelemetry eBPF Instrumentation k8s-cache service.
Configuration is provided via YAML file and/or environment variables.

Generated from [`config-schema.json`](config-schema.json).

---

## Table of Contents

- [Top-Level Properties](#top-level-properties)
- [`internal_metrics`](#internal-metrics)
- [Type Definitions](#type-definitions)

---

## Top-Level Properties

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `informer_resync_period` | `duration` | `OTEL_EBPF_K8S_CACHE_INFORMER_RESYNC_PERIOD` | `30m` | `30s`, `5m`, `1ms`, etc |  | Time interval between complete resyncs of the informers |
| `log_level` | `string` | `OTEL_EBPF_K8S_CACHE_LOG_LEVEL` | `info` | `debug`, `error`, `info`, `warn` |  |  |
| `max_connections` | `integer` | `OTEL_EBPF_K8S_CACHE_MAX_CONNECTIONS` | `150` |  |  | Maximum number of concurrent streams per HTTP/2 transport |
| `port` | `integer` | `OTEL_EBPF_K8S_CACHE_PORT` | `50055` |  |  | Grpc port k8s-cache is listening to |
| `profile_port` | `integer` | `OTEL_EBPF_K8S_CACHE_PROFILE_PORT` | `0` |  |  | Port where the pprof server is going to listen to. 0 means disabled |

## `internal_metrics`

| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |
|---|---|---|---|---|---|---|
| `internal_metrics.path` | `string` | `OTEL_EBPF_K8S_CACHE_INTERNAL_METRICS_PROMETHEUS_PATH` | `/metrics` |  |  | The path to expose Prometheus metrics on |
| `internal_metrics.port` | `integer` | `OTEL_EBPF_K8S_CACHE_INTERNAL_METRICS_PROMETHEUS_PORT` | `0` |  |  | The port to run the http metric server on, 0 means disabled |
