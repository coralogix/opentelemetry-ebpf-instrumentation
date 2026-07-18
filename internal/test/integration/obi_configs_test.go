// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

// Inline OBI configurations, wired per suite via docker.OBI.ConfigYAML.
// Only structures that environment variables cannot express (routes,
// discovery services, attribute selections) belong here; scalar settings
// go in the OBI Env map.

const obiConfigContainerMeta = `otel_metrics_export:
  endpoint: http://otelcol:4318
otel_traces_export:
  endpoint: http://jaeger:4318
  otel_sdk_log_level: debug
attributes:
  select:
    "*":
      include: ["*"]
discovery:
  instrument:
    # test that we can now select by container_name attribute
    - container_name: "integration-testserver-*"

`

const obiConfigElixir = `routes:
  patterns:
    - /test/:test_id
  unmatched: path
otel_metrics_export:
  endpoint: http://otelcol:4318
attributes:
  select:
    "*":
      include: ["*"]
discovery:
  instrument:
    - open_ports: 4000
      namespace: integration-test
      # TODO: elixir fails to be recognized as running in a container on kernels 6.14+.
      # https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/780
      # containers_only: true
`

const obiConfigGoKafkaTraceparent = `attributes:
  kubernetes:
    cluster_name: obi-k8s-test-cluster
  select:
    "*":
      include: ["*"]
ebpf:
  log_enricher:
    services:
      - service:
        - exe_path: testserver
discovery:
  min_process_age: "0s"
log_config: "yaml"
`

const obiConfigGoOtelGrpc = `routes:
  unmatched: path
prometheus_export:
  port: 8999
otel_traces_export:
  endpoint: http://jaeger:4318
metrics:
  features:
    - application
attributes:
  kubernetes:
    cluster_name: obi-k8s-test-cluster
  select:
    "*":
      include: ["*"]`

const obiConfigGrpcHttp2Mux = `routes:
  unmatched: path
prometheus_export:
  port: 8999
  features:
    - application
otel_metrics_export:
  endpoint: http://otelcol:4318
otel_traces_export:
  endpoint: http://otelcol:4318
discovery:
  instrument:
    - namespace: grpc-http2-go
      name: server
      exe_path: "*/testserver"
attributes:
  select:
    "*":
      include: ["*"]`

const obiConfigGrpcRelay = `routes:
  unmatched: path
otel_traces_export:
  endpoint: http://jaeger:4318
discovery:
  services:
    - name: go-entry
      open_ports: 8080
    - name: python-relay
      open_ports: 50051
    - name: go-grpc-to-http
      open_ports: 50060
    - name: go-http-to-grpc
      open_ports: 8081
    - name: nodejs-relay
      open_ports: 50053
    - name: java-relay
      open_ports: 50055
    - name: dotnet-relay
      open_ports: 50056
    - name: go-terminal
      open_ports: 50054
`

const obiConfigHttp2 = `routes:
  unmatched: path
prometheus_export:
  port: 8999
  features:
    - application
otel_metrics_export:
  endpoint: http://otelcol:4318
otel_traces_export:
  endpoint: http://otelcol:4318
discovery:
  instrument:
    - namespace: http2-go
      name: client
      exe_path: "*/http2client"
      containers_only: true
    - namespace: http2-go
      name: server
      exe_path: "*/http2srv"
      containers_only: true
attributes:
  select:
    "*":
      include: ["*"]`

const obiConfigJvmRuntimeMetrics = `prometheus_export:
  port: 8999
otel_metrics_export:
  endpoint: http://otelcol:4318
metrics:
  features:
    - application_runtime
jvm_runtime_metrics:
  sampling_interval: 10ms
attributes:
  select:
    "*":
      include: ["*"]
`

const obiConfigKeepalive = `trace_printer: text
log_level: debug
routes:
  unmatched: path
ebpf:
  context_propagation: headers
  bpf_debug: true
discovery:
  skip_go_specific_tracers: true
  services:
    - name: keepaliveclient
      exe_path: keepaliveclient
    - name: tpinjector-server
      exe_path: tpinjector-server
`

const obiConfigLogEnricher = `routes:
  patterns:
    - /basic/:rnd
  unmatched: path
  ignored_patterns:
    - /metrics
attributes:
  kubernetes:
    cluster_name: obi-k8s-test-cluster
    resource_labels:
      deployment.environment: ["deployment.environment"]
  select:
    "*":
      include: ["*"]
ebpf:
  log_enricher:
    services:
      - service:
        - open_ports: "8380,50051,3030,8085,3040,8388"
discovery:
  min_process_age: "0s"
log_config: "yaml"
`

const obiConfigMultiexecHost = `routes:
  patterns:
    - /basic/:rnd
  unmatched: path
otel_metrics_export:
  endpoint: http://127.0.0.1:4318
otel_traces_export:
  endpoint: http://127.0.0.1:4318
discovery:
  instrument:
    - namespace: just-will-be-ignored
      name: another-service
      exe_path: "*/asdflkjasdf"
    - namespace: initial-set
      name: some-server
      open_ports: 18080
      exe_path: "*dupe*" # choose only the dupe* process that uses port 18080
    - namespace: initial-set
      exe_path: "*{testserver,rename1}"
    - namespace: multi-k
      name: rust-service-ssl
      open_ports: 8490
    - namespace: multi-k
      name: python-service-ssl
      open_ports: 8380      
    - namespace: multi-k
      name: python-service
      open_ports: 7773
    - namespace: multi-k
      name: nodejs-service-ssl
      open_ports: 3033      
    - namespace: multi-k
      name: nodejs-service
      open_ports: 3030
    - namespace: multi-k
      name: rails-service-ssl
      open_ports: 3043      
    - namespace: multi-k
      name: rails-service
      open_ports: 3040
    - namespace: multi-k
      name: java-service
      open_ports: 8085
    - namespace: multi-k
      name: rust-service
      open_ports: 8090
    - namespace: multi-k
      exe_path: "*{docker-proxy}"
      exports: [] # test exports field, do not export docker-proxy metrics or traces
attributes:
  kubernetes:
    cluster_name: my-kube
  select:
    http_server_request_duration_seconds_count:
      exclude: ["server_address"]
    "*":
      include: ["*"]
`

const obiConfigNode = `routes:
  patterns:
    - /greeting
  unmatched: path
otel_metrics_export:
  endpoint: http://otelcol:4318
otel_traces_export:
  endpoint: http://jaeger:4318
attributes:
  select:
    "*":
      include: ["*"]`

const obiConfigOtherGrpc = `discovery:
  instrument:
    - exe_path: "*backend"
      namespace: integration-test
    - exe_path: "*worker"
      namespace: integration-test
    - exe_path: "*grpcpinger"
      namespace: integration-test
routes:
  patterns:
    - /factorial/:rnd
  unmatched: path
  ignored_patterns:
    - /metrics
  ignore_mode: traces
otel_metrics_export:
  endpoint: http://otelcol:4318
otel_traces_export:
  endpoint: http://jaeger:4318
attributes:
  select:
    "*":
      include: ["*"]
`

const obiConfigPerapp = `routes:
  patterns:
    - /basic/:rnd
  unmatched: path
metrics:
  features: ["application_span_otel"]
otel_metrics_export:
  endpoint: http://otelcol:4318
prometheus_export:
  port: 8999
discovery:
  instrument:
    - open_ports: 3030,3040
      metrics: { features: ["application", "application_span_otel"] }
    - name: pytestserver
      open_ports: 7773
      metrics: { features: ["application", "application_span_otel"] }
    - name: testserver
      open_ports: 8080
    - name: jtestserver
      open_ports: 8085
    # testing that the later match overrides the to-be-ignored features
    # with the global metrics features
    - name: to-be-ignored
      open_ports: 8090
      metrics: { features: [ "application", "application_span_otel" ] }
    - name: rtestserver
      open_ports: 8090
`

const obiConfigPhp = `otel_metrics_export:
  endpoint: http://127.0.0.1:4318
otel_traces_export:
  endpoint: http://127.0.0.1:4318
attributes:
  select:
    "*":
      include: ["*"]
ebpf:
  buffer_sizes:
    tcp: 65536
`

const obiConfigRedis = `ebpf:
  redis_db_cache:
    enabled: true
routes:
  patterns:
    - /basic/:rnd
  unmatched: path
  ignored_patterns:
    - /metrics
  ignore_mode: traces
otel_metrics_export:
  endpoint: http://otelcol:4318
otel_traces_export:
  endpoint: http://otelcol:4318
attributes:
  kubernetes:
    cluster_name: obi-k8s-test-cluster
    resource_labels:
      deployment.environment: ["deployment.environment"]
  select:
    "*":
      include: ["*"]`

const obiConfigRuby = `routes:
  unmatched: path
otel_metrics_export:
  endpoint: http://127.0.0.1:4318
otel_traces_export:
  endpoint: http://127.0.0.1:4418
attributes:
  select:
    "*":
      include: ["*"]`

const obiConfigTpclient = `routes:
  unmatched: path
attributes:
  select:
    "*":
      include: ["*"]
otel_metrics_export:
  endpoint: http://otelcol:4318
otel_traces_export:
  endpoint: http://jaeger:4318
discovery:
  services:
    - name: tpclient-a
      open_ports: 6000
    - name: tpclient-b
      open_ports: 6001
    - name: tpclient-c
      open_ports: 6002
`

const obiConfigWithJaegerHost = `routes:
  unmatched: path
otel_metrics_export:
  endpoint: http://127.0.0.1:4318
otel_traces_export:
  endpoint: http://127.0.0.1:4318
attributes:
  select:
    dns_lookup_duration:
      include: ["dns.question.name"]
`

const obiConfigWithJaeger = `routes:
  unmatched: path
otel_metrics_export:
  endpoint: http://otelcol:4318
otel_traces_export:
  endpoint: http://otelcol:4318
`
