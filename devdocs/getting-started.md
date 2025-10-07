# Getting started

The following guide is a **Getting Started** tutorial for trying out OBI and learning how to run it in different environments (local, Docker, and Kubernetes).

For details on how to contribuite to OBI, please refere to the [CONTRIBUTING.md](../CONTRIBUTING.md) file.


### Table Of Contents 

- [Overview](#overview)
- [Prerequisities](#prerequisities)
- [Installation](#installation)


## Overview

OBI or OpenTelemetry eBPF Intrumentation provides a lightweight and efficient way to collect telemetry data using eBPF for user-space applications. 

## Prerequisities

Before staring, make sure you have:
* Linux Kernel >= 5.8 with eBPF and BTF enabled 
* GO >= 1.17 
* clang
* docker
* make
* clang-format
* clang-tidy

## Installation 

Clone the repository:
```
git clone https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation.git
cd opentelemetry-ebpf-instrumentation
```

For this tutorial the only needed tool is `bpf2go` but, if you want to install all needed tools you just need to run `make tools` command that will download every needed tool inside `.tools` folder.

`bpf2go` is needed to generate all the needed files, it will look in all files for a string like `go:generate $BPF2GO...`. This command needs to be executed every time there is a change in the eBPF code. 

## Configuration

OBI requires a configuration file (or you can set the corresponding ENV variables) to define what to monitor, how to export telemetries and many other things. An example of full, default configuration is [this](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/8f68d11367b48c8370268333dabb182245ce0f45/pkg/obi/config.go#L61). The default configuration is overriden first by the provided file (if any) and then by the ENV variables, in order of increasing priority.

Below is an example configuration file that will be used throughout the tutorial:

```
log_config: yaml

discovery:
  instrument:
      - exe_path: "*/http*"

prometheus_export:
  features:  
    - application
    - network
  port: 9876

ebpf:
  track_request_headers: true
  context_propagation: all

trace_printer: "json_indent"
```
Explanation:
- `log_config` or `OTEL_EBPF_LOG_CONFIG` enables the logging of the configuration on startup.
- `discovery.instrument.exe_path` or `OTEL_EBPF_AUTO_TARGET_EXE` or `OTEL_GO_AUTO_TARGET_EXE` allows defining the regular expression matching the full executable path. In the configuration file, `exe_path: "*/http*"` means that we are interested in a executable with `"http"` in its name.
- `prometheus_export.features` or `OTEL_EBPF_PROMETHEUS_FEATURES` defines features of metrics that can be exported. Another way is to use `otel_metrics_export.features` or `OTEL_EBPF_METRIC_FEATURES`.
- `prometheus_export.port` or `OTEL_EBPF_PROMETHEUS_PORT` defines the port where OBI displays metrics.
- `ebpf.track_request_headers` or `OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS` the kprobes based HTTP request tracking will start tracking the request headers to process any `'Traceparent'` fields.
- `ebpf.context_propagation` or `OTEL_EBPF_BPF_CONTEXT_PROPAGATION` enables distributed context propagation.
- `trace_printer` or `OTEL_EBPF_TRACE_PRINTER` enables printing of traces to stdout. **NOTE**: the printed traces represent OBI's internal data format. In this tutorial, they are used to help you understand the content of a trace without requiring the installation of any additional components.

With the previous configuration we can see both metrics and traces.  Unfortunately OBI does not support log correlation yet.


## Running locally as binary

### Build the binary

```
make generate && make compile

# Or, if you are using an arm64 architecture
GOARCH="arm64" make generate && GOARCH="arm64" make compile
```
This produces a binary at `.bin/ebpf-instrument`.

### Run it

```
cat << EOF > obi_conf_example.yaml
log_config: yaml

discovery:
  instrument:
      - exe_path: "*/http*"

prometheus_export:
  features:  
    - application
    - network
  port: 9876

ebpf:
  track_request_headers: true
  context_propagation: all

trace_printer: "json_indent"
EOF


sudo ./bin/ebpf-instrument --config obi_conf_example.yaml
```
Once running, we can see the printed YAML configuration.

### Run [httpServer](../examples/http/server/)

In a new terminal:
```
cd opentelemetry-ebpf-instrumentation/examples/http/server
go build -o httpServer httpserver.go
./httpServer
```
In the terminal where OBI is running we can see the printout of a trace of type `ProcessAlive` related to `httpServer`. 
```
[
 {
  "type": "ProcessAlive",
  "peer": "",
  "peerPort": "0",
  "host": "",
  "hostPort": "0",
  "traceID": "00000000000000000000000000000000",
  "spanID": "0000000000000000",
  "parentSpanID": "0000000000000000",
  "traceFlags": "0",
  "peerName": "",
  "hostName": "httpserver",
  "kind": "SPAN_KIND_INTERNAL",
  "start": "1759922777016787",
  "handlerStart": "1759922777016787",
  "end": "1759922777016787",
  "duration": "0s",
  "durationUSec": "0",
  "handlerDuration": "0s",
  "handlerDurationUSec": "0",
  "attributes": {}
 }
]
```
This trace type is an internal signal and it is ignored by the metrics exporters. We can alse see that `traceID`, `spanID` and `parentSpanID` are 0; the `hostName` is `httpserver` like our exectuable and finally the `kind` is `SPAN_KIND_INTERNAL`.

### Run [httpClient](../examples/http/client/)

In a new terminal:
```
cd opentelemetry-ebpf-instrumentation/examples/http/client
go build -o httpClient httpclient.go
./httpClient # it will run until Ctrl+C
```
In the terminal where OBI is running we can see the printout of a trace of type `ProcessAlive` related to `httpClient`.

### Check Traces. 

In the terminal where OBI is running we can see the printout of various traces relating to the requests that the `httpClient` makes to the `httpServer`. 

For example:
```
[
 {
  "type": "HTTP",
  "peer": "127.0.0.1",
  "peerPort": "41414",
  "host": "127.0.0.1",
  "hostPort": "8080",
  "traceID": "1dfcd06b7f05c21fb976495124f6b563",
  "spanID": "8317b051e1ff97f2",
  "parentSpanID": "8afe8c7f347a909a",
  "traceFlags": "1",
  "peerName": "127.0.0.1",
  "hostName": "httpserver",
  "kind": "SPAN_KIND_SERVER",
  "start": "1760098892370473",
  "handlerStart": "1760098892370508",
  "end": "1760098892370568",
  "duration": "94.71µs",
  "durationUSec": "94",
  "handlerDuration": "60.001µs",
  "handlerDurationUSec": "60",
  "attributes": {
   "clientAddr": "127.0.0.1",
   "contentLen": "0",
   "method": "GET",
   "responseLen": "0",
   "route": "/",
   "serverAddr": "httpserver",
   "serverPort": "8080",
   "status": "200",
   "url": "/"
  }
 },
 {
  "type": "HTTPClient",
  "peer": "127.0.0.1",
  "peerPort": "41414",
  "host": "127.0.0.1",
  "hostPort": "8080",
  "traceID": "1dfcd06b7f05c21fb976495124f6b563",
  "spanID": "8afe8c7f347a909a",
  "parentSpanID": "0000000000000000",
  "traceFlags": "1",
  "peerName": "httpclient",
  "hostName": "localhost:8080",
  "kind": "SPAN_KIND_CLIENT",
  "start": "1760098892370120",
  "handlerStart": "1760098892370120",
  "end": "1760098892370739",
  "duration": "618.424µs",
  "durationUSec": "618",
  "handlerDuration": "618.424µs",
  "handlerDurationUSec": "618",
  "attributes": {
   "clientAddr": "httpclient",
   "method": "GET",
   "serverAddr": "localhost:8080",
   "serverPort": "8080",
   "status": "200",
   "url": ""
  }
 }
]
```
One span is of type `SPAN_KIND_CLIENT` and one of type `SPAN_KIND_SERVER`. The client span lacks a `parentSpanID` and its `spanID` is `8afe8c7f347a909a`. This `spanID` serves as the `parentSpanID` for the server span, linking the two.

Notice that both spans share the same `traceID`, tying them to the same request. Every span also contains useful information that are the basic components used to build the final, exported trace.

### Check Metrics

The metrics are available at [http://localhost:9876/metrics](http://localhost:9876/metrics). This endpoint exposes all the metrics generated by OBI.

As configured in our YAML configuration file, we specified "application" and "networks" as the featured to export, and we can see metrics related to both of these.

For example:

```
# HELP http_client_request_body_size_bytes size, in bytes, of the HTTP request body as sent from the client side
# TYPE http_client_request_body_size_bytes histogram
http_client_request_body_size_bytes_bucket{http_request_method="GET",http_response_status_code="200",http_route="",instance="lima-ubuntu-ebpf:443246",job="httpclient",server_address="localhost:8080",server_port="8080",service_name="httpclient",service_namespace="",le="0"} 39

# HELP obi_network_flow_bytes_total bytes submitted from a source network endpoint to a destination network endpoint
# TYPE obi_network_flow_bytes_total counter
obi_network_flow_bytes_total{direction="request"} 8826
obi_network_flow_bytes_total{direction="response"} 75846

```

## Running as Docker container

TODO

### Running in K8s

TODO

## Troubleshooting

TODO








