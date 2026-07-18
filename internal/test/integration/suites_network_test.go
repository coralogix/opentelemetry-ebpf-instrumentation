// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestNetwork_Deduplication(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": &docker.OBI{
			NetworkMode: "service:testserver",
			RunDir:      "run-netolly",
			Env: map[string]string{
				"GOCOVERDIR":                             "/coverage",
				"OTEL_EBPF_BPF_BATCH_TIMEOUT":            "1s",
				"OTEL_EBPF_BPF_DEBUG":                    "TRUE",
				"OTEL_EBPF_CONFIG_PATH":                  "/configs/obi-config-netolly${OTEL_EBPF_CONFIG_SUFFIX}.yml",
				"OTEL_EBPF_HOSTNAME":                     "obi",
				"OTEL_EBPF_LOG_LEVEL":                    "DEBUG",
				"OTEL_EBPF_METRICS_INTERVAL":             "1s",
				"OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT": "1s",
				"OTEL_EBPF_NETWORK_DEDUPER":              "${OTEL_EBPF_NETWORK_DEDUPER}",
				"OTEL_EBPF_NETWORK_METRICS":              "true",
				"OTEL_EBPF_NETWORK_PRINT_FLOWS":          "true",
				"OTEL_EBPF_NETWORK_SOURCE":               "${OTEL_EBPF_NETWORK_SOURCE}",
				"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":    "1ms",
				"OTEL_EXPORTER_OTLP_ENDPOINT":            "http://otelcol:4318",
			},
		},
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/testserver/Dockerfile${TESTSERVER_DOCKERFILE_SUFFIX}",
			Ports:           []string{"8080:8080", "8081:8081", "8082:8082", "8083:8083", "8087:8087", "50051:50051"},
			Env: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, "OTEL_EBPF_NETWORK_DEDUPER=first_come", "OTEL_EBPF_EXECUTABLE_PATH=", `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	// When there flow deduplication, results must not include "iface" field.
	for _, f := range getNetFlows(t) {
		require.NotContains(t, f.Metric, "iface")
		require.Contains(t, f.Metric, "iface_direction")
	}

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestNetwork_Deduplication_Use_Socket_Filter(t *testing.T) {
	compose := docker.SuiteStack(t, &docker.OBI{
		NetworkMode: "service:testserver",
		RunDir:      "run-netolly",
		Env: map[string]string{
			"GOCOVERDIR":                             "/coverage",
			"OTEL_EBPF_BPF_BATCH_TIMEOUT":            "1s",
			"OTEL_EBPF_BPF_DEBUG":                    "TRUE",
			"OTEL_EBPF_CONFIG_PATH":                  "/configs/obi-config-netolly${OTEL_EBPF_CONFIG_SUFFIX}.yml",
			"OTEL_EBPF_HOSTNAME":                     "obi",
			"OTEL_EBPF_LOG_LEVEL":                    "DEBUG",
			"OTEL_EBPF_METRICS_INTERVAL":             "1s",
			"OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT": "1s",
			"OTEL_EBPF_NETWORK_DEDUPER":              "${OTEL_EBPF_NETWORK_DEDUPER}",
			"OTEL_EBPF_NETWORK_METRICS":              "true",
			"OTEL_EBPF_NETWORK_PRINT_FLOWS":          "true",
			"OTEL_EBPF_NETWORK_SOURCE":               "${OTEL_EBPF_NETWORK_SOURCE}",
			"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":    "1ms",
			"OTEL_EXPORTER_OTLP_ENDPOINT":            "http://otelcol:4318",
		},
	}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-netolly.yml")
	compose.Env = append(compose.Env, "OTEL_EBPF_NETWORK_DEDUPER=first_come", "OTEL_EBPF_EXECUTABLE_PATH=", "OTEL_EBPF_NETWORK_SOURCE=socket_filter", `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	// When there flow deduplication, results must not include "iface" field.
	for _, f := range getNetFlows(t) {
		require.NotContains(t, f.Metric, "iface")
		require.Contains(t, f.Metric, "iface_direction")
	}

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestNetwork_NoDeduplication(t *testing.T) {
	compose := docker.SuiteStack(t, &docker.OBI{
		NetworkMode: "service:testserver",
		RunDir:      "run-netolly",
		Env: map[string]string{
			"GOCOVERDIR":                             "/coverage",
			"OTEL_EBPF_BPF_BATCH_TIMEOUT":            "1s",
			"OTEL_EBPF_BPF_DEBUG":                    "TRUE",
			"OTEL_EBPF_CONFIG_PATH":                  "/configs/obi-config-netolly${OTEL_EBPF_CONFIG_SUFFIX}.yml",
			"OTEL_EBPF_HOSTNAME":                     "obi",
			"OTEL_EBPF_LOG_LEVEL":                    "DEBUG",
			"OTEL_EBPF_METRICS_INTERVAL":             "1s",
			"OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT": "1s",
			"OTEL_EBPF_NETWORK_DEDUPER":              "${OTEL_EBPF_NETWORK_DEDUPER}",
			"OTEL_EBPF_NETWORK_METRICS":              "true",
			"OTEL_EBPF_NETWORK_PRINT_FLOWS":          "true",
			"OTEL_EBPF_NETWORK_SOURCE":               "${OTEL_EBPF_NETWORK_SOURCE}",
			"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":    "1ms",
			"OTEL_EXPORTER_OTLP_ENDPOINT":            "http://otelcol:4318",
		},
	}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-netolly.yml")
	compose.Env = append(compose.Env, "OTEL_EBPF_NETWORK_DEDUPER=none", "OTEL_EBPF_EXECUTABLE_PATH=", `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	// When there is no flow deduplication, results must include "iface".
	validIfaceDirections := regexp.MustCompile("^(ingress|egress)$")
	for _, f := range getNetFlows(t) {
		require.Contains(t, f.Metric, "iface")
		require.Contains(t, f.Metric, "iface_direction")
		assert.NotEmpty(t, f.Metric["iface"])
		assert.Regexp(t, validIfaceDirections, f.Metric["iface_direction"])
	}

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestNetwork_AllowedAttributes(t *testing.T) {
	compose := docker.SuiteStack(t, &docker.OBI{
		NetworkMode: "service:testserver",
		RunDir:      "run-netolly",
		Env: map[string]string{
			"GOCOVERDIR":                             "/coverage",
			"OTEL_EBPF_BPF_BATCH_TIMEOUT":            "1s",
			"OTEL_EBPF_BPF_DEBUG":                    "TRUE",
			"OTEL_EBPF_CONFIG_PATH":                  "/configs/obi-config-netolly${OTEL_EBPF_CONFIG_SUFFIX}.yml",
			"OTEL_EBPF_HOSTNAME":                     "obi",
			"OTEL_EBPF_LOG_LEVEL":                    "DEBUG",
			"OTEL_EBPF_METRICS_INTERVAL":             "1s",
			"OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT": "1s",
			"OTEL_EBPF_NETWORK_DEDUPER":              "${OTEL_EBPF_NETWORK_DEDUPER}",
			"OTEL_EBPF_NETWORK_METRICS":              "true",
			"OTEL_EBPF_NETWORK_PRINT_FLOWS":          "true",
			"OTEL_EBPF_NETWORK_SOURCE":               "${OTEL_EBPF_NETWORK_SOURCE}",
			"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":    "1ms",
			"OTEL_EXPORTER_OTLP_ENDPOINT":            "http://otelcol:4318",
		},
	}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-netolly.yml")
	compose.Env = append(compose.Env, "OTEL_EBPF_EXECUTABLE_PATH=", `OTEL_EBPF_CONFIG_SUFFIX=-disallowattrs`, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	// When there flow deduplication, results must only include
	// the attributes under the attributes.allow section
	for _, f := range getNetFlows(t) {
		require.Contains(t, f.Metric, "obi_ip")
		require.Contains(t, f.Metric, "src_name")
		require.Contains(t, f.Metric, "dst_port")
		assert.NotEmpty(t, f.Metric["obi_ip"])
		assert.NotEmpty(t, f.Metric["src_name"])
		assert.NotEmpty(t, f.Metric["dst_port"])

		assert.NotContains(t, f.Metric, "src_address")
		assert.NotContains(t, f.Metric, "dst_address")
		assert.NotContains(t, f.Metric, "dst_name")
		assert.NotContains(t, f.Metric, "src_port")

		// src_name is just an IP address, as reverse DNS is disabled
		// assert.Regexp(t, `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, f.Metric["src_name"])
		parsed := net.ParseIP(f.Metric["src_name"])
		if parsed == nil {
			assert.Nil(t, parsed, "src_name is NULL")
		}
	}

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestNetwork_ReverseDNS(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": &docker.OBI{
			NetworkMode: "host",
			RunDir:      "run-netolly",
			Env: map[string]string{
				"GOCOVERDIR":                             "/coverage",
				"OTEL_EBPF_BPF_BATCH_TIMEOUT":            "1s",
				"OTEL_EBPF_BPF_DEBUG":                    "TRUE",
				"OTEL_EBPF_CONFIG_PATH":                  "/configs/obi-config-netolly.yml",
				"OTEL_EBPF_HOSTNAME":                     "obi",
				"OTEL_EBPF_LOG_LEVEL":                    "DEBUG",
				"OTEL_EBPF_METRICS_INTERVAL":             "1s",
				"OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT": "1s",
				"OTEL_EBPF_NETWORK_METRICS":              "true",
				"OTEL_EBPF_NETWORK_PRINT_FLOWS":          "true",
				"OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE":     "ebpf",
				"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":    "1ms",
				"OTEL_EXPORTER_OTLP_ENDPOINT":            "http://localhost:4318",
			},
		},
		"curler": &docker.ServiceDef{
			Image:   "alpine/curl@sha256:e62df00da54d9b51ae83ecdf4ad84a4fc4bca3a91189f1d6eae84d5f46d3a9cc",
			Command: []string{"sh", "-c", "while true; do curl -s https://github.com/; sleep 5; done"},
		},
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	checkCurlFlows := func(query string) {
		pq := promtest.Client{HostPort: prometheusHostPort}
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			// now, verify that the network metric has been reported.
			results, err := pq.Query(`obi_network_flow_bytes_total` + query)
			require.NoError(ct, err)
			require.NotEmpty(ct, results)
		}, 4*testTimeout, 100*time.Millisecond)
	}

	checkCurlFlows(`{dst_name="github.com"}`)
	checkCurlFlows(`{src_name="github.com"}`)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestNetwork_Direction(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": &docker.OBI{
			NetworkMode: "service:testserver",
			RunDir:      "run-netolly-direction",
			Env: map[string]string{
				"GOCOVERDIR":                             "/coverage",
				"OTEL_EBPF_BPF_BATCH_TIMEOUT":            "1s",
				"OTEL_EBPF_BPF_DEBUG":                    "TRUE",
				"OTEL_EBPF_CONFIG_PATH":                  "/configs/obi-config-netolly${OTEL_EBPF_CONFIG_SUFFIX}.yml",
				"OTEL_EBPF_FORCE_BPF_MAP_READER":         "legacy",
				"OTEL_EBPF_HOSTNAME":                     "obi",
				"OTEL_EBPF_LOG_LEVEL":                    "DEBUG",
				"OTEL_EBPF_METRICS_FEATURES":             "network",
				"OTEL_EBPF_METRICS_INTERVAL":             "1s",
				"OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT": "1s",
				"OTEL_EBPF_NETWORK_DEDUPER":              "${OTEL_EBPF_NETWORK_DEDUPER}",
				"OTEL_EBPF_NETWORK_PRINT_FLOWS":          "true",
				"OTEL_EBPF_NETWORK_SOURCE":               "${OTEL_EBPF_NETWORK_SOURCE}",
				"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":    "1ms",
				"OTEL_EXPORTER_OTLP_ENDPOINT":            "http://otelcol:4318",
			},
		},
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/testserver/Dockerfile${TESTSERVER_DOCKERFILE_SUFFIX}",
			Ports:           []string{"8080:8080", "8081:8081", "8082:8082", "8083:8083", "8087:8087", "50051:50051"},
			Env: map[string]string{
				"LOG_LEVEL":  "DEBUG",
				"TARGET_URL": "http://testserver2:8080",
			},
		},
		"testserver2": &docker.ServiceDef{
			Image:     "hatest-testserver",
			DependsOn: map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, "OTEL_EBPF_NETWORK_DEDUPER=first_come", "OTEL_EBPF_NETWORK_SOURCE=tc", "OTEL_EBPF_EXECUTABLE_PATH=", `OTEL_EBPF_CONFIG_SUFFIX=-direction`, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	results := getDirectionNetFlows(t)
	for _, f := range results {
		require.Contains(t, f.Metric, "iface_direction")
	}

	// test correct direction labels and client/server ports
	client := results[slices.IndexFunc(results, func(result promtest.Result) bool { return result.Metric["dst_port"] == "8080" })]
	assert.Equal(t, "request", client.Metric["direction"])
	assert.Equal(t, "egress", client.Metric["iface_direction"])
	assert.Equal(t, "7000", client.Metric["client_port"])
	assert.Equal(t, "8080", client.Metric["server_port"])

	server := results[slices.IndexFunc(results, func(result promtest.Result) bool { return result.Metric["src_port"] == "8080" })]
	assert.Equal(t, "response", server.Metric["direction"])
	assert.Equal(t, "ingress", server.Metric["iface_direction"], "ingress")
	assert.Equal(t, "7000", server.Metric["client_port"])
	assert.Equal(t, "8080", server.Metric["server_port"])

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestNetwork_IfaceDirection_Use_Socket_Filter(t *testing.T) {
	compose := docker.SuiteStack(t, &docker.OBI{
		NetworkMode: "service:testserver",
		RunDir:      "run-netolly-direction",
		Env: map[string]string{
			"GOCOVERDIR":                             "/coverage",
			"OTEL_EBPF_BPF_BATCH_TIMEOUT":            "1s",
			"OTEL_EBPF_BPF_DEBUG":                    "TRUE",
			"OTEL_EBPF_CONFIG_PATH":                  "/configs/obi-config-netolly${OTEL_EBPF_CONFIG_SUFFIX}.yml",
			"OTEL_EBPF_FORCE_BPF_MAP_READER":         "legacy",
			"OTEL_EBPF_HOSTNAME":                     "obi",
			"OTEL_EBPF_LOG_LEVEL":                    "DEBUG",
			"OTEL_EBPF_METRICS_FEATURES":             "network",
			"OTEL_EBPF_METRICS_INTERVAL":             "1s",
			"OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT": "1s",
			"OTEL_EBPF_NETWORK_DEDUPER":              "${OTEL_EBPF_NETWORK_DEDUPER}",
			"OTEL_EBPF_NETWORK_PRINT_FLOWS":          "true",
			"OTEL_EBPF_NETWORK_SOURCE":               "${OTEL_EBPF_NETWORK_SOURCE}",
			"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":    "1ms",
			"OTEL_EXPORTER_OTLP_ENDPOINT":            "http://otelcol:4318",
		},
	}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-netolly-direction.yml")
	compose.Env = append(compose.Env, "OTEL_EBPF_NETWORK_DEDUPER=first_come", "OTEL_EBPF_EXECUTABLE_PATH=", "OTEL_EBPF_NETWORK_SOURCE=socket_filter", `OTEL_EBPF_CONFIG_SUFFIX=-direction`, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	results := getDirectionNetFlows(t)
	for _, f := range results {
		require.Contains(t, f.Metric, "iface_direction")
	}

	// test correct direction labels and client/server ports
	client := results[slices.IndexFunc(results, func(result promtest.Result) bool { return result.Metric["dst_port"] == "8080" })]
	require.Equal(t, "request", client.Metric["direction"])
	require.Equal(t, "egress", client.Metric["iface_direction"])
	require.Equal(t, "7000", client.Metric["client_port"])
	require.Equal(t, "8080", client.Metric["server_port"])

	server := results[slices.IndexFunc(results, func(result promtest.Result) bool { return result.Metric["src_port"] == "8080" })]
	require.Equal(t, "response", server.Metric["direction"])
	require.Equal(t, "ingress", server.Metric["iface_direction"])
	require.Equal(t, "7000", server.Metric["client_port"])
	require.Equal(t, "8080", server.Metric["server_port"])

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func getNetFlows(t *testing.T) []promtest.Result {
	var results []promtest.Result
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, instrumentedServiceStdURL, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// now, verify that the network metric has been reported.
		results, err = pq.Query(`obi_network_flow_bytes_total`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, 4*testTimeout, time.Second)
	return results
}

func getDirectionNetFlows(t *testing.T) []promtest.Result {
	var results []promtest.Result
	pq := promtest.Client{HostPort: prometheusHostPort}

	// wait for first network flow metrics
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, 4*testTimeout, time.Second)

	// make a few calls to the testserver, which will call testserver2 with a source port lower than a destination port (7000 -> 8080)
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/echoLowPort", nil)
	require.NoError(t, err)
	clientBytes, serverBytes := callAndCheckMetrics(t, req, pq, 0, 0)
	clientBytes, serverBytes = callAndCheckMetrics(t, req, pq, clientBytes, serverBytes)
	callAndCheckMetrics(t, req, pq, clientBytes, serverBytes)

	// verify that the correct network metric has been reported.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err = pq.Query(`obi_network_flow_bytes_total{src_port="7000", dst_port="8080"} or obi_network_flow_bytes_total{src_port="8080", dst_port="7000"}`)
		require.NoError(ct, err)
		require.Len(ct, results, 2)
		require.NotEmpty(ct, results)
	}, 4*testTimeout, time.Second)
	return results
}

func callAndCheckMetrics(t *testing.T, req *http.Request, pq promtest.Client, previousClientValue int, previousServerValue int) (int, int) {
	var clientValue, serverValue int

	// make call
	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode)

	// wait for fetching aggregated flows in OBI about this call
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_port="7000", dst_port="8080"} or obi_network_flow_bytes_total{src_port="8080", dst_port="7000"}`)
		require.NoError(ct, err)
		require.Len(ct, results, 2)
		require.NotEmpty(ct, results)
		// wait till the amount of bytes is greater than the previous read
		client := results[slices.IndexFunc(results, func(result promtest.Result) bool { return result.Metric["dst_port"] == "8080" })]
		clientValue, _ = strconv.Atoi(client.Value[1].(string))
		require.Greater(ct, clientValue, previousClientValue)
		server := results[slices.IndexFunc(results, func(result promtest.Result) bool { return result.Metric["src_port"] == "8080" })]
		serverValue, _ = strconv.Atoi(server.Value[1].(string))
		require.Greater(ct, serverValue, previousServerValue)
	}, 4*testTimeout, time.Second)
	return clientValue, serverValue
}
