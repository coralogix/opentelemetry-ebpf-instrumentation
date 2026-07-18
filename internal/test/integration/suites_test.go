// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// Digest-pinned obi-testimg references. These were previously selected at
// compose-time via `${JAVA_TEST_MODE}` / `${TESTSERVER_IMAGE_SUFFIX}`
// interpolation in the tag, which made it impossible to pin by sha256 and
// left the integration suite vulnerable to a compromise of the OBI ghcr
// publish workflow swapping in a malicious image.
const (
	obiTestImgJavaNative = "ghcr.io/open-telemetry/obi-testimg:java-native-0.1.1@sha256:063c5013cc4cccfd015a054d2595a4a09105eba549cb96e1a2aac7456f831b5b"
	obiTestImgJavaJar    = "ghcr.io/open-telemetry/obi-testimg:java-jar-0.1.1@sha256:474c4c5a836c99aa023ca8fb16693cd5f9edb5c22501c17069992fd4e87aaf48"
	obiTestImgRust       = "ghcr.io/open-telemetry/obi-testimg:rust-0.1.1@sha256:c818c207ff40f474e8f7cd183f58d47a0dce8030c89cf1b44bfc18a7f625da28"
	obiTestImgRustSSL    = "ghcr.io/open-telemetry/obi-testimg:rust-ssl-0.1.1@sha256:52868bb841454f657a3797c4d7cd255d5fa25e84e1d97be0c9ef6c59502a0a9b"
	obiTestImgRails      = "ghcr.io/open-telemetry/obi-testimg:rails-0.1.1@sha256:d51943f3b10e73a8e924c4cf2f06815172a7332ecfa4618765b2ba342dd7c10f"
	obiTestImgRailsSSL   = "ghcr.io/open-telemetry/obi-testimg:rails-ssl-0.1.1@sha256:770361b1480c2301829951c83230caa268a0761de255cdd2ef79885180f3245f"
)

func TestSuite_Go(t *testing.T) {
	type testCase struct {
		name string
		env  []string
	}

	for _, tc := range []testCase{
		{name: "go-old-supported"},
		{name: "go-latest", env: []string{"TESTSERVER_DOCKERFILE_SUFFIX=_latest", "PINGSERVER_DOCKERFILE_SUFFIX=_latest"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compose, err := docker.ComposeStack(path.Join(pathOutput, "test-suite-"+tc.name+".log"), docker.StdOBI(docker.OBI{
				Pid:     "host",
				Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
				Ports:   []string{"8999:8999"},
				Volumes: []string{
					"./configs/:/configs",
					"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
					"../../../testoutput:/coverage",
					"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
				},
				Env: map[string]string{
					"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
					"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
					"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
					"OTEL_EBPF_LOG_FORMAT":                                "json",
					"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
					"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
					"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
					"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
					"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
					"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
					"OTEL_EBPF_TRACE_PRINTER":                             "json",
				},
			}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml")
			require.NoError(t, err)
			compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=(pingclient|testserver)`)
			compose.Env = append(compose.Env, tc.env...)
			require.NoError(t, compose.Up())

			// Cleanups run LIFO: register `compose.Close()` first so it runs
			// last, *after* runWeaverValidation has had a chance to /stop the
			// still-running weaver container.
			t.Cleanup(func() {
				require.NoError(t, compose.Close())
			})
			t.Cleanup(func() {
				runWeaverValidation(t)
			})

			config := ti.DefaultOBIConfig()

			t.Run("RED metrics", testREDMetricsHTTP)
			t.Run("RED JSON RPC metrics", testREDMetricsJSONRPCHTTP)
			t.Run("HTTP traces", testHTTPTraces)
			t.Run("HTTP traces (no traceID)", testHTTPTracesNoTraceID)
			t.Run("HTTP traces (manual spans)", testHTTPTracesNestedManualSpans)
			t.Run("GRPC traces", testGRPCTraces)
			t.Run("GRPC RED metrics", testREDMetricsGRPC)
			t.Run("GRPC TLS RED metrics", testREDMetricsGRPCTLS)
			t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })
			t.Run("Exemplars exist", testExemplarsExist)
			t.Run("Testing Host Info metric", testHostInfo)
			t.Run("Client RED metrics", testREDMetricsForClientHTTPLibrary)
			t.Run("Harvested auto routes", testREDMetricsHTTPAutoRoutes)
		})
	}
}

func TestSuiteNestedTraces(t *testing.T) {
	// We run the test depending on what the host environment is. If the host is in lockdown mode integrity
	// the nesting of spans will be limited. If we are in none (which should be in any non secure boot environment, e.g. Virtual Machines or CI)
	// then we expect full nesting of trace spans in this test.

	// Echo (server) -> echo (client) -> EchoBack (server)
	lockdown := KernelLockdownMode()
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml")
	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}
	require.NoError(t, compose.Up())
	if !lockdown {
		t.Run("HTTP traces (all spans nested)", testHTTPTracesNestedClientWithContextPropagation)
		t.Run("HTTP -> gRPC traces (all spans nested)", testHTTP2GRPCTracesNestedCallsWithContextPropagation)
	} else {
		t.Run("HTTP traces (nested client span)", testHTTPTracesNestedClient)
		t.Run("HTTP -> gRPC traces (nested client span)", testHTTP2GRPCTracesNestedCallsNoPropagation)
	}
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuiteGoGeneric(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		Command:     []string{"--config=/configs/obi-config.yml"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security_none:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base:/var/run/obi",
		},
		DependsOn: map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_LOG_LEVEL":                                 "INFO",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_OPEN_PORT":                                 "8080",
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-go-generic.yml"), nil, true,
		st("Generic Go HTTP/TCP traces (all spans nested)", testGoGenericHTTPTraces),
		st("Generic Go HTTPS/TCP(TLS) traces (all spans nested)", testGoGenericHTTPSTraces))
}

func TestSuiteClientPromScrape(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
			Ports:   []string{"8999:8999"},
			Pid:     "service:testserver",
			RunDir:  "run-client",
			Env: map[string]string{
				"OTEL_EBPF_ENFORCE_SYS_CAPS":                 "false",
				"OTEL_EBPF_EXECUTABLE_PATH":                  "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_METRIC_FEATURES":                  "application",
				"OTEL_EBPF_PROCESSES_INTERVAL":               "100ms",
				"OTEL_EBPF_PROMETHEUS_FEATURES":              "application,application_span,application_service_graph,application_host",
			},
		}),
		"jaeger": &docker.ServiceDef{
			Ports: []string{"16686:16686", "4317", "4318"},
		},
		"otelcol": &docker.ServiceDef{
			Ports:     []string{"4317", "4318", "9464", "8888"},
			DependsOn: map[string]string{"jaeger": "service_started", "obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-pingclient",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/pingclient/Dockerfile",
			Env: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=pingclient`)
	compose.Env = append(compose.Env,
		`INSTRUMENTER_CONFIG_SUFFIX=-promscrape`,
		`PROM_CONFIG_SUFFIX=-promscrape`,
	)
	require.NoError(t, compose.Up())
	t.Run("Client RED metrics", testREDMetricsForClientHTTPLibraryNoTraces)
	t.Run("Testing OBI Build Info metric", testPrometheusOBIBuildInfo)
	t.Run("Testing Host Info metric", testHostInfo)

	require.NoError(t, compose.Close())
}

// Same as Test suite, but the generated test image does not contain debug information
func TestSuite_NoDebugInfo(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml")
	compose.Env = append(compose.Env, `TESTSERVER_DOCKERFILE_SUFFIX=_nodebug`)
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

// Same as Test suite, but the generated test image does not contain debug information
func TestSuite_StaticCompilation(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml")
	compose.Env = append(compose.Env, `TESTSERVER_DOCKERFILE_SUFFIX=_static`)
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestSuite_OldestGoVersion(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			Pid:     "service:testserver",
			Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
			Ports:   []string{"8999:8999"},
			Volumes: []string{
				"./configs/:/configs",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-1.17:/var/run/obi",
			},
			Env: map[string]string{
				"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
				"OTEL_EBPF_METRICS_FEATURES":                          featuresAppSpan,
				"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
				"OTEL_GO_AUTO_TARGET_EXE":                             "${OTEL_GO_AUTO_TARGET_EXE}",
			},
		}),
		"jaeger": &docker.ServiceDef{
			Ports: []string{"16686:16686", "4317", "4318"},
		},
		"otelcol": &docker.ServiceDef{
			Ports:     []string{"4317", "4318", "9464", "8888"},
			DependsOn: map[string]string{"jaeger": "service_started", "obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/testserver_1.17/Dockerfile",
			Ports:           []string{"8080:8080", "8081:8081", "8082:8082", "8083:8083", "8087:8087", "5051:5051"},
			Env: map[string]string{
				"LOG_LEVEL":                "DEBUG",
				"OTEL_RESOURCE_ATTRIBUTES": "service.version=1.0.0",
			},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `OTEL_GO_AUTO_TARGET_EXE=*testserver`, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsOldHTTP)
	t.Run("HTTP traces", testHTTPTraces)
	t.Run("GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("HTTP traces (manual spans)", testHTTPTracesNestedManualSpans)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestSuite_SkipGoTracers(t *testing.T) {
	t.Skip("seems flaky, we need to look into this")
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml"), []string{`OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=1`}, true,
		st("RED metrics", testREDMetricsShortHTTP))
}

func TestSuite_GRPCExport(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml")
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-grpc-export")
	require.NoError(t, compose.Up())
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("trace HTTP service and export as GRPC traces", testHTTPTraces)
	t.Run("trace GRPC service and export as GRPC traces", testGRPCTraces)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestSuite_GRPCExportKProbes(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml")
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-grpc-export")
	compose.Env = append(compose.Env, `OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=1`)
	require.NoError(t, compose.Up())

	waitForTestComponents(t, instrumentedServiceStdURL)

	t.Run("trace GRPC service and export as GRPC traces - kprobes", testGRPCKProbeTraces)
	t.Run("GRPC RED metrics - kprobes", testREDMetricsGRPC)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

// Instead of submitting metrics via OTEL, exposes them as an obi:8999/metrics endpoint
// that is scraped by the Prometheus server
func TestSuite_PrometheusScrape(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml")
	compose.Env = append(compose.Env,
		`INSTRUMENTER_CONFIG_SUFFIX=-promscrape`,
		`PROM_CONFIG_SUFFIX=-promscrape`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`OTEL_EBPF_OPEN_PORT=8082,8999`, // force OBI self-instrumentation to ensure we don't do it
	)

	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
	t.Run("Exemplars exist", testExemplarsExist)
	t.Run("Internal Prometheus metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })
	t.Run("Testing OBI Build Info metric", testPrometheusOBIBuildInfo)
	t.Run("Testing for no OBI self metrics", testPrometheusNoOBIEvents)
	t.Run("Testing BPF metrics", testPrometheusBPFMetrics)

	require.NoError(t, compose.Close())
}

func TestSuite_Java(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			Image:       "hatest-javaobi",
			NetworkMode: "service:testserver",
			Pid:         "host",
			Command:     []string{"--config=/configs/obi-config-java.yml"},
			RunDir:      "run-java",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_EXECUTABLE_PATH": "${JAVA_EXECUTABLE_PATH}",
				"OTEL_EBPF_OPEN_PORT":       "${JAVA_OPEN_PORT}",
				"OTEL_SERVICE_NAME":         "${OTEL_SERVICE_NAME}",
			},
		}),
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:     "${TESTSERVER_IMAGE:?TESTSERVER_IMAGE must be set to a digest-pinned obi-testimg java reference}",
			Ports:     []string{"8086:8085"},
			DependsOn: map[string]string{"otelcol": "service_started"},
			Env: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml"), []string{`TESTSERVER_IMAGE=` + obiTestImgJavaNative}, true,
		st("Java RED metrics", testREDMetricsJavaHTTP))
}

// Same as TestSuite_Java but we run in the process namespace and it uses process namespace filtering
func TestSuite_Java_PID(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			Image:       "hatest-javaobi",
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-java-pid",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_HIGH_REQUEST_VOLUME": "true",
				"OTEL_EBPF_CONFIG_PATH":             "/configs/obi-config-java.yml",
				"OTEL_EBPF_EXECUTABLE_PATH":         "${JAVA_EXECUTABLE_PATH}",
				"OTEL_EBPF_OPEN_PORT":               "${JAVA_OPEN_PORT}",
				"OTEL_SERVICE_NAME":                 "${OTEL_SERVICE_NAME}",
			},
		}),
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image: "${TESTSERVER_IMAGE:?TESTSERVER_IMAGE must be set to a digest-pinned obi-testimg java reference}",
			Ports: []string{"8086:8085"},
			Env: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml"), []string{`JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_PATH=`, `TESTSERVER_IMAGE=` + obiTestImgJavaJar, `OTEL_SERVICE_NAME=greeting`}, true,
		st("Java RED metrics", testREDMetricsJavaHTTP))
}

// Same as Java Test suite, but searching the executable by port instead of executable name. We also run the jar version of Java instead of native image
func TestSuite_Java_OpenPort(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "host",
		Command:     []string{"--config=/configs/obi-config-java.yml"},
		RunDir:      "run-java",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH": "${JAVA_EXECUTABLE_PATH}",
			"OTEL_EBPF_OPEN_PORT":       "${JAVA_OPEN_PORT}",
			"OTEL_SERVICE_NAME":         "${OTEL_SERVICE_NAME}",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-java.yml")
	compose.Env = append(compose.Env, `JAVA_OPEN_PORT=8085`, `JAVA_EXECUTABLE_PATH=`, `TESTSERVER_IMAGE=`+obiTestImgJavaJar, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

// Test that we can also instrument when running with host network mode
func TestSuite_Java_Host_Network(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			Image:       "hatest-javaobi",
			NetworkMode: "host",
			Pid:         "host",
			Ports:       []string{"8999:8999"},
			RunDir:      "run-java-host",
			Env: map[string]string{
				"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config-java.yml",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://127.0.0.1:4318",
				"OTEL_EBPF_EXECUTABLE_PATH":          "${JAVA_EXECUTABLE_PATH}",
				"OTEL_EBPF_OPEN_PORT":                "${JAVA_OPEN_PORT}",
				"OTEL_SERVICE_NAME":                  "${OTEL_SERVICE_NAME}",
			},
		}),
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image: "${TESTSERVER_IMAGE:?TESTSERVER_IMAGE must be set to a digest-pinned obi-testimg java reference}",
			Ports: []string{"8086:8085"},
			Env: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml"), []string{`TESTSERVER_IMAGE=` + obiTestImgJavaNative}, true,
		st("Java RED metrics", testREDMetricsJavaHTTP))
}

func TestSuite_Rust(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		Command:     []string{"--config=/configs/obi-config.yml"},
		RunDir:      "run-rust",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
			"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_TRACE_PRINTER":             "json_indent",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-rust.yml"), []string{`OTEL_EBPF_OPEN_PORT=8090`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8091:8090`, `TESTSERVER_IMAGE=` + obiTestImgRust}, true,
		st("Rust RED metrics", testREDMetricsRustHTTP))
}

func TestSuite_RustSSL(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		Command:     []string{"--config=/configs/obi-config.yml"},
		RunDir:      "run-rust",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
			"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_TRACE_PRINTER":             "json_indent",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-rust.yml"), []string{`OTEL_EBPF_OPEN_PORT=8490`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE=` + obiTestImgRustSSL}, true,
		st("Rust RED metrics", testREDMetricsRustHTTPS))
}

// The actix server that we built our Rust example will enable HTTP2 for SSL automatically if the client supports it.
// We use this feature to implement our kprobes HTTP2 tests, with special http client settings that triggers the Go
// client to attempt http connection.
func TestSuite_RustHTTP2(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		Command:     []string{"--config=/configs/obi-config.yml"},
		RunDir:      "run-rust",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
			"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_TRACE_PRINTER":             "json_indent",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-rust.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8490`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8491:8490`, `TESTSERVER_IMAGE=`+obiTestImgRustSSL)

	require.NoError(t, compose.Up())
	t.Run("Rust RED metrics", testREDMetricsRustHTTP2)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeJS(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		ConfigYAML:  obiConfigNode,
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-nodejs",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
			"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-nodejs.yml"), []string{`OTEL_EBPF_OPEN_PORT=3030`, `OTEL_EBPF_EXECUTABLE_PATH=`, `NODE_APP=app`}, true,
		st("NodeJS RED metrics", testREDMetricsNodeJSHTTP),
		st("HTTP traces (kprobes)", testHTTPTracesKProbes),
		st("HTTP nested traces large HTTPS (kprobes)", testHTTPTracesNestedNodeJSLargeHTTPS))
}

func TestSuite_NodeJSTLS(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		ConfigYAML:  obiConfigNode,
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-nodejs",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
			"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-nodejs.yml"), []string{`OTEL_EBPF_OPEN_PORT=3033`, `OTEL_EBPF_EXECUTABLE_PATH=`, `NODE_APP=app_tls`}, true,
		st("NodeJS SSL RED metrics", testREDMetricsNodeJSHTTPS))
}

func TestSuite_Rails(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, railsFamilyStack(), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml"), []string{`OTEL_EBPF_OPEN_PORT=3040,443`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=3041:3040`, `TESTSERVER_IMAGE=` + obiTestImgRails}, true,
		st("Rails RED metrics", testREDMetricsRailsHTTP),
		st("Rails NGINX traces", testHTTPTracesNestedNginx))
}

func TestSuite_RailsNginxSupportFloor(t *testing.T) {
	compose := docker.SuiteStackServices(t, railsFamilyStack(), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(
		compose.Env,
		`OTEL_EBPF_OPEN_PORT=3040,443`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`TEST_SERVICE_PORTS=3041:3040`,
		`NGINX_IMAGE=`+nginxReverseProxySupportFloorImage,
		`TESTSERVER_IMAGE=`+obiTestImgRails,
	)
	require.NoError(t, compose.Up())

	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	t.Run("Rails NGINX traces", testHTTPTracesNestedNginx)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_RailsRuby302Puma5(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			ConfigYAML:  obiConfigRuby,
			NetworkMode: "host",
			Pid:         "host",
			RunDir:      "run-ruby",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_EXECUTABLE_PATH": "${OTEL_EBPF_EXECUTABLE_PATH}",
			},
		}),
		"jaeger": &docker.ServiceDef{
			Ports: []string{"16686:16686", "4417:4317", "4418:4318"},
		},
		"nginx": &docker.ServiceDef{
			Image:         "nginx:latest@sha256:dec7a90bd0973b076832dc56933fe876bc014929e14b4ec49923951405370112",
			ContainerName: "nginx_server",
			Ports:         []string{"8443:443"},
			Volumes: []string{
				"./components/rubytestserver/nginx/nginx.conf:/etc/nginx/nginx.conf:ro",
				"./components/rubytestserver/nginx/cert.pem:/etc/nginx/cert.pem:ro",
				"./components/rubytestserver/nginx/key.pem:/etc/nginx/key.pem:ro",
			},
			DependsOn: map[string]string{"testserver": "service_started"},
		},
		"otelcol": &docker.ServiceDef{
			Ports:     []string{"4317:4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"jaeger": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-ruby302-puma5",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/rubytestserver/testapi/Dockerfile_ruby302_puma5",
			Ports:           []string{"${TEST_SERVICE_PORTS}"},
			DependsOn:       map[string]string{"otelcol": "service_started"},
			Env: map[string]string{
				"OTEL_RESOURCE_ATTRIBUTES": "cloud.region=ca,deployment.environment.name=staging",
				"OTEL_SERVICE_NAME":        "my-ruby-app",
			},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3040,443`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=3041:3040`)
	require.NoError(t, compose.Up())
	t.Run("Ruby/Puma support contract", func(t *testing.T) {
		assertRubyPumaSupportVersion(t, compose, "3.0.2", "5.6.6")
	})
	t.Run("Rails RED metrics", testREDMetricsRailsHTTP)
	t.Run("Rails NGINX traces", testHTTPTracesNestedNginx)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_RailsNginxSQL(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		ConfigYAML:  obiConfigRuby,
		NetworkMode: "host",
		Pid:         "host",
		RunDir:      "run-ruby",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH": "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_OPEN_PORT":       "3040,443",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-ruby-nginx-sql.yml"), []string{`OTEL_EBPF_OPEN_PORT=3040,443`, `OTEL_EBPF_EXECUTABLE_PATH=`}, true,
		st("Rails RED metrics", testREDMetricsRailsHTTP),
		st("Rails NGINX SQL traces nested", testHTTPTracesNestedNginxSQL))
}

func TestSuite_RailsTLS(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, railsFamilyStack(), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml"), []string{`OTEL_EBPF_OPEN_PORT=3043`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TESTSERVER_IMAGE=` + obiTestImgRailsSSL, `TEST_SERVICE_PORTS=3044:3043`}, true,
		st("Rails SSL RED metrics", testREDMetricsRailsHTTPS))
}

func TestSuite_DotNet(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/obi/Dockerfile${INSTRUMENT_DOCKERFILE_SUFFIX}",
			Entrypoint:      []string{"/obi${INSTRUMENT_COMMAND_SUFFIX}"},
			Command:         []string{"--config=/configs/obi-config-java.yml"},
			NetworkMode:     "service:testserver",
			Pid:             "service:testserver",
			RunDir:          "run-dotnet",
			DependsOn:       map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_BATCH_TIMEOUT": "100ms",
				"OTEL_EBPF_EXECUTABLE_PATH":   "${OTEL_EBPF_EXECUTABLE_PATH}",
			},
		}),
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/dotnetserver/Dockerfile",
			Ports:           []string{"5267:5266", "7034:7033"},
			DependsOn:       map[string]string{"otelcol": "service_started"},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml"), []string{`OTEL_EBPF_OPEN_PORT=5266`, `OTEL_EBPF_EXECUTABLE_PATH=`}, true,
		st("DotNet RED metrics", testREDMetricsDotNetHTTP))
}

// Disabled for now as we randomly fail to register 3 events, but only get 2
// Issue: https://github.com/grafana/beyla/issues/208
func TestSuite_DotNetTLS(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			Command:     []string{"--config=/configs/obi-config-java.yml"},
			RunDir:      "run-dotnet",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_BATCH_TIMEOUT": "100ms",
				"OTEL_EBPF_EXECUTABLE_PATH":   "${OTEL_EBPF_EXECUTABLE_PATH}",
			},
		}),
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/dotnetserver/Dockerfile",
			Ports:           []string{"5267:5266", "7034:7033"},
			DependsOn:       map[string]string{"otelcol": "service_started"},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=7033`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	// Add these above if you want to get the trace_pipe output in the test logs: `INSTRUMENT_DOCKERFILE_SUFFIX=_dbg`, `INSTRUMENT_COMMAND_SUFFIX=_wrapper.sh`
	require.NoError(t, compose.Up())
	t.Run("DotNet SSL RED metrics", testREDMetricsDotNetHTTPS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_Python(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-python",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
				"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml",
				"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_METRICS_FEATURES":         "application,application_span_otel,application_service_graph",
				"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
				"OTEL_EBPF_PROMETHEUS_FEATURES":      "application,application_span,application_service_graph",
			},
		}),
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver-python",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/pythonserver/Dockerfile${TESTSERVER_DOCKERFILE_SUFFIX}",
			Ports:           []string{"${TEST_SERVICE_PORTS}", "8999:8999"},
			DependsOn:       map[string]string{"otelcol": "service_started"},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml")
	compose.Env = append(
		compose.Env,
		`OTEL_EBPF_OPEN_PORT=8380`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`TEST_SERVICE_PORTS=8381:8380`,
		`INSTRUMENTER_CONFIG_SUFFIX=-java`,
	)
	require.NoError(t, compose.Up())
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("Python RED metrics with timeouts", testREDMetricsTimeoutPythonHTTP)
	t.Run("Python DNS RED metrics", testREDMetricsDNSPython)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonProm(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-python",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application,application_span_otel,application_service_graph",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_PROMETHEUS_FEATURES":      "application,application_span,application_service_graph",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-python.yml")
	compose.Env = append(
		compose.Env,
		`OTEL_EBPF_OPEN_PORT=8380`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`TEST_SERVICE_PORTS=8381:8380`,
		`INSTRUMENTER_CONFIG_SUFFIX=-promscrape`,
	)
	require.NoError(t, compose.Up())
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("Python RED metrics with timeouts", testREDMetricsTimeoutPythonHTTP)
	t.Run("Python DNS RED metrics", testREDMetricsDNSPython)
	require.NoError(t, compose.Close())
}

func pythonSQLSuite(t *testing.T, name, fragment, dockerfile, image string, obiEnv map[string]string, tests func(t *testing.T)) {
	env := map[string]string{
		"GOCOVERDIR":                          "/coverage",
		"OTEL_EBPF_CONFIG_PATH":               "/configs/obi-config.yml",
		"OTEL_EBPF_OPEN_PORT":                 "${OTEL_EBPF_OPEN_PORT}",
		"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
		"OTEL_EBPF_DISCOVERY_POLL_INTERVAL":   "500ms",
		"OTEL_EBPF_SERVICE_NAMESPACE":         "integration-test",
		"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT":  "5s",
		"OTEL_EBPF_PROCESSES_INTERVAL":        "100ms",
		"OTEL_EBPF_TRACES_INSTRUMENTATIONS":   "sql",
		"OTEL_EBPF_METRICS_INSTRUMENTATIONS":  "sql",
		"OTEL_EBPF_METRICS_FEATURES":          "application",
		"OTEL_EBPF_TRACE_PRINTER":             "text",
		"OTEL_EBPF_METRICS_INTERVAL":          "1s",
		"OTEL_EBPF_BPF_BATCH_TIMEOUT":         "10ms",
		"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT": "1ms",
		"OTEL_EBPF_LOG_LEVEL":                 "DEBUG",
		"OTEL_EBPF_BPF_DEBUG":                 "TRUE",
		"OTEL_EBPF_HOSTNAME":                  "obi",
	}
	for k, v := range obiEnv {
		env[k] = v
	}
	compose, err := docker.ComposeStack(path.Join(pathOutput, "test-suite-"+name+".log"), &docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/${RUN_DIR:-run-default}:/var/run/obi",
		},
		DependsOn: map[string]string{"testserver": "service_started"},
		Env:       env,
	},
		"compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml",
		"compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-family-sql.yml", fragment)
	require.NoError(t, err)

	compose.Env = append(compose.Env,
		`OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`,
		`RUN_DIR=run-`+name,
		`TESTSERVER_CONTEXT=pythonsql`,
		`TESTSERVER_DOCKERFILE=`+dockerfile,
		`TESTSERVER_IMAGE=`+image)
	require.NoError(t, compose.Up())
	tests(t)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonPostgres(t *testing.T) {
	pythonSQLSuite(t, "python-postgresql", "compose-frag-postgres.yml", "Dockerfile", "hatest-testserver-python-sql",
		map[string]string{"OTEL_EBPF_BPF_BUFFER_SIZE_POSTGRES": "1024"},
		func(t *testing.T) { t.Run("Python Postgres tests", testPythonPostgres) })
}

func TestSuite_PythonMySQL(t *testing.T) {
	pythonSQLSuite(t, "python-mysql", "compose-frag-mysql.yml", "Dockerfile_mysql", "hatest-testserver-python-sql",
		map[string]string{"OTEL_EBPF_BPF_BUFFER_SIZE_MYSQL": "8192"},
		func(t *testing.T) { t.Run("Python MySQL tests", testPythonMySQL) })
}

func TestSuite_PythonMSSQL(t *testing.T) {
	pythonSQLSuite(t, "python-mssql", "compose-frag-mssql.yml", "Dockerfile_mssql", "hatest-testserver-python-mssql",
		map[string]string{"OTEL_EBPF_BPF_BUFFER_SIZE_MSSQL": "8192"},
		func(t *testing.T) { t.Run("Python MSSQL tests", testPythonMSSQL) })
}

func TestSuite_PythonKafka(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			Volumes: []string{
				"./configs/:/configs",
				"./system/sys/kernel/security:/sys/kernel/security",
				"../../../testoutput:/coverage",
				"../../../testoutput/${RUN_DIR}:/var/run/obi",
			},
			DependsOn: map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
				"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
				"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_METRICS_FEATURES":         "application",
				"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
				"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
				"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
				"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
			},
		}),
		"jaeger": &docker.ServiceDef{
			Ports: []string{"16686:16686", "4317", "4318"},
		},
		"kafka": &docker.ServiceDef{
			Image:         "docker.io/bitnamilegacy/kafka:3.9@sha256:55df55bfc7ed5980447387620afa3498eab3985a4d8c731013d82b3fa8b43bff",
			ContainerName: "kafka-like",
			Restart:       "always",
			Ports:         []string{"9093:9093"},
			Volumes: []string{
				"kafka-volume:/bitnami",
			},
			DependsOn: map[string]string{"zookeeper": "service_started"},
			Env: map[string]string{
				"ALLOW_PLAINTEXT_LISTENER":                 "yes",
				"KAFKA_BROKER_ID":                          "1",
				"KAFKA_CFG_ADVERTISED_LISTENERS":           "CLIENT://kafka:9092,EXTERNAL://localhost:9093",
				"KAFKA_CFG_INTER_BROKER_LISTENER_NAME":     "CLIENT",
				"KAFKA_CFG_LISTENERS":                      "CLIENT://:9092,EXTERNAL://:9093",
				"KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP": "CLIENT:PLAINTEXT,EXTERNAL:PLAINTEXT",
				"KAFKA_CFG_ZOOKEEPER_CONNECT":              "zookeeper:2181",
			},
		},
		"otelcol": &docker.ServiceDef{
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"jaeger": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "${TESTSERVER_IMAGE}",
			BuildContext:    "${TESTSERVER_CONTEXT}",
			BuildDockerfile: "${TESTSERVER_DOCKERFILE}",
			Ports:           []string{"${TEST_SERVICE_PORTS}"},
			DependsOn:       map[string]string{"kafka": "service_started", "otelcol": "service_started"},
		},
		"zookeeper": &docker.ServiceDef{
			Image:         "docker.io/bitnamilegacy/zookeeper:3.9@sha256:46d5bcbdf4434f40b7a453a7f53e6ea436a770981433c173ab782c0b13a5fb87",
			ContainerName: "kafka-like-zookeeper",
			Restart:       "always",
			Ports:         []string{"2181:2181"},
			Volumes: []string{
				"zookeeper-volume:/bitnami",
			},
			Env: map[string]string{
				"ALLOW_ANONYMOUS_LOGIN": "yes",
			},
		},
	}, NamedVolumes: []string{"kafka-volume", "zookeeper-volume"}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml"), []string{`OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`, `TESTSERVER_CONTEXT=../../../internal/test/integration/components/pythonkafka/`, `TESTSERVER_DOCKERFILE=Dockerfile`, `TESTSERVER_IMAGE=hatest-testserver-python-kafka`, `RUN_DIR=run-python`}, true,
		st("Python Kafka tests", testREDMetricsPythonKafkaOnly))
}

func TestSuite_GoKafkaTraceparent(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": &docker.OBI{
			ConfigYAML: obiConfigGoKafkaTraceparent,
			Networks:   []string{"shared"},
			Pid:        "host",
			Volumes: []string{
				"./configs/:/configs",
				"/sys/kernel/security:/sys/kernel/security:ro",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-go-kafka-traceparent:/var/run/obi",
				"/sys/fs/bpf:/sys/fs/bpf",
			},
			DependsOn: map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"GOCOVERDIR":                          "/coverage",
				"OTEL_EBPF_BPF_BATCH_TIMEOUT":         "10ms",
				"OTEL_EBPF_BPF_DEBUG":                 "TRUE",
				"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT":  "5s",
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
				"OTEL_EBPF_DISCOVERY_POLL_INTERVAL":   "500ms",
				"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_HOSTNAME":                  "obi",
				"OTEL_EBPF_LOG_LEVEL":                 "DEBUG",
				"OTEL_EBPF_METRICS_FEATURES":          "application,application_process",
				"OTEL_EBPF_OPEN_PORT":                 "${OTEL_EBPF_OPEN_PORT}",
				"OTEL_EBPF_PROCESSES_INTERVAL":        "100ms",
				"OTEL_EBPF_PROMETHEUS_FEATURES":       "application,application_process",
				"OTEL_EBPF_SERVICE_NAMESPACE":         "integration-test",
				"OTEL_EBPF_TRACE_PRINTER":             "text",
			},
		},
		"kafka": &docker.ServiceDef{
			Image:         "docker.io/bitnamilegacy/kafka:3.9@sha256:55df55bfc7ed5980447387620afa3498eab3985a4d8c731013d82b3fa8b43bff",
			ContainerName: "kafka-tp",
			Restart:       "always",
			Networks:      []string{"shared"},
			Ports:         []string{"9093:9093"},
			Volumes: []string{
				"kafka-tp-volume:/bitnami",
			},
			DependsOn: map[string]string{"zookeeper": "service_started"},
			Env: map[string]string{
				"ALLOW_PLAINTEXT_LISTENER":                 "yes",
				"KAFKA_BROKER_ID":                          "1",
				"KAFKA_CFG_ADVERTISED_LISTENERS":           "CLIENT://kafka:9092,EXTERNAL://localhost:9093",
				"KAFKA_CFG_INTER_BROKER_LISTENER_NAME":     "CLIENT",
				"KAFKA_CFG_LISTENERS":                      "CLIENT://:9092,EXTERNAL://:9093",
				"KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP": "CLIENT:PLAINTEXT,EXTERNAL:PLAINTEXT",
				"KAFKA_CFG_ZOOKEEPER_CONNECT":              "zookeeper:2181",
			},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver-go-kafka-traceparent",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/gokafka-seg/Dockerfile",
			Networks:        []string{"shared"},
			Ports:           []string{"${TEST_SERVICE_PORTS}"},
			DependsOn:       map[string]string{"kafka": "service_started"},
			Env: map[string]string{
				"groupID":  "1",
				"kafkaURL": "kafka:9092",
				"topic":    "my-topic",
			},
		},
		"zookeeper": &docker.ServiceDef{
			Image:         "docker.io/bitnamilegacy/zookeeper:3.9@sha256:46d5bcbdf4434f40b7a453a7f53e6ea436a770981433c173ab782c0b13a5fb87",
			ContainerName: "kafka-tp-zookeeper",
			Restart:       "always",
			Networks:      []string{"shared"},
			Ports:         []string{"2181:2181"},
			Volumes: []string{
				"zookeeper-tp-volume:/bitnami",
			},
			Env: map[string]string{
				"ALLOW_ANONYMOUS_LOGIN": "yes",
			},
		},
	}, NamedVolumes: []string{"kafka-tp-volume", "zookeeper-tp-volume"}, Networks: []string{"shared"}}, "compose-base.yml")
	// Discover by executable name: the Kafka broker and Zookeeper are Java processes
	// (Zookeeper's admin server also listens on 8080), so port-based discovery is
	// ambiguous under pid:host. Match only the Go "testserver" binary.
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=`, `OTEL_EBPF_EXECUTABLE_PATH=testserver`, `TEST_SERVICE_PORTS=8389:8080`)
	require.NoError(t, compose.Up())
	t.Run("Go Kafka stale traceparent contamination (#2046)", testGoKafkaTraceparent)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonMQTT(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-mqtt",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "*",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "*",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-family-mqtt.yml"), []string{`OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`, `TESTSERVER_DOCKERFILE=./internal/test/integration/components/pythonmqtt/Dockerfile`, `TESTSERVER_IMAGE=hatest-testserver-python-mqtt`}, true,
		st("Python MQTT publish tests", testREDMetricsPythonMQTT),
		st("Python MQTT subscribe tests", testREDMetricsPythonMQTTSubscribe))
}

func TestSuite_GoMQTT(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-mqtt",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "*",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "*",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-family-mqtt.yml"), []string{`OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`, `TESTSERVER_DOCKERFILE=./internal/test/integration/components/gomqtt/Dockerfile`, `TESTSERVER_IMAGE=hatest-testserver-go-mqtt`}, false,
		st("Go MQTT publish tests", testREDMetricsGoMQTT))
}

func TestSuite_GoSunRPC(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-sunrpc",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_PROMETHEUS_FEATURES":      "application",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "sunrpc",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "sunrpc",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-go-sunrpc.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Go SunRPC tests", testREDMetricsGoSunRPC)
	t.Run("Go SunRPC Prometheus metrics", testREDMetricsGoSunRPCPrometheus)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaKafka(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-java",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
				"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
				"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_METRICS_FEATURES":         "application",
				"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
				"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
				"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
				"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
			},
		}),
		"jaeger": &docker.ServiceDef{
			Command: []string{"--query.ui-config=/etc/jaeger/ui-config.json"},
			Ports:   []string{"16686:16686", "4317", "4318"},
			Volumes: []string{
				"./configs/jaeger-ui-config.json:/etc/jaeger/ui-config.json",
			},
		},
		"kafka": &docker.ServiceDef{
			Image:         "docker.io/bitnamilegacy/kafka:4.0.0@sha256:f45d5b813412e1ef7ce67b467309a84e4c6dc03d7626a0b6da867db9b69bd107",
			ContainerName: "kafka-like",
			Restart:       "always",
			Ports:         []string{"9093:9093"},
			Volumes: []string{
				"kafka-volume:/bitnami",
			},
			Env: map[string]string{
				"ALLOW_PLAINTEXT_LISTENER":                 "yes",
				"KAFKA_BROKER_ID":                          "1",
				"KAFKA_CFG_ADVERTISED_LISTENERS":           "PLAINTEXT://kafka:9092",
				"KAFKA_CFG_CONTROLLER_LISTENER_NAMES":      "CONTROLLER",
				"KAFKA_CFG_CONTROLLER_QUORUM_VOTERS":       "1@kafka:9093",
				"KAFKA_CFG_INTER_BROKER_LISTENER_NAME":     "PLAINTEXT",
				"KAFKA_CFG_LISTENERS":                      "PLAINTEXT://:9092,CONTROLLER://:9093",
				"KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP": "PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT",
				"KAFKA_CFG_NODE_ID":                        "1",
				"KAFKA_CFG_PROCESS_ROLES":                  "broker,controller",
				"KAFKA_ENABLE_KRAFT":                       "yes",
				"KAFKA_KRAFT_CLUSTER_ID":                   "\"13fda84d-f438-4b56-921c-9f156c809a31\"",
			},
		},
		"otelcol": &docker.ServiceDef{
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"jaeger": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver-java-kafka",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/javakafka/Dockerfile_400",
			Ports:           []string{"${TEST_SERVICE_PORTS}"},
			DependsOn:       map[string]string{"kafka": "service_started", "otelcol": "service_started"},
		},
	}, NamedVolumes: []string{"kafka-volume"}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Java Kafka 4.0.0 tests", func(t *testing.T) { testJavaKafka(t, 9092, "javakafka") })
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaKafkaTLS(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-java",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_LOG_LEVEL":                "INFO",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
			"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-java-kafka-400-tls.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Java Kafka 4.0.0 tests", func(t *testing.T) { testJavaKafka(t, 9094, "java") })
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaKafkaLargeBuffer(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-java",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_BUFFER_SIZE_KAFKA":    "1024",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
			"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-java-kafka-400-lb.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Java Kafka 4.0.0 large buffer tests", testJavaKafkaLargeBuffer)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeRdkafka(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-node-rdkafka",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_BUFFER_SIZE_KAFKA":    "65536",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
			"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-node-rdkafka.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Node librdkafka topic resolution", testNodeRdkafka)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonAsyncUvloop_3_9(t *testing.T) {
	compose := docker.SuiteStackServices(t, uvloopFamilyStack(), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `UVLOOP_DOCKERFILE=Dockerfile-3.9`)
	require.NoError(t, compose.Up())

	t.Run("Sequential", testPythonAsyncSequential)
	t.Run("Concurrent", testPythonAsyncConcurrent)
	t.Run("To Thread", testPythonAsyncToThread)
	t.Run("Nested", testPythonAsyncNested)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonAsyncUvloop_3_14(t *testing.T) {
	compose := docker.SuiteStackServices(t, uvloopFamilyStack(), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `UVLOOP_DOCKERFILE=Dockerfile-3.14`)
	require.NoError(t, compose.Up())

	t.Run("Sequential", testPythonAsyncSequential)
	t.Run("Concurrent", testPythonAsyncConcurrent)
	t.Run("To Thread", testPythonAsyncToThread)
	t.Run("Nested", testPythonAsyncNested)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonRedis(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		ConfigYAML:  obiConfigRedis,
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-python",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "redis",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "redis",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-python-redis.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Python Redis metrics", testREDMetricsPythonRedisOnly)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeBullMQ(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		ConfigYAML:  obiConfigRedis,
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-nodejs-bullmq",
		DependsOn:   map[string]string{"testserver": "service_healthy"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_BUFFER_SIZE_TCP":      "4096",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "redis",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "redis",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-nodejs-bullmq.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3040`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8382:3040`)
	require.NoError(t, compose.Up())
	t.Run("Node BullMQ blocking Redis worker", func(t *testing.T) {
		waitForBullMQTestComponents(t, "http://localhost:8382")
		testREDMetricsNodeBullMQ(t)
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_Aerospike(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"aerospike": &docker.ServiceDef{
			Image:        "aerospike/aerospike-server:8.1.2.3@sha256:73c78ec8c2010dbc83ffb4b1249abbdfad3a66173492f46fa54996d0608f122d",
			Ports:        []string{"3000"},
			UlimitNofile: [2]int{20000, 20000},
		},
		"jaeger": &docker.ServiceDef{
			Image: "jaegertracing/all-in-one:1.60@sha256:4fd2d70fa347d6a47e79fcb06b1c177e6079f92cba88b083153d56263082135e",
			Ports: []string{"16686:16686", "4317", "4318"},
			Env: map[string]string{
				"COLLECTOR_OTLP_ENABLED": "true",
				"LOG_LEVEL":              "debug",
			},
		},
		"otelcol": &docker.ServiceDef{
			Image:       "otel/opentelemetry-collector-contrib:0.156.0@sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108",
			Restart:     "unless-stopped",
			Command:     []string{"--config=/etc/otelcol-config/otelcol-config-weaver.yml"},
			Ports:       []string{"4317", "4318:4318", "9464", "8888"},
			MemoryLimit: "125M",
			Volumes: []string{
				"./configs/:/etc/otelcol-config",
			},
			DependsOn: map[string]string{"jaeger": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Image:   "quay.io/prometheus/prometheus:v3.13.0@sha256:c6b27ea434f8389bfe233fbc7be381cf50587c286e871bc842008f5a1b1908a7",
			Command: []string{"--config.file=/etc/prometheus/prometheus-config.yml", "--web.enable-lifecycle", "--web.route-prefix=/"},
			Ports:   []string{"9090:9090"},
			Volumes: []string{
				"./configs/:/etc/prometheus",
			},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver-aerospike",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/javaaerospike/Dockerfile",
			Ports:           []string{"${TEST_SERVICE_PORTS}"},
			DependsOn:       map[string]string{"aerospike": "service_started", "otelcol": "service_started"},
		},
	}}, "compose-frag-weaver.yml"), []string{`OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8390:8080`}, true,
		st("Aerospike RED metrics and traces", testREDMetricsAerospikeOnly))
}

func TestSuite_PythonMongo(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-python",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "mongo",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "mongo",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-python-mongo.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Python Mongo metrics", testREDMetricsPythonMongoOnly)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonCouchbase(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-python",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":     "2048",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_HTTP_SQLPP_ENABLED":       "true",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "http,couchbase",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "http,couchbase",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-python-couchbase.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Python Couchbase metrics", testREDMetricsPythonCouchbaseOnly)
	t.Run("Python Couchbase default collection", testREDMetricsPythonCouchbaseDefaultCollection)
	t.Run("Python Couchbase error", testREDMetricsPythonCouchbaseError)
	t.Run("Python Couchbase SQL++ metrics", testREDMetricsPythonCouchbaseSQLPP)
	t.Run("Python Couchbase SQL++ with context", testREDMetricsPythonCouchbaseSQLPPWithContext)
	t.Run("Python Couchbase SQL++ error", testREDMetricsPythonCouchbaseSQLPPError)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonSQLSSL(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-python-sql",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-python-sql-ssl.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Python SQL metrics", testREDMetricsPythonSQLSSL)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonTLS(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-python",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_METRICS_FEATURES":         "application,application_span_otel,application_service_graph",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_PROMETHEUS_FEATURES":      "application,application_span,application_service_graph",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-python.yml")
	compose.Env = append(
		compose.Env,
		`OTEL_EBPF_OPEN_PORT=8380`,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`TEST_SERVICE_PORTS=8381:8380`,
		`TESTSERVER_DOCKERFILE_SUFFIX=_tls`,
		`INSTRUMENTER_CONFIG_SUFFIX=-java`,
	)
	require.NoError(t, compose.Up())
	t.Run("Python SSL RED metrics", testREDMetricsPythonHTTPS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonSelfReference(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		ConfigYAML:  obiConfigWithJaeger,
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-python",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":             "1024",
			"OTEL_EBPF_BPF_CONTEXT_PROPAGATION":          "all",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT":         "5s",
			"OTEL_EBPF_BPF_MAX_TRANSACTION_TIME":         "500ms",
			"OTEL_EBPF_EXECUTABLE_PATH":                  "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PATH": "/metrics",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
			"OTEL_EBPF_METRICS_FEATURES":                 "application,application_span_otel,application_service_graph",
			"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":        "0ms",
			"OTEL_EBPF_PROCESSES_INTERVAL":               "100ms",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-python-self.yml"), []string{`OTEL_EBPF_OPEN_PORT=7771`, `OTEL_EBPF_EXECUTABLE_PATH=`}, true,
		st("Python Traces with self-references", testHTTPTracesNestedSelfCalls),
		st("Python Traces transaction too long", testHTTPTracesNestedCallsTooLong))
}

func TestSuite_PythonGraphQL(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/${RUN_DIR}:/var/run/obi",
		},
		DependsOn: map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":     "1024",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_HTTP_GRAPHQL_ENABLED":     "true",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-family-python-payload.yml"), []string{`OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`, `TESTSERVER_CONTEXT=pythongraphql`, `TESTSERVER_IMAGE=hatest-testserver-python-graphql`, `RUN_DIR=run-python-graphql`}, true,
		st("Python GraphQL", testPythonGraphQL))
}

func TestSuite_PythonJsonRPC(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/${RUN_DIR}:/var/run/obi",
		},
		DependsOn: map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":     "1024",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_HTTP_JSONRPC_ENABLED":     "true",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-family-python-payload.yml"), []string{`OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`, `TESTSERVER_CONTEXT=pythonjsonrpc`, `TESTSERVER_IMAGE=hatest-testserver-python-jsonrpc`, `RUN_DIR=run-python-jsonrpc`}, true,
		st("Python JSON-RPC server span", testPythonJSONRPCServer),
		st("Python JSON-RPC RPC metrics", testPythonJSONRPCMetrics))
}

func TestSuite_PythonMCP(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/${RUN_DIR}:/var/run/obi",
		},
		DependsOn: map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":     "1024",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":          "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_HTTP_MCP_ENABLED":         "true",
			"OTEL_EBPF_METRICS_FEATURES":         "application",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-family-python-payload.yml"), []string{`OTEL_EBPF_OPEN_PORT=8080`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=8381:8080`, `TESTSERVER_CONTEXT=pythonmcp`, `TESTSERVER_IMAGE=hatest-testserver-python-mcp`, `RUN_DIR=run-python-mcp`}, true,
		st("Python MCP server span", testPythonMCPServer),
		st("Python MCP initialize", testPythonMCPInitialize))
}

func TestSuite_PythonElasticsearch(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      "run-python-elasticsearch",
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":       "1024",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT":   "5s",
			"OTEL_EBPF_CONFIG_PATH":                "/configs/obi-config.yml",
			"OTEL_EBPF_EXECUTABLE_PATH":            "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_HTTP_ELASTICSEARCH_ENABLED": "true",
			"OTEL_EBPF_LOG_CONFIG":                 "yaml",
			"OTEL_EBPF_METRICS_FEATURES":           "application",
			"OTEL_EBPF_PROCESSES_INTERVAL":         "100ms",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":       "true",
			"OTEL_EBPF_TRACE_PRINTER":              "json_indent",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-elasticsearch.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Python Elasticsearch", func(t *testing.T) {
		testPythonElasticsearch(t, "elasticsearch")
	})
	t.Run("Python Opensearch", func(t *testing.T) {
		testPythonElasticsearch(t, "opensearch")
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonAWSS3(t *testing.T) {
	compose := docker.SuiteStackServices(t, awsFamilyStack(), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Python AWS S3", testPythonAWSS3)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonAWSSQS(t *testing.T) {
	compose := docker.SuiteStackServices(t, awsFamilyStack(), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`)

	require.NoError(t, compose.Up())
	t.Run("Python AWS SQS", testPythonAWSSQS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_NodeJSDist(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		ConfigYAML:  obiConfigWithJaegerHost,
		NetworkMode: "host",
		Pid:         "host",
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security:/sys/kernel/security",
			"/sys/fs/cgroup:/sys/fs/cgroup",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-nodejsdist:/var/run/obi",
		},
		DependsOn: map[string]string{"testserver_b": "service_started", "testserver_r": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_CONTEXT_PROPAGATION":          "all",
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT":         "5s",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PATH": "/metrics",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
			"OTEL_EBPF_METRICS_FEATURES":                 "application,application_span_otel,application_service_graph",
			"OTEL_EBPF_OPEN_PORT":                        "5001,5006",
			"OTEL_EBPF_PROCESSES_INTERVAL":               "100ms",
		},
	}), "compose-base.yml", "compose-infra.yml", "compose-suite-nodejs-dist.yml"), []string{`OTEL_EBPF_OPEN_PORT=`, `OTEL_EBPF_EXECUTABLE_PATH=`}, true,
		st("NodeJS Distributed Traces with multiple chained calls", testHTTPTracesNestedNodeJSDistCalls))
}

func TestSuite_DisableKeepAlives(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml")
	require.NoError(t, compose.Up())

	config := ti.DefaultOBIConfig()

	// Run tests with keepalives disabled:
	setHTTPClientDisableKeepAlives(true)
	t.Run("RED metrics", testREDMetricsHTTP)

	t.Run("HTTP DisableKeepAlives traces", testHTTPTraces)
	t.Run("Internal Prometheus DisableKeepAlives metrics", func(t *testing.T) { ti.InternalPrometheusExport(t, config) })
	// Reset to defaults for any tests run afterward
	setHTTPClientDisableKeepAlives(false)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestSuite_OverrideServiceName(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml")
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-override-svcname")
	require.NoError(t, compose.Up())

	// Just few simple test cases to verify that the tracers properly override the service name
	// according to the configuration
	t.Run("RED metrics", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceStdURL)
		testREDMetricsForHTTPLibrary(t, instrumentedServiceStdURL, "overridden-svc-name", "integration-test")
	})
	t.Run("GRPC traces", func(t *testing.T) {
		testGRPCTracesForServiceName(t, "overridden-svc-name")
	})

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestSuiteNodeClient(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			NetworkMode: "service:nodeclient",
			Pid:         "service:nodeclient",
			Command:     []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
			RunDir:      "run-nodeclient",
			DependsOn:   map[string]string{"nodeclient": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_AUTO_TARGET_LANGUAGE":             "nodejs",
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS":        "true",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
			},
		}),
		"jaeger": &docker.ServiceDef{
			Ports: []string{"16686:16686", "4317", "4318"},
		},
		"nodeclient": &docker.ServiceDef{
			Image:           "hatest-nodeclient",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/nodeclient/Dockerfile",
			Command:         []string{"node", "${NODE_APP}.js"},
			DependsOn:       map[string]string{"otelcol": "service_started"},
			Env: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
		},
		"otelcol": &docker.ServiceDef{
			Ports:     []string{"4317", "4318", "9464", "8888"},
			DependsOn: map[string]string{"jaeger": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=node`, `NODE_APP=client`, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 301, 80, "0000000000000000")
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuiteNodeClientTLS(t *testing.T) {
	compose := docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		NetworkMode: "service:nodeclient",
		Pid:         "service:nodeclient",
		Command:     []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		RunDir:      "run-nodeclient",
		DependsOn:   map[string]string{"nodeclient": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_AUTO_TARGET_LANGUAGE":             "nodejs",
			"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS":        "true",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-nodeclient.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=node`, `NODE_APP=client_tls`, `PROM_CONFIG_SUFFIX=`)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 200, 443, "0000000000000001")
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuiteNoRoutes(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml"), []string{"INSTRUMENTER_CONFIG_SUFFIX=-no-route"}, true,
		st("RED metrics", testREDMetricsHTTPNoRoute))
}

func TestSuiteNoRoutesLowCardinality(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:     "host",
		Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
		Ports:   []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
		},
		Env: map[string]string{
			"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
			"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_LOG_FORMAT":                                "json",
			"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
			"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
			"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
			"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
			"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
			"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			"OTEL_EBPF_TRACE_PRINTER":                             "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml", "compose-frag-weaver.yml", "compose-suite-default.yml"), []string{"INSTRUMENTER_CONFIG_SUFFIX=-no-route-lc"}, true,
		st("RED metrics", testREDMetricsHTTPNoRouteLowCardinality))
}

func TestSuite_Elixir(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			ConfigYAML:  obiConfigElixir,
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-elixir",
			DependsOn:   map[string]string{"testserver": "service_started"},
		}),
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver-elixir",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/elixir/Dockerfile",
			Ports:           []string{"4000:4000"},
			DependsOn:       map[string]string{"otelcol": "service_started"},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml"), nil, true,
		st("Elixir RED metrics", testREDMetricsElixirHTTP))
}

func TestSuite_LogEnricherHTTP(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack(), "compose-base.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8380`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher HTTP", func(t *testing.T) {
		testLogEnricher(t, logEnricherHTTPConstants)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherGoGRPC(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack(), "compose-base.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=50051`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Go gRPC", func(t *testing.T) {
		testLogEnricher(t, logEnricherGoGRPCConstants)
	})
	t.Run("Log Enricher Go writev clamp", func(t *testing.T) {
		testLogEnricherWritevClamp(t, logEnricherGoWritevRegressionConstants)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherNodeJS(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack(), "compose-base.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3030`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Node.js", func(t *testing.T) {
		testLogEnricherNodeJS(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherJava(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack(), "compose-base.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8085`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Java", func(t *testing.T) {
		testLogEnricherJava(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherRuby(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack(), "compose-base.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3040`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Ruby puts (writev)", func(t *testing.T) {
		testLogEnricherRuby(t, logEnricherRubyWritevConstants)
	})
	t.Run("Log Enricher Ruby syswrite (write)", func(t *testing.T) {
		testLogEnricherRuby(t, logEnricherRubyWriteConstants)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherDotNet(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack(), "compose-base.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=5266`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher .NET", func(t *testing.T) {
		testLogEnricherDotNet(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherPythonAsync(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack(), "compose-base.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8391`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Python async", func(t *testing.T) {
		testLogEnricherPythonAsync(t)
	})
	// Must run after the regular Python async test: this subtest causes OBI to
	// flag the service as OTel-exporting, which persists for the rest of the
	// container's lifetime.
	t.Run("Log Enricher Python async OTel-instrumented", func(t *testing.T) {
		testLogEnricherPythonAsyncOTelInstrumented(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherMultiSegWritev(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack(), "compose-base.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=8388`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Log Enricher multi-seg writev", func(t *testing.T) {
		testLogEnricherMultiSegWritev(t)
	})
	t.Run("Log Enricher shipper filters", func(t *testing.T) {
		testLogEnricherShipperFilters(t)
	})
	require.NoError(t, compose.Close())
}

// The idea behind this test suite is to make sure that when an HTTP request is bigger than 1KB,
// the traceparent is detected and parsed correctly during an ingress flow (protocol_http kprob)
// and an egress flow (tpinjector sk_msg kprobe).
// In previous versions of OBI, tpinjector.c:obi_packet_extender_find_existing_tp()
// and protocol_http.h:__obi_continue_protocol_http_tp() had problematic bitwise operations that
// can change or corrupt the traceparent header when parsing a 1KB+ HTTP request.
func TestSuite_LargeHTTPRequest(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			NetworkMode: "service:httpproxyserver",
			Pid:         "service:httpproxyserver",
			Command:     []string{"--config=/configs/obi-config.yml"},
			Volumes: []string{
				"./configs/:/configs",
				"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
				"/sys/fs/cgroup:/sys/fs/cgroup",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-large-http-req:/var/run/obi",
			},
			DependsOn: map[string]string{"httpproxyserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_CONTEXT_PROPAGATION":   "all",
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
				"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_METRICS_FEATURES":          "application,application_span_otel,application_process,application_service_graph,ebpf,application_host",
				"OTEL_EBPF_METRICS_INTERVAL":          "10ms",
				"OTEL_EBPF_PROMETHEUS_FEATURES":       "application,application_span_otel,application_process,application_service_graph,ebpf,application_host",
			},
		}),
		"httpproxyserver": &docker.ServiceDef{
			Image:           "hatest-httpproxyserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/http_proxy_server/Dockerfile",
			Ports:           []string{"3035:3030"},
			DependsOn:       map[string]string{"otelcol": "service_started"},
			Env: map[string]string{
				"OTEL_SERVICE_NAME": "httpproxyserver",
			},
		},
		"jaeger": &docker.ServiceDef{
			Ports: []string{"16686:16686", "4317", "4318"},
		},
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-jaeger.yml")
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3030`, `OTEL_EBPF_EXECUTABLE_PATH=`)
	require.NoError(t, compose.Up())

	t.Run("Large HTTP Request egress flow (kprobe: tpinjector[sk_msg])", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:3035")
		testLargeHTTPRequestEgress(t)
	})

	t.Run("Large HTTP Request ingress flow (kprobe: protocol_http)", func(t *testing.T) {
		testLargeHTTPRequestIngress(t)
	})

	t.Run("Large HTTP Request egress flow with arbitrary size (kprobe: tpinjector[sk_msg])", func(t *testing.T) {
		testLargeHTTPRequestEgressArbitrarySize(t)
	})

	t.Run("Large HTTP Request ingress flow with arbitrary size (kprobe: protocol_http)", func(t *testing.T) {
		testLargeHTTPRequestIngressArbitrarySize(t)
	})

	require.NoError(t, compose.Close())
}

// Helpers

var lockdownPath = "/sys/kernel/security/lockdown"

func KernelLockdownMode() bool {
	// If we can't find the file, assume no lockdown
	if _, err := os.Stat(lockdownPath); err == nil {
		f, err := os.Open(lockdownPath)
		if err != nil {
			return true
		}

		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			lockdown := scanner.Text()
			switch {
			case strings.Contains(lockdown, "[none]"):
				return false
			case strings.Contains(lockdown, "[integrity]"):
				return true
			case strings.Contains(lockdown, "[confidentiality]"):
				return true
			default:
				return true
			}
		}

		return true
	}

	return false
}

func logEnricherStack() docker.Stack {
	return docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			ConfigYAML: obiConfigLogEnricher,
			Networks:   []string{"shared"},
			Pid:        "host",
			Volumes: []string{
				"./configs/:/configs",
				"/sys/kernel/security:/sys/kernel/security:ro",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-python:/var/run/obi",
				"/sys/fs/bpf:/sys/fs/bpf",
			},
			DependsOn: map[string]string{"testserverdotnet": "service_started", "testservergrpcgo": "service_started", "testserverhttp": "service_started", "testserverjava": "service_started", "testservermultisegwritev": "service_started", "testservernodejs": "service_started", "testserverpythonasync": "service_started", "testserverruby": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT":  "5s",
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
				"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_METRICS_FEATURES":          "application,application_process,application_span_otel,application_service_graph",
				"OTEL_EBPF_METRICS_INTERVAL":          "10ms",
				"OTEL_EBPF_PROCESSES_INTERVAL":        "100ms",
				"OTEL_EBPF_PROMETHEUS_FEATURES":       featuresProcess,
			},
		}),
		"multisegwritev_fluentbit": &docker.ServiceDef{
			Image:    "fluent/fluent-bit:5.0.5@sha256:18dcc82ddc16f3ff567effd3dc6f7c7f8d542cebefbb1b7ecd8bc28c04daf871",
			User:     "0:0",
			Networks: []string{"shared"},
			Volumes: []string{
				"/var/lib/docker/containers:/var/lib/docker/containers:ro",
				"./configs/fluentbit-multiseg-filter.conf:/fluent-bit/etc/fluent-bit.conf:ro",
				"../../../testoutput/multiseg-shipper-output:/output",
			},
			DependsOn: map[string]string{"testservermultisegwritev": "service_started"},
		},
		"multisegwritev_otelcol": &docker.ServiceDef{
			Image:    "otel/opentelemetry-collector-contrib:0.156.0@sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108",
			User:     "0:0",
			Networks: []string{"shared"},
			Command:  []string{"--config=/etc/otelcol-contrib/config.yaml"},
			Volumes: []string{
				"/var/lib/docker/containers:/var/lib/docker/containers:ro",
				"./configs/otelcol-multiseg-filter.yaml:/etc/otelcol-contrib/config.yaml:ro",
				"../../../testoutput/multiseg-shipper-output:/output",
			},
			DependsOn: map[string]string{"testservermultisegwritev": "service_started"},
		},
		"testserverdotnet": &docker.ServiceDef{
			Image:           "hatest-testserver-logenricher-dotnet",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/dotnetserver/Dockerfile",
			Networks:        []string{"shared"},
			Ports:           []string{"8386:5266"},
		},
		"testservergrpcgo": &docker.ServiceDef{
			Image:           "hatest-testserver-logenricher-grpc-go",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/go_simple_grpc/Dockerfile",
			Networks:        []string{"shared"},
			Ports:           []string{"8382:8080"},
		},
		"testserverhttp": &docker.ServiceDef{
			Image:           "hatest-testserver-logenricher-http",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/pythonserver/Dockerfile",
			Networks:        []string{"shared"},
			Ports:           []string{"8381:8380"},
		},
		"testserverjava": &docker.ServiceDef{
			Image:           "hatest-testserver-logenricher-java",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/javatestserver/Dockerfile_jar",
			Networks:        []string{"shared"},
			Ports:           []string{"8384:8085"},
		},
		"testservermultisegwritev": &docker.ServiceDef{
			Image:           "hatest-testserver-logenricher-multiseg-writev",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/logenricher_writev/Dockerfile",
			Networks:        []string{"shared"},
			Ports:           []string{"8388:8388"},
			Env: map[string]string{
				"PORT": "8388",
			},
		},
		"testservernodejs": &docker.ServiceDef{
			Image:           "hatest-testserver-node",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/nodejsserver/Dockerfile",
			Networks:        []string{"shared"},
			Ports:           []string{"8383:3030"},
		},
		"testserverpythonasync": &docker.ServiceDef{
			Image:           "hatest-testserver-logenricher-pythonasync",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/pythonasync-uvloop/Dockerfile-3.14",
			Networks:        []string{"shared"},
			Ports:           []string{"8387:8391"},
			Env: map[string]string{
				"BACKEND_URL":      "http://testserverhttp:8380",
				"PYTHONUNBUFFERED": "1",
				"UVICORN_LOOP":     "uvloop",
			},
		},
		"testserverruby": &docker.ServiceDef{
			Image:           "hatest-testserver-logenricher-ruby",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/rubytestserver/testapi/Dockerfile",
			Networks:        []string{"shared"},
			Ports:           []string{"8385:3040"},
			Env: map[string]string{
				"PORT":              "3040",
				"RAILS_MAX_THREADS": "2",
			},
		},
	}, Networks: []string{"shared"}}
}

func railsFamilyStack() docker.Stack {
	return docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			ConfigYAML:  obiConfigRuby,
			NetworkMode: "host",
			Pid:         "host",
			RunDir:      "run-ruby",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_EXECUTABLE_PATH": "${OTEL_EBPF_EXECUTABLE_PATH}",
			},
		}),
		"jaeger": &docker.ServiceDef{
			Ports: []string{"16686:16686", "4417:4317", "4418:4318"},
		},
		"nginx": &docker.ServiceDef{
			Image:         "${NGINX_IMAGE:-nginx:latest@sha256:dec7a90bd0973b076832dc56933fe876bc014929e14b4ec49923951405370112}",
			ContainerName: "nginx_server",
			Ports:         []string{"8443:443"},
			Volumes: []string{
				"./components/rubytestserver/nginx/nginx.conf:/etc/nginx/nginx.conf:ro",
				"./components/rubytestserver/nginx/cert.pem:/etc/nginx/cert.pem:ro",
				"./components/rubytestserver/nginx/key.pem:/etc/nginx/key.pem:ro",
			},
			DependsOn: map[string]string{"testserver": "service_started"},
		},
		"otelcol": &docker.ServiceDef{
			Ports:     []string{"4317:4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"jaeger": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:     "${TESTSERVER_IMAGE:?TESTSERVER_IMAGE must be set to a digest-pinned obi-testimg rails reference}",
			Ports:     []string{"${TEST_SERVICE_PORTS}"},
			DependsOn: map[string]string{"otelcol": "service_started"},
			Env: map[string]string{
				"OTEL_RESOURCE_ATTRIBUTES": "cloud.region=ca,deployment.environment.name=staging",
				"OTEL_SERVICE_NAME":        "my-ruby-app",
			},
		},
	}}
}

func uvloopFamilyStack() docker.Stack {
	return docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			Pid:     "host",
			Command: []string{"--config=/configs/obi-config.yml"},
			Ports:   []string{"8999:8999"},
			Volumes: []string{
				"./configs/:/configs",
				"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-python-async:/var/run/obi",
			},
			DependsOn: map[string]string{"jaeger": "service_started", "pythonasync": "service_started", "testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_EXECUTABLE_NAME":                           "",
				"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
				"OTEL_EBPF_METRICS_FEATURES":                          "application,application_span_otel,application_process,application_service_graph,ebpf,application_host",
				"OTEL_EBPF_OPEN_PORT":                                 "8391,8080",
				"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
				"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
				"OTEL_EBPF_PROMETHEUS_FEATURES":                       "application,application_span_otel,application_process,application_service_graph,ebpf,application_host",
			},
		}),
		"jaeger": &docker.ServiceDef{
			Ports: []string{"16686:16686", "4317", "4318"},
		},
		"otelcol": &docker.ServiceDef{
			Ports:     []string{"4317", "4318", "9464", "8888"},
			DependsOn: map[string]string{"jaeger": "service_started", "obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Command: []string{"--config.file=/etc/prometheus/prometheus-config.yml", "--web.enable-lifecycle", "--enable-feature=exemplar-storage", "--web.route-prefix=/"},
			Ports:   []string{"9090:9090"},
		},
		"pythonasync": &docker.ServiceDef{
			Image:           "hatest-pythonasync-uvloop",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/pythonasync-uvloop/${UVLOOP_DOCKERFILE}",
			Ports:           []string{"8391:8391"},
			DependsOn:       map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"BACKEND_URL":       "http://testserver:8080",
				"LOG_LEVEL":         "DEBUG",
				"OTEL_SERVICE_NAME": "pythonasync-uvloop",
				"UVICORN_LOOP":      "uvloop",
			},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/testserver/Dockerfile",
			Ports:           []string{"8085:8080"},
		},
	}}
}

func awsFamilyStack() docker.Stack {
	return docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-python-graphql",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_BATCH_TIMEOUT":         "100ms",
				"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":      "2048",
				"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT":  "5s",
				"OTEL_EBPF_CONFIG_PATH":               "/configs/obi-config.yml",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "http://otelcol:4318",
				"OTEL_EBPF_EXECUTABLE_PATH":           "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_HTTP_AWS_ENABLED":          "true",
				"OTEL_EBPF_METRICS_FEATURES":          "application",
				"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT": "100ms",
				"OTEL_EBPF_PROCESSES_INTERVAL":        "100ms",
				"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":      "true",
			},
		}),
		"jaeger": &docker.ServiceDef{
			Ports: []string{"16686:16686", "14317:4317", "14318:4318"},
		},
		"localstack": &docker.ServiceDef{
			Image:         "localstack/localstack:4.14@sha256:3ebc37595918b8accb852f8048fef2aff047d465167edd655528065b07bc364a",
			ContainerName: "localstack",
			Ports:         []string{"4566:4566"},
		},
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-debug.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"jaeger": "service_started", "prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Ports: []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver-python-aws-client",
			BuildContext:    "../../../internal/test/integration/components/pythonawsclient/",
			BuildDockerfile: "Dockerfile",
			Ports:           []string{"${TEST_SERVICE_PORTS}"},
			DependsOn:       map[string]string{"localstack": "service_started", "otelcol": "service_started"},
		},
	}}
}
