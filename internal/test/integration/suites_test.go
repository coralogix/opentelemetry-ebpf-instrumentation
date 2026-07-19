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

// hostOBIStack is the default-suite shape: host-pid obi over the shared Go
// testserver from docker-compose.yml, with the given /configs file
func hostOBIStack(t *testing.T, config string) *docker.Compose {
	return docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Pid:     "host",
			Command: []string{"--config=/configs/" + config},
			Ports:   []string{"8999:8999"},
			RunDir:  "run-base${TESTSERVER_DOCKERFILE_SUFFIX}",
			Env: map[string]string{
				"OTEL_EBPF_EXECUTABLE_PATH":                  "testserver",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresFull,
				"OTEL_EBPF_PROMETHEUS_FEATURES":              featuresFull,
				"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":         "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			},
		}),
		"otelcol": docker.OtelcolAfterOBI(),
	}), "docker-compose.yml")
}

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
			compose, err := docker.ComposeStackServices(path.Join(pathOutput, "test-suite-"+tc.name+".log"), docker.NewStack(map[string]*docker.ServiceDef{
				"obi": docker.NewOBI(docker.OBI{
					Pid:     "host",
					Command: []string{"--config=/configs/obi-config.yml"},
					Ports:   []string{"8999:8999"},
					RunDir:  "run-base${TESTSERVER_DOCKERFILE_SUFFIX}",
					Env: map[string]string{
						"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
						"OTEL_EBPF_EXECUTABLE_PATH":                  "(pingclient|testserver)",
						"OTEL_EBPF_METRICS_FEATURES":                 featuresFull,
						"OTEL_EBPF_PROMETHEUS_FEATURES":              featuresFull,
						"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":         "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
					},
				}),
				"otelcol": docker.OtelcolAfterOBI(),
			}), "docker-compose.yml")
			require.NoError(t, err)
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
	compose := hostOBIStack(t, "obi-config.yml")
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
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
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
				"OTEL_EBPF_OPEN_PORT":                        "8080",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_LOG_LEVEL":                        "INFO",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresFull,
				"OTEL_EBPF_PROMETHEUS_FEATURES":              featuresFull,
			},
		}),
		"otelcol": docker.OtelcolAfterOBI(),
	}), "docker-compose-go-generic.yml"), nil, true,
		st("Generic Go HTTP/TCP traces (all spans nested)", testGoGenericHTTPTraces),
		st("Generic Go HTTPS/TCP(TLS) traces (all spans nested)", testGoGenericHTTPSTraces))
}

func TestSuiteClientPromScrape(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Command: []string{"--config=/configs/obi-config-promscrape.yml"},
			Ports:   []string{"8999:8999"},
			Pid:     "service:testserver",
			RunDir:  "run-client",
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_ENFORCE_SYS_CAPS":                 "false",
				"OTEL_EBPF_EXECUTABLE_PATH":                  "pingclient",
				"OTEL_EBPF_METRIC_FEATURES":                  "application",
				"OTEL_EBPF_PROMETHEUS_FEATURES":              "application,application_span,application_service_graph,application_host",
			},
		}),
		"otelcol": docker.OtelcolAfterOBI(),
	}), "docker-compose-client.yml")
	compose.Env = append(compose.Env,
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
	compose := hostOBIStack(t, "obi-config.yml")
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
	compose := hostOBIStack(t, "obi-config.yml")
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
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Pid:     "service:testserver",
			Command: []string{"--config=/configs/obi-config.yml"},
			Ports:   []string{"8999:8999"},
			Volumes: []string{
				"./configs/:/configs",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-1.17:/var/run/obi",
			},
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresAppSpan,
				"OTEL_GO_AUTO_TARGET_EXE":                    "${OTEL_GO_AUTO_TARGET_EXE}",
			},
		}),
		"otelcol": docker.OtelcolAfterOBI(),
	}), "docker-compose-1.17.yml")
	compose.Env = append(compose.Env, `OTEL_GO_AUTO_TARGET_EXE=*testserver`)
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
	runSuite(t, hostOBIStack(t, "obi-config.yml"), []string{`OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=1`}, true,
		st("RED metrics", testREDMetricsShortHTTP))
}

func TestSuite_GRPCExport(t *testing.T) {
	runSuite(t, hostOBIStack(t, "obi-config-grpc-export.yml"), nil, true,
		st("RED metrics", testREDMetricsHTTP),
		st("trace HTTP service and export as GRPC traces", testHTTPTraces),
		st("trace GRPC service and export as GRPC traces", testGRPCTraces),
		st("GRPC RED metrics", testREDMetricsGRPC))
}

func TestSuite_GRPCExportKProbes(t *testing.T) {
	compose := hostOBIStack(t, "obi-config-grpc-export.yml")
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
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Pid:     "host",
			Command: []string{"--config=/configs/obi-config-promscrape.yml"},
			Ports:   []string{"8999:8999"},
			RunDir:  "run-base${TESTSERVER_DOCKERFILE_SUFFIX}",
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_OPEN_PORT":                        "8082,8999",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresFull,
				"OTEL_EBPF_PROMETHEUS_FEATURES":              featuresFull,
				"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":         "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
			},
		}),
		"otelcol": docker.OtelcolAfterOBI(),
	}), "docker-compose.yml")
	compose.Env = append(compose.Env,
		`PROM_CONFIG_SUFFIX=-promscrape`,
		// force OBI self-instrumentation to ensure we don't do it,
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
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Image:           "hatest-javaobi",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/obi/Dockerfile",
			NetworkMode:     "service:testserver",
			Pid:             "host",
			Command:         []string{"--config=/configs/obi-config-java.yml"},
			RunDir:          "run-java",
			DependsOn:       map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_EXECUTABLE_PATH": "greeting",
				"OTEL_EBPF_OPEN_PORT":       "",
				"OTEL_SERVICE_NAME":         "${OTEL_SERVICE_NAME}",
			},
		}),
		"otelcol": docker.OtelcolNoJaeger(),
		"jaeger":  nil,
	}), "docker-compose-java.yml"), []string{`TESTSERVER_IMAGE=` + obiTestImgJavaNative}, true,
		st("Java RED metrics", testREDMetricsJavaHTTP))
}

// Same as TestSuite_Java but we run in the process namespace and it uses process namespace filtering
func TestSuite_Java_PID(t *testing.T) {
	vOtelcol := docker.NewServices()["otelcol"]
	vOtelcol.Command = []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"}
	vOtelcol.DependsOn = map[string]string{"obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"}
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Image:           "hatest-javaobi",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/obi/Dockerfile",
			NetworkMode:     "service:testserver",
			Pid:             "service:testserver",
			RunDir:          "run-java-pid",
			DependsOn:       map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_BPF_HIGH_REQUEST_VOLUME": "true",
				"OTEL_EBPF_CONFIG_PATH":             "/configs/obi-config-java.yml",
				"OTEL_EBPF_OPEN_PORT":               "8085",
				"OTEL_SERVICE_NAME":                 "${OTEL_SERVICE_NAME}",
			},
		}),
		"otelcol": vOtelcol,
		"jaeger":  nil,
	}), "docker-compose-java-pid.yml"), []string{`TESTSERVER_IMAGE=` + obiTestImgJavaJar, `OTEL_SERVICE_NAME=greeting`}, true,
		st("Java RED metrics", testREDMetricsJavaHTTP))
}

// Same as Java Test suite, but searching the executable by port instead of executable name. We also run the jar version of Java instead of native image
func TestSuite_Java_OpenPort(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Image:           "hatest-javaobi",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/obi/Dockerfile",
			NetworkMode:     "service:testserver",
			Pid:             "host",
			Command:         []string{"--config=/configs/obi-config-java.yml"},
			RunDir:          "run-java",
			DependsOn:       map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT": "8085",
				"OTEL_SERVICE_NAME":   "${OTEL_SERVICE_NAME}",
			},
		}),
		"otelcol": docker.OtelcolNoJaeger(),
		"jaeger":  nil,
	}), "docker-compose-java.yml")
	compose.Env = append(compose.Env, `TESTSERVER_IMAGE=`+obiTestImgJavaJar, `OTEL_SERVICE_NAME=greeting`)
	require.NoError(t, compose.Up())
	t.Run("Java RED metrics", testREDMetricsJavaHTTP)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

// Test that we can also instrument when running with host network mode
func TestSuite_Java_Host_Network(t *testing.T) {
	vOtelcol := docker.NewServices()["otelcol"]
	vOtelcol.Command = []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"}
	vOtelcol.DependsOn = map[string]string{"obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"}
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Image:           "hatest-javaobi",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/obi/Dockerfile",
			NetworkMode:     "host",
			Pid:             "host",
			Ports:           []string{"8999:8999"},
			RunDir:          "run-java-host",
			Env: map[string]string{
				"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config-java.yml",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://127.0.0.1:4318",
				"OTEL_EBPF_EXECUTABLE_PATH":          "greeting",
				"OTEL_EBPF_OPEN_PORT":                "",
				"OTEL_SERVICE_NAME":                  "${OTEL_SERVICE_NAME}",
			},
		}),
		"otelcol": vOtelcol,
		"jaeger":  nil,
	}), "docker-compose-java-host.yml"), []string{`TESTSERVER_IMAGE=` + obiTestImgJavaNative}, true,
		st("Java RED metrics", testREDMetricsJavaHTTP))
}

func rustSuite(t *testing.T, port, hostPort, image string, tests ...subtest) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			Command:     []string{"--config=/configs/obi-config.yml"},
			RunDir:      "run-rust",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":                 port,
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
				"OTEL_EBPF_TRACE_PRINTER":             "json_indent",
			},
		}),
	}), "docker-compose-rust.yml"), []string{`TEST_SERVICE_PORTS=` + hostPort + `:` + port, `TESTSERVER_IMAGE=` + image}, true, tests...)
}

func TestSuite_Rust(t *testing.T) {
	rustSuite(t, "8090", "8091", obiTestImgRust,
		st("Rust RED metrics", testREDMetricsRustHTTP))
}

func TestSuite_RustSSL(t *testing.T) {
	rustSuite(t, "8490", "8491", obiTestImgRustSSL,
		st("Rust RED metrics", testREDMetricsRustHTTPS))
}

// The actix server that we built our Rust example will enable HTTP2 for SSL automatically if the client supports it.
// We use this feature to implement our kprobes HTTP2 tests, with special http client settings that triggers the Go
// client to attempt http connection.
func TestSuite_RustHTTP2(t *testing.T) {
	rustSuite(t, "8490", "8491", obiTestImgRustSSL,
		st("Rust RED metrics", testREDMetricsRustHTTP2))
}

func nodeJSSuite(t *testing.T, port, app string, tests ...subtest) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigNode,
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-nodejs",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":                 port,
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
			},
		}),
	}), "docker-compose-nodejs.yml"), []string{`NODE_APP=` + app}, true, tests...)
}

func TestSuite_NodeJS(t *testing.T) {
	nodeJSSuite(t, "3030", "app",
		st("NodeJS RED metrics", testREDMetricsNodeJSHTTP),
		st("HTTP traces (kprobes)", testHTTPTracesKProbes),
		st("HTTP nested traces large HTTPS (kprobes)", testHTTPTracesNestedNodeJSLargeHTTPS))
}

func TestSuite_NodeJSTLS(t *testing.T) {
	nodeJSSuite(t, "3033", "app_tls",
		st("NodeJS SSL RED metrics", testREDMetricsNodeJSHTTPS))
}

func TestSuite_Rails(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, railsFamilyStack("3040,443"), "docker-compose-ruby.yml"), []string{`TEST_SERVICE_PORTS=3041:3040`, `TESTSERVER_IMAGE=` + obiTestImgRails}, true,
		st("Rails RED metrics", testREDMetricsRailsHTTP),
		st("Rails NGINX traces", testHTTPTracesNestedNginx))
}

func TestSuite_RailsNginxSupportFloor(t *testing.T) {
	compose := docker.SuiteStackServices(t, railsFamilyStack("3040,443"), "docker-compose-ruby.yml")
	compose.Env = append(
		compose.Env,
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
	vOtelcol := docker.NewServices()["otelcol"]
	vOtelcol.Ports = []string{"4317:4317", "4318:4318", "9464", "8888"}
	vJaeger := docker.NewServices()["jaeger"]
	vJaeger.Ports = []string{"16686:16686", "4417:4317", "4418:4318"}
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigRuby,
			NetworkMode: "host",
			Pid:         "host",
			RunDir:      "run-ruby",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT": "3040,443",
			},
		}),
		"otelcol": vOtelcol,
		"jaeger":  vJaeger,
	}), "docker-compose-ruby-3.0.2-puma5.yml")
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=3041:3040`)
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
	vOtelcol := docker.NewServices()["otelcol"]
	vOtelcol.Ports = []string{"4317:4317", "4318:4318", "9464", "8888"}
	vJaeger := docker.NewServices()["jaeger"]
	vJaeger.Ports = []string{"16686:16686", "4417:4317", "4418:4318"}
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigRuby,
			NetworkMode: "host",
			Pid:         "host",
			RunDir:      "run-ruby",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT": "3040,443",
			},
		}),
		"otelcol": vOtelcol,
		"jaeger":  vJaeger,
	}), "docker-compose-ruby-nginx-sql.yml"), nil, true,
		st("Rails RED metrics", testREDMetricsRailsHTTP),
		st("Rails NGINX SQL traces nested", testHTTPTracesNestedNginxSQL))
}

func TestSuite_RailsTLS(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, railsFamilyStack("3043"), "docker-compose-ruby.yml"), []string{`TESTSERVER_IMAGE=` + obiTestImgRailsSSL, `TEST_SERVICE_PORTS=3044:3043`}, true,
		st("Rails SSL RED metrics", testREDMetricsRailsHTTPS))
}

func TestSuite_DotNet(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Image:           "hatest-obi",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/obi/Dockerfile${INSTRUMENT_DOCKERFILE_SUFFIX}",
			Entrypoint:      []string{"/obi${INSTRUMENT_COMMAND_SUFFIX}"},
			Command:         []string{"--config=/configs/obi-config-java.yml"},
			NetworkMode:     "service:testserver",
			Pid:             "service:testserver",
			RunDir:          "run-dotnet",
			DependsOn:       map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":         "5266",
				"OTEL_EBPF_BPF_BATCH_TIMEOUT": "100ms",
			},
		}),
		"otelcol": docker.OtelcolNoJaeger(),
		"jaeger":  nil,
	}), "docker-compose-dotnet.yml"), nil, true,
		st("DotNet RED metrics", testREDMetricsDotNetHTTP))
}

// Disabled for now as we randomly fail to register 3 events, but only get 2
// Issue: https://github.com/grafana/beyla/issues/208
func TestSuite_DotNetTLS(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			Command:     []string{"--config=/configs/obi-config-java.yml"},
			RunDir:      "run-dotnet",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":         "7033",
				"OTEL_EBPF_BPF_BATCH_TIMEOUT": "100ms",
			},
		}),
		"otelcol": docker.OtelcolNoJaeger(),
		"jaeger":  nil,
	}), "docker-compose-dotnet.yml")
	// Add these above if you want to get the trace_pipe output in the test logs: `INSTRUMENT_DOCKERFILE_SUFFIX=_dbg`, `INSTRUMENT_COMMAND_SUFFIX=_wrapper.sh`
	require.NoError(t, compose.Up())
	t.Run("DotNet SSL RED metrics", testREDMetricsDotNetHTTPS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_Python(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-python", map[string]string{
			"OTEL_EBPF_OPEN_PORT":           "8380",
			"OTEL_EBPF_CONFIG_PATH":         "/configs/obi-config-java.yml",
			"OTEL_EBPF_METRICS_FEATURES":    featuresSpanGraph,
			"OTEL_EBPF_PROMETHEUS_FEATURES": featuresPromSpanGraph,
		}),
		"otelcol": docker.OtelcolNoJaeger(),
		"jaeger":  nil,
	}), "docker-compose-python.yml")
	compose.Env = append(
		compose.Env,
		`TEST_SERVICE_PORTS=8381:8380`,
	)
	require.NoError(t, compose.Up())
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("Python RED metrics with timeouts", testREDMetricsTimeoutPythonHTTP)
	t.Run("Python DNS RED metrics", testREDMetricsDNSPython)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonProm(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-python", map[string]string{
			"OTEL_EBPF_OPEN_PORT":           "8380",
			"OTEL_EBPF_CONFIG_PATH":         "/configs/obi-config-promscrape.yml",
			"OTEL_EBPF_METRICS_FEATURES":    featuresSpanGraph,
			"OTEL_EBPF_PROMETHEUS_FEATURES": featuresPromSpanGraph,
		}),
		"otelcol": docker.OtelcolNoJaeger(),
		"jaeger":  nil,
	}), "docker-compose-python.yml")
	compose.Env = append(
		compose.Env,
		`TEST_SERVICE_PORTS=8381:8380`,
	)
	require.NoError(t, compose.Up())
	t.Run("Python RED metrics", testREDMetricsPythonHTTP)
	t.Run("Python RED metrics with timeouts", testREDMetricsTimeoutPythonHTTP)
	t.Run("Python DNS RED metrics", testREDMetricsDNSPython)
	require.NoError(t, compose.Close())
}

func pythonSQLSuite(t *testing.T, name, yml string, obiEnv map[string]string, tests func(t *testing.T)) {
	env := map[string]string{
		"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
		"OTEL_EBPF_OPEN_PORT":                "8080",
		"OTEL_EBPF_EXECUTABLE_PATH":          "",
		"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
		"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
		"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "sql",
		"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "sql",
		"OTEL_EBPF_METRICS_FEATURES":         "application",
	}
	for k, v := range obiEnv {
		env[k] = v
	}
	compose, err := docker.ComposeStackServices(path.Join(pathOutput, "test-suite-"+name+".log"), docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-"+name, env),
	}), yml)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	tests(t)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonPostgres(t *testing.T) {
	pythonSQLSuite(t, "python-postgresql", "docker-compose-python-postgresql.yml",
		map[string]string{"OTEL_EBPF_BPF_BUFFER_SIZE_POSTGRES": "1024"},
		func(t *testing.T) { t.Run("Python Postgres tests", testPythonPostgres) })
}

func TestSuite_PythonMySQL(t *testing.T) {
	pythonSQLSuite(t, "python-mysql", "docker-compose-python-mysql.yml",
		map[string]string{"OTEL_EBPF_BPF_BUFFER_SIZE_MYSQL": "8192"},
		func(t *testing.T) { t.Run("Python MySQL tests", testPythonMySQL) })
}

func TestSuite_PythonMSSQL(t *testing.T) {
	pythonSQLSuite(t, "python-mssql", "docker-compose-python-mssql.yml",
		map[string]string{"OTEL_EBPF_BPF_BUFFER_SIZE_MSSQL": "8192"},
		func(t *testing.T) { t.Run("Python MSSQL tests", testPythonMSSQL) })
}

func TestSuite_PythonKafka(t *testing.T) {
	stack := docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("${RUN_DIR}", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                "8080",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
			"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
		}),
	})
	runSuite(t, docker.SuiteStackServices(t, stack, "docker-compose-python-kafka.yml"), []string{`TESTSERVER_CONTEXT=../../../internal/test/integration/components/pythonkafka/`, `TESTSERVER_DOCKERFILE=Dockerfile`, `TESTSERVER_IMAGE=hatest-testserver-python-kafka`, `RUN_DIR=run-python`}, true,
		st("Python Kafka tests", testREDMetricsPythonKafkaOnly))
}

func TestSuite_GoKafkaTraceparent(t *testing.T) {
	stack := docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			NoDefaultEnv: true,
			ConfigYAML:   obiConfigGoKafkaTraceparent,
			Networks:     []string{"shared"},
			Pid:          "host",
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
				"OTEL_EBPF_EXECUTABLE_PATH":           "testserver",
				"OTEL_EBPF_HOSTNAME":                  "obi",
				"OTEL_EBPF_LOG_LEVEL":                 "DEBUG",
				"OTEL_EBPF_METRICS_FEATURES":          "application,application_process",
				"OTEL_EBPF_OPEN_PORT":                 "",
				"OTEL_EBPF_PROCESSES_INTERVAL":        "100ms",
				"OTEL_EBPF_PROMETHEUS_FEATURES":       "application,application_process",
				"OTEL_EBPF_SERVICE_NAMESPACE":         "integration-test",
				"OTEL_EBPF_TRACE_PRINTER":             "text",
			},
		}),
		"otelcol":    nil,
		"prometheus": nil,
		"jaeger":     nil,
		"weaver":     nil,
	})
	compose := docker.SuiteStackServices(t, stack, "docker-compose-go-kafka-traceparent.yml")
	// Executable-name discovery: the Kafka broker and Zookeeper are Java processes
	// (Zookeeper's admin server also listens on 8080), so port-based discovery is
	// ambiguous under pid:host
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=8389:8080`)
	require.NoError(t, compose.Up())
	t.Run("Go Kafka stale traceparent contamination (#2046)", testGoKafkaTraceparent)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonMQTT(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-mqtt", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                "8080",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "*",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "*",
		}),
	}), "docker-compose-python-mqtt.yml"), []string{`TESTSERVER_DOCKERFILE=./internal/test/integration/components/pythonmqtt/Dockerfile`, `TESTSERVER_IMAGE=hatest-testserver-python-mqtt`}, true,
		st("Python MQTT publish tests", testREDMetricsPythonMQTT),
		st("Python MQTT subscribe tests", testREDMetricsPythonMQTTSubscribe))
}

func TestSuite_GoMQTT(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-mqtt", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                "8080",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "*",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "*",
		}),
	}), "docker-compose-go-mqtt.yml"), []string{`TESTSERVER_DOCKERFILE=./internal/test/integration/components/gomqtt/Dockerfile`, `TESTSERVER_IMAGE=hatest-testserver-go-mqtt`}, false,
		st("Go MQTT publish tests", testREDMetricsGoMQTT))
}

func TestSuite_GoSunRPC(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-sunrpc", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                "8080",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_PROMETHEUS_FEATURES":      featuresApp,
			"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "sunrpc",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "sunrpc",
		}),
	}), "docker-compose-go-sunrpc.yml"), nil, true,
		st("Go SunRPC tests", testREDMetricsGoSunRPC),
		st("Go SunRPC Prometheus metrics", testREDMetricsGoSunRPCPrometheus))
}

func TestSuite_JavaKafka(t *testing.T) {
	stack := docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-java", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                "8080",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
			"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
		}),
		"jaeger": docker.JaegerUI(),
	})
	compose := docker.SuiteStackServices(t, stack, "docker-compose-java-kafka-400.yml")

	require.NoError(t, compose.Up())
	t.Run("Java Kafka 4.0.0 tests", func(t *testing.T) { testJavaKafka(t, 9092, "javakafka") })
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaKafkaTLS(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Image:           "hatest-obi",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/obi/Dockerfile-with-javaagent",
			NetworkMode:     "service:testserver",
			Pid:             "service:testserver",
			RunDir:          "run-java",
			DependsOn:       map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":                "8080",
				"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
				"OTEL_EBPF_LOG_LEVEL":                "INFO",
				"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
				"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
				"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
				"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
			},
		}),
		"jaeger": docker.JaegerUI(),
	}), "docker-compose-java-kafka-400-tls.yml")

	require.NoError(t, compose.Up())
	t.Run("Java Kafka 4.0.0 tests", func(t *testing.T) { testJavaKafka(t, 9094, "java") })
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_JavaKafkaLargeBuffer(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-java", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                "8080",
			"OTEL_EBPF_BPF_BUFFER_SIZE_KAFKA":    "1024",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
			"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
		}),
		"jaeger": docker.JaegerUI(),
	}), "docker-compose-java-kafka-400-lb.yml"), nil, true,
		st("Java Kafka 4.0.0 large buffer tests", testJavaKafkaLargeBuffer))
}

func TestSuite_NodeRdkafka(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"jaeger": docker.JaegerUI(),
		"obi": docker.TestserverOBI("run-node-rdkafka", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                "8080",
			"OTEL_EBPF_BPF_BUFFER_SIZE_KAFKA":    "65536",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "kafka",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "kafka",
			"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE":   "1000",
		}),
	}), "docker-compose-node-rdkafka.yml"), nil, true,
		st("Node librdkafka topic resolution", testNodeRdkafka))
}

func TestSuite_PythonAsyncUvloop_3_9(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, uvloopFamilyStack(), "docker-compose-python-async-uvloop-3.9.yml"), nil, true,
		st("Sequential", testPythonAsyncSequential),
		st("Concurrent", testPythonAsyncConcurrent),
		st("To Thread", testPythonAsyncToThread),
		st("Nested", testPythonAsyncNested))
}

func TestSuite_PythonAsyncUvloop_3_14(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, uvloopFamilyStack(), "docker-compose-python-async-uvloop-3.14.yml"), nil, true,
		st("Sequential", testPythonAsyncSequential),
		st("Concurrent", testPythonAsyncConcurrent),
		st("To Thread", testPythonAsyncToThread),
		st("Nested", testPythonAsyncNested))
}

func TestSuite_PythonRedis(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigRedis,
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-python",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":                "8080",
				"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
				"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "redis",
				"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "redis",
			},
		}),
	}), "docker-compose-python-redis.yml"), nil, true,
		st("Python Redis metrics", testREDMetricsPythonRedisOnly))
}

func TestSuite_NodeBullMQ(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigRedis,
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-nodejs-bullmq",
			DependsOn:   map[string]string{"testserver": "service_healthy"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":                "3040",
				"OTEL_EBPF_BPF_BUFFER_SIZE_TCP":      "4096",
				"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
				"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "redis",
				"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "redis",
			},
		}),
	}), "docker-compose-nodejs-bullmq.yml")
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=8382:3040`)
	require.NoError(t, compose.Up())
	t.Run("Node BullMQ blocking Redis worker", func(t *testing.T) {
		waitForBullMQTestComponents(t, "http://localhost:8382")
		testREDMetricsNodeBullMQ(t)
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_Aerospike(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigAerospike,
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-aerospike",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
				"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "aerospike",
				"OTEL_EBPF_OPEN_PORT":                "8080",
				"OTEL_EBPF_TRACE_PRINTER":            "text",
				"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "aerospike",
			},
		}),
		"jaeger": {
			Image: "jaegertracing/all-in-one:1.60@sha256:4fd2d70fa347d6a47e79fcb06b1c177e6079f92cba88b083153d56263082135e",
			Ports: []string{"16686:16686", "4317", "4318"},
			Env: map[string]string{
				"COLLECTOR_OTLP_ENABLED": "true",
				"LOG_LEVEL":              "debug",
			},
		},
		"otelcol": {
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
		"prometheus": {
			Image:   "quay.io/prometheus/prometheus:v3.13.0@sha256:c6b27ea434f8389bfe233fbc7be381cf50587c286e871bc842008f5a1b1908a7",
			Command: []string{"--config.file=/etc/prometheus/prometheus-config.yml", "--web.enable-lifecycle", "--web.route-prefix=/"},
			Ports:   []string{"9090:9090"},
			Volumes: []string{
				"./configs/:/etc/prometheus",
			},
		},
	}), "docker-compose-aerospike.yml"), []string{`TEST_SERVICE_PORTS=8390:8080`}, true,
		st("Aerospike RED metrics and traces", testREDMetricsAerospikeOnly))
}

func TestSuite_PythonMongo(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-python", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                "8080",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "mongo",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "mongo",
		}),
	}), "docker-compose-python-mongo.yml"), nil, true,
		st("Python Mongo metrics", testREDMetricsPythonMongoOnly))
}

func TestSuite_PythonCouchbase(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-python", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                "8080",
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":     "2048",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config.yml",
			"OTEL_EBPF_HTTP_SQLPP_ENABLED":       "true",
			"OTEL_EBPF_METRICS_FEATURES":         featuresApp,
			"OTEL_EBPF_METRICS_INSTRUMENTATIONS": "http,couchbase",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACES_INSTRUMENTATIONS":  "http,couchbase",
		}),
	}), "docker-compose-python-couchbase.yml"), nil, true,
		st("Python Couchbase metrics", testREDMetricsPythonCouchbaseOnly),
		st("Python Couchbase default collection", testREDMetricsPythonCouchbaseDefaultCollection),
		st("Python Couchbase error", testREDMetricsPythonCouchbaseError),
		st("Python Couchbase SQL++ metrics", testREDMetricsPythonCouchbaseSQLPP),
		st("Python Couchbase SQL++ with context", testREDMetricsPythonCouchbaseSQLPPWithContext),
		st("Python Couchbase SQL++ error", testREDMetricsPythonCouchbaseSQLPPError))
}

func TestSuite_PythonSQLSSL(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-python-sql", map[string]string{
			"OTEL_EBPF_OPEN_PORT":        "8080",
			"OTEL_EBPF_CONFIG_PATH":      "/configs/obi-config.yml",
			"OTEL_EBPF_METRICS_FEATURES": featuresApp,
		}),
	}), "docker-compose-python-sql-ssl.yml"), nil, true,
		st("Python SQL metrics", testREDMetricsPythonSQLSSL))
}

func TestSuite_PythonTLS(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-python", map[string]string{
			"OTEL_EBPF_OPEN_PORT":           "8380",
			"OTEL_EBPF_CONFIG_PATH":         "/configs/obi-config-java.yml",
			"OTEL_EBPF_METRICS_FEATURES":    featuresSpanGraph,
			"OTEL_EBPF_PROMETHEUS_FEATURES": featuresPromSpanGraph,
		}),
		"otelcol": docker.OtelcolNoJaeger(),
		"jaeger":  nil,
	}), "docker-compose-python.yml")
	compose.Env = append(
		compose.Env,
		`TEST_SERVICE_PORTS=8381:8380`,
		`TESTSERVER_DOCKERFILE_SUFFIX=_tls`,
	)
	require.NoError(t, compose.Up())
	t.Run("Python SSL RED metrics", testREDMetricsPythonHTTPS)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuite_PythonSelfReference(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigWithJaeger,
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-python",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PATH": "/metrics",
				"OTEL_EBPF_OPEN_PORT":                        "7771",
				"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":             "1024",
				"OTEL_EBPF_BPF_CONTEXT_PROPAGATION":          "all",
				"OTEL_EBPF_BPF_MAX_TRANSACTION_TIME":         "500ms",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresSpanGraph,
				"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":        "0ms",
			},
		}),
	}), "docker-compose-python-self.yml"), nil, true,
		st("Python Traces with self-references", testHTTPTracesNestedSelfCalls),
		st("Python Traces transaction too long", testHTTPTracesNestedCallsTooLong))
}

func TestSuite_PythonGraphQL(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("${RUN_DIR}", map[string]string{
			"OTEL_EBPF_OPEN_PORT":            "8080",
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP": "1024",
			"OTEL_EBPF_CONFIG_PATH":          "/configs/obi-config.yml",
			"OTEL_EBPF_HTTP_GRAPHQL_ENABLED": "true",
			"OTEL_EBPF_METRICS_FEATURES":     featuresApp,
		}),
	}), "docker-compose-python-graphql.yml"), []string{`TESTSERVER_CONTEXT=pythongraphql`, `TESTSERVER_IMAGE=hatest-testserver-python-graphql`, `RUN_DIR=run-python-graphql`}, true,
		st("Python GraphQL", testPythonGraphQL))
}

func TestSuite_PythonJsonRPC(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("${RUN_DIR}", map[string]string{
			"OTEL_EBPF_OPEN_PORT":            "8080",
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP": "1024",
			"OTEL_EBPF_CONFIG_PATH":          "/configs/obi-config.yml",
			"OTEL_EBPF_HTTP_JSONRPC_ENABLED": "true",
			"OTEL_EBPF_METRICS_FEATURES":     featuresApp,
		}),
	}), "docker-compose-python-jsonrpc.yml"), []string{`TESTSERVER_CONTEXT=pythonjsonrpc`, `TESTSERVER_IMAGE=hatest-testserver-python-jsonrpc`, `RUN_DIR=run-python-jsonrpc`}, true,
		st("Python JSON-RPC server span", testPythonJSONRPCServer),
		st("Python JSON-RPC RPC metrics", testPythonJSONRPCMetrics))
}

func TestSuite_PythonMCP(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("${RUN_DIR}", map[string]string{
			"OTEL_EBPF_OPEN_PORT":            "8080",
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP": "1024",
			"OTEL_EBPF_CONFIG_PATH":          "/configs/obi-config.yml",
			"OTEL_EBPF_HTTP_MCP_ENABLED":     "true",
			"OTEL_EBPF_METRICS_FEATURES":     featuresApp,
		}),
	}), "docker-compose-python-mcp.yml"), []string{`TESTSERVER_CONTEXT=pythonmcp`, `TESTSERVER_IMAGE=hatest-testserver-python-mcp`, `RUN_DIR=run-python-mcp`}, true,
		st("Python MCP server span", testPythonMCPServer),
		st("Python MCP initialize", testPythonMCPInitialize))
}

func TestSuite_PythonElasticsearch(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-python-elasticsearch", map[string]string{
			"OTEL_EBPF_OPEN_PORT":                  "8080",
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":       "1024",
			"OTEL_EBPF_CONFIG_PATH":                "/configs/obi-config.yml",
			"OTEL_EBPF_HTTP_ELASTICSEARCH_ENABLED": "true",
			"OTEL_EBPF_LOG_CONFIG":                 "yaml",
			"OTEL_EBPF_METRICS_FEATURES":           featuresApp,
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":       "true",
			"OTEL_EBPF_TRACE_PRINTER":              "json_indent",
		}),
	}), "docker-compose-elasticsearch.yml")

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
	runSuite(t, docker.SuiteStackServices(t, awsFamilyStack(), "docker-compose-python-aws.yml"), nil, true,
		st("Python AWS S3", testPythonAWSS3))
}

func TestSuite_PythonAWSSQS(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, awsFamilyStack(), "docker-compose-python-aws.yml"), nil, true,
		st("Python AWS SQS", testPythonAWSSQS))
}

func TestSuite_NodeJSDist(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Image:           "hatest-obi-b",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/obi/Dockerfile-with-javaagent",
			ConfigYAML:      obiConfigWithJaegerHost,
			NetworkMode:     "host",
			Pid:             "host",
			RunDir:          "run-nodejsdist",
			ExtraVolumes:    []string{"/sys/fs/cgroup:/sys/fs/cgroup"},
			DependsOn:       map[string]string{"testserver_b": "service_started", "testserver_r": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PATH": "/metrics",
				"OTEL_EBPF_BPF_CONTEXT_PROPAGATION":          "all",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresSpanGraph,
				"OTEL_EBPF_OPEN_PORT":                        "5001,5006",
			},
		}),
	}), "docker-compose-nodejs-dist.yml"), nil, true,
		st("NodeJS Distributed Traces with multiple chained calls", testHTTPTracesNestedNodeJSDistCalls))
}

func TestSuite_DisableKeepAlives(t *testing.T) {
	compose := hostOBIStack(t, "obi-config.yml")
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
	compose := hostOBIStack(t, "obi-config-override-svcname.yml")
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
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigAerospike,
			NetworkMode: "service:nodeclient",
			Pid:         "service:nodeclient",
			Command:     []string{"--config=/configs/obi-config.yml"},
			RunDir:      "run-nodeclient",
			DependsOn:   map[string]string{"nodeclient": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_AUTO_TARGET_LANGUAGE":             "nodejs",
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS":        "true",
			},
		}),
	}), "docker-compose-nodeclient.yml")
	compose.Env = append(compose.Env, `NODE_APP=client`)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 301, 80, "0000000000000000")
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuiteNodeClientTLS(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			NetworkMode: "service:nodeclient",
			Pid:         "service:nodeclient",
			Command:     []string{"--config=/configs/obi-config.yml"},
			RunDir:      "run-nodeclient",
			DependsOn:   map[string]string{"nodeclient": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_AUTO_TARGET_LANGUAGE":             "nodejs",
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS":        "true",
			},
		}),
	}), "docker-compose-nodeclient.yml")
	compose.Env = append(compose.Env, `NODE_APP=client_tls`)
	require.NoError(t, compose.Up())
	t.Run("Node Client RED metrics", func(t *testing.T) {
		testNodeClientWithMethodAndStatusCode(t, "GET", 200, 443, "0000000000000001")
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestSuiteNoRoutes(t *testing.T) {
	runSuite(t, hostOBIStack(t, "obi-config-no-route.yml"), nil, true,
		st("RED metrics", testREDMetricsHTTPNoRoute))
}

func TestSuiteNoRoutesLowCardinality(t *testing.T) {
	runSuite(t, hostOBIStack(t, "obi-config-no-route-lc.yml"), nil, true,
		st("RED metrics", testREDMetricsHTTPNoRouteLowCardinality))
}

func TestSuite_Elixir(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigElixir,
			NetworkMode: "service:testserver",
			Pid:         "service:testserver",
			RunDir:      "run-elixir",
			DependsOn:   map[string]string{"testserver": "service_started"},
		}),
		"otelcol": docker.OtelcolNoJaeger(),
		"jaeger":  nil,
	}), "docker-compose-elixir.yml"), nil, true,
		st("Elixir RED metrics", testREDMetricsElixirHTTP))
}

func TestSuite_LogEnricherHTTP(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack("8380"), "docker-compose-log-enricher.yml")
	require.NoError(t, compose.Up())

	t.Run("Log Enricher HTTP", func(t *testing.T) {
		testLogEnricher(t, logEnricherHTTPConstants)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherGoGRPC(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack("50051"), "docker-compose-log-enricher.yml")
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
	compose := docker.SuiteStackServices(t, logEnricherStack("3030"), "docker-compose-log-enricher.yml")
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Node.js", func(t *testing.T) {
		testLogEnricherNodeJS(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherJava(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack("8085"), "docker-compose-log-enricher.yml")
	require.NoError(t, compose.Up())

	t.Run("Log Enricher Java", func(t *testing.T) {
		testLogEnricherJava(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherRuby(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack("3040"), "docker-compose-log-enricher.yml")
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
	compose := docker.SuiteStackServices(t, logEnricherStack("5266"), "docker-compose-log-enricher.yml")
	require.NoError(t, compose.Up())

	t.Run("Log Enricher .NET", func(t *testing.T) {
		testLogEnricherDotNet(t)
	})
	require.NoError(t, compose.Close())
}

func TestSuite_LogEnricherPythonAsync(t *testing.T) {
	compose := docker.SuiteStackServices(t, logEnricherStack("8391"), "docker-compose-log-enricher.yml")
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
	compose := docker.SuiteStackServices(t, logEnricherStack("8388"), "docker-compose-log-enricher.yml")
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
	vOtelcol := docker.NewServices()["otelcol"]
	vOtelcol.Command = []string{"--config=/etc/otelcol-config/otelcol-config.yml"}
	vOtelcol.DependsOn = map[string]string{"prometheus": "service_started"}
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			NetworkMode:  "service:httpproxyserver",
			Pid:          "service:httpproxyserver",
			Command:      []string{"--config=/configs/obi-config.yml"},
			RunDir:       "run-large-http-req",
			ExtraVolumes: []string{"/sys/fs/cgroup:/sys/fs/cgroup"},
			DependsOn:    map[string]string{"httpproxyserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT":                 "3030",
				"OTEL_EBPF_BPF_CONTEXT_PROPAGATION":   "all",
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
				"OTEL_EBPF_METRICS_FEATURES":          featuresProcessFull,
				"OTEL_EBPF_METRICS_INTERVAL":          "10ms",
				"OTEL_EBPF_PROMETHEUS_FEATURES":       featuresProcessFull,
			},
		}),
		"otelcol": vOtelcol,
		"weaver":  nil,
	}), "docker-compose-large-http-req.yml")
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

func logEnricherStack(openPort string) docker.Stack {
	s := docker.NewStack(map[string]*docker.ServiceDef{
		"otelcol":    nil,
		"prometheus": nil,
		"jaeger":     nil,
		"weaver":     nil,
		"obi": docker.NewOBI(docker.OBI{
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
				"OTEL_EBPF_OPEN_PORT":                 openPort,
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "true",
				"OTEL_EBPF_METRICS_FEATURES":          "application,application_process,application_span_otel,application_service_graph",
				"OTEL_EBPF_METRICS_INTERVAL":          "10ms",
				"OTEL_EBPF_PROMETHEUS_FEATURES":       featuresProcess,
			},
		}),
	})
	s.Networks = []string{"shared"}
	return s
}

func railsFamilyStack(openPort string) docker.Stack {
	vJaeger := docker.NewServices()["jaeger"]
	vJaeger.Ports = []string{"16686:16686", "4417:4317", "4418:4318"}
	vOtelcol := docker.NewServices()["otelcol"]
	vOtelcol.Ports = []string{"4317:4317", "4318:4318", "9464", "8888"}
	return docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			ConfigYAML:  obiConfigRuby,
			NetworkMode: "host",
			Pid:         "host",
			RunDir:      "run-ruby",
			DependsOn:   map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_OPEN_PORT": openPort,
			},
		}),
		"jaeger":  vJaeger,
		"otelcol": vOtelcol,
	})
}

func uvloopFamilyStack() docker.Stack {
	vPrometheus := docker.NewServices()["prometheus"]
	vPrometheus.Command = []string{"--config.file=/etc/prometheus/prometheus-config.yml", "--web.enable-lifecycle", "--enable-feature=exemplar-storage", "--web.route-prefix=/"}
	return docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Pid:       "host",
			Command:   []string{"--config=/configs/obi-config.yml"},
			Ports:     []string{"8999:8999"},
			RunDir:    "run-python-async",
			DependsOn: map[string]string{"jaeger": "service_started", "pythonasync": "service_started", "testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_EXECUTABLE_NAME":                  "",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresProcessFull,
				"OTEL_EBPF_OPEN_PORT":                        "8391,8080",
				"OTEL_EBPF_PROMETHEUS_FEATURES":              featuresProcessFull,
			},
		}),
		"otelcol":    docker.OtelcolAfterOBI(),
		"prometheus": vPrometheus,
	})
}

func awsFamilyStack() docker.Stack {
	vJaeger := docker.NewServices()["jaeger"]
	vJaeger.Ports = []string{"16686:16686", "14317:4317", "14318:4318"}
	vOtelcol := docker.NewServices()["otelcol"]
	vOtelcol.Command = []string{"--config=/etc/otelcol-config/otelcol-config-weaver-debug.yml"}
	return docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.TestserverOBI("run-python-graphql", map[string]string{
			"OTEL_EBPF_BPF_BATCH_TIMEOUT":         "100ms",
			"OTEL_EBPF_OPEN_PORT":                 "8080",
			"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP":      "2048",
			"OTEL_EBPF_CONFIG_PATH":               "/configs/obi-config.yml",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "http://otelcol:4318",
			"OTEL_EBPF_HTTP_AWS_ENABLED":          "true",
			"OTEL_EBPF_METRICS_FEATURES":          featuresApp,
			"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT": "100ms",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":      "true",
		}),
		"jaeger":  vJaeger,
		"otelcol": vOtelcol,
	})
}
