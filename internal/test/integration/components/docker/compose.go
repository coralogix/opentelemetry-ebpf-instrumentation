// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package docker provides some helpers to manage docker-compose clusters from the test suites
package docker // import "go.opentelemetry.io/obi/internal/test/integration/components/docker"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/obi/internal/test/tools"
)

// composeArgs prepends the standard compose invocation with one -f per layered file
func (c *Compose) composeArgs(args ...string) []string {
	intDir := filepath.Join(tools.ProjectDir(), "internal", "test", "integration")
	cmdArgs := []string{"compose", "--ansi", "never", "--project-directory", intDir}
	for _, p := range c.Paths {
		cmdArgs = append(cmdArgs, "-f", p)
	}
	return append(cmdArgs, args...)
}

// stopTimeout bounds how long `docker compose stop` waits between SIGTERM and
// SIGKILL for each container. Keeps shutdown predictable when a container is
// hung.
const stopTimeout = "5"

// waitTimeout bounds how long Close() will wait for the obi container to
// exit. A stuck container would otherwise burn the shard's job timeout.
const waitTimeout = 30 * time.Second

type Compose struct {
	Paths    []string
	Logger   io.WriteCloser
	Env      []string
	skipWait bool
}

func defaultEnv() []string {
	env := os.Environ()
	// suite appends may repeat this key: compose takes the last occurrence
	env = append(env, "TEST_SERVICE_PORTS=8381:8080")
	return env
}

func ComposeSuite(composeFile, logFile string) (*Compose, error) {
	logs, err := os.OpenFile(logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	if err != nil {
		return nil, err
	}

	// Construct the full path to the Docker Compose file
	projectRoot := tools.ProjectDir()
	composePath := filepath.Join(projectRoot, "internal", "test", "integration", composeFile)

	return &Compose{
		Paths:  []string{composePath},
		Logger: logs,
		Env:    defaultEnv(),
	}, nil
}

// OBI declares the per-suite configuration of the obi service. It is
// rendered as the last compose override layer, so suites configure obi
// entirely from Go instead of re-declaring it in a compose file. Values may
// contain ${VAR} references, which compose interpolates as usual
type Healthcheck struct {
	Test        []string
	Interval    string
	Timeout     string
	Retries     int
	StartPeriod string
}

type ServiceDef struct {
	// RunDir mounts the standard obi volume set with this per-suite
	// /var/run/obi directory under testoutput; ignored when Volumes is set
	RunDir string
	// ExtraVolumes are appended to the RunDir standard set
	ExtraVolumes []string
	// ConfigYAML is written under testoutput and wired as OTEL_EBPF_CONFIG_PATH
	// through the /coverage mount, so suites carry their OBI config inline
	ConfigYAML string
	// CPMatrix passes the CI context-propagation matrix toggles through
	CPMatrix bool
	// NoDefaultEnv skips the shared obiEnv defaults: the suite's Env is the
	// complete obi environment
	NoDefaultEnv    bool
	Image           string
	BuildContext    string
	BuildDockerfile string
	ContainerName   string
	Hostname        string
	User            string
	WorkingDir      string
	Cgroup          string
	Restart         string
	MemoryLimit     string
	Privileged      *bool
	Entrypoint      []string
	CapAdd          []string
	CapDrop         []string
	Networks        []string
	// UlimitNofile renders ulimits.nofile soft/hard values when non-zero
	UlimitNofile [2]int
	Healthcheck  *Healthcheck
	Env          map[string]string
	NetworkMode  string
	Pid          string
	Command      []string
	Ports        []string
	Volumes      []string
	// DependsOn maps a service name to its wait condition (e.g. service_started)
	DependsOn map[string]string
}

// Stack is a full per-suite topology rendered as one compose override layer
type Stack struct {
	Services map[string]*ServiceDef
	// NamedVolumes and Networks declare top-level compose objects
	NamedVolumes []string
	Networks     []string
}

// OBI is the obi service definition; other services use the same shape
type OBI = ServiceDef

// obiEnv is the obi environment shared by most suites; NewOBI merges
// per-suite overrides on top of it
var obiEnv = map[string]string{
	"GOCOVERDIR":                          "/coverage",
	"OTEL_EBPF_TRACE_PRINTER":             "json",
	"OTEL_EBPF_METRICS_INTERVAL":          "1s",
	"OTEL_EBPF_BPF_BATCH_TIMEOUT":         "10ms",
	"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT": "1ms",
	"OTEL_EBPF_LOG_LEVEL":                 "DEBUG",
	"OTEL_EBPF_LOG_FORMAT":                "json",
	"OTEL_EBPF_BPF_DEBUG":                 "TRUE",
	"OTEL_EBPF_HOSTNAME":                  "obi",
	"OTEL_EBPF_SERVICE_NAMESPACE":         "integration-test",
	"OTEL_EBPF_DISCOVERY_POLL_INTERVAL":   "500ms",
	"OTEL_EBPF_PROCESSES_INTERVAL":        "100ms",
	"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT":  "5s",
	// keep unresolved peer addresses raw: no suite asserts renamed hosts
	"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS": "",
	// service.version passthrough, asserted by the exemplar tests and
	// harmless elsewhere
	"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
	"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
}

// cpMatrixEnv passes the CI context-propagation matrix toggles through to obi
var cpMatrixEnv = map[string]string{
	"OTEL_EBPF_BPF_CONTEXT_PROPAGATION":   "${OTEL_EBPF_BPF_CONTEXT_PROPAGATION}",
	"OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP":  "${OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP}",
	"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS": "${OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS}",
}

// Bool returns a pointer for optional boolean fields like Privileged
func Bool(b bool) *bool { return &b }

// logPathFor derives the suite log path from the test name:
// TestSuite_PythonPostgres -> testoutput/test-suite-python-postgres.log
func logPathFor(tb testing.TB) string {
	name := strings.TrimPrefix(tb.Name(), "Test")
	var sb strings.Builder
	for i, r := range name {
		if r == '_' || r == '/' {
			sb.WriteByte('-')
			continue
		}
		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := name[i-1]
			if prev != '_' && prev != '/' && (prev < 'A' || prev > 'Z') {
				sb.WriteByte('-')
			}
		}
		sb.WriteRune(r)
	}
	slug := strings.ToLower(sb.String())
	return filepath.Join(tools.ProjectDir(), "testoutput", "test-"+slug+".log")
}

// TestserverOBI is the obi definition for the most common suite shape: obi
// sharing the test server's network and pid namespaces, with the standard
// volume set. env carries only suite-specific settings; NewOBI fills the rest
func TestserverOBI(runDir string, env map[string]string) *OBI {
	return NewOBI(OBI{
		NetworkMode: "service:testserver",
		Pid:         "service:testserver",
		RunDir:      runDir,
		DependsOn:   map[string]string{"testserver": "service_started"},
		Env:         env,
	})
}

// SuiteStack is ComposeStack with the log file derived from the test name
func SuiteStack(tb testing.TB, obi *OBI, composeFiles ...string) *Compose {
	tb.Helper()
	c, err := ComposeStack(logPathFor(tb), obi, composeFiles...)
	if err != nil {
		tb.Fatalf("creating compose stack: %v", err)
	}
	return c
}

// SuiteStackServices is ComposeStackServices with the log file derived from
// the test name
func SuiteStackServices(tb testing.TB, stack Stack, composeFiles ...string) *Compose {
	tb.Helper()
	c, err := ComposeStackServices(logPathFor(tb), stack, composeFiles...)
	if err != nil {
		tb.Fatalf("creating compose stack: %v", err)
	}
	return c
}

// NewOBI returns o with the standard obi image, privileged mode and
// environment filled in; keys present in o.Env win over the defaults
func NewOBI(o OBI) *OBI {
	if !o.NoDefaultEnv {
		env := maps.Clone(obiEnv)
		if o.CPMatrix {
			maps.Copy(env, cpMatrixEnv)
		}
		maps.Copy(env, o.Env)
		o.Env = env
	}
	if o.BuildContext == "" && o.Image == "" {
		o.BuildContext = "../../.."
		o.BuildDockerfile = "./internal/test/integration/components/obi/Dockerfile"
		o.Image = "hatest-obi"
	}
	if o.Privileged == nil {
		o.Privileged = Bool(true)
	}
	return &o
}

// NewServices returns the standard infrastructure: a wired OpenTelemetry
// collector, prometheus, jaeger and the weaver semconv validator. NewStack
// merges these under a suite's own services; set an entry to nil to omit it
func NewServices() map[string]*ServiceDef {
	return map[string]*ServiceDef{
		"otelcol": {
			Image:         "otel/opentelemetry-collector-contrib:0.156.0@sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108",
			ContainerName: "otel-col",
			MemoryLimit:   "125M",
			Restart:       "unless-stopped",
			Command:       []string{"--config=/etc/otelcol-config/otelcol-config-weaver.yml"},
			Volumes:       []string{"./configs/:/etc/otelcol-config"},
			Ports:         []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{
				"prometheus": "service_started",
				"jaeger":     "service_started",
				"weaver":     "service_healthy",
			},
		},
		"prometheus": {
			Image:         "quay.io/prometheus/prometheus:v3.13.0@sha256:c6b27ea434f8389bfe233fbc7be381cf50587c286e871bc842008f5a1b1908a7",
			ContainerName: "prometheus",
			Command: []string{
				"--config.file=/etc/prometheus/prometheus-config${PROM_CONFIG_SUFFIX:-}.yml",
				"--web.enable-lifecycle",
				"--enable-feature=exemplar-storage",
				"--web.route-prefix=/",
			},
			Volumes: []string{"./configs/:/etc/prometheus"},
			Ports:   []string{"9090:9090"},
		},
		"jaeger": {
			Image: "jaegertracing/all-in-one:1.60@sha256:4fd2d70fa347d6a47e79fcb06b1c177e6079f92cba88b083153d56263082135e",
			Env:   map[string]string{"COLLECTOR_OTLP_ENABLED": "true", "LOG_LEVEL": "debug"},
			Ports: []string{"16686:16686", "4317", "4318"},
		},
		"weaver": {
			Image:         "otel/weaver:v0.24.1@sha256:263964a7d444e77812f7a2d654e17683c4760a968c91278acdb7a44c20ccd572",
			ContainerName: "weaver",
			User:          "0:0",
			WorkingDir:    "/obi-registry",
			Command: []string{
				"registry", "live-check", "--registry", "/obi-registry",
				"--include-unreferenced", "--inactivity-timeout", "300",
				"--admin-port", "4320", "--format", "json",
				"--diagnostic-format", "json", "--output", "/tmp/weaver-out",
			},
			Volumes: []string{"/tmp/obi-weaver-out:/tmp/weaver-out", "../../../schemas/obi:/obi-registry:ro"},
			Ports:   []string{"4320:4320"},
			Healthcheck: &Healthcheck{
				Test:        []string{"CMD-SHELL", "wget --timeout=1 -q -O /dev/null http://127.0.0.1:4317/ 2>&1 | grep -qv refused"},
				Interval:    "5s",
				Timeout:     "2s",
				Retries:     60,
				StartPeriod: "90s",
			},
		},
	}
}

// JaegerUI is the standard jaeger with the kafka UI config mounted
func JaegerUI() *ServiceDef {
	v := NewServices()["jaeger"]
	v.Command = []string{"--query.ui-config=/etc/jaeger/ui-config.json"}
	v.Volumes = []string{"./configs/jaeger-ui-config.json:/etc/jaeger/ui-config.json"}
	return v
}

// OtelcolNoJaeger is the standard collector without the jaeger exporter;
// pair with a `"jaeger": nil` entry
func OtelcolNoJaeger() *ServiceDef {
	v := NewServices()["otelcol"]
	v.Command = []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"}
	return v
}

// OtelcolAfterOBI is the standard collector, additionally waiting for obi
func OtelcolAfterOBI() *ServiceDef {
	v := NewServices()["otelcol"]
	v.DependsOn["obi"] = "service_started"
	return v
}

// NewStack merges the standard infrastructure under the given services.
// Suite entries win; a nil entry removes the service entirely
func NewStack(services map[string]*ServiceDef) Stack {
	merged := NewServices()
	maps.Copy(merged, services)
	for k, v := range merged {
		if v == nil {
			delete(merged, k)
		}
	}
	// drop dependencies on services removed via explicit nil entries; deps on
	// services provided by overlay yml files must survive
	for _, svc := range merged {
		for dep := range svc.DependsOn {
			if v, wasSet := services[dep]; wasSet && v == nil {
				delete(svc.DependsOn, dep)
			}
		}
	}
	return Stack{Services: merged}
}

// ComposeStack builds a suite from layered compose files (base, family,
// fragments), all relative to internal/test/integration, plus the rendered
// per-suite OBI layer
func ComposeStack(logFile string, obi *OBI, composeFiles ...string) (*Compose, error) {
	logs, err := os.OpenFile(logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	if err != nil {
		return nil, err
	}

	projectRoot := tools.ProjectDir()
	intDir := filepath.Join(projectRoot, "internal", "test", "integration")
	paths := make([]string, 0, len(composeFiles)+1)
	for _, f := range composeFiles {
		paths = append(paths, filepath.Join(intDir, f))
	}

	if obi != nil {
		if obi.Image == "" && obi.BuildContext == "" {
			return nil, errors.New("obi service has no image: construct it with docker.NewOBI")
		}
		obi, err = materializeConfig(projectRoot, logFile, obi)
		if err != nil {
			return nil, err
		}
		overlay, err := renderStackOverlay(projectRoot, logFile, Stack{Services: map[string]*ServiceDef{"obi": obi}})
		if err != nil {
			return nil, err
		}
		paths = append(paths, overlay)
	}

	return &Compose{
		Paths:  paths,
		Logger: logs,
		Env:    defaultEnv(),
	}, nil
}

// ComposeStackServices is ComposeStack for suites that define additional
// services (test servers, databases) directly from Go instead of a
// compose-suite yml file
func ComposeStackServices(logFile string, stack Stack, composeFiles ...string) (*Compose, error) {
	logs, err := os.OpenFile(logFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o666)
	if err != nil {
		return nil, err
	}

	projectRoot := tools.ProjectDir()
	intDir := filepath.Join(projectRoot, "internal", "test", "integration")
	paths := make([]string, 0, len(composeFiles)+1)
	for _, f := range composeFiles {
		paths = append(paths, filepath.Join(intDir, f))
	}
	if obi := stack.Services["obi"]; obi != nil {
		if obi.Image == "" && obi.BuildContext == "" {
			return nil, errors.New("obi service has no image: construct it with docker.NewOBI")
		}
		mat, err := materializeConfig(projectRoot, logFile, obi)
		if err != nil {
			return nil, err
		}
		services := maps.Clone(stack.Services)
		services["obi"] = mat
		stack.Services = services
	}
	overlay, err := renderStackOverlay(projectRoot, logFile, stack)
	if err != nil {
		return nil, err
	}
	paths = append(paths, overlay)

	return &Compose{
		Paths:  paths,
		Logger: logs,
		Env:    defaultEnv(),
	}, nil
}

// materializeConfig writes an inline OBI config under testoutput and points
// OTEL_EBPF_CONFIG_PATH at it via the /coverage mount
func materializeConfig(projectRoot, logFile string, obi *ServiceDef) (*ServiceDef, error) {
	if obi.ConfigYAML == "" {
		return obi, nil
	}
	base := strings.TrimSuffix(filepath.Base(logFile), filepath.Ext(logFile))
	name := base + "-obi-config.yml"
	if err := os.WriteFile(filepath.Join(projectRoot, "testoutput", name), []byte(obi.ConfigYAML), 0o666); err != nil {
		return nil, err
	}
	out := *obi
	out.Env = maps.Clone(obi.Env)
	if out.Env == nil {
		out.Env = map[string]string{}
	}
	out.Env["OTEL_EBPF_CONFIG_PATH"] = "/coverage/" + name
	return &out, nil
}

// renderServicesOverlay writes a compose override with the given service
// definitions. Written under testoutput, named after the suite log so
// concurrent suites cannot collide. Key order is fixed so renders are
// deterministic
func renderStackOverlay(projectRoot, logFile string, stack Stack) (string, error) {
	var sb strings.Builder
	sb.WriteString("services:\n")
	for _, name := range slices.Sorted(maps.Keys(stack.Services)) {
		if stack.Services[name] == nil {
			continue
		}
		writeService(&sb, name, stack.Services[name])
	}
	if len(stack.NamedVolumes) > 0 {
		sb.WriteString("volumes:\n")
		for _, v := range stack.NamedVolumes {
			fmt.Fprintf(&sb, "  %s:\n", v)
		}
	}
	if len(stack.Networks) > 0 {
		sb.WriteString("networks:\n")
		for _, n := range stack.Networks {
			fmt.Fprintf(&sb, "  %s:\n", n)
		}
	}

	base := strings.TrimSuffix(filepath.Base(logFile), filepath.Ext(logFile))
	path := filepath.Join(projectRoot, "testoutput", base+"-obi.yml")
	if err := os.WriteFile(path, []byte(sb.String()), 0o666); err != nil {
		return "", err
	}
	return path, nil
}

func writeService(sb *strings.Builder, name string, obi *ServiceDef) {
	fmt.Fprintf(sb, "  %s:\n", name)
	if obi.BuildContext != "" {
		fmt.Fprintf(sb, "    build:\n      context: %q\n", obi.BuildContext)
		if obi.BuildDockerfile != "" {
			fmt.Fprintf(sb, "      dockerfile: %q\n", obi.BuildDockerfile)
		}
	}
	if obi.Image != "" {
		fmt.Fprintf(sb, "    image: %q\n", obi.Image)
	}
	if obi.ContainerName != "" {
		fmt.Fprintf(sb, "    container_name: %q\n", obi.ContainerName)
	}
	if obi.Hostname != "" {
		fmt.Fprintf(sb, "    hostname: %q\n", obi.Hostname)
	}
	if obi.User != "" {
		fmt.Fprintf(sb, "    user: %q\n", obi.User)
	}
	if obi.WorkingDir != "" {
		fmt.Fprintf(sb, "    working_dir: %q\n", obi.WorkingDir)
	}
	if obi.Cgroup != "" {
		fmt.Fprintf(sb, "    cgroup: %q\n", obi.Cgroup)
	}
	if obi.Restart != "" {
		fmt.Fprintf(sb, "    restart: %q\n", obi.Restart)
	}
	if obi.Privileged != nil {
		fmt.Fprintf(sb, "    privileged: %t\n", *obi.Privileged)
	}
	// a non-nil empty Entrypoint renders as [] to clear the image entrypoint
	if obi.Entrypoint != nil {
		if len(obi.Entrypoint) == 0 {
			sb.WriteString("    entrypoint: []\n")
		} else {
			sb.WriteString("    entrypoint:\n")
			for _, e := range obi.Entrypoint {
				fmt.Fprintf(sb, "      - %q\n", e)
			}
		}
	}
	if len(obi.CapAdd) > 0 {
		sb.WriteString("    cap_add:\n")
		for _, c := range obi.CapAdd {
			fmt.Fprintf(sb, "      - %q\n", c)
		}
	}
	if len(obi.CapDrop) > 0 {
		sb.WriteString("    cap_drop:\n")
		for _, c := range obi.CapDrop {
			fmt.Fprintf(sb, "      - %q\n", c)
		}
	}
	if len(obi.Networks) > 0 {
		sb.WriteString("    networks:\n")
		for _, n := range obi.Networks {
			fmt.Fprintf(sb, "      - %q\n", n)
		}
	}
	if obi.UlimitNofile != [2]int{} {
		fmt.Fprintf(sb, "    ulimits:\n      nofile:\n        soft: %d\n        hard: %d\n", obi.UlimitNofile[0], obi.UlimitNofile[1])
	}
	if obi.MemoryLimit != "" {
		fmt.Fprintf(sb, "    deploy:\n      resources:\n        limits:\n          memory: %s\n", obi.MemoryLimit)
	}
	if hc := obi.Healthcheck; hc != nil {
		sb.WriteString("    healthcheck:\n      test:\n")
		for _, t := range hc.Test {
			fmt.Fprintf(sb, "        - %q\n", t)
		}
		if hc.Interval != "" {
			fmt.Fprintf(sb, "      interval: %s\n", hc.Interval)
		}
		if hc.Timeout != "" {
			fmt.Fprintf(sb, "      timeout: %s\n", hc.Timeout)
		}
		if hc.Retries > 0 {
			fmt.Fprintf(sb, "      retries: %d\n", hc.Retries)
		}
		if hc.StartPeriod != "" {
			fmt.Fprintf(sb, "      start_period: %s\n", hc.StartPeriod)
		}
	}
	if len(obi.Command) > 0 {
		sb.WriteString("    command:\n")
		for _, c := range obi.Command {
			fmt.Fprintf(sb, "      - %q\n", c)
		}
	}
	if obi.NetworkMode != "" {
		fmt.Fprintf(sb, "    network_mode: %q\n", obi.NetworkMode)
	}
	if obi.Pid != "" {
		fmt.Fprintf(sb, "    pid: %q\n", obi.Pid)
	}
	if len(obi.Ports) > 0 {
		sb.WriteString("    ports:\n")
		for _, p := range obi.Ports {
			fmt.Fprintf(sb, "      - %q\n", p)
		}
	}
	vols := obi.Volumes
	if len(vols) == 0 && obi.RunDir != "" {
		vols = []string{
			"./configs/:/configs",
			"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX:-}:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/" + obi.RunDir + ":/var/run/obi",
		}
		vols = append(vols, obi.ExtraVolumes...)
	}
	if len(vols) > 0 {
		sb.WriteString("    volumes:\n")
		for _, v := range vols {
			fmt.Fprintf(sb, "      - %q\n", v)
		}
	}
	if len(obi.DependsOn) > 0 {
		sb.WriteString("    depends_on:\n")
		for _, svc := range slices.Sorted(maps.Keys(obi.DependsOn)) {
			fmt.Fprintf(sb, "      %s:\n        condition: %s\n", svc, obi.DependsOn[svc])
		}
	}
	if len(obi.Env) > 0 {
		sb.WriteString("    environment:\n")
		for _, k := range slices.Sorted(maps.Keys(obi.Env)) {
			fmt.Fprintf(sb, "      %s: %q\n", k, obi.Env[k])
		}
	}
}

func (c *Compose) Up() error {
	// OBI_RENDER_ONLY diverts Up into `compose config`, dumping the rendered
	// stack under testoutput/render/ and failing the suite immediately
	if os.Getenv("OBI_RENDER_ONLY") != "" {
		dir := filepath.Join(tools.ProjectDir(), "testoutput", "render")
		_ = os.MkdirAll(dir, 0o777)
		base := strings.TrimSuffix(filepath.Base(c.Paths[len(c.Paths)-1]), ".yml")
		cmd := exec.Command("docker", c.composeArgs("config")...)
		cmd.Env = c.Env
		out, err := cmd.CombinedOutput()
		suffix := ""
		if err != nil {
			suffix = ".err"
		}
		_ = os.WriteFile(filepath.Join(dir, base+suffix+".render.yml"), out, 0o666)
		return errors.New("OBI_RENDER_ONLY")
	}
	// When SKIP_DOCKER_BUILD is set, Docker images have been pre-built on the host
	// and loaded into the VM's Docker daemon. Skip --build to avoid rebuilding them
	// inside the VM (which is extremely slow under TCG/software CPU emulation).
	// Without --build, compose will still auto-build any missing images.
	if os.Getenv("SKIP_DOCKER_BUILD") != "" {
		return c.command("up", "--detach", "--quiet-pull")
	}
	return c.command("up", "--build", "--detach", "--quiet-pull")
}

func (c *Compose) Run(service string) error {
	c.skipWait = true
	args := []string{"up"}
	if os.Getenv("SKIP_DOCKER_BUILD") == "" {
		args = append(args, "--build")
	}
	args = append(args, "--quiet-pull", "--abort-on-container-exit", "--exit-code-from", service)
	return c.command(args...)
}

func (c *Compose) Logs() error {
	return c.command("logs")
}

func (c *Compose) LogsOutput(services ...string) (string, error) {
	cmdArgs := c.composeArgs("logs")
	cmdArgs = append(cmdArgs, services...)
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.Env

	output, err := cmd.CombinedOutput()

	if c.Logger != nil && len(output) > 0 {
		if _, writeErr := c.Logger.Write(output); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}

	return strings.TrimSpace(string(output)), err
}

func (c *Compose) Stop() error {
	return c.command("stop", "--timeout", stopTimeout)
}

func (c *Compose) Remove() error {
	cmdArgs := c.composeArgs("rm", "-f", "-v")
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.Env

	output, err := cmd.CombinedOutput()
	if c.Logger != nil && len(output) > 0 {
		if _, writeErr := c.Logger.Write(output); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}

	if err != nil && strings.Contains(string(output), "already in progress") {
		return nil
	}

	return err
}

func (c *Compose) command(args ...string) error {
	return c.commandContext(context.Background(), args...)
}

func (c *Compose) commandContext(ctx context.Context, args ...string) error {
	cmdArgs := c.composeArgs(args...)
	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Env = c.Env
	if c.Logger != nil {
		cmd.Stdout = c.Logger
		cmd.Stderr = c.Logger
	}
	return cmd.Run()
}

// Exec runs `docker exec <container> <args...>`. Use when there's no Compose handle.
func Exec(ctx context.Context, container string, args ...string) (string, error) {
	cmdArgs := append([]string{"exec", container}, args...)
	out, err := exec.CommandContext(ctx, "docker", cmdArgs...).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)),
			fmt.Errorf("docker exec %s %v: %w; output: %s", container, args, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (c *Compose) ExecOutput(service string, args ...string) (string, error) {
	cmdArgs := c.composeArgs("exec", "-T", service)
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Env = c.Env

	output, err := cmd.CombinedOutput()

	if c.Logger != nil && len(output) > 0 {
		if _, writeErr := c.Logger.Write(output); writeErr != nil {
			err = errors.Join(err, writeErr)
		}
	}
	return strings.TrimSpace(string(output)), err
}

func (c *Compose) Close() error {
	var errs []error

	// Logs is read-only; run it in parallel with Stop so neither blocks the other.
	logsErr := make(chan error, 1)
	go func() {
		logsErr <- c.Logs()
	}()

	if err := c.Stop(); err != nil {
		// we just warn, as the container will be force-removed later
		slog.Warn("stopping docker compose. Will force remove", "error", err)
	}

	if err := <-logsErr; err != nil {
		errs = append(errs, fmt.Errorf("flushing logs: %w", err))
	}

	if !c.skipWait {
		waitCtx, cancel := context.WithTimeout(context.Background(), waitTimeout)
		if err := c.commandContext(waitCtx, "wait", "obi"); err != nil {
			slog.Warn("waiting for obi to stop. Will force remove", "error", err)
		}
		cancel()
	}

	if err := c.Remove(); err != nil {
		errs = append(errs, fmt.Errorf("removing container: %w", err))
	}

	if err := c.Logger.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing logger: %w", err))
	}

	return errors.Join(errs...)
}
