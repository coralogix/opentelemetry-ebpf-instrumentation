// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/internal/test/weavercheck"
)

const (
	weaverContainer = "weaver"
	weaverAdminPort = 4320
	// weaverTimeout bounds the /stop request-response: weaver drains its
	// buffered signals and returns the live-check report as the HTTP response
	// body. The drain scales with the unique signal count — heavy
	// multi-language suites need real headroom.
	weaverTimeout = 3 * time.Minute
)

func SemconvVersion() string {
	// semconv.SchemaURL is "https://opentelemetry.io/schemas/1.41.0"
	return semconv.SchemaURL[strings.LastIndex(semconv.SchemaURL, "/")+1:]
}

func weaverReportPath(t *testing.T) string {
	t.Helper()
	name := strings.ReplaceAll(t.Name(), "/", "_")
	return path.Join(pathOutput, fmt.Sprintf("weaver-report-%s.json", name))
}

// runWeaverValidation stops the weaver container (Docker transport) and
// validates that the emitted telemetry conforms to OpenTelemetry semantic
// conventions, FAILING the test on any actionable advisory (enforce mode).
// This is the entry point for the docker-compose suites and must be called
// while the Docker Compose stack is still running.
func runWeaverValidation(t *testing.T) {
	t.Helper()

	report, ok := fetchWeaverReportDocker(t)
	if !ok {
		return
	}
	weavercheck.Validate(t, report)
}

// fetchWeaverReportDocker stops the weaver container (which runs as a service
// in the Docker Compose stack receiving OTLP from the collector) via its admin
// /stop endpoint and reads the live-check report straight from the /stop
// response body — weaver runs with `--output http`, so no report file or bind
// mount is involved. It archives and parses the report and returns it with
// ok=true on success. On any failure it records the error (or, when a prior
// test failure is detected, simply tears weaver down so the surrounding
// compose teardown stays clean) and returns ok=false.
//
// This must be called while the Docker Compose stack is still running.
func fetchWeaverReportDocker(t *testing.T) (*weavercheck.Report, bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), weaverTimeout)
	defer cancel()

	// Signal weaver to stop accepting data and return its report. If the /stop
	// call fails (timeout, container already killed, …) we record the failure
	// and force-remove the container so the surrounding `compose.Close()` still
	// runs and the next test invocation starts from a clean slate.
	adminURL := fmt.Sprintf("http://127.0.0.1:%d/stop", weaverAdminPort)
	rawReport, err := weavercheck.StopAndRead(ctx, adminURL)
	if err != nil {
		t.Errorf("stopping weaver and reading its report: %v", err)
		forceRemoveWeaverContainer(t)
		return nil, false
	}

	// A prior test failure means the emitted telemetry is suspect. We still
	// POST /stop above so weaver drains and compose teardown stays clean, but
	// skip validating the report.
	if t.Failed() {
		t.Logf("skipping weaver validation: prior test failure detected " +
			"(weaver stopped for a clean compose teardown)")
		return nil, false
	}

	return archiveAndParseWeaverReport(t, rawReport)
}

// archiveAndParseWeaverReport archives the raw report next to the other test
// output and parses it into a weavercheck.Report.
func archiveAndParseWeaverReport(t *testing.T, rawReport []byte) (*weavercheck.Report, bool) {
	t.Helper()
	if len(rawReport) == 0 {
		t.Errorf("weaver report is empty")
		return nil, false
	}
	reportPath := weaverReportPath(t)
	if err := os.WriteFile(reportPath, rawReport, 0o644); err != nil {
		t.Logf("warn: failed to archive weaver report to %s: %v", reportPath, err)
	} else {
		t.Logf("weaver report saved to %s", reportPath)
	}
	report, err := weavercheck.Parse(rawReport)
	if err != nil {
		t.Errorf("failed to parse weaver JSON report: %v", err)
		return nil, false
	}
	return report, true
}

// forceRemoveWeaverContainer is the best-effort cleanup we use when the normal
// /stop + docker-wait sequence couldn't finish. Without this, a stuck or
// killed weaver container survives the failed test invocation and the next
// run hits "container name already in use" (or, worse, a half-broken admin
// port that returns "connection reset by peer").
func forceRemoveWeaverContainer(t *testing.T) {
	t.Helper()
	rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(rmCtx, "docker", "rm", "-f", weaverContainer).CombinedOutput(); err != nil {
		t.Logf("failed to force-remove weaver container (already gone?): %v; output: %s", err, strings.TrimSpace(string(out)))
	}
}
