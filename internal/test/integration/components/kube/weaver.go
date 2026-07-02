// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube // import "go.opentelemetry.io/obi/internal/test/integration/components/kube"

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"go.opentelemetry.io/obi/internal/test/integration/components/weaver/weavercheck"
	"go.opentelemetry.io/obi/internal/test/integration/k8s/common/testpath"
)

const (
	// WeaverK8sAdminHostPort is the host port the kind clusters map weaver's
	// admin port (4320) to via an extraPortMapping (see manifests/00-kind*.yml).
	// kind host ports live in the 30000-32767 range.
	WeaverK8sAdminHostPort = 32320
	// weaverK8sReportSubdir / weaverK8sReportFile locate the report the
	// in-cluster weaver pod writes. The pod command passes
	// `--output /testoutput/weaver-out`, and `/testoutput` is the shared kind
	// extraMount mapping to the host `testoutput` directory (testpath.Output),
	// so the host reads the report directly from there — the same file-based
	// handoff the Docker transport uses via its bind mount.
	weaverK8sReportSubdir = "weaver-out"
	weaverK8sReportFile   = "live_check.json"

	// weaverK8sTimeout bounds the /stop + drain + read sequence.
	weaverK8sTimeout = 3 * time.Minute
)

// ValidateWeaver stops the in-cluster weaver pod (HTTP POST /stop on its
// host-exposed admin port) and validates the report it writes to the shared
// testoutput mount. It is meant to be called from a dedicated, last-running
// test of each weaver-wired k8s suite (e.g. a `TestZZ_WeaverValidate` in a
// `z_weaver_test.go` so it sorts after the suite's real tests but still runs
// while the cluster is up).
//
// observeOnly=true brings a new suite online observe-first: it logs the full
// advisory breakdown (including which advisories WOULD fail under enforce) but
// never fails the test. Switch to observeOnly=false to enforce once the
// suite's emitted-attribute set is declared in schemas/obi.
//
// Requirements (wired in the suite's manifests):
//   - a weaver pod (manifests/08-weaver*.yml) mounting /obi-registry from the
//     kind `obi-registry` extraMount and /testoutput from the testoutput mount;
//   - an OTLP-exporting otelcol that taps weaver (03-otelcol*.yml);
//   - the kind config (00-kind*.yml) with the weaver admin extraPortMapping
//     4320 -> WeaverK8sAdminHostPort.
func (k *Kind) ValidateWeaver(t *testing.T, observeOnly bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), weaverK8sTimeout)
	defer cancel()

	url := fmt.Sprintf("http://127.0.0.1:%d/stop", WeaverK8sAdminHostPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		t.Errorf("weaver(k8s): building /stop request: %v", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("weaver(k8s): failed to stop weaver (is the pod running and the admin port mapped?): %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Errorf("weaver(k8s): /stop returned HTTP %d", resp.StatusCode)
		return
	}

	// Weaver flushes its report to the testoutput mount after /stop. Poll the
	// host path until it appears (or the context deadline hits) rather than
	// guessing a fixed sleep.
	reportPath := path.Join(testpath.Output, weaverK8sReportSubdir, weaverK8sReportFile)
	rawReport, err := waitForFile(ctx, reportPath)
	if err != nil {
		t.Errorf("weaver(k8s): reading report at %s: %v", reportPath, err)
		return
	}

	// Archive next to the other k8s test output for post-mortem.
	archivePath := path.Join(k.logsDir, k.clusterName, "weaver-report.json")
	_ = os.MkdirAll(path.Dir(archivePath), 0o755)
	if err := os.WriteFile(archivePath, rawReport, 0o644); err == nil {
		t.Logf("weaver(k8s) report archived to %s", archivePath)
	}

	report, err := weavercheck.Parse(rawReport)
	if err != nil {
		t.Errorf("weaver(k8s): %v", err)
		return
	}
	weavercheck.Validate(t, report, observeOnly)
}

// waitForFile polls path until it is non-empty or ctx is done.
func waitForFile(ctx context.Context, p string) ([]byte, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		b, err := os.ReadFile(p)
		if err == nil && len(b) > 0 {
			return b, nil
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return nil, fmt.Errorf("file never appeared: %w", err)
			}
			return nil, fmt.Errorf("file %s stayed empty", p)
		case <-ticker.C:
		}
	}
}
