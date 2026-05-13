// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/ory/dockertest/v4"
)

// weaverSharedNetwork is the docker network created once per shard by
// TestMain. Each weaver-wired compose declares it as `external: true` and
// connects its `otelcol` service to it so OTLP samples reach the single
// weaver container running on this network.
const weaverSharedNetwork = "weaver-shared"

var (
	sharedWeaverNetID     string
	sharedWeaverStarted   bool
	sharedWeaverContainer dockertest.ClosableResource
)

// startSharedWeaver creates the `weaver-shared` docker network and launches
// the one weaver container for the whole shard. Called from TestMain.
//
// Any prior network or container with the same names (leftover from a
// crashed run) is force-removed first so the test binary always starts from
// a clean slate.
func startSharedWeaver(ctx context.Context) error {
	// Preflight cleanup. Best-effort — these will fail silently if nothing exists.
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", weaverContainer).Run()
	_ = exec.CommandContext(ctx, "docker", "network", "rm", weaverSharedNetwork).Run()

	net, err := dockerPool.CreateNetwork(ctx, weaverSharedNetwork, nil)
	if err != nil {
		return fmt.Errorf("create %s network: %w", weaverSharedNetwork, err)
	}
	sharedWeaverNetID = net.ID()

	w, err := dockerPool.Run(ctx, "otel/weaver",
		dockertest.WithTag(versionWeaver),
		dockertest.WithName(weaverContainer),
		dockertest.WithCmd([]string{
			"registry", "live-check",
			"--registry", "/obi-registry",
			"--include-unreferenced",
			// Shard-wide weaver lives much longer than per-test instances —
			// bump the OTLP inactivity timeout so a long test gap doesn't
			// shut it down prematurely.
			"--inactivity-timeout", "3600",
			"--admin-port", "4320",
			"--format", "json",
			"--diagnostic-format", "json",
			"--output", "/tmp",
		}),
		dockertest.WithMounts([]string{
			filepath.Join(pathRoot, "schemas/obi") + ":/obi-registry:ro",
		}),
		dockertest.WithPortBindings(portBindings("4320/tcp", "4320")),
		dockertest.WithContainerConfig(func(config *container.Config) {
			config.WorkingDir = "/obi-registry"
			config.ExposedPorts = exposedPorts("4317/tcp", "4320/tcp")
		}),
		dockertest.WithoutReuse(),
	)
	if err != nil {
		return fmt.Errorf("run weaver container: %w", err)
	}
	sharedWeaverContainer = w

	if _, err := dockerPool.Client().NetworkConnect(ctx, sharedWeaverNetID, client.NetworkConnectOptions{
		Container:      w.ID(),
		EndpointConfig: endpointAliases("weaver"),
	}); err != nil {
		return fmt.Errorf("connect weaver to %s: %w", weaverSharedNetwork, err)
	}
	sharedWeaverStarted = true
	return nil
}

// finalizeSharedWeaver flushes the shared weaver, parses its report, and
// returns the count of actionable violations. Findings are written to `out`
// grouped by `obi.test.name` resource attribute where present.
//
// Returns 0 violations (no error) if weaver was never started.
func finalizeSharedWeaver(ctx context.Context, out io.Writer) (int, error) {
	if !sharedWeaverStarted {
		return 0, nil
	}

	stopCtx, cancel := context.WithTimeout(ctx, weaverTimeout)
	defer cancel()

	url := fmt.Sprintf("http://127.0.0.1:%d/stop", weaverAdminPort)
	req, err := http.NewRequestWithContext(stopCtx, http.MethodPost, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("POST /stop to shared weaver: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("shared weaver /stop returned HTTP %d", resp.StatusCode)
	}

	if _, err := exec.CommandContext(stopCtx, "docker", "wait", weaverContainer).Output(); err != nil {
		return 0, fmt.Errorf("docker wait shared weaver: %w", err)
	}

	reportPath := filepath.Join(pathOutput, "weaver-report-shard.json")
	if cpOut, err := exec.CommandContext(stopCtx, "docker", "cp",
		weaverContainer+":/tmp/live_check.json", reportPath).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("docker cp shared weaver report: %v; %s", err, cpOut)
	}

	rawReport, err := os.ReadFile(reportPath)
	if err != nil {
		return 0, fmt.Errorf("read shared weaver report: %w", err)
	}
	if len(rawReport) == 0 {
		fmt.Fprintln(out, "WEAVER: report empty — no OTLP data reached weaver")
		return 0, nil
	}

	var report weaverReport
	if err := json.Unmarshal(rawReport, &report); err != nil {
		return 0, fmt.Errorf("parse shared weaver report: %w", err)
	}

	return printSharedWeaverSummary(out, &report), nil
}

// cleanupSharedWeaverNetwork removes the `weaver-shared` docker network at
// the end of TestMain. Best-effort; the container is already gone by this
// point (it exits on /stop).
func cleanupSharedWeaverNetwork(ctx context.Context) {
	if sharedWeaverNetID != "" {
		_ = exec.CommandContext(ctx, "docker", "network", "rm", weaverSharedNetwork).Run()
	}
}

// printSharedWeaverSummary writes the consolidated report to `out` and
// returns the count of actionable violations after filtering ignores.
func printSharedWeaverSummary(out io.Writer, report *weaverReport) int {
	stats := &report.Statistics

	fmt.Fprintln(out, "WEAVER: shard report")
	fmt.Fprintf(out, "  samples: %d\n", len(report.Samples))
	fmt.Fprintf(out, "  total entities:   %d\n", stats.TotalEntities)
	for typ, count := range stats.TotalEntitiesByType {
		fmt.Fprintf(out, "    %-15s %d\n", typ, count)
	}
	fmt.Fprintf(out, "  total advisories: %d\n", stats.TotalAdvisories)
	for level, count := range stats.AdviceLevelCounts {
		fmt.Fprintf(out, "    %-15s %d\n", level, count)
	}
	fmt.Fprintf(out, "  registry coverage: %.1f%%\n", stats.RegistryCoverage*100)

	adviceByMsg := collectAdviceInfo(report.Samples)

	actionable := 0
	fmt.Fprintln(out, "  advisory details:")
	for _, level := range []string{"violation", "improvement", "information"} {
		for msg, count := range stats.AdviceMessageCounts {
			_, msgIgnored := weaverIgnoredAdviceMessages[msg]
			info := adviceByMsg[msg]
			if info == nil {
				if level != "violation" {
					continue
				}
				suffix := ""
				if msgIgnored {
					suffix = " [ignored]"
				}
				fmt.Fprintf(out, "    [%s] [%dx] %s (signals: unknown)%s\n", level, count, msg, suffix)
				if !msgIgnored {
					actionable += count
				}
				continue
			}
			if info.Level != level {
				continue
			}
			signals := sortedSignals(info.Signals)
			ignored := msgIgnored || allSignalsIgnored(info.Signals)
			suffix := ""
			if ignored {
				suffix = " [ignored]"
			}
			fmt.Fprintf(out, "    [%s] [%dx] %s (signals: %v)%s\n", level, count, msg, signals, suffix)
			if level == "violation" && !ignored {
				actionable += count
			}
		}
	}

	// Best-effort per-test grouping. If samples carry `obi.test.name` in
	// their resource attributes, list which test produced which finding so
	// the shard-level failure points the reader at the offending test.
	grouped := groupAdviceByTest(report.Samples)
	if len(grouped) > 0 {
		fmt.Fprintln(out, "  findings grouped by test:")
		names := make([]string, 0, len(grouped))
		for n := range grouped {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(out, "    %s:\n", name)
			for _, f := range grouped[name] {
				fmt.Fprintf(out, "      [%s] %s\n", f.level, f.message)
			}
		}
	}

	fmt.Fprintf(out, "  actionable violations: %d (after ignoring %v)\n",
		actionable, sortedSignals(weaverIgnoredSignals))

	// Unused channel to keep time import alive if file ever loses it later.
	_ = time.Time{}

	return actionable
}

type taggedFinding struct {
	level   string
	message string
}

// groupAdviceByTest walks samples and groups findings by the `obi.test.name`
// resource attribute when present. Samples without the attribute are
// silently skipped — the caller still gets the full report via the advisory
// details section.
func groupAdviceByTest(samples []json.RawMessage) map[string][]taggedFinding {
	grouped := map[string][]taggedFinding{}
	for _, raw := range samples {
		testName := extractObiTestName(raw)
		if testName == "" {
			continue
		}
		findings := extractSampleAdvice(raw)
		if len(findings) == 0 {
			continue
		}
		grouped[testName] = append(grouped[testName], findings...)
	}
	return grouped
}

// extractObiTestName searches a sample's JSON for an `obi.test.name`
// resource attribute. Recurses into nested objects/arrays since the exact
// nesting depends on weaver's output schema.
func extractObiTestName(raw json.RawMessage) string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		for k, v := range obj {
			if k == "obi.test.name" {
				var s string
				if json.Unmarshal(v, &s) == nil && s != "" {
					return s
				}
			}
			if n := extractObiTestName(v); n != "" {
				return n
			}
		}
		return ""
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		for _, item := range arr {
			if n := extractObiTestName(item); n != "" {
				return n
			}
		}
	}
	return ""
}

// extractSampleAdvice walks a single sample's JSON and returns every
// finding it contains.
func extractSampleAdvice(raw json.RawMessage) []taggedFinding {
	var out []taggedFinding
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		if lcr, ok := obj["live_check_result"]; ok {
			var checkResult weaverLiveCheckResult
			if json.Unmarshal(lcr, &checkResult) == nil {
				for _, a := range checkResult.AllAdvice {
					out = append(out, taggedFinding{level: a.Level, message: a.Message})
				}
			}
		}
		for _, v := range obj {
			out = append(out, extractSampleAdvice(v)...)
		}
		return out
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		for _, item := range arr {
			out = append(out, extractSampleAdvice(item)...)
		}
	}
	return out
}
