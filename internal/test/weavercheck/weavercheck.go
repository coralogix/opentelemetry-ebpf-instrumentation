// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package weavercheck holds the transport-agnostic parsing and validation of
// the OpenTelemetry weaver live-check report. Both the Docker-Compose
// integration suites (package integration) and the OATS suites (package
// harness) feed weaver the same OTLP stream and read back the same JSON
// report; this package owns the shared report schema and the
// advisory-accounting + assertion logic so the transports stay in lockstep.
//
// The transports differ only in the admin URL they POST /stop to; weaver runs
// with `--output http`, so the report comes back in the /stop response body
// (see StopAndRead / FetchReport) and there is no report file to read.
//
// Advisories OBI deliberately accepts (e.g. the servicegraph `server`/`client`
// and netolly `iface` namespace collisions) are dropped by weaver itself via
// the `[[live-check.finding_filters]]` in schemas/obi/weaver.toml before the
// report reaches this package, so they are absent from the accounting below.
// What remains here is the enforcement that weaver's config can't express: in
// addition to `violation`-level advice, OBI also fails on the advice types in
// actionableAdviceTypes (today `extends_namespace`, which weaver classifies as
// information-level).
package weavercheck // import "go.opentelemetry.io/obi/internal/test/weavercheck"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestingT is the minimal test-reporter interface Validate needs. Both
// *testing.T (the Docker and Kubernetes suites) and ginkgo.GinkgoT() (the OATS
// suites) satisfy it, so the exact same enforce logic runs across every
// transport rather than being reimplemented per suite.
type TestingT interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	FailNow()
}

// Advisories OBI deliberately accepts (the servicegraph `server`/`client` and
// netolly `iface` namespace collisions) are dropped by weaver's
// `[[live-check.finding_filters]]` in schemas/obi/weaver.toml before the report
// reaches this package — they are not re-listed here. New suppressions belong
// in that config, not in Go.

// actionableAdviceTypes lists the weaver finding-type values OBI treats as
// failures in addition to `violation`-level advice. Hoisted here (rather than
// matched as an inline string literal) so the coupling to weaver's advice-type
// vocabulary lives in one documented place and is easy to extend.
//
//   - "extends_namespace": an attribute emitted under an existing semconv
//     namespace but declared in no registry (upstream semconv or
//     `schemas/obi/`). Weaver classifies these as `information`-level, so
//     without this they would silently pass; OBI requires every emitted
//     attribute to be declared.
//
// NOTE: these strings come from weaver's rego policy output. If a weaver
// version bump renames them, enforcement silently weakens — re-verify when
// bumping the pinned weaver image.
var actionableAdviceTypes = map[string]struct{}{
	"extends_namespace": {},
}

// Report is the top-level JSON structure emitted by weaver with --format json.
type Report struct {
	Samples    []json.RawMessage `json:"samples"`
	Statistics Statistics        `json:"statistics"`
}

type Statistics struct {
	TotalEntities       int            `json:"total_entities"`
	TotalEntitiesByType map[string]int `json:"total_entities_by_type"`
	TotalAdvisories     int            `json:"total_advisories"`
	AdviceLevelCounts   map[string]int `json:"advice_level_counts"`
	AdviceTypeCounts    map[string]int `json:"advice_type_counts"`
	AdviceMessageCounts map[string]int `json:"advice_message_counts"`
	RegistryCoverage    float64        `json:"registry_coverage"`
}

// Advice represents a single advisory finding from the weaver report.
type Advice struct {
	Message    string `json:"message"`
	Level      string `json:"level"`
	AdviceType string `json:"id"`
	SignalType string `json:"signal_type"`
	SignalName string `json:"signal_name"`
}

type liveCheckResult struct {
	AllAdvice []Advice `json:"all_advice"`
}

type adviceInfo struct {
	Level      string
	AdviceType string
	Signals    map[string]struct{} // set of "signal_type:signal_name"
}

// Parse unmarshals a raw weaver JSON report.
func Parse(rawReport []byte) (*Report, error) {
	if len(rawReport) == 0 {
		return nil, errors.New("weaver report is empty")
	}
	var report Report
	if err := json.Unmarshal(rawReport, &report); err != nil {
		return nil, fmt.Errorf("parsing weaver JSON report: %w", err)
	}
	return &report, nil
}

// StopAndRead POSTs to the weaver live-check admin /stop endpoint and returns
// the raw report bytes from the HTTP response body. This requires the
// container to run live-check with `--output http`, which makes /stop respond
// with the full report instead of writing it to a file — so no shared report
// file or bind mount is needed, and the report can't be a stale one from an
// earlier test. It is transport-agnostic and logging-agnostic (returns an
// error rather than failing a test): any transport that publishes weaver's
// admin port to the test host can reuse it. Callers that want to archive the
// raw report (e.g. per-test debugging artifacts) use this and Parse
// separately; FetchReport is the parse-only convenience wrapper.
func StopAndRead(ctx context.Context, adminURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, adminURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building weaver /stop request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stopping weaver (is it running and the admin port mapped?): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("weaver /stop returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading weaver /stop response body: %w", err)
	}
	return raw, nil
}

// FetchReport stops the weaver live-check container via its admin /stop
// endpoint and returns the parsed report read straight from the /stop response
// body (see StopAndRead). The container must run live-check with
// `--output http`.
func FetchReport(ctx context.Context, adminURL string) (*Report, error) {
	raw, err := StopAndRead(ctx, adminURL)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Validate logs the full advisory breakdown and asserts that zero actionable
// advisories remain. An advisory is actionable when it is `violation`-level OR
// its advice_type is in actionableAdviceTypes, after applying the ignore lists.
// It always enforces: if weaver found actionable advisories, the test fails.
func Validate(t TestingT, report *Report) {
	t.Helper()

	stats := &report.Statistics

	// Weaver must have received telemetry data.
	require.NotEmptyf(t, report.Samples,
		"weaver received no samples — OTLP data did not reach weaver")

	violations := stats.AdviceLevelCounts["violation"]

	t.Logf("weaver statistics:")
	t.Logf("  total entities:   %d", stats.TotalEntities)
	for typ, count := range stats.TotalEntitiesByType {
		t.Logf("    %-15s %d", typ, count)
	}
	t.Logf("  total advisories: %d", stats.TotalAdvisories)
	for level, count := range stats.AdviceLevelCounts {
		t.Logf("    %-15s %d", level, count)
	}
	t.Logf("  registry coverage: %.1f%%", stats.RegistryCoverage*100)

	// Build message → {level, type, signals} lookup from the sample data.
	adviceByMsg := collectAdviceInfo(report.Samples)

	// Log all advisory messages grouped by level.
	t.Logf("  advisory details:")
	for _, level := range []string{"violation", "improvement", "information"} {
		for msg, count := range stats.AdviceMessageCounts {
			info := adviceByMsg[msg]
			if info == nil {
				if level != "violation" {
					continue
				}
				t.Logf("    [%s] [%dx] %s (signals: unknown)", level, count, msg)
				continue
			}
			if info.Level != level {
				continue
			}
			signals := sortedSignals(info.Signals)
			t.Logf("    [%s] [%dx] %s (signals: %s)", level, count, msg, strings.Join(signals, ", "))
		}
	}

	actionableAdvisories := countActionableAdvisories(stats, adviceByMsg)
	t.Logf("  advisories: %d violation(s), %d actionable (violations + actionableAdviceTypes)",
		violations, actionableAdvisories)

	assert.Zero(t, actionableAdvisories,
		"weaver found %d actionable semantic convention advisory(ies) "+
			"(violations or undeclared attributes under existing semconv namespaces)", actionableAdvisories)
}

// isActionableAdvice reports whether an advisory at the given level and
// advice type must fail validation: `violation`-level advice always is, and
// so is any advice type listed in actionableAdviceTypes (e.g.
// `extends_namespace`, which weaver classifies as information-level).
func isActionableAdvice(level, adviceType string) bool {
	if level == "violation" {
		return true
	}

	_, actionable := actionableAdviceTypes[adviceType]
	return actionable
}

// countActionableAdvisories counts advisories that must fail validation:
// `violation`-level advice plus any advice type in actionableAdviceTypes.
// Advisories OBI accepts are already dropped from the report by weaver
// (schemas/obi/weaver.toml), so there is nothing to ignore here. Messages
// present in the statistics but absent from the sample data carry no
// level/type attribution, so they are conservatively counted as actionable.
func countActionableAdvisories(stats *Statistics, adviceByMsg map[string]*adviceInfo) int {
	var count int
	for msg, occurrences := range stats.AdviceMessageCounts {
		info := adviceByMsg[msg]
		if info == nil {
			count += occurrences
			continue
		}
		if isActionableAdvice(info.Level, info.AdviceType) {
			count += occurrences
		}
	}
	return count
}

// collectAdviceInfo scans all weaver samples to build a complete map from
// advisory message to its severity level, advice type, and the set of signals
// that triggered it.
func collectAdviceInfo(samples []json.RawMessage) map[string]*adviceInfo {
	result := make(map[string]*adviceInfo)

	for _, raw := range samples {
		var generic map[string]json.RawMessage
		if json.Unmarshal(raw, &generic) != nil {
			continue
		}
		for _, v := range generic {
			extractAdviceInfo(v, result)
		}
	}

	return result
}

// extractAdviceInfo recursively walks JSON looking for all_advice arrays and
// records message → {level, type, signals} mappings.
func extractAdviceInfo(data json.RawMessage, result map[string]*adviceInfo) {
	// Try as object with live_check_result or nested fields.
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) == nil {
		if lcr, ok := obj["live_check_result"]; ok {
			var checkResult liveCheckResult
			if json.Unmarshal(lcr, &checkResult) == nil {
				for i := range checkResult.AllAdvice {
					a := &checkResult.AllAdvice[i]
					info, exists := result[a.Message]
					if !exists {
						info = &adviceInfo{
							Level:      a.Level,
							AdviceType: a.AdviceType,
							Signals:    make(map[string]struct{}),
						}
						result[a.Message] = info
					}
					if a.SignalName != "" {
						sig := a.SignalType + ":" + a.SignalName
						info.Signals[sig] = struct{}{}
					}
				}
			}
		}
		// Recurse into all values.
		for _, v := range obj {
			extractAdviceInfo(v, result)
		}
		return
	}

	// Try as array.
	var arr []json.RawMessage
	if json.Unmarshal(data, &arr) == nil {
		for _, item := range arr {
			extractAdviceInfo(item, result)
		}
	}
}

func sortedSignals(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
