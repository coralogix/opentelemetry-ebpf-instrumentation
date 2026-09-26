// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package weavercheck holds the transport-agnostic parsing and validation of
// the OpenTelemetry weaver live-check report. The Docker-Compose integration
// suites (package integration) and the OATS suites feed weaver the same OTLP
// stream and read back the same JSON report; this package owns the shared
// report schema and the assertion logic so the transports stay in lockstep.
//
// Weaver runs with `--output http` and the `compact` output template;
// FetchReport POSTs the admin `/stop` endpoint and reads the report back from
// the response body (kept small enough by the template to avoid truncation).
// Which advisories are suppressed (the accepted `server`/`client`/`iface`
// namespace collisions) and which advice is promoted to a failure
// (`undefined_enum_variant`, `unexpected_attribute`, `kind_mismatch`) is
// declared in `schemas/obi/.weaver.toml` via `[[live-check.finding_filters]]`
// and `[[live-check.finding_level_overrides]]`, so weaver applies both before
// the report reaches this package. So are the `[[live-check.matchers]]` that
// pair each span with its span definition. What remains here is two rules: fail
// on any `violation`-level advisory, and on any span no matcher paired with a
// span definition.
package weavercheck // import "go.opentelemetry.io/obi/internal/test/weavercheck"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestingT is the minimal test-reporter interface Validate needs. Both
// *testing.T (the Docker-Compose integration suites) and ginkgo.GinkgoT() (the
// OATS suites) satisfy it, so the exact same enforce logic runs across every
// transport rather than being reimplemented per suite.
type TestingT interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	FailNow()
}

// Report is the top-level JSON structure emitted by weaver's `compact`
// live-check template: the statistics block plus a deduplicated findings list,
// the samples no matcher paired with a signal, and how many samples each signal
// was checked against. The per-sample bodies weaver's builtin `--format json`
// would emit (attribute values, exemplars, data points) are dropped, and the
// advisories are collapsed by message, keeping the report small while
// preserving every finding's level and the signals that triggered it.
type Report struct {
	Findings       []Finding        `json:"findings"`
	Statistics     Statistics       `json:"statistics"`
	Unmatched      []UnmatchedGroup `json:"unmatched"`
	MatchedSignals map[string]int   `json:"matched_signals"`
}

// Finding is one deduplicated advisory: a message reported at a given level and
// advice type, how many times it occurred, and the distinct signals
// (`<signal_type>:<signal_name>`) that triggered it.
type Finding struct {
	Message string   `json:"message"`
	Level   string   `json:"level"`
	Type    string   `json:"type"`
	Count   int      `json:"count"`
	Signals []string `json:"signals"`
}

// UnmatchedGroup is a set of samples that expected a signal but that no
// matcher paired with one, grouped by sample type, span kind and attribute
// keys, with up to five of their names.
type UnmatchedGroup struct {
	SampleType string   `json:"sample_type"`
	Kind       string   `json:"kind"`
	Attributes []string `json:"attributes"`
	Count      int      `json:"count"`
	Names      []string `json:"names"`
}

type Statistics struct {
	TotalEntities       int            `json:"total_entities"`
	TotalEntitiesByType map[string]int `json:"total_entities_by_type"`
	TotalAdvisories     int            `json:"total_advisories"`
	AdviceLevelCounts   map[string]int `json:"advice_level_counts"`
	RegistryCoverage    float64        `json:"registry_coverage"`
	Matchers            []Matcher      `json:"matchers"`
}

// Matcher is what one configured matcher did over the run. A suite exercises
// only some span definitions, so a matcher that applied to no sample is normal.
type Matcher struct {
	ID         string `json:"id"`
	Matched    int    `json:"matched"`
	Errors     int    `json:"errors"`
	FirstError string `json:"first_error"`
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

// FetchReport stops the weaver live-check container via its admin /stop
// endpoint and returns the parsed report from the /stop response body (weaver
// runs with `--output http`). The `compact` template keeps that body small
// enough to clear the socket buffer before weaver exits, so the response is not
// truncated. A refused connection (weaver never came up / admin port unmapped)
// is reported distinctly so callers can hint at a mis-wired stack. It is
// transport-agnostic and logging-agnostic (returns an error rather than failing
// a test).
func FetchReport(ctx context.Context, adminURL string) (*Report, error) {
	raw, err := FetchRawReport(ctx, adminURL)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// FetchRawReport is FetchReport without the parsing, for callers that also
// archive the report verbatim: cmd/obi-weaver-coverage reads the statistics
// and per-signal attributes that the parsed Report does not carry.
func FetchRawReport(ctx context.Context, adminURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, adminURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building weaver /stop request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("stopping weaver (is it running and the admin port mapped?): %w", err)
		}
		return nil, fmt.Errorf("posting weaver /stop: %w", err)
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

// ArchiveReport writes a raw report to dir as weaver-report-<name>.json, the
// name cmd/obi-weaver-coverage collects, and returns the path written.
func ArchiveReport(dir, name string, raw []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	reportPath := filepath.Join(dir, fmt.Sprintf("weaver-report-%s.json", strings.ReplaceAll(name, "/", "_")))
	if err := os.WriteFile(reportPath, raw, 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", reportPath, err)
	}
	return reportPath, nil
}

// Validate logs the full advisory breakdown and the matcher statistics, and
// asserts that weaver reported no `violation`-level advisory and no sample that
// expected a signal but matched none. Suppression of the accepted namespace
// collisions, the promotions to `violation` and the matchers are configured in
// `schemas/obi/.weaver.toml`, so what weaver reports here already reflects
// them.
func Validate(t TestingT, report *Report) {
	t.Helper()

	stats := &report.Statistics

	// Weaver must have received telemetry data. The `compact` report drops the
	// per-sample bodies, so assert on the entity count rather than sample count.
	require.Positivef(t, stats.TotalEntities,
		"weaver received no telemetry — OTLP data did not reach weaver")

	// Counted from the findings rather than the statistics: the compact report
	// drops findings the template ignores, which the statistics still count.
	violations := 0
	for i := range report.Findings {
		if report.Findings[i].Level == "violation" {
			violations += report.Findings[i].Count
		}
	}

	t.Logf("weaver statistics:")
	t.Logf("  total entities:   %d", stats.TotalEntities)
	for _, typ := range sortedKeys(stats.TotalEntitiesByType) {
		t.Logf("    %-15s %d", typ, stats.TotalEntitiesByType[typ])
	}
	t.Logf("  total advisories: %d", stats.TotalAdvisories)
	for _, level := range sortedKeys(stats.AdviceLevelCounts) {
		t.Logf("    %-15s %d", level, stats.AdviceLevelCounts[level])
	}
	t.Logf("  registry coverage: %.1f%%", stats.RegistryCoverage*100)

	// Surface the violation-level advisories first so the cause of a failure is
	// obvious, then log every finding grouped by level. Findings arrive sorted
	// by message (weaver's group_by), so the output is stable.
	if violations > 0 {
		t.Logf("  violation advisories:")
		for i := range report.Findings {
			if f := &report.Findings[i]; f.Level == "violation" {
				t.Logf("    [%dx] %s (signals: %s)", f.Count, f.Message, strings.Join(f.Signals, ", "))
			}
		}
	}
	t.Logf("  advisory details:")
	for _, level := range []string{"violation", "improvement", "information"} {
		for i := range report.Findings {
			if f := &report.Findings[i]; f.Level == level {
				t.Logf("    [%s] [%dx] %s (signals: %s)", f.Level, f.Count, f.Message, strings.Join(f.Signals, ", "))
			}
		}
	}

	logMatching(t, report)

	assert.Zero(t, violations,
		"weaver found %d violation-level semantic convention advisory(ies)", violations)
	assert.Emptyf(t, report.Unmatched,
		"weaver paired %d sample(s) with no signal; each needs a matcher in schemas/obi/.weaver.toml "+
			"and a definition in schemas/obi/groups", unmatchedCount(report.Unmatched))
}

// logMatching logs which matchers applied, how many samples each signal was
// checked against, and every group of samples that matched no signal.
func logMatching(t TestingT, report *Report) {
	t.Helper()

	t.Logf("  matchers:")
	for _, m := range report.Statistics.Matchers {
		switch {
		case m.Errors > 0:
			t.Logf("    %-45s %d sample(s), %d error(s): %s", m.ID, m.Matched, m.Errors, m.FirstError)
		case m.Matched > 0:
			t.Logf("    %-45s %d sample(s)", m.ID, m.Matched)
		}
	}
	t.Logf("  matched signals:")
	for _, signal := range sortedKeys(report.MatchedSignals) {
		t.Logf("    %-45s %d", signal, report.MatchedSignals[signal])
	}
	if len(report.Unmatched) > 0 {
		t.Logf("  samples matched to no signal:")
		for _, u := range report.Unmatched {
			t.Logf("    [%dx] %s kind=%q attributes=[%s] names=[%s]",
				u.Count, u.SampleType, u.Kind, strings.Join(u.Attributes, ", "), strings.Join(u.Names, ", "))
		}
	}
}

func unmatchedCount(groups []UnmatchedGroup) int {
	total := 0
	for _, g := range groups {
		total += g.Count
	}
	return total
}

// sortedKeys returns a count map's keys in lexical order, for stable log output.
func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
