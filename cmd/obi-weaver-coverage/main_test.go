// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObservedUnionsCountPositiveKeysAcrossReports(t *testing.T) {
	reports := []Report{
		{Statistics: Statistics{
			SeenRegistryMetrics:    map[string]int{"http.server.request.duration": 2, "db.client.operation.duration": 0},
			SeenRegistryAttributes: map[string]int{"http.request.method": 1, "url.path": 0},
		}},
		{Statistics: Statistics{
			SeenNonRegistryMetrics:    map[string]int{"obi.network.flow.bytes": 3},
			SeenRegistryAttributes:    map[string]int{"url.path": 5},
			SeenNonRegistryAttributes: map[string]int{"src.country": 1},
		}},
	}

	metrics, attributes := Observed(reports)

	assert.Contains(t, metrics, "http.server.request.duration")
	assert.Contains(t, metrics, "obi.network.flow.bytes")
	assert.NotContains(t, metrics, "db.client.operation.duration", "count 0 must not count as observed")

	assert.Contains(t, attributes, "http.request.method")
	assert.Contains(t, attributes, "url.path", "count 0 in one report, >0 in another → observed")
	assert.Contains(t, attributes, "src.country", "non-registry attribute counts as observed")
}

func TestAggregateSplitsCoveredAndGaps(t *testing.T) {
	intended := Surface{
		MetricNames:      []string{"A", "B", "C"},
		MetricAttributes: []string{"x", "y", "z"},
	}
	reports := []Report{
		{Statistics: Statistics{
			SeenRegistryMetrics:    map[string]int{"A": 1, "B": 0},
			SeenRegistryAttributes: map[string]int{"x": 1},
		}},
		{Statistics: Statistics{
			SeenNonRegistryMetrics: map[string]int{"C": 1},
			SeenRegistryAttributes: map[string]int{"y": 2},
		}},
	}

	res := Aggregate(intended, reports)

	assert.Equal(t, 2, res.Reports)
	assert.Equal(t, []string{"A", "C"}, res.MetricNames.Covered)
	assert.Equal(t, []string{"B"}, res.MetricNames.Gaps)
	assert.Equal(t, []string{"x", "y"}, res.MetricAttributes.Covered)
	assert.Equal(t, []string{"z"}, res.MetricAttributes.Gaps)
	assert.Equal(t, 2, res.TotalGaps())
}

func TestAggregateFullCoverageHasNoGaps(t *testing.T) {
	intended := Surface{MetricNames: []string{"A"}, MetricAttributes: []string{"x"}}
	reports := []Report{{Statistics: Statistics{
		SeenRegistryMetrics:    map[string]int{"A": 1},
		SeenRegistryAttributes: map[string]int{"x": 1},
	}}}

	res := Aggregate(intended, reports)

	assert.Zero(t, res.TotalGaps())
	assert.Equal(t, []string{"A"}, res.MetricNames.Covered)
}

func TestMarkdownReportsTableAndGaps(t *testing.T) {
	res := Aggregate(
		Surface{MetricNames: []string{"A", "B"}, MetricAttributes: []string{"x"}},
		[]Report{{Statistics: Statistics{SeenRegistryMetrics: map[string]int{"A": 1}}}},
	)

	md := res.Markdown()

	assert.Contains(t, md, "## Weaver telemetry coverage")
	assert.Contains(t, md, "| metric names | 1 | 2 | 50.0% |")
	assert.Contains(t, md, "**Uncovered metric names — 1 never observed")
	assert.Contains(t, md, "- `B`")
	assert.Contains(t, md, "**Uncovered metric attributes — 1 never observed")
	assert.Contains(t, md, "- `x`")
}

func TestMarkdownAllCovered(t *testing.T) {
	res := Aggregate(
		Surface{MetricNames: []string{"A"}, MetricAttributes: []string{"x"}},
		[]Report{{Statistics: Statistics{
			SeenRegistryMetrics:    map[string]int{"A": 1},
			SeenRegistryAttributes: map[string]int{"x": 1},
		}}},
	)

	md := res.Markdown()

	assert.Contains(t, md, "**Uncovered metric names:** all covered ✅")
	assert.Contains(t, md, "| metric names | 1 | 1 | 100.0% |")
}

func TestLoadReportsWalksAndParses(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "shard-1"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "shard-2"), 0o755))
	write := func(p, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644))
	}
	write("shard-1/weaver-report-Foo.json", `{"statistics":{"seen_registry_metrics":{"A":1}}}`)
	write("shard-2/weaver-report-Bar.json", `{"statistics":{"seen_registry_metrics":{"B":1}}}`)
	write("shard-1/other.json", `not a report`)
	write("shard-1/integration.log", `ignored`)

	reports, err := LoadReports(dir)
	require.NoError(t, err)
	require.Len(t, reports, 2, "only weaver-report-*.json files are loaded")

	metrics, _ := Observed(reports)
	assert.Contains(t, metrics, "A")
	assert.Contains(t, metrics, "B")
}

func TestLoadReportsFailsOnMalformedReport(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "weaver-report-Bad.json"), []byte(`{not json}`), 0o644))
	_, err := LoadReports(dir)
	assert.Error(t, err)
}

func TestLoadReportsEmptyDir(t *testing.T) {
	reports, err := LoadReports(t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, reports)
}

func TestParseDenominatorExtractsAllMetricsAndAttributes(t *testing.T) {
	resolved := []byte(`{"groups":[
		{"type":"metric","metric_name":"http.server.request.duration","attributes":[
			{"name":"http.request.method"},{"name":"server.address"}]},
		{"type":"metric","metric_name":"obi.network.flow.bytes","attributes":[{"name":"src.address"}]},
		{"type":"metric","metric_name":"obi.bpf.probe.executions","attributes":[]},
		{"type":"metric","metric_name":"obi.internal.build.info","attributes":[]},
		{"type":"attribute_group","attributes":[{"name":"url.path"}]}
	]}`)

	got, err := parseDenominator(resolved)
	require.NoError(t, err)

	assert.Equal(t, []string{
		"http.server.request.duration", "obi.bpf.probe.executions",
		"obi.internal.build.info", "obi.network.flow.bytes",
	}, got.MetricNames, "OBI internal metrics are OTLP-emitted (metrics_internal.go) and belong in the denominator")
	assert.Equal(t, []string{"http.request.method", "server.address", "src.address", "url.path"}, got.MetricAttributes)
}

func TestParseDenominatorUnwrapsRegistryAndFallsBackAttrKey(t *testing.T) {
	resolved := []byte(`{"registry":{"groups":[
		{"type":"metric","metric_name":"db.client.operation.duration","attributes":[
			{"id":"db.system.name"},{"ref":"error.type"}]}
	]}}`)

	got, err := parseDenominator(resolved)
	require.NoError(t, err)

	assert.Equal(t, []string{"db.client.operation.duration"}, got.MetricNames)
	assert.Equal(t, []string{"db.system.name", "error.type"}, got.MetricAttributes,
		"attribute name falls back to id then ref")
}

