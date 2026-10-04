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

const resolvedFixture = `{"registry":{
	"attributes":[{"key":"http.route"}],
	"attribute_groups":[{"id":"attributes.obi.http.server","attributes":[{"key":"url.path"}]}],
	"metrics":[
		{"name":"http.server.request.duration","instrument":"histogram","unit":"s","attributes":[
			{"key":"http.request.method","requirement_level":"required"},
			{"key":"http.route","requirement_level":{"conditionally_required":"if the route is known"}},
			{"key":"client.address","requirement_level":"opt_in"}]},
		{"name":"go.goroutine.count","instrument":"updowncounter","unit":"{goroutine}","attributes":[]},
		{"name":"target.info","instrument":"updowncounter","unit":"","attributes":[
			{"key":"service.name","requirement_level":"required"},
			{"key":"host.id"}]}
	],
	"spans":[
		{"type":"obi.http.server","kind":"server","name":{"templates":["{http.request.method} {http.route}"]},"attributes":[
			{"key":"url.path","requirement_level":"required"},
			{"key":"http.request.header","type":"template[string[]]","requirement_level":"opt_in"},
			{"key":"server.port","requirement_level":{"recommended":"if known"}}]}
	],
	"entities":[
		{"type":"cloud","identity":[{"key":"cloud.resource_id"}],"description":[{"key":"cloud.provider"}]}
	],
	"events":[]
}}`

func TestParseDenominatorReadsSignalsAndResourceAttributes(t *testing.T) {
	got, err := parseDenominator([]byte(resolvedFixture))
	require.NoError(t, err)

	assert.Equal(t, []Signal{
		{Name: "go.goroutine.count", Kind: kindMetric, Attributes: []DeclaredAttribute{}},
		{Name: "http.server.request.duration", Kind: kindMetric, Attributes: []DeclaredAttribute{
			{Key: "client.address", RequirementLevel: levelOptIn},
			{Key: "http.request.method", RequirementLevel: levelRequired},
			{Key: "http.route", RequirementLevel: levelConditionallyRequired},
		}},
		{Name: "obi.http.server", Kind: kindSpan, Attributes: []DeclaredAttribute{
			{Key: "http.request.header", RequirementLevel: levelOptIn, Template: true},
			{Key: "server.port", RequirementLevel: levelRecommended},
			{Key: "url.path", RequirementLevel: levelRequired},
		}},
		{Name: "target.info", Kind: kindMetric, Attributes: []DeclaredAttribute{
			{Key: "host.id", RequirementLevel: levelRecommended},
			{Key: "service.name", RequirementLevel: levelRequired},
		}},
	}, got.Signals)
	assert.Equal(t, []string{"cloud.provider", "cloud.resource_id", "host.id", "service.name"}, got.ResourceAttributes,
		"resource attributes are the target.info carrier labels plus the entity attributes")
}

func TestParseDenominatorRejectsAnEmptyRegistry(t *testing.T) {
	_, err := parseDenominator([]byte(`{"registry":{"metrics":[],"spans":[]}}`))
	require.Error(t, err)

	_, err = parseDenominator([]byte(`not json`))
	require.Error(t, err)
}

func TestObserveUnionsReports(t *testing.T) {
	reports := []Report{
		{
			Statistics: Statistics{
				SeenRegistryMetrics:    map[string]int{"http.server.request.duration": 2, "go.goroutine.count": 0},
				SeenRegistryAttributes: map[string]int{"obi.version": 1, "url.path": 0},
			},
			MatchedSignals:   map[string]int{"obi.http.server": 3},
			SignalAttributes: map[string][]string{"obi.http.server": {"url.path"}},
		},
		{
			Statistics: Statistics{
				SeenRegistryAttributes:    map[string]int{"url.path": 5},
				SeenNonRegistryAttributes: map[string]int{"http.request.method": 1},
			},
			MatchedSignals:   map[string]int{"target.info": 1},
			SignalAttributes: map[string][]string{"obi.http.server": {"server.port"}, "target.info": {"service.name"}},
		},
	}

	o := Observe(reports)

	assert.Equal(t, []string{"http.server.request.duration", "obi.http.server", "target.info"}, sortedKeys(o.Signals),
		"a zero seen count is not an observation")
	assert.Equal(t, []string{"http.request.method", "obi.version", "url.path"}, sortedKeys(o.Attributes),
		"zero in one report and positive in another is observed; upstream attributes count too")
	assert.Equal(t, []string{"server.port", "url.path"}, sortedKeys(o.SignalAttributes["obi.http.server"]))
	assert.Equal(t, []string{"service.name"}, sortedKeys(o.SignalAttributes["target.info"]))
}

func fixtureDenominator(t *testing.T) Denominator {
	t.Helper()
	d, err := parseDenominator([]byte(resolvedFixture))
	require.NoError(t, err)
	return d
}

func TestAggregateSplitsCoveredAndGaps(t *testing.T) {
	reports := []Report{{
		Statistics: Statistics{
			SeenRegistryMetrics:       map[string]int{"http.server.request.duration": 1},
			SeenNonRegistryAttributes: map[string]int{"service.name": 1, "cloud.provider": 2},
		},
		MatchedSignals: map[string]int{"obi.http.server": 1, "http.server.request.duration": 1},
		SignalAttributes: map[string][]string{
			"obi.http.server":              {"url.path", "undeclared.key", "http.request.header.accept"},
			"http.server.request.duration": {"http.request.method"},
		},
	}}

	res := Aggregate(fixtureDenominator(t), reports)

	assert.Equal(t, 1, res.Reports)
	assert.Equal(t, SurfaceResult{Covered: []string{"http.server.request.duration"}, Gaps: []string{"go.goroutine.count", "target.info"}}, res.Metrics)
	assert.Equal(t, SurfaceResult{Covered: []string{"obi.http.server"}, Gaps: []string{}}, res.Spans)
	assert.Equal(t, SurfaceResult{Covered: []string{"cloud.provider", "service.name"}, Gaps: []string{"cloud.resource_id", "host.id"}}, res.ResourceAttributes)

	assert.Equal(t, []SignalAttributesResult{
		{
			Signal: "http.server.request.duration", Kind: kindMetric,
			Covered: []DeclaredAttribute{{Key: "http.request.method", RequirementLevel: levelRequired}},
			Gaps: []DeclaredAttribute{
				{Key: "client.address", RequirementLevel: levelOptIn},
				{Key: "http.route", RequirementLevel: levelConditionallyRequired},
			},
		},
		{
			Signal: "obi.http.server", Kind: kindSpan,
			Covered: []DeclaredAttribute{
				{Key: "http.request.header", RequirementLevel: levelOptIn, Template: true},
				{Key: "url.path", RequirementLevel: levelRequired},
			},
			Gaps: []DeclaredAttribute{{Key: "server.port", RequirementLevel: levelRecommended}},
		},
	}, res.SignalAttributes, "only observed signals are measured, a template is observed through its keys, and undeclared keys are ignored")

	assert.Equal(t, 3, res.FailingGaps(), "two signal gaps and one conditionally required attribute; opt-in and recommended never fail")
}

func TestAggregateFullCoverageHasNoFailingGaps(t *testing.T) {
	d := Denominator{Signals: []Signal{
		{Name: "m", Kind: kindMetric, Attributes: []DeclaredAttribute{
			{Key: "a", RequirementLevel: levelRequired},
			{Key: "o", RequirementLevel: levelOptIn},
		}},
	}}
	res := Aggregate(d, []Report{{
		MatchedSignals:   map[string]int{"m": 1},
		SignalAttributes: map[string][]string{"m": {"a"}},
	}})

	assert.Zero(t, res.FailingGaps())
	assert.Equal(t, []DeclaredAttribute{{Key: "o", RequirementLevel: levelOptIn}}, res.SignalAttributes[0].Gaps)
}

func TestMarkdownReportsTableAndGaps(t *testing.T) {
	res := Aggregate(fixtureDenominator(t), []Report{{
		MatchedSignals: map[string]int{"obi.http.server": 1, "http.server.request.duration": 1},
		SignalAttributes: map[string][]string{
			"obi.http.server":              {"url.path"},
			"http.server.request.duration": {"http.request.method"},
		},
	}})

	md := res.Markdown()

	assert.Contains(t, md, "## Weaver telemetry coverage")
	assert.Contains(t, md, "| metrics | 1 | 3 | 33.3% |")
	assert.Contains(t, md, "| spans | 1 | 1 | 100.0% |")
	assert.Contains(t, md, "| signal attributes, required | 2 | 2 | 100.0% |")
	assert.Contains(t, md, "| signal attributes, conditionally_required | 0 | 1 | 0.0% |")
	assert.Contains(t, md, "| signal attributes, opt_in (informational) | 0 | 2 | 0.0% |")
	assert.Contains(t, md, "**Uncovered metrics: 2 never observed**")
	assert.Contains(t, md, "- `go.goroutine.count`")
	assert.Contains(t, md, "**Uncovered spans:** all covered")
	assert.Contains(t, md, "- metric `http.server.request.duration`: `http.route` (conditionally_required)\n")
	assert.Contains(t, md, "<details><summary>Recommended and opt-in signal attributes never observed (2 signal(s))</summary>")
	assert.Contains(t, md, "- metric `http.server.request.duration`: `client.address` (opt_in)\n")
	assert.Contains(t, md, "- span `obi.http.server`: `http.request.header` (opt_in), `server.port` (recommended)\n")
}

func TestMarkdownAllCovered(t *testing.T) {
	d := Denominator{
		Signals:            []Signal{{Name: "m", Kind: kindMetric, Attributes: []DeclaredAttribute{{Key: "a", RequirementLevel: levelRequired}}}},
		ResourceAttributes: []string{"service.name"},
	}
	res := Aggregate(d, []Report{{
		Statistics:       Statistics{SeenRegistryAttributes: map[string]int{"service.name": 1}},
		MatchedSignals:   map[string]int{"m": 1},
		SignalAttributes: map[string][]string{"m": {"a"}},
	}})

	md := res.Markdown()

	assert.Contains(t, md, "**Uncovered metrics:** all covered")
	assert.Contains(t, md, "**Required and conditionally required signal attributes:** all covered")
	assert.Contains(t, md, "**Uncovered resource attributes:** all covered")
	assert.NotContains(t, md, "<details>")
}

func TestLoadReportsWalksAndParses(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "shard-1"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "shard-2"), 0o755))
	write := func(p, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644))
	}
	write("shard-1/weaver-report-Foo.json", `{"statistics":{"seen_registry_metrics":{"A":1}},"matched_signals":{"obi.dns":1},"signal_attributes":{"obi.dns":["dns.question.name"]}}`)
	write("shard-2/weaver-report-Bar.json", `{"statistics":{"seen_registry_metrics":{"B":1}}}`)
	write("shard-1/other.json", `not a report`)
	write("shard-1/integration.log", `ignored`)

	reports, err := LoadReports(dir)
	require.NoError(t, err)
	require.Len(t, reports, 2, "only weaver-report-*.json files are loaded")

	o := Observe(reports)
	assert.Equal(t, []string{"A", "B", "obi.dns"}, sortedKeys(o.Signals))
	assert.Equal(t, []string{"dns.question.name"}, sortedKeys(o.SignalAttributes["obi.dns"]))
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
