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

func testModel() *Model {
	return &Model{
		SchemaURL: "https://example.invalid/schemas/obi/0.0.0",
		Spans: map[string]ModelSpan{
			"obi.http.server": {Kind: "server", Attributes: Attributes{
				"http.request.method":       {Level: LevelRequired},
				"http.response.status_code": {Level: LevelRequired},
				"http.route":                {Level: LevelConditionallyRequired, Condition: "if a route template could be matched"},
				"url.path":                  {Level: LevelOptIn},
			}},
			"obi.dns": {Kind: "internal", Attributes: Attributes{
				"dns.question.name": {Level: LevelOptIn},
			}},
		},
		Metrics: map[string]ModelMetric{
			"http.server.request.duration": {Instrument: "histogram", Unit: "s", Attributes: Attributes{
				"http.request.method": {Level: LevelRequired},
				"http.route":          {Level: LevelConditionallyRequired, Condition: "if a route template could be matched"},
			}},
		},
		Entities: map[string]ModelEntity{
			"service": {
				Identity:    Attributes{"service.name": {Level: LevelRequired}},
				Description: Attributes{"service.version": {Level: LevelRecommended}},
			},
		},
	}
}

func TestAggregateCountsCoverageAndUnobservedSignals(t *testing.T) {
	u := &Union{
		Reports: 2,
		SpanShapes: []SpanShape{
			{Kind: "server", Attributes: []string{"http.request.method", "http.response.status_code"}},
		},
		Metrics: map[string]map[string]struct{}{
			"http.server.request.duration": {"http.request.method": {}},
		},
		Resource: map[string]struct{}{"service.name": {}},
	}

	r := Aggregate(testModel(), u)

	spans := byName(r.Spans)
	assert.True(t, spans["obi.http.server"].Observed)
	assert.Equal(t, []string{"http.request.method", "http.response.status_code"}, spans["obi.http.server"].Covered)
	assert.Equal(t, []string{"http.route"}, spans["obi.http.server"].Missing[LevelConditionallyRequired])
	assert.Equal(t, []string{"url.path"}, spans["obi.http.server"].Missing[LevelOptIn])
	assert.False(t, spans["obi.dns"].Observed)

	metrics := byName(r.Metrics)
	assert.True(t, metrics["http.server.request.duration"].Observed)
	assert.Equal(t, []string{"http.route"}, metrics["http.server.request.duration"].Missing[LevelConditionallyRequired])

	require.Len(t, r.Entities, 1)
	assert.True(t, r.Entities[0].Observed)
	assert.Equal(t, []string{"service.name"}, r.Entities[0].Identity)
	assert.Equal(t, []string{"service.version"}, r.Entities[0].Missing)
}

func TestAggregateRecordsAnUnclassifiedShapeRatherThanCreditingIt(t *testing.T) {
	u := &Union{
		Reports:    1,
		SpanShapes: []SpanShape{{Kind: "server", Attributes: []string{"server.address"}}},
		Metrics:    map[string]map[string]struct{}{},
		Resource:   map[string]struct{}{},
	}

	r := Aggregate(testModel(), u)

	require.Len(t, r.UnclassifiedShapes, 1)
	for _, s := range r.Spans {
		assert.Falsef(t, s.Observed, "span type %s was credited by an unclassified shape", s.Name)
	}
	assert.True(t, Evaluate(r).Failed())
}

func TestAggregateReportsAMetricEmittedButNotDeclared(t *testing.T) {
	u := &Union{
		Reports:    1,
		SpanShapes: []SpanShape{},
		Metrics: map[string]map[string]struct{}{
			"obi.undeclared.thing": {"a": {}},
		},
		Resource: map[string]struct{}{},
	}

	r := Aggregate(testModel(), u)

	assert.Equal(t, []string{"obi.undeclared.thing"}, r.UndeclaredMetrics)
}

func TestEvaluateFailsOnAnUnobservedSignalAndOnAMissingRequiredAttribute(t *testing.T) {
	u := &Union{
		Reports: 1,
		SpanShapes: []SpanShape{
			{Kind: "server", Attributes: []string{"http.request.method"}},
			{Kind: "internal", Attributes: []string{"dns.question.name"}},
		},
		Metrics:  map[string]map[string]struct{}{"http.server.request.duration": {"http.request.method": {}}},
		Resource: map[string]struct{}{"service.name": {}},
	}

	g := Evaluate(Aggregate(testModel(), u))

	assert.True(t, g.Failed())
	assert.Equal(t, []string{"span obi.http.server: http.response.status_code"}, g.MissingRequired)
	assert.Empty(t, g.UnobservedSpans)
	assert.Empty(t, g.UnobservedMetrics)
}

func TestAMissingDiscriminatorMakesTheShapeUnclassifiedRatherThanAMissingAttribute(t *testing.T) {
	u := &Union{
		Reports:    1,
		SpanShapes: []SpanShape{{Kind: "server", Attributes: []string{"http.response.status_code"}}},
		Metrics:    map[string]map[string]struct{}{},
		Resource:   map[string]struct{}{},
	}

	r := Aggregate(testModel(), u)
	g := Evaluate(r)

	assert.Len(t, r.UnclassifiedShapes, 1)
	assert.Empty(t, g.MissingRequired)
	assert.Contains(t, g.UnobservedSpans, "obi.http.server")
	assert.True(t, g.Failed())
}

func TestEvaluatePassesWhenEverySignalIsObservedWithItsRequiredAttributes(t *testing.T) {
	u := &Union{
		Reports: 1,
		SpanShapes: []SpanShape{
			{Kind: "server", Attributes: []string{"http.request.method", "http.response.status_code"}},
			{Kind: "internal", Attributes: []string{"dns.question.name"}},
		},
		Metrics:  map[string]map[string]struct{}{"http.server.request.duration": {"http.request.method": {}}},
		Resource: map[string]struct{}{"service.name": {}},
	}

	g := Evaluate(Aggregate(testModel(), u))

	assert.False(t, g.Failed())
}

func TestLoadReportsUnionsShapesAcrossShardsAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, dir, "weaver-report-TestA.json", `{"observed":{
		"spans":[{"kind":"server","attributes":["http.request.method"],"discriminators":{}}],
		"metrics":{"http.server.request.duration":["http.request.method"]},
		"resource":["service.name"]}}`)
	writeReport(t, dir, "weaver-report-TestB.json", `{"observed":{
		"spans":[{"kind":"server","attributes":["http.request.method"],"discriminators":{}},
		         {"kind":"internal","attributes":["dns.question.name"],"discriminators":{}}],
		"metrics":{"http.server.request.duration":["http.route"],"dns.lookup.duration":[]},
		"resource":["service.version"]}}`)
	writeReport(t, dir, "not-a-weaver-report.json", `{"observed":{"spans":[{"kind":"consumer","attributes":["x"]}]}}`)

	u, err := LoadReports(dir)
	require.NoError(t, err)

	assert.Equal(t, 2, u.Reports)
	assert.Len(t, u.SpanShapes, 2)
	assert.Len(t, u.Metrics["http.server.request.duration"], 2)
	assert.Contains(t, u.Metrics, "dns.lookup.duration")
	assert.Len(t, u.Resource, 2)
}

func TestLoadReportsFailsWhenNoReportWasArchived(t *testing.T) {
	_, err := LoadReports(t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no weaver-report-")
}

func TestLoadModelRejectsAnEmptyRegistry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "coverage-model.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"spans":{},"metrics":{}}`), 0o644))

	_, err := LoadModel(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute --registry path")
}

func byName(sigs []SignalCoverage) map[string]SignalCoverage {
	out := map[string]SignalCoverage{}
	for _, s := range sigs {
		out[s.Name] = s
	}
	return out
}

func writeReport(t *testing.T, dir, name, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
}
