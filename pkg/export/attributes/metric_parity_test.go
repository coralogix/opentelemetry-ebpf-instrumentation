// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/prometheus/otlptranslator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// instrument records the OTLP unit and instrument type that the exporters declare for a
// metric, so the Prom name in this package can be checked against the name a Prometheus
// consumer derives from the OTLP one. Keep in sync with the meter.* calls in
// pkg/export/otel.
type instrument struct {
	unit string
	typ  otlptranslator.MetricType
}

var otlpInstruments = map[string]instrument{
	"obi.network.flow.bytes":              {"{bytes}", otlptranslator.MetricTypeMonotonicCounter},
	"obi.network.flow.packets":            {"{packets}", otlptranslator.MetricTypeMonotonicCounter},
	"obi.network.inter.zone.bytes":        {"{bytes}", otlptranslator.MetricTypeMonotonicCounter},
	"http.server.request.body.size":       {"By", otlptranslator.MetricTypeHistogram},
	"http.server.response.body.size":      {"By", otlptranslator.MetricTypeHistogram},
	"http.client.request.body.size":       {"By", otlptranslator.MetricTypeHistogram},
	"http.client.response.body.size":      {"By", otlptranslator.MetricTypeHistogram},
	"http.server.request.duration":        {"s", otlptranslator.MetricTypeHistogram},
	"http.client.request.duration":        {"s", otlptranslator.MetricTypeHistogram},
	"rpc.server.call.duration":            {"s", otlptranslator.MetricTypeHistogram},
	"rpc.client.call.duration":            {"s", otlptranslator.MetricTypeHistogram},
	"db.client.operation.duration":        {"s", otlptranslator.MetricTypeHistogram},
	"messaging.client.operation.duration": {"s", otlptranslator.MetricTypeHistogram},
	"messaging.process.duration":          {"s", otlptranslator.MetricTypeHistogram},
	"gpu.cuda.kernel.launch.calls":        {"", otlptranslator.MetricTypeMonotonicCounter},
	"gpu.cuda.graph.launch.calls":         {"", otlptranslator.MetricTypeMonotonicCounter},
	"gpu.cuda.kernel.grid.size":           {"1", otlptranslator.MetricTypeHistogram},
	"gpu.cuda.kernel.block.size":          {"1", otlptranslator.MetricTypeHistogram},
	"gpu.cuda.memory.allocations":         {"By", otlptranslator.MetricTypeMonotonicCounter},
	"gpu.cuda.memory.copies":              {"By", otlptranslator.MetricTypeHistogram},
	"dns.lookup.duration":                 {"s", otlptranslator.MetricTypeHistogram},
	"gen_ai.client.token.usage":           {"{token}", otlptranslator.MetricTypeHistogram},
	"gen_ai.client.operation.duration":    {"s", otlptranslator.MetricTypeHistogram},
	"go.memory.limit":                     {"By", otlptranslator.MetricTypeNonMonotonicCounter},
	"go.memory.gc.goal":                   {"By", otlptranslator.MetricTypeNonMonotonicCounter},
	"go.memory.gc.cycles":                 {"{gc_cycle}", otlptranslator.MetricTypeMonotonicCounter},
	"go.memory.gc.pause.duration":         {"s", otlptranslator.MetricTypeHistogram},
	"go.memory.used":                      {"By", otlptranslator.MetricTypeNonMonotonicCounter},
	"go.memory.allocated":                 {"By", otlptranslator.MetricTypeMonotonicCounter},
	"go.memory.allocations":               {"{allocation}", otlptranslator.MetricTypeMonotonicCounter},
	"go.cpu.time":                         {"s", otlptranslator.MetricTypeMonotonicCounter},
	"go.goroutine.count":                  {"{goroutine}", otlptranslator.MetricTypeNonMonotonicCounter},
	"go.processor.limit":                  {"{thread}", otlptranslator.MetricTypeNonMonotonicCounter},
	"go.config.gogc":                      {"%", otlptranslator.MetricTypeNonMonotonicCounter},
	"go.schedule.duration":                {"s", otlptranslator.MetricTypeHistogram},
	"jvm.memory.used":                     {"By", otlptranslator.MetricTypeNonMonotonicCounter},
	"jvm.memory.committed":                {"By", otlptranslator.MetricTypeNonMonotonicCounter},
	"jvm.memory.limit":                    {"By", otlptranslator.MetricTypeNonMonotonicCounter},
	"jvm.memory.used_after_last_gc":       {"By", otlptranslator.MetricTypeNonMonotonicCounter},
	"obi.stat.tcp.rtt":                    {"s", otlptranslator.MetricTypeHistogram},
	"obi.stat.tcp.failed.connections":     {"", otlptranslator.MetricTypeMonotonicCounter},
	"obi.stat.tcp.retransmits":            {"", otlptranslator.MetricTypeMonotonicCounter},
	"obi.stat.tcp.io":                     {"By", otlptranslator.MetricTypeMonotonicCounter},
}

// resource is not a metric, it only names the attributes.select section for resource attributes.
var notMetrics = map[string]bool{"resource": true}

func TestPromNamesMatchOTLPTranslation(t *testing.T) {
	namer := otlptranslator.NewMetricNamer("", otlptranslator.UnderscoreEscapingWithSuffixes)

	for _, m := range parseMetricNames(t) {
		if notMetrics[m.otel] {
			continue
		}
		t.Run(m.otel, func(t *testing.T) {
			inst, ok := otlpInstruments[m.otel]
			require.True(t, ok,
				"metric %q has no entry in otlpInstruments: add its OTLP unit and instrument type", m.otel)

			derived, err := namer.Build(otlptranslator.Metric{Name: m.otel, Unit: inst.unit, Type: inst.typ})
			require.NoError(t, err)

			assert.Equal(t, m.prom, derived,
				"a Prometheus consumer of the OTLP metric %q (unit %q) derives %q, but OBI exports it as %q",
				m.otel, inst.unit, derived, m.prom)
		})
	}
}

type metricName struct {
	otel string
	prom string
}

func parseMetricNames(t *testing.T) []metricName {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "metric.go", nil, 0)
	require.NoError(t, err)

	var names []metricName
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if ident, ok := lit.Type.(*ast.Ident); !ok || ident.Name != "Name" {
			return true
		}

		var m metricName
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			val, ok := kv.Value.(*ast.BasicLit)
			if !ok || val.Kind != token.STRING {
				continue
			}
			unquoted := val.Value[1 : len(val.Value)-1]
			switch key.Name {
			case "OTEL":
				m.otel = unquoted
			case "Prom":
				m.prom = unquoted
			}
		}
		if m.otel != "" && m.prom != "" {
			names = append(names, m)
		}
		return true
	})

	require.NotEmpty(t, names, "parsed no metric names out of metric.go")
	return names
}
