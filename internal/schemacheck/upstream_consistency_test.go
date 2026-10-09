// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package schemacheck holds tests that validate the OBI semantic-convention
// registry against the pinned upstream OpenTelemetry semantic conventions it
// depends on.
package schemacheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	obiGroupsDir = "../../schemas/obi/groups"
	upstreamDeps = "../../schemas/obi/.deps"
)

type metricFields struct {
	Unit       string `yaml:"unit"`
	Instrument string `yaml:"instrument"`
	Stability  string `yaml:"stability"`
}

// metricGroupsFile reads metrics from both definition formats: OBI's registry
// is definition/2 (`metrics:`), while the upstream semconv release it pins is
// still the groups format (`groups:` of `type: metric`).
type metricGroupsFile struct {
	Groups []struct {
		Type         string `yaml:"type"`
		MetricName   string `yaml:"metric_name"`
		metricFields `yaml:",inline"`
	} `yaml:"groups"`
	Metrics []struct {
		Name         string `yaml:"name"`
		metricFields `yaml:",inline"`
	} `yaml:"metrics"`
}

type metricDef struct {
	unit       string
	instrument string
	stability  string
	source     string
}

func metricsFromFile(t *testing.T, path string, out map[string]metricDef) {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	var f metricGroupsFile
	require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)
	add := func(name string, m metricFields) {
		out[name] = metricDef{
			unit:       m.Unit,
			instrument: m.Instrument,
			stability:  m.Stability,
			source:     path,
		}
	}
	for _, g := range f.Groups {
		if g.Type == "metric" && g.MetricName != "" {
			add(g.MetricName, g.metricFields)
		}
	}
	for _, m := range f.Metrics {
		add(m.Name, m.metricFields)
	}
}

func obiMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
	out := map[string]metricDef{}
	err := filepath.WalkDir(obiGroupsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		metricsFromFile(t, path, out)
		return nil
	})
	require.NoError(t, err)
	return out
}

// overrideMetrics returns the OBI metrics declared under the name of an
// upstream semconv metric — the narrowed re-declarations of upstream metrics,
// as opposed to OBI-invented metrics.
func overrideMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
	upstream := upstreamMetrics(t)
	out := map[string]metricDef{}
	for name, m := range obiMetrics(t) {
		if _, ok := upstream[name]; ok {
			out[name] = m
		}
	}
	return out
}

func upstreamMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
	if _, err := os.Stat(upstreamDeps); os.IsNotExist(err) {
		t.Skipf("%s is not populated; run `make fetch-upstream-semconv`", upstreamDeps)
	}
	out := map[string]metricDef{}
	err := filepath.WalkDir(upstreamDeps, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		metricsFromFile(t, path, out)
		return nil
	})
	require.NoError(t, err)
	return out
}

// TestOBIMetricOverridesMatchUpstream asserts that every metric OBI declares
// under an upstream metric's name keeps the upstream unit, instrument and
// stability. Redeclaring a metric copies that wrapper and lets it drift, so this
// test pins it.
func TestOBIMetricOverridesMatchUpstream(t *testing.T) {
	overrides := overrideMetrics(t)
	upstream := upstreamMetrics(t)
	require.NotEmpty(t, overrides)
	require.NotEmpty(t, upstream)

	for name, m := range overrides {
		up := upstream[name]
		assert.Equalf(t, up.unit, m.unit,
			"metric %q unit %q differs from upstream %q (%s vs %s)",
			name, m.unit, up.unit, m.source, up.source)
		assert.Equalf(t, up.instrument, m.instrument,
			"metric %q instrument %q differs from upstream %q (%s vs %s)",
			name, m.instrument, up.instrument, m.source, up.source)
		assert.Equalf(t, up.stability, m.stability,
			"metric %q stability %q differs from upstream %q (%s vs %s)",
			name, m.stability, up.stability, m.source, up.source)
	}
}
