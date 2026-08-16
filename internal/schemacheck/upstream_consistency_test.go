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

type metricGroupsFile struct {
	Groups []struct {
		Type        string `yaml:"type"`
		MetricName  string `yaml:"metric_name"`
		Unit        string `yaml:"unit"`
		Instrument  string `yaml:"instrument"`
		Stability   string `yaml:"stability"`
		Annotations struct {
			OBI struct {
				// upstream_override marks a metric OBI re-declares as a narrowed
				// copy of an upstream semconv metric (vs an OBI-invented one).
				UpstreamOverride bool `yaml:"upstream_override"`
			} `yaml:"obi"`
		} `yaml:"annotations"`
	} `yaml:"groups"`
}

type metricDef struct {
	unit       string
	instrument string
	stability  string
	override   bool
	source     string
}

func metricsFromFile(t *testing.T, path string, out map[string]metricDef) {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	var f metricGroupsFile
	require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)
	for _, g := range f.Groups {
		if g.Type != "metric" || g.MetricName == "" {
			continue
		}
		out[g.MetricName] = metricDef{
			unit:       g.Unit,
			instrument: g.Instrument,
			stability:  g.Stability,
			override:   g.Annotations.OBI.UpstreamOverride,
			source:     path,
		}
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

// overrideMetrics returns the OBI metrics tagged with the
// annotations.obi.upstream_override marker across all group files — the
// narrowed re-declarations of upstream semconv metrics, as opposed to
// OBI-invented metrics.
func overrideMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
	out := map[string]metricDef{}
	for name, m := range obiMetrics(t) {
		if m.override {
			out[name] = m
		}
	}
	return out
}

func upstreamMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
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

// TestOBIMetricOverridesMatchUpstream asserts that every metric OBI marks as an
// upstream override (annotations.obi.upstream_override) — its narrowed copy of
// an upstream semconv metric — exists upstream and declares the same unit,
// instrument, and stability as the pinned upstream definition.
//
// OBI redeclares these metrics instead of importing them because weaver cannot
// narrow an imported metric's attributes down to the subset OBI emits
// (open-telemetry/weaver#1667). Redeclaring copies the metric wrapper — unit,
// instrument, stability — which can then drift from upstream, so this test pins
// it to the upstream definition. It also fails closed: a metric_name typo or an
// upstream rename makes the name disappear from upstream and fails the test
// rather than being silently reclassified as an OBI-only metric. Attributes are
// not compared: OBI refs them, so they resolve against this same upstream
// registry and cannot drift.
func TestOBIMetricOverridesMatchUpstream(t *testing.T) {
	overrides := overrideMetrics(t)
	upstream := upstreamMetrics(t)
	require.NotEmpty(t, overrides)
	require.NotEmpty(t, upstream)

	for name, m := range overrides {
		up, ok := upstream[name]
		require.Truef(t, ok,
			"metric %q is marked annotations.obi.upstream_override in %s but has no "+
				"upstream semconv definition; fix the metric_name, or drop the "+
				"annotation if it is an OBI-only metric",
			name, m.source)
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
