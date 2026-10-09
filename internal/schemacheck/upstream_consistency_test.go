// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package schemacheck holds tests that validate the OBI semantic-convention
// registry against the pinned upstream OpenTelemetry semantic conventions it
// depends on.
package schemacheck

import (
	"os"
	"path/filepath"
	"slices"
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
	Unit        string `yaml:"unit"`
	Instrument  string `yaml:"instrument"`
	Stability   string `yaml:"stability"`
	Annotations struct {
		OBI struct {
			Upstream upstreamLink `yaml:"upstream"`
		} `yaml:"obi"`
	} `yaml:"annotations"`
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
	link       upstreamLink
	override   bool
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
			link:       m.Annotations.OBI.Upstream,
			override:   slices.Contains(m.Annotations.OBI.Upstream, name),
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

// overrideMetrics returns the OBI metrics that name their own upstream metric in
// annotations.obi.upstream across all group files — the narrowed
// re-declarations of upstream semconv metrics, as opposed to OBI-invented
// metrics.
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

// TestOBIMetricOverridesMatchUpstream asserts that every metric naming an
// upstream metric in annotations.obi.upstream declares the same unit,
// instrument and stability as the first one it names. Redeclaring a metric
// copies that wrapper and lets it drift, so this test pins it; it also fails
// closed on a typo or an upstream rename.
func TestOBIMetricOverridesMatchUpstream(t *testing.T) {
	local := obiMetrics(t)
	upstream := upstreamMetrics(t)
	require.NotEmpty(t, overrideMetrics(t))
	require.NotEmpty(t, upstream)

	for name, m := range local {
		if len(m.link) == 0 || m.link.none() {
			continue
		}
		up, ok := upstream[m.link[0]]
		require.Truef(t, ok,
			"metric %q names %q in annotations.obi.upstream in %s but that has no "+
				"upstream semconv definition; fix the name, or set the annotation "+
				"to none if it is an OBI-only metric",
			name, m.link[0], m.source)
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

// TestLocalMetricsMatchingUpstreamAreMarkedOverrides asserts the inverse of
// TestOBIMetricOverridesMatchUpstream: a locally declared metric whose
// metric_name also exists upstream must carry the annotation, so it cannot
// silently shadow the upstream definition and escape the drift check.
func TestLocalMetricsMatchingUpstreamAreMarkedOverrides(t *testing.T) {
	local := obiMetrics(t)
	upstream := upstreamMetrics(t)
	require.NotEmpty(t, local)
	require.NotEmpty(t, upstream)

	for name, m := range local {
		if m.override {
			continue
		}
		_, ok := upstream[name]
		assert.Falsef(t, ok,
			"metric %q is declared in %s but also exists upstream; name it in "+
				"annotations.obi.upstream, or import the upstream definition "+
				"instead of redeclaring it",
			name, m.source)
	}
}
