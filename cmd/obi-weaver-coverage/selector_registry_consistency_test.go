// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

const registryGroupsDir = "../../schemas/obi/groups"

type registryFile struct {
	Groups []struct {
		Type       string `yaml:"type"`
		MetricName string `yaml:"metric_name"`
		Attributes []struct {
			ID  string `yaml:"id"`
			Ref string `yaml:"ref"`
		} `yaml:"attributes"`
	} `yaml:"groups"`
}

// metricRefsFromRegistry maps each metric_name to the set of attribute names
// ref'd on its registry group, read straight from the schema YAML.
func metricRefsFromRegistry(t *testing.T) map[string]map[string]struct{} {
	t.Helper()
	entries, err := os.ReadDir(registryGroupsDir)
	require.NoError(t, err)

	refs := map[string]map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(registryGroupsDir, e.Name()))
		require.NoError(t, err)
		var rf registryFile
		require.NoErrorf(t, yaml.Unmarshal(body, &rf), "parsing %s", e.Name())
		for _, g := range rf.Groups {
			if g.Type != "metric" || g.MetricName == "" {
				continue
			}
			set := refs[g.MetricName]
			if set == nil {
				set = map[string]struct{}{}
				refs[g.MetricName] = set
			}
			for _, a := range g.Attributes {
				name := a.Ref
				if name == "" {
					name = a.ID
				}
				if name != "" {
					set[name] = struct{}{}
				}
			}
		}
	}
	return refs
}

// netolly and statsolly attach any selected attribute to the datapoint — their
// getters fall back to the flow/stat metadata map — so every attribute their
// sections make selectable is a real datapoint label. Every other metric builds
// its attributes from the span getters, which serve only datapoint attributes
// and leave resource attributes (k8s.*, container.*, …) to target.info.
func attachesEverySelectableAttr(metricName string) bool {
	return strings.HasPrefix(metricName, "obi.network.") ||
		strings.HasPrefix(metricName, "obi.stat.")
}

// Go / JVM runtime metrics are produced by the RuntimeMetricsReporter, not the
// span getters: it attaches service/container to the meter resource
// (pkg/export/otel/metrics_runtime.go newMetricsInstance) and each record call
// adds only the runtime-specific data-point attribute. So service.* — which the
// span getters would otherwise report as served — are resource attributes here
// and are correctly not ref'd on the runtime metric groups.
func attachesServiceToResource(metricName string) bool {
	return strings.HasPrefix(metricName, "go.") || strings.HasPrefix(metricName, "jvm.")
}

var resourceAttrsOnRuntimeMeter = map[string]struct{}{
	"service.name":        {},
	"service.namespace":   {},
	"service.instance.id": {},
}

// TestEmittedDatapointAttributesAreDeclaredPerMetric asserts that every
// attribute OBI can attach to a metric's datapoints is ref'd in that metric's
// registry group. "Can attach" is the metric's selectable set intersected with
// the getters that actually populate a datapoint, so resource attributes routed
// to target.info do not count as a per-metric gap.
func TestEmittedDatapointAttributesAreDeclaredPerMetric(t *testing.T) {
	registry := metricRefsFromRegistry(t)
	require.NotEmpty(t, registry)

	spanGetters := request.SpanOTELGetters(request.UnresolvedNames{})

	byMetric := attributes.EmittedAttributesByMetric()
	require.NotEmpty(t, byMetric)

	for metricName, selectable := range byMetric {
		var emitted []string
		switch {
		case attachesEverySelectableAttr(metricName):
			emitted = selectable
		case attachesServiceToResource(metricName):
			for _, name := range selectable {
				if _, resource := resourceAttrsOnRuntimeMeter[name]; resource {
					continue
				}
				if _, served := spanGetters(attr.Name(name)); served {
					emitted = append(emitted, name)
				}
			}
		default:
			for _, name := range selectable {
				if _, served := spanGetters(attr.Name(name)); served {
					emitted = append(emitted, name)
				}
			}
		}

		// Metrics OBI inherits from upstream (e.g. dns.lookup.duration) have no
		// local metric_name group to compare against; their emission is covered
		// by the global metric-drift guard, so skip them here.
		declared, ok := registry[metricName]
		if !ok {
			continue
		}
		for _, name := range emitted {
			_, found := declared[name]
			assert.Truef(t, found,
				"attribute %q is attached to metric %q's datapoints but is not ref'd in its registry group",
				name, metricName)
		}
	}
}
