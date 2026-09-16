// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

const obiGroupsDir = "../../../schemas/obi/groups"

type registryMetricFile struct {
	Groups []struct {
		ID         string `yaml:"id"`
		Type       string `yaml:"type"`
		MetricName string `yaml:"metric_name"`
		Attributes []struct {
			ID               string    `yaml:"id"`
			Ref              string    `yaml:"ref"`
			RequirementLevel yaml.Node `yaml:"requirement_level"`
		} `yaml:"attributes"`
	} `yaml:"groups"`
}

// Whether an attribute reaches a metric is decided here, in getDefinitions: an
// attribute the user must name in attributes.select is opt-in, and one that is
// on by default is not. The registry states the same thing for consumers, and
// nothing else keeps the two in step — weaver validates that a level is a legal
// word, and live-check only ever looks at attributes that were emitted, so a
// level that contradicts the code is invisible to both.
func TestMetricRequirementLevelsMatchDefaults(t *testing.T) {
	defs := getDefinitions(^AttrGroups(0), NewGroupAttributes(nil))

	bySection := map[string]AttrReportGroup{}
	for section, group := range defs {
		bySection[string(section)] = group
	}

	// The registry names a metric by its OTLP name; getDefinitions keys on the
	// section, which is not always the same string.
	sectionFor := map[string]string{}
	for _, n := range allMetricNames() {
		sectionFor[n.OTEL] = string(n.Section)
	}

	checked := 0
	for _, path := range metricFiles(t) {
		body, err := os.ReadFile(path)
		require.NoError(t, err)

		var f registryMetricFile
		require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)

		for _, g := range f.Groups {
			if g.Type != "metric" || g.MetricName == "" {
				continue
			}
			section, ok := sectionFor[g.MetricName]
			if !ok {
				continue
			}
			group, ok := bySection[section]
			if !ok {
				continue
			}

			defaults := group.Default()
			all := group.All()

			for _, a := range g.Attributes {
				name := attr.Name(a.Ref)
				if name == "" {
					name = attr.Name(a.ID)
				}
				if _, known := all[name]; !known {
					continue
				}
				if a.RequirementLevel.IsZero() {
					continue
				}
				checked++

				_, onByDefault := defaults[name]
				declaredOptIn := a.RequirementLevel.Kind == yaml.ScalarNode &&
					a.RequirementLevel.Value == "opt_in"

				if onByDefault {
					assert.Falsef(t, declaredOptIn,
						"%s declares %s opt_in, but getDefinitions has it on by default; "+
							"a reader would add it to attributes.select for nothing",
						g.ID, name)
					continue
				}

				assert.Truef(t, declaredOptIn,
					"%s declares %s as something other than opt_in, but getDefinitions has it "+
						"off by default: it reaches the metric only when named in attributes.select",
					g.ID, name)
			}
		}
	}

	require.NotZero(t, checked, "no metric attribute levels were compared")
}

func metricFiles(t *testing.T) []string {
	t.Helper()

	var out []string
	for _, pattern := range []string{"*/metrics.yaml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(obiGroupsDir, pattern))
		require.NoError(t, err)
		out = append(out, matches...)
	}
	return out
}

// allMetricNames lists every metric this package declares, so the comparison
// below can map a registry metric_name onto the section getDefinitions keys on.
// A metric missing here is simply not compared; TestAllMetricSectionsAreListed
// keeps that from going unnoticed.
func allMetricNames() []Name {
	return []Name{
		NetworkFlow,
		NetworkFlowPackets,
		NetworkInterZone,
		HTTPServerRequestSize,
		HTTPServerResponseSize,
		HTTPClientRequestSize,
		HTTPClientResponseSize,
		HTTPServerDuration,
		HTTPClientDuration,
		RPCServerDuration,
		RPCClientDuration,
		DBClientDuration,
		DBServerDuration,
		MessagingPublishDuration,
		MessagingProcessDuration,
		GPUCudaKernelLaunchCalls,
		GPUCudaGraphLaunchCalls,
		GPUCudaKernelGridSize,
		GPUCudaKernelBlockSize,
		GPUCudaMemoryAllocations,
		GPUCudaMemoryCopies,
		DNSLookupDuration,
		GenAIClientInputTokenUsage,
		GenAIClientOutputTokenUsage,
		GenAIClientOperationDuration,
		MCPClientOperationDuration,
		MCPServerOperationDuration,
		GoRuntimeMemoryLimit,
		GoRuntimeMemoryGCGoal,
		GoRuntimeMemoryGCCycles,
		GoRuntimeMemoryGCPauseDuration,
		GoRuntimeMemoryUsed,
		GoRuntimeMemoryAllocated,
		GoRuntimeMemoryAllocations,
		GoRuntimeCPUTime,
		GoRuntimeGoroutineCount,
		GoRuntimeProcessorLimit,
		GoRuntimeConfigGOGC,
		GoRuntimeScheduleDuration,
		CPythonGCCollections,
		CPythonGCCollectedObjects,
		CPythonGCUncollectableObjects,
		JVMMemoryUsed,
		JVMMemoryCommitted,
		JVMMemoryLimit,
		JVMMemoryUsedAfterLastGC,
		JVMClassLoaded,
		JVMClassUnloaded,
		JVMClassCount,
		JVMThreadCount,
		JVMCPUTime,
		JVMCPUCount,
		JVMCPURecentUtilization,
		JVMGCDuration,
		NodejsEventLoopTime,
		NodejsEventLoopUtilization,
		NodejsEventLoopDelayMin,
		NodejsEventLoopDelayMax,
		NodejsEventLoopDelayMean,
		NodejsEventLoopDelayStddev,
		NodejsEventLoopDelayP50,
		NodejsEventLoopDelayP90,
		NodejsEventLoopDelayP99,
		V8JSGCDuration,
		V8JSMemoryHeapLimit,
		V8JSMemoryHeapUsed,
		V8JSMemoryHeapSpaceAvailableSize,
		V8JSMemoryHeapSpacePhysicalSize,
		V8JSResourceActive,
		Resource,
		StatTCPRtt,
		StatTCPFailedConnections,
		StatTCPRetransmits,
		StatTCPIo,
	}
}

// getDefinitions keys on Section, and every section it defines should be
// reachable from allMetricNames, or the comparison above silently skips it.
func TestAllMetricSectionsAreListed(t *testing.T) {
	listed := map[Section]struct{}{}
	for _, n := range allMetricNames() {
		listed[n.Section] = struct{}{}
	}

	// Two sections carry no metric of their own: `traces` holds the span
	// attribute set, and the placeholder stands in for the span and
	// service-graph metrics, whose labels are fixed rather than selected.
	notAMetric := map[Section]struct{}{
		"traces": {},
		"---- temporary placeholder for span and service graph metrics ----": {},
	}

	for section := range getDefinitions(^AttrGroups(0), NewGroupAttributes(nil)) {
		if _, skip := notAMetric[section]; skip {
			continue
		}
		_, ok := listed[section]
		assert.Truef(t, ok, "section %q is defined but not listed in allMetricNames", section)
	}
}

// The `traces` section decides the same thing for span attributes that a metric
// section does for metric labels: whether an attribute is on by default or has
// to be named in attributes.select. Span groups state it per shape, but the
// opt-in question is answered once, here, for all of them.
func TestSpanRequirementLevelsMatchTracesDefaults(t *testing.T) {
	traces, ok := getDefinitions(^AttrGroups(0), NewGroupAttributes(nil))["traces"]
	require.True(t, ok, "no traces section in getDefinitions")

	defaults := traces.Default()
	all := traces.All()

	checked := 0
	for _, path := range spanFiles(t) {
		body, err := os.ReadFile(path)
		require.NoError(t, err)

		var f registryMetricFile
		require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)

		for _, g := range f.Groups {
			if g.Type != "span" {
				continue
			}
			for _, a := range g.Attributes {
				name := attr.Name(a.Ref)
				if name == "" {
					name = attr.Name(a.ID)
				}
				if _, known := all[name]; !known {
					continue
				}
				if a.RequirementLevel.IsZero() {
					continue
				}
				checked++

				_, onByDefault := defaults[name]
				declaredOptIn := a.RequirementLevel.Kind == yaml.ScalarNode &&
					a.RequirementLevel.Value == "opt_in"

				if onByDefault {
					assert.Falsef(t, declaredOptIn,
						"%s declares %s opt_in, but it is on by default for traces; "+
							"a reader would add it to attributes.select for nothing",
						g.ID, name)
					continue
				}

				assert.Truef(t, declaredOptIn,
					"%s declares %s as something other than opt_in, but it is off by default "+
						"for traces: it reaches the span only when named in attributes.select",
					g.ID, name)
			}
		}
	}

	require.NotZero(t, checked, "no span attribute levels were compared")
}

func spanFiles(t *testing.T) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(obiGroupsDir, "*/spans.yaml"))
	require.NoError(t, err)
	return matches
}
