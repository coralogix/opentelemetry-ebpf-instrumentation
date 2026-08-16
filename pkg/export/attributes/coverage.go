// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import (
	"sort"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

var nonEmittedMetricSections = map[Section]struct{}{
	Resource.Section: {},
}

// prometheus-only attributes: `instance` and `job` are scrape labels the
// Prometheus exporter synthesizes; they are never emitted over OTLP, so they
// are not part of the OTLP contract the coverage denominator describes.
// (service.namespace, though grouped with them in attr_defs.go, IS emitted as
// an OTLP resource attribute, so it is not excluded.)
var prometheusOnlyAttributes = map[attr.Name]struct{}{
	attr.Instance: {},
	attr.Job:      {},
}

var internalSelectorNames = map[attr.Name]struct{}{
	attr.GenAITokenTypeOutput: {},
	attr.DBResponseError:      {},
	attr.GenAIResponseError:   {},
}

func maximalAttrGroups() AttrGroups {
	var g AttrGroups
	for _, bit := range []AttrGroups{
		GroupKubernetes, GroupContainer, GroupPrometheus, GroupHTTPRoutes,
		GroupNetIfaceDirection, GroupNetCIDR, GroupTraces, GroupApp, GroupNet,
		GroupNetKube, GroupAppKube, GroupServerInfo, GroupHTTPClientInfo,
		GroupGRPCClientInfo, GroupHTTPCommon, GroupHost, GroupMessaging,
		GroupNetGeoIP, GroupStats, GroupStatsKube,
	} {
		g.Add(bit)
	}
	return g
}

// nonMetricAttributeSections hold attributes that never appear on a metric
// datapoint: Resource is the resource attribute set, and Traces is the span
// attribute set (db.query.text, url.query, graphql.document, gen_ai.* content)
// emitted by tracesgen. Neither is part of the metric-coverage contract.
var nonMetricAttributeSections = map[Section]struct{}{
	Traces.Section: {},
}

// EmittedMetricNames is the set of OTLP metric names OBI emits, derived from
// AllMetrics. The weaver-coverage tool compares it against the resolved schema
// denominator to fail when the code emits a metric the registry does not
// declare (a metric absent from the denominator can never show up as a coverage
// gap, so coverage would silently over-report).
func EmittedMetricNames() []string {
	seen := map[string]struct{}{}
	for _, m := range AllMetrics {
		if _, skip := nonEmittedMetricSections[m.Section]; skip {
			continue
		}
		if m.OTEL != "" {
			seen[m.OTEL] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

// EmittedMetricAttributes is the set of attribute names OBI can attach to its
// OTLP metrics (the maximal attribute groups, minus the Prometheus-only and
// internal-selector attributes). It is the attribute-level counterpart of
// EmittedMetricNames used to fail when the code emits an attribute the registry
// does not declare.
func EmittedMetricAttributes() []string {
	defs := getDefinitions(maximalAttrGroups(), GroupAttributes{})
	seen := map[string]struct{}{}
	for section := range defs {
		if _, skip := nonMetricAttributeSections[section]; skip {
			continue
		}
		grp := defs[section]
		for name := range grp.All() {
			if _, internal := internalSelectorNames[name]; internal {
				continue
			}
			if _, prom := prometheusOnlyAttributes[name]; prom {
				continue
			}
			seen[string(name)] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

// EmittedAttributesByMetric maps each OTLP metric name to the attribute names
// its section makes selectable (default and opt-in), minus prometheus scrape
// labels and internal selectors. This is the universe a metric may emit; the
// caller narrows it to what is actually attached to the datapoint by
// intersecting with the metric's attribute getters (a catch-all getter serves
// every name, an explicit span getter serves only its datapoint attributes,
// leaving resource attributes for target.info). It backs a test that asserts
// every attribute a metric emits is ref'd in that metric's registry group.
func EmittedAttributesByMetric() map[string][]string {
	defs := getDefinitions(maximalAttrGroups(), GroupAttributes{})
	out := map[string][]string{}
	for _, m := range AllMetrics {
		if m.OTEL == "" {
			continue
		}
		if _, skip := nonEmittedMetricSections[m.Section]; skip {
			continue
		}
		grp, ok := defs[m.Section]
		if !ok {
			continue
		}
		seen := map[string]struct{}{}
		for name := range grp.All() {
			if _, skip := internalSelectorNames[name]; skip {
				continue
			}
			if _, skip := prometheusOnlyAttributes[name]; skip {
				continue
			}
			seen[string(name)] = struct{}{}
		}
		out[m.OTEL] = sortedKeys(seen)
	}
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
