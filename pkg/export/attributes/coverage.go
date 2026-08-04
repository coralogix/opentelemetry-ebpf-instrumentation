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

func EmittedMetricAttributes() []string {
	defs := getDefinitions(maximalAttrGroups(), GroupAttributes{})
	seen := map[string]struct{}{}
	for section := range defs {
		grp := defs[section]
		for name := range grp.All() {
			if _, internal := internalSelectorNames[name]; internal {
				continue
			}
			seen[string(name)] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
