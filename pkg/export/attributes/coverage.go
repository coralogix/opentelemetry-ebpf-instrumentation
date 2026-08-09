// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import (
	"sort"
)

var nonEmittedMetricSections = map[Section]struct{}{
	Resource.Section: {},
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

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
