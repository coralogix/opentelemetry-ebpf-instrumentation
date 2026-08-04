// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllMetricsMatchesDeclarations(t *testing.T) {
	src, err := os.ReadFile("metric.go")
	require.NoError(t, err)

	declared := regexp.MustCompile(`(?m)^\t[A-Z][A-Za-z0-9]* = Name\{`).FindAllString(string(src), -1)
	assert.Len(t, AllMetrics, len(declared),
		"every Name{...} declared in metric.go must be listed in AllMetrics")
}

func TestEmittedMetricNamesNonEmpty(t *testing.T) {
	names := EmittedMetricNames()
	require.NotEmpty(t, names)
	for _, n := range names {
		assert.NotEqual(t, "resource", n, "resource is an attribute-selection section, not a metric")
	}
}

func TestEmittedMetricAttributesNonEmpty(t *testing.T) {
	attrs := EmittedMetricAttributes()
	require.NotEmpty(t, attrs)
	assert.Contains(t, attrs, "http.request.method")
}
