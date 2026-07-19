// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

// Standard OTEL_EBPF_*_FEATURES combinations used across suites
const (
	featuresApp           = "application"
	featuresAppSpan       = "application,application_span_otel"
	featuresSpanGraph     = "application,application_span_otel,application_service_graph"
	featuresPromSpan      = "application,application_span"
	featuresPromSpanGraph = "application,application_span,application_service_graph"
	featuresProcessFull   = "application,application_span_otel,application_process,application_service_graph,ebpf,application_host"
	featuresFull          = "application,application_span_otel,application_service_graph,ebpf,application_host"
	featuresProcess       = "application,application_span_otel,application_process,application_service_graph"
)

// subtest pairs a t.Run name with its function
type subtest struct {
	name string
	fn   func(*testing.T)
}

func st(name string, fn func(*testing.T)) subtest { return subtest{name, fn} }

// runSuite drives the standard suite lifecycle: env, Up, subtests, optional
// weaver validation, Close
func runSuite(t *testing.T, compose *docker.Compose, env []string, weaver bool, tests ...subtest) {
	t.Helper()
	compose.Env = append(compose.Env, env...)
	require.NoError(t, compose.Up())
	for _, tc := range tests {
		t.Run(tc.name, tc.fn)
	}
	if weaver {
		runWeaverValidation(t)
	}
	require.NoError(t, compose.Close())
}
