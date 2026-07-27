// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

const defaultInspectorPort = 9229

// listeningTCPPorts is a no-op on non-Linux platforms: without /proc there is
// no per-pid socket table to consult, so callers fall back to probing the
// default inspector port.
func listeningTCPPorts(_ int) (map[int]struct{}, error) {
	return map[int]struct{}{}, nil
}

// candidateInspectorPorts is a no-op on non-Linux platforms.
func candidateInspectorPorts(_ int) []int {
	return []int{defaultInspectorPort}
}
