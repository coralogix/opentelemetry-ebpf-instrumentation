// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// runLintSchemaFilter pipes a diagnostics JSON document through
// lint-schema-filter.jq and returns the surviving diagnostics.
func runLintSchemaFilter(t *testing.T, diagnostics string) []json.RawMessage {
	t.Helper()

	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}

	cmd := exec.Command("jq", "-f", "lint-schema-filter.jq")
	cmd.Stdin = strings.NewReader(diagnostics)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jq failed: %v\n%s", err, out)
	}

	var remaining []json.RawMessage
	if err := json.Unmarshal(out, &remaining); err != nil {
		t.Fatalf("filter output is not a JSON array: %v\n%s", err, out)
	}
	return remaining
}

const expectedDNSUnstableFormat = `[{
	"diagnostic": {"severity": "Error"},
	"error": {"FailToResolveDefinition": {"UnstableFileFormat": {
		"file_format": "definition/2",
		"provenance": "/obi-registry/groups/dns.yaml"
	}}}
}]`

func TestLintSchemaFilterAllowsExpectedDNSUnstableFormat(t *testing.T) {
	remaining := runLintSchemaFilter(t, expectedDNSUnstableFormat)
	if len(remaining) != 0 {
		t.Fatalf("expected the documented definition/2 dns.yaml unstable-format diagnostic to be filtered, got %d diagnostics", len(remaining))
	}
}

func TestLintSchemaFilterKeepsUnrelatedDiagnostics(t *testing.T) {
	cases := map[string]string{
		"unstable format for a different file": `[{
			"error": {"FailToResolveDefinition": {"UnstableFileFormat": {
				"file_format": "definition/2",
				"provenance": "/obi-registry/groups/network.yaml"
			}}}
		}]`,
		"duplicate metric name": `[{
			"error": {"DuplicateMetricName": {
				"metric_name": "dns.lookup.duration",
				"provenances": [
					{"path": ".deps/upstream-v1.41.0/model/dns/metrics.yaml"},
					{"path": "/obi-registry/groups/dns.yaml"}
				]
			}}
		}]`,
		"resolution failure other than unstable format": `[{
			"error": {"FailToResolveDefinition": {"UnresolvedAttributeRef": {
				"attribute": "dns.question.name"
			}}}
		}]`,
		"different error type": `[{
			"diagnostic": {"severity": "Error"},
			"error": {"DuplicateGroupId": {"group_id": "metric.dns.lookup.duration"}}
		}]`,
	}

	for name, diags := range cases {
		t.Run(name, func(t *testing.T) {
			remaining := runLintSchemaFilter(t, diags)
			if len(remaining) != 1 {
				t.Fatalf("expected the diagnostic to survive the filter, got %d remaining", len(remaining))
			}
		})
	}
}
