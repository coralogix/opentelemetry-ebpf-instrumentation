// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const registryDir = "../../schemas/obi"

type resolvedGroup struct {
	ID         string `json:"id"`
	MetricName string `json:"metric_name"`
}

type resolveOutput struct {
	Groups   []resolvedGroup `json:"groups"`
	Registry struct {
		Groups []resolvedGroup `json:"groups"`
	} `json:"registry"`
}

func (o resolveOutput) groups() []resolvedGroup {
	if len(o.Groups) > 0 {
		return o.Groups
	}
	return o.Registry.Groups
}

var weaverImageRE = regexp.MustCompile(`(?m)^FROM\s+(otel/weaver:\S+)\s+AS\s+weaver`)

func weaverImage(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../../dependencies.Dockerfile")
	require.NoError(t, err)
	m := weaverImageRE.FindSubmatch(body)
	require.Lenf(t, m, 2, "could not find the weaver image in dependencies.Dockerfile")
	return string(m[1])
}

// resolveRegistry runs `weaver registry resolve` (without --include-unreferenced)
// through the pinned weaver docker image and returns the resolved groups. It
// uses the same pinned image as `make lint-schema` rather than a `weaver`
// binary on PATH so the resolution matches the version OBI targets. If docker
// is unavailable it skips: the provenance guarantee is only assertable when
// weaver can actually resolve the registry, and `make lint-schema` covers real
// resolution errors separately.
func resolveRegistry(t *testing.T) resolveOutput {
	t.Helper()
	if !lookPathOK("docker") {
		t.Skip("docker is not available; skipping provenance check")
	}
	registryAbs, err := filepath.Abs(registryDir)
	require.NoError(t, err)

	cmd := exec.Command("docker", "run", "--rm",
		"-v", registryAbs+":/obi-registry:ro", "-w", "/obi-registry",
		weaverImage(t),
		"registry", "resolve", "--registry", "/obi-registry", "--format", "json")

	// weaver exits non-zero whenever diagnostics exist (e.g. the expected
	// definition/2 UnstableFileFormat warnings), yet still writes the resolved
	// registry JSON to stdout. Parse stdout regardless of the exit code, and
	// treat the run as unavailable only when there is no JSON to parse.
	out, err := cmd.Output()

	var res resolveOutput
	if jsonErr := json.Unmarshal(out, &res); jsonErr != nil {
		if err != nil {
			t.Skipf("weaver resolve could not run (%v); skipping provenance check", err)
		}
		require.NoErrorf(t, jsonErr, "parsing weaver resolve output")
	}
	require.NotEmpty(t, res.groups(), "weaver resolve returned no groups")
	return res
}

func lookPathOK(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// TestOBIMetricOverridesResolveToLocalNarrowedDefinition verifies that, without
// --include-unreferenced (the flag live-check no longer uses), every metric OBI
// marks as an upstream override (annotations.obi.upstream_override) resolves to
// OBI's own narrowed group rather than the broader upstream definition. Because
// the upstream metric groups are unreferenced once OBI stops importing them,
// they drop from resolution, leaving exactly one group per shared metric_name:
// OBI's. This is what makes the coverage denominator reflect OBI's true OTLP
// contract.
func TestOBIMetricOverridesResolveToLocalNarrowedDefinition(t *testing.T) {
	overrides := overrideMetrics(t)
	require.NotEmpty(t, overrides)

	byName := map[string][]resolvedGroup{}
	for _, g := range resolveRegistry(t).groups() {
		if g.MetricName != "" {
			byName[g.MetricName] = append(byName[g.MetricName], g)
		}
	}

	for name := range overrides {
		groups := byName[name]
		require.Lenf(t, groups, 1,
			"metric %q should resolve to exactly one group without --include-unreferenced, got %d: %v",
			name, len(groups), groups)
		assert.Truef(t, strings.HasPrefix(groups[0].ID, "metric.obi."),
			"metric %q resolves to group %q; expected OBI's narrowed local group (metric.obi.*), not the upstream definition",
			name, groups[0].ID)
	}
}
