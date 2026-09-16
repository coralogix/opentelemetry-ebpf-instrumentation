// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// carrierFile is a registry file holding signal groups. Attribute definitions
// live in registry.yaml files and carry no requirement level: the level is a
// property of the carrier that references an attribute, not of the definition.
// Upstream semconv declares none on its own definition files either.
func carrierFiles(t *testing.T) []string {
	t.Helper()

	var out []string
	for _, pattern := range []string{"*/spans.yaml", "*/metrics.yaml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(obiGroupsDir, pattern))
		require.NoError(t, err)
		out = append(out, matches...)
	}
	return out
}

type carrierGroupsFile struct {
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

type carrierAttr struct {
	file  string
	group string
	name  string
	level yaml.Node
}

func carrierAttributes(t *testing.T) []carrierAttr {
	t.Helper()

	var out []carrierAttr
	for _, path := range carrierFiles(t) {
		body, err := os.ReadFile(path)
		require.NoError(t, err)

		var f carrierGroupsFile
		require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)

		for _, g := range f.Groups {
			if g.Type != "span" && g.Type != "metric" {
				continue
			}
			for _, a := range g.Attributes {
				name := a.Ref
				if name == "" {
					name = a.ID
				}
				out = append(out, carrierAttr{
					file:  filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path),
					group: g.ID,
					name:  name,
					level: a.RequirementLevel,
				})
			}
		}
	}
	return out
}

// A level is either one of the plain vocabulary words or a single-key mapping
// naming the condition. weaver rejects an unknown word, but it accepts a
// conditionally_required with an empty condition, which tells a reader nothing.
func TestRequirementLevelsAreWellFormed(t *testing.T) {
	plain := map[string]struct{}{
		"required":    {},
		"recommended": {},
		"opt_in":      {},
	}

	for _, a := range carrierAttributes(t) {
		if a.level.IsZero() {
			continue
		}

		if a.level.Kind == yaml.ScalarNode {
			_, ok := plain[a.level.Value]
			assert.Truef(t, ok, "%s: %s/%s has unknown requirement_level %q",
				a.file, a.group, a.name, a.level.Value)
			continue
		}

		var mapping map[string]string
		require.NoErrorf(t, a.level.Decode(&mapping),
			"%s: %s/%s requirement_level is neither a word nor a condition mapping",
			a.file, a.group, a.name)

		assert.Lenf(t, mapping, 1, "%s: %s/%s requirement_level names %d conditions, expected one",
			a.file, a.group, a.name, len(mapping))

		for kind, condition := range mapping {
			assert.Containsf(t, []string{"conditionally_required", "recommended"}, kind,
				"%s: %s/%s has unknown conditional requirement_level %q", a.file, a.group, a.name, kind)
			assert.NotEmptyf(t, strings.TrimSpace(condition),
				"%s: %s/%s declares %s with no condition", a.file, a.group, a.name, kind)
		}
	}
}
