// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const upstreamFixture = `
groups:
  - id: registry.server
    type: attribute_group
    attributes:
      - id: server.address
        type: string
        stability: stable
      - id: network.type
        stability: stable
        type:
          members:
            - id: ipv4
              value: "ipv4"
            - id: ipv6
              value: "ipv6"
      - id: error.type
        stability: stable
        type:
          members:
            - id: other
              value: "_OTHER"
`

func writeFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "registry.yaml"), []byte(body), 0o600))
	return dir
}

func loadFixture(t *testing.T, body string) map[string]attrDef {
	t.Helper()
	attrs, err := attributesFromTree(writeFixture(t, body))
	require.NoError(t, err)
	return attrs
}

// TestRefsAreNotDeclarations pins the distinction the whole check rests on: an
// attribute pulled in with `ref` is a use of the upstream definition, not a
// redefinition, and must never be reported as drift.
func TestRefsAreNotDeclarations(t *testing.T) {
	attrs := loadFixture(t, `
groups:
  - id: span.obi.example
    type: span
    attributes:
      - ref: server.address
        requirement_level: required
      - id: obi.example.own
        type: string
        stability: development
`)
	assert.NotContains(t, attrs, "server.address")
	assert.Contains(t, attrs, "obi.example.own")
}

func TestShadowedAttributesDetectsRedeclaration(t *testing.T) {
	upstream := loadFixture(t, upstreamFixture)

	local := loadFixture(t, `
groups:
  - id: registry.obi.network
    type: attribute_group
    attributes:
      - id: server.address
        type: string
        stability: development
      - id: obi.network.flow.direction
        type: string
        stability: development
`)

	assert.Equal(t, []string{"server.address"}, shadowedAttributes(local, upstream))
}

func TestShadowedAttributesIgnoresOBIOwnAttributes(t *testing.T) {
	upstream := loadFixture(t, upstreamFixture)

	local := loadFixture(t, `
groups:
  - id: registry.obi.network
    type: attribute_group
    attributes:
      - id: obi.network.flow.direction
        type: string
        stability: development
`)

	assert.Empty(t, shadowedAttributes(local, upstream))
}

func TestOrphanOverridesDetectsMissingUpstream(t *testing.T) {
	upstream := loadFixture(t, upstreamFixture)

	overrides := loadFixture(t, `
groups:
  - id: x.obi.network
    type: attribute_group
    attributes:
      - id: network.type
        type: string
        stability: stable
      - id: network.typo
        type: string
        stability: stable
`)

	assert.Equal(t, []string{"network.typo"}, orphanOverrides(overrides, upstream))
}

func TestDroppedEnumMembersDetectsNarrowing(t *testing.T) {
	upstream := loadFixture(t, upstreamFixture)

	overrides := loadFixture(t, `
groups:
  - id: x.obi.network
    type: attribute_group
    attributes:
      - id: network.type
        stability: stable
        type:
          members:
            - id: arp
              value: "arp"
            - id: ipv4
              value: "ipv4"
`)

	assert.Equal(t, map[string][]string{"network.type": {"ipv6"}},
		droppedEnumMembers(overrides, upstream))
}

func TestDroppedEnumMembersAllowsSupersets(t *testing.T) {
	upstream := loadFixture(t, upstreamFixture)

	overrides := loadFixture(t, `
groups:
  - id: x.obi.network
    type: attribute_group
    attributes:
      - id: network.type
        stability: stable
        type:
          members:
            - id: arp
              value: "arp"
            - id: ipv4
              value: "ipv4"
            - id: ipv6
              value: "ipv6"
`)

	assert.Empty(t, droppedEnumMembers(overrides, upstream))
}

// TestDroppedEnumMembersSkipsRetypedOverrides covers the second override style
// in schemas/obi/README.md: an unbounded value space re-typed to a plain
// string is not an enum narrowing and must not be reported.
func TestDroppedEnumMembersSkipsRetypedOverrides(t *testing.T) {
	upstream := loadFixture(t, upstreamFixture)

	overrides := loadFixture(t, `
groups:
  - id: x.obi.error
    type: attribute_group
    attributes:
      - id: error.type
        type: string
        stability: stable
`)

	assert.Empty(t, droppedEnumMembers(overrides, upstream))
}

func TestStabilityDriftDetectsMismatch(t *testing.T) {
	upstream := loadFixture(t, upstreamFixture)

	overrides := loadFixture(t, `
groups:
  - id: x.obi.server
    type: attribute_group
    attributes:
      - id: server.address
        type: string
        stability: development
`)

	assert.Equal(t, map[string][2]string{"server.address": {"development", "stable"}},
		stabilityDrift(overrides, upstream))
}
