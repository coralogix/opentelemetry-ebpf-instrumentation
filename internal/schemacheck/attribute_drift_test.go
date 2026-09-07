// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	overrideGroupPrefix = "x.obi."
	localGroupPrefix    = "registry.obi."
)

// attrType captures the two shapes the `type` key takes in a semconv attribute
// declaration: a scalar type name, or an enum carrying members.
type attrType struct {
	scalar  string
	members []string
}

func (a *attrType) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		a.scalar = node.Value
		return nil
	}

	var enum struct {
		Members []struct {
			Value any `yaml:"value"`
		} `yaml:"members"`
	}
	if err := node.Decode(&enum); err != nil {
		return err
	}

	for _, m := range enum.Members {
		a.members = append(a.members, fmt.Sprint(m.Value))
	}
	return nil
}

func (a attrType) isEnum() bool {
	return len(a.members) > 0
}

type attrGroupsFile struct {
	Groups []struct {
		ID         string `yaml:"id"`
		Attributes []struct {
			ID        string   `yaml:"id"`
			Ref       string   `yaml:"ref"`
			Type      attrType `yaml:"type"`
			Stability string   `yaml:"stability"`
		} `yaml:"attributes"`
	} `yaml:"groups"`
}

type attrDef struct {
	typ       attrType
	stability string
	group     string
	source    string
}

func isOverrideGroup(group string) bool {
	return strings.HasPrefix(group, overrideGroupPrefix)
}

// isSchemaFile accepts both spellings of the YAML extension. Upstream semconv
// is almost entirely `.yaml`, but a few files use `.yml`, and matching only the
// former silently drops the groups they declare.
func isSchemaFile(path string) bool {
	switch filepath.Ext(path) {
	case ".yaml", ".yml":
		return true
	}
	return false
}

func attributesFromFile(path string, out map[string]attrDef) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var f attrGroupsFile
	if err := yaml.Unmarshal(body, &f); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	for _, g := range f.Groups {
		for _, a := range g.Attributes {
			if a.ID == "" || a.Ref != "" {
				continue
			}
			out[a.ID] = attrDef{
				typ:       a.Type,
				stability: a.Stability,
				group:     g.ID,
				source:    path,
			}
		}
	}
	return nil
}

func attributesFromTree(root string) (map[string]attrDef, error) {
	out := map[string]attrDef{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isSchemaFile(path) {
			return nil
		}
		return attributesFromFile(path, out)
	})
	return out, err
}

func partitionByGroup(all map[string]attrDef, want func(string) bool) map[string]attrDef {
	out := map[string]attrDef{}
	for id, a := range all {
		if want(a.group) {
			out[id] = a
		}
	}
	return out
}

// shadowedAttributes returns the ids OBI declares outside an override group
// that upstream semconv already defines.
func shadowedAttributes(local, upstream map[string]attrDef) []string {
	var out []string
	for id := range local {
		if _, ok := upstream[id]; ok {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// orphanOverrides returns the ids declared in an override group that have no
// upstream definition to override.
func orphanOverrides(overrides, upstream map[string]attrDef) []string {
	var out []string
	for id := range overrides {
		if _, ok := upstream[id]; !ok {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// droppedEnumMembers returns, per override id, the upstream enum members the
// override fails to carry. Overrides that deliberately re-type an enum to a
// scalar are not enum narrowings and are excluded.
func droppedEnumMembers(overrides, upstream map[string]attrDef) map[string][]string {
	out := map[string][]string{}
	for id, a := range overrides {
		up, ok := upstream[id]
		if !ok || !up.typ.isEnum() || !a.typ.isEnum() {
			continue
		}

		have := map[string]bool{}
		for _, m := range a.typ.members {
			have[m] = true
		}

		var missing []string
		for _, m := range up.typ.members {
			if !have[m] {
				missing = append(missing, m)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			out[id] = missing
		}
	}
	return out
}

// stabilityDrift returns, per override id, the OBI and upstream stability
// levels when they disagree.
func stabilityDrift(overrides, upstream map[string]attrDef) map[string][2]string {
	out := map[string][2]string{}
	for id, a := range overrides {
		up, ok := upstream[id]
		if !ok || up.stability == a.stability {
			continue
		}
		out[id] = [2]string{a.stability, up.stability}
	}
	return out
}

func upstreamAttributes(t *testing.T) map[string]attrDef {
	t.Helper()
	if _, err := os.Stat(upstreamDeps); os.IsNotExist(err) {
		t.Skipf("%s is not populated; run `make fetch-upstream-semconv`", upstreamDeps)
	}
	all, err := attributesFromTree(upstreamDeps)
	require.NoError(t, err)
	return all
}

func obiAttributes(t *testing.T) map[string]attrDef {
	t.Helper()
	all, err := attributesFromTree(obiGroupsDir)
	require.NoError(t, err)
	return all
}

// TestOBIAttributeOverridesExistUpstream asserts that every attribute declared
// in an `x.obi.*` group really does override an upstream attribute. The prefix
// is the registry's marker for a deliberate redefinition, so an id with no
// upstream counterpart is either a typo or an OBI-own attribute filed in the
// wrong group.
func TestOBIAttributeOverridesExistUpstream(t *testing.T) {
	overrides := partitionByGroup(obiAttributes(t), isOverrideGroup)
	upstream := upstreamAttributes(t)
	require.NotEmpty(t, overrides)
	require.NotEmpty(t, upstream)

	for _, id := range orphanOverrides(overrides, upstream) {
		assert.Failf(t, "override has no upstream definition",
			"attribute %q is declared in the override group %q (%s) but has no "+
				"upstream semconv definition; fix the id, or move it to a %s* "+
				"group if it is an OBI-own attribute",
			id, overrides[id].group, overrides[id].source, localGroupPrefix)
	}
}

// TestLocalAttributesMatchingUpstreamAreOverrides asserts the inverse: an
// attribute OBI declares outside an `x.obi.*` group must not already exist
// upstream. Such a declaration silently shadows the upstream definition
// depending on group-id sort order, so it must either become a `ref` or move
// into an override group where the drift checks apply.
func TestLocalAttributesMatchingUpstreamAreOverrides(t *testing.T) {
	local := partitionByGroup(obiAttributes(t), func(g string) bool { return !isOverrideGroup(g) })
	upstream := upstreamAttributes(t)
	require.NotEmpty(t, local)
	require.NotEmpty(t, upstream)

	for _, id := range shadowedAttributes(local, upstream) {
		assert.Failf(t, "attribute shadows upstream",
			"attribute %q is declared in %q (%s) but is already defined upstream "+
				"in %s; reference it with `ref: %s` instead, or move the "+
				"declaration to an %s<namespace> group to make the override "+
				"deliberate",
			id, local[id].group, local[id].source, upstream[id].source, id,
			overrideGroupPrefix)
	}
}

// TestOBIEnumOverridesKeepUpstreamMembers asserts that an enum override carries
// the full upstream member list, per the replacement-not-merge rule in
// schemas/obi/README.md. A member dropped when re-syncing a semconv bump makes
// weaver reject a value OBI legitimately emits, and only surfaces if some test
// happens to produce it.
func TestOBIEnumOverridesKeepUpstreamMembers(t *testing.T) {
	overrides := partitionByGroup(obiAttributes(t), isOverrideGroup)
	upstream := upstreamAttributes(t)
	require.NotEmpty(t, overrides)
	require.NotEmpty(t, upstream)

	for id, missing := range droppedEnumMembers(overrides, upstream) {
		assert.Failf(t, "enum override drops upstream members",
			"enum override %q in %q (%s) is missing upstream members %v; an "+
				"override replaces the upstream definition wholesale, so it must "+
				"carry every upstream member plus OBI's extensions (upstream: %s)",
			id, overrides[id].group, overrides[id].source, missing,
			upstream[id].source)
	}
}

// TestOBIAttributeOverridesMatchUpstreamStability asserts an override pins the
// same stability as the attribute it replaces, so a bump that promotes an
// attribute upstream does not leave OBI publishing it at the old level.
func TestOBIAttributeOverridesMatchUpstreamStability(t *testing.T) {
	overrides := partitionByGroup(obiAttributes(t), isOverrideGroup)
	upstream := upstreamAttributes(t)
	require.NotEmpty(t, overrides)
	require.NotEmpty(t, upstream)

	for id, levels := range stabilityDrift(overrides, upstream) {
		assert.Failf(t, "override stability differs from upstream",
			"attribute %q declares stability %q in %q (%s) but upstream declares "+
				"%q (%s)",
			id, levels[0], overrides[id].group, overrides[id].source, levels[1],
			upstream[id].source)
	}
}
