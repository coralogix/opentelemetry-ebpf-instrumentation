// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// addedEnumMembers returns the members an override adds on top of the upstream
// enum, the intended direction of an enum override.
func addedEnumMembers(override, upstream attrDef) []string {
	up := map[string]bool{}
	for _, m := range upstream.typ.members {
		up[m] = true
	}

	var added []string
	for _, m := range override.typ.members {
		if !up[m] {
			added = append(added, m)
		}
	}
	sort.Strings(added)
	return added
}

func describeOverride(override, upstream attrDef, upstreamFound bool) string {
	if !upstreamFound {
		return "NO UPSTREAM DEFINITION"
	}

	switch {
	case upstream.typ.isEnum() && !override.typ.isEnum():
		return fmt.Sprintf("enum -> %s (re-typed, membership no longer validated)", override.typ.scalar)

	case upstream.typ.isEnum() && override.typ.isEnum():
		added := addedEnumMembers(override, upstream)
		dropped := droppedEnumMembers(
			map[string]attrDef{"x": override},
			map[string]attrDef{"x": upstream},
		)["x"]

		parts := []string{fmt.Sprintf("enum %d upstream members", len(upstream.typ.members))}
		if len(added) > 0 {
			parts = append(parts, "adds "+strings.Join(added, " "))
		}
		if len(dropped) > 0 {
			parts = append(parts, "DROPS "+strings.Join(dropped, " "))
		}
		return strings.Join(parts, ", ")

	default:
		return fmt.Sprintf("%s (upstream %s)", override.typ.scalar, upstream.typ.scalar)
	}
}

// TestAttributeDriftReport prints the full state the drift guards assert on.
// The guards themselves are silent while the registry is clean, so this is how
// the override surface is inspected without breaking something first. It never
// fails; run it with `go test -v -run TestAttributeDriftReport`.
func TestAttributeDriftReport(t *testing.T) {
	upstream := upstreamAttributes(t)
	all := obiAttributes(t)
	overrides := partitionByGroup(all, isOverrideGroup)
	own := partitionByGroup(all, func(g string) bool { return !isOverrideGroup(g) })

	t.Logf("upstream attribute declarations   %d", len(upstream))
	t.Logf("OBI overrides (%s*)            %d", overrideGroupPrefix, len(overrides))
	t.Logf("OBI own declarations              %d", len(own))

	t.Logf("")
	t.Logf("--- deliberate overrides ---")
	ids := make([]string, 0, len(overrides))
	for id := range overrides {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		up, found := upstream[id]
		t.Logf("  %-24s %-18s %s", id, overrides[id].group, describeOverride(overrides[id], up, found))
	}

	t.Logf("")
	t.Logf("--- OBI-own attributes by group ---")
	byGroup := map[string]int{}
	for _, a := range own {
		byGroup[a.group]++
	}
	groups := make([]string, 0, len(byGroup))
	for g := range byGroup {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		t.Logf("  %-34s %d", g, byGroup[g])
	}

	t.Logf("")
	t.Logf("--- findings ---")
	report := func(label string, items []string) {
		if len(items) == 0 {
			t.Logf("  %-42s none", label)
			return
		}
		t.Logf("  %-42s %d", label, len(items))
		for _, i := range items {
			t.Logf("      %s", i)
		}
	}

	report("attributes shadowing upstream", shadowedAttributes(own, upstream))
	report("overrides with no upstream definition", orphanOverrides(overrides, upstream))

	var narrowed []string
	for id, missing := range droppedEnumMembers(overrides, upstream) {
		narrowed = append(narrowed, fmt.Sprintf("%s drops %s", id, strings.Join(missing, " ")))
	}
	sort.Strings(narrowed)
	report("enum overrides dropping members", narrowed)

	var stability []string
	for id, levels := range stabilityDrift(overrides, upstream) {
		stability = append(stability, fmt.Sprintf("%s obi=%s upstream=%s", id, levels[0], levels[1]))
	}
	sort.Strings(stability)
	report("overrides with stability drift", stability)
}
