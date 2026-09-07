// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// spanUpstreamNone is the value `annotations.obi.upstream_span` carries when
// upstream models nothing equivalent. It is a stated decision rather than an
// absent key, so a typo in a counterpart id cannot read as "OBI-only".
const spanUpstreamNone = "none"

const obiSpanPrefix = "span.obi."

type spanAbsorbed struct {
	id     string
	reason string
}

type spanGroup struct {
	extends string
	attrs   []string
	isSpan  bool

	upstream       string
	absentReason   string
	omits          []string
	absorbs        []spanAbsorbed
	hasAnnotations bool
}

type spanGroupsFile struct {
	Groups []struct {
		ID          string `yaml:"id"`
		Type        string `yaml:"type"`
		Extends     string `yaml:"extends"`
		Annotations struct {
			OBI struct {
				UpstreamSpan         string   `yaml:"upstream_span"`
				UpstreamAbsentReason string   `yaml:"upstream_absent_reason"`
				UpstreamOmits        []string `yaml:"upstream_omits"`
				UpstreamAbsorbs      []struct {
					ID     string `yaml:"id"`
					Reason string `yaml:"reason"`
				} `yaml:"upstream_absorbs"`
			} `yaml:"obi"`
		} `yaml:"annotations"`
		Attributes []struct {
			ID         string    `yaml:"id"`
			Ref        string    `yaml:"ref"`
			Deprecated yaml.Node `yaml:"deprecated"`
		} `yaml:"attributes"`
	} `yaml:"groups"`
}

// deprecatedUpstreamAttributes collects the upstream attributes marked
// deprecated. A span group that still lists one is describing a rename OBI has
// already followed, so counting it as an omission reports OBI as behind
// upstream when it is ahead.
func deprecatedUpstreamAttributes(t *testing.T) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	err := filepath.WalkDir(upstreamDeps, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isSchemaFile(path) {
			return err
		}
		body, rerr := os.ReadFile(path)
		require.NoError(t, rerr)

		var f spanGroupsFile
		if yaml.Unmarshal(body, &f) != nil {
			return nil
		}
		for _, g := range f.Groups {
			for _, a := range g.Attributes {
				if a.ID != "" && !a.Deprecated.IsZero() {
					out[a.ID] = true
				}
			}
		}
		return nil
	})
	require.NoError(t, err)
	return out
}

func loadSpanGroups(t *testing.T) map[string]spanGroup {
	t.Helper()
	if _, err := os.Stat(upstreamDeps); os.IsNotExist(err) {
		t.Skipf("%s is not populated; run `make fetch-upstream-semconv`", upstreamDeps)
	}

	out := map[string]spanGroup{}
	for _, root := range []string{obiGroupsDir, upstreamDeps} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !isSchemaFile(path) {
				return err
			}
			body, rerr := os.ReadFile(path)
			require.NoError(t, rerr)

			var f spanGroupsFile
			if yaml.Unmarshal(body, &f) != nil {
				return nil
			}
			for _, g := range f.Groups {
				if g.ID == "" {
					continue
				}
				var attrs []string
				for _, a := range g.Attributes {
					switch {
					case a.Ref != "":
						attrs = append(attrs, a.Ref)
					case a.ID != "":
						attrs = append(attrs, a.ID)
					}
				}

				obi := g.Annotations.OBI
				absorbs := make([]spanAbsorbed, 0, len(obi.UpstreamAbsorbs))
				for _, a := range obi.UpstreamAbsorbs {
					absorbs = append(absorbs, spanAbsorbed{id: a.ID, reason: a.Reason})
				}

				out[g.ID] = spanGroup{
					extends:        g.Extends,
					attrs:          attrs,
					isSpan:         g.Type == "span",
					upstream:       obi.UpstreamSpan,
					absentReason:   obi.UpstreamAbsentReason,
					omits:          obi.UpstreamOmits,
					absorbs:        absorbs,
					hasAnnotations: obi.UpstreamSpan != "",
				}
			}
			return nil
		})
		require.NoError(t, err)
	}
	return out
}

// resolveSpanAttributes walks the `extends` chain, which upstream uses heavily
// to share a common attribute set between the client and server span of a
// protocol.
func resolveSpanAttributes(groups map[string]spanGroup, id string) map[string]bool {
	seen := map[string]bool{}

	var walk func(string) map[string]bool
	walk = func(gid string) map[string]bool {
		out := map[string]bool{}
		g, ok := groups[gid]
		if !ok || seen[gid] {
			return out
		}
		seen[gid] = true
		if g.extends != "" {
			for a := range walk(g.extends) {
				out[a] = true
			}
		}
		for _, a := range g.attrs {
			out[a] = true
		}
		return out
	}
	return walk(id)
}

func obiSpanTypes(groups map[string]spanGroup) []string {
	var out []string
	for id, g := range groups {
		if g.isSpan && len(id) > len(obiSpanPrefix) && id[:len(obiSpanPrefix)] == obiSpanPrefix {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// comparedOBISpans lists the OBI span types that have an upstream counterpart
// to be measured against, in a stable order.
func comparedOBISpans(groups map[string]spanGroup) []string {
	var out []string
	for _, id := range obiSpanTypes(groups) {
		if u := groups[id].upstream; u != "" && u != spanUpstreamNone {
			out = append(out, id)
		}
	}
	return out
}

func omittedAttributes(groups map[string]spanGroup, obiID, upstreamID string, deprecated map[string]bool) []string {
	up := resolveSpanAttributes(groups, upstreamID)
	obi := resolveSpanAttributes(groups, obiID)

	var out []string
	for a := range up {
		if obi[a] || deprecated[a] {
			continue
		}
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func extraAttributes(groups map[string]spanGroup, obiID, upstreamID string) []string {
	up := resolveSpanAttributes(groups, upstreamID)
	obi := resolveSpanAttributes(groups, obiID)

	var out []string
	for a := range obi {
		if !up[a] {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

func acceptedOmissions(g spanGroup) map[string]bool {
	out := map[string]bool{}
	for _, a := range g.omits {
		out[a] = true
	}
	return out
}

// TestEveryOBISpanTypeHasACounterpartDecision asserts every declared OBI span
// type states, at its point of definition, which upstream span type it answers
// to. A new span type therefore cannot be added without recording whether
// upstream already models it.
func TestEveryOBISpanTypeHasACounterpartDecision(t *testing.T) {
	groups := loadSpanGroups(t)
	types := obiSpanTypes(groups)
	require.NotEmpty(t, types)

	for _, id := range types {
		assert.Truef(t, groups[id].hasAnnotations,
			"span type %q declares no annotations.obi.upstream_span; name the upstream "+
				"span type it corresponds to, or %q with an upstream_absent_reason if "+
				"upstream models nothing equivalent",
			id, spanUpstreamNone)
	}
}

// TestOBIOnlySpansStateWhyUpstreamHasNone keeps `upstream_span: none` from
// becoming a silent default: claiming upstream models nothing has to come with
// the reason it does not.
func TestOBIOnlySpansStateWhyUpstreamHasNone(t *testing.T) {
	groups := loadSpanGroups(t)

	for _, id := range obiSpanTypes(groups) {
		g := groups[id]
		if g.upstream != spanUpstreamNone {
			continue
		}
		assert.NotEmptyf(t, g.absentReason,
			"span type %q claims %q but gives no upstream_absent_reason",
			id, spanUpstreamNone)
		assert.Emptyf(t, g.omits,
			"span type %q claims %q, so it has no upstream counterpart to omit "+
				"attributes relative to; drop its upstream_omits",
			id, spanUpstreamNone)
	}
}

// TestSpanCounterpartsExist asserts every counterpart an OBI span names is a
// real upstream group, so a rename upstream surfaces here rather than silently
// comparing against an empty attribute set.
func TestSpanCounterpartsExist(t *testing.T) {
	groups := loadSpanGroups(t)

	for _, id := range comparedOBISpans(groups) {
		up := groups[id].upstream
		_, ok := groups[up]
		assert.Truef(t, ok,
			"span type %q names upstream counterpart %q, which does not exist; it was "+
				"probably renamed in the pinned semconv dependency",
			id, up)
	}
}

// TestAbsorbedUpstreamSpansExist keeps an absorbed-type record from naming a
// span type upstream renamed or removed, which would leave a stale decision on
// record.
func TestAbsorbedUpstreamSpansExist(t *testing.T) {
	groups := loadSpanGroups(t)

	for _, id := range obiSpanTypes(groups) {
		for _, a := range groups[id].absorbs {
			_, ok := groups[a.id]
			assert.Truef(t, ok,
				"span type %q records absorbing upstream type %q, which no longer "+
					"exists; update or drop the entry",
				id, a.id)
			assert.NotEmptyf(t, a.reason,
				"span type %q records absorbing %q with no reason",
				id, a.id)
		}
	}
}

// TestOBISpansOmitOnlyAcceptedAttributes is the drift guard: an attribute the
// upstream counterpart declares and OBI's span does not must be recorded in
// that span's upstream_omits. An upstream addition, or an attribute dropped
// from an OBI span, fails here.
func TestOBISpansOmitOnlyAcceptedAttributes(t *testing.T) {
	groups := loadSpanGroups(t)
	deprecated := deprecatedUpstreamAttributes(t)

	for _, id := range comparedOBISpans(groups) {
		up := groups[id].upstream
		ok := acceptedOmissions(groups[id])
		for _, a := range omittedAttributes(groups, id, up, deprecated) {
			if ok[a] {
				continue
			}
			assert.Failf(t, "span omits an upstream attribute",
				"span %q does not carry %q, which its upstream counterpart %q "+
					"declares; add it to the span, or record it in the span's "+
					"annotations.obi.upstream_omits with the reason OBI cannot emit it",
				id, a, up)
		}
	}
}

// TestAcceptedSpanOmissionsAreCurrent keeps the baseline honest: an entry for an
// attribute upstream no longer declares, or one OBI has since implemented, is
// stale and must be deleted so the record stays a true statement of divergence.
func TestAcceptedSpanOmissionsAreCurrent(t *testing.T) {
	groups := loadSpanGroups(t)
	deprecated := deprecatedUpstreamAttributes(t)

	for _, id := range comparedOBISpans(groups) {
		up := groups[id].upstream

		missing := map[string]bool{}
		for _, a := range omittedAttributes(groups, id, up, deprecated) {
			missing[a] = true
		}
		for _, a := range groups[id].omits {
			assert.Truef(t, missing[a],
				"span %q lists %q in annotations.obi.upstream_omits, but it is no "+
					"longer omitted; delete the entry",
				a, id)
		}
	}
}

// TestSpanDriftReport prints how far each OBI span type diverges from its
// upstream counterpart. It never fails; run it with
// `go test -v -run TestSpanDriftReport`.
func TestSpanDriftReport(t *testing.T) {
	groups := loadSpanGroups(t)
	deprecated := deprecatedUpstreamAttributes(t)

	t.Logf("%-34s %-30s %6s %6s %6s", "OBI span type", "upstream counterpart", "attrs", "omits", "adds")
	for _, id := range obiSpanTypes(groups) {
		up := groups[id].upstream
		if up == spanUpstreamNone {
			t.Logf("%-34s %-30s %6d %6s %6s", id, "(OBI-only)",
				len(resolveSpanAttributes(groups, id)), "-", "-")
			continue
		}
		t.Logf("%-34s %-30s %6d %6d %6d", id, up,
			len(resolveSpanAttributes(groups, id)),
			len(omittedAttributes(groups, id, up, deprecated)),
			len(extraAttributes(groups, id, up)))
	}

	t.Logf("")
	t.Logf("--- upstream span types OBI absorbs rather than declaring ---")
	for _, id := range obiSpanTypes(groups) {
		for _, a := range groups[id].absorbs {
			t.Logf("  %-30s -> %-24s %s", a.id, id, a.reason)
		}
	}

	t.Logf("")
	t.Logf("--- per span type: what OBI omits and what it adds ---")
	for _, id := range obiSpanTypes(groups) {
		g := groups[id]
		if g.upstream == spanUpstreamNone {
			t.Logf("%s  (OBI-only: %s)", id, g.absentReason)
			for _, a := range sortedSetKeys(resolveSpanAttributes(groups, id)) {
				t.Logf("    has   %s", a)
			}
			continue
		}

		t.Logf("%s  <-  %s", id, g.upstream)
		for _, a := range omittedAttributes(groups, id, g.upstream, deprecated) {
			t.Logf("    omits %s", a)
		}
		for _, a := range extraAttributes(groups, id, g.upstream) {
			t.Logf("    adds  %s", a)
		}
	}
}

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
