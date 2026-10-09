// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	upstreamNone = "none"
	obiNamespace = "obi"

	levelRequired              = "required"
	levelConditionallyRequired = "conditionally_required"
	levelRecommended           = "recommended"
	levelOptIn                 = "opt_in"

	sideClient = "client"
	sideServer = "server"
)

type parityProblem string

const (
	problemMissingRequired    parityProblem = "upstream requires it, OBI does not declare it"
	problemMissingConditional parityProblem = "upstream conditionally requires it, OBI does not declare it"
	problemOppositeSide       parityProblem = "upstream defines it only for the other side of the exchange"
	problemInventedUpstreamNS parityProblem = "OBI defines it in a namespace that belongs to upstream"
	problemMoreOnThanUpstream parityProblem = "upstream makes it opt_in, OBI turns it on by default"
)

type parityFinding struct {
	signal    string
	upstream  string
	attribute string
	problem   parityProblem
}

func (f parityFinding) String() string {
	return fmt.Sprintf("%s (upstream %s): %s: %s", f.signal, f.upstream, f.attribute, f.problem)
}

func requirementLevel(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	if len(raw) == 0 || string(raw) == "null" {
		return levelRecommended
	}
	var word string
	if json.Unmarshal(raw, &word) == nil {
		return word
	}
	var conditional map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &conditional))
	require.Len(t, conditional, 1, "requirement level %s", raw)
	for level := range conditional {
		return level
	}
	return ""
}

func namespaceOf(key string) string {
	ns, _, _ := strings.Cut(key, ".")
	return ns
}

func spanSide(kind string) string {
	switch kind {
	case "client", "producer":
		return sideClient
	case "server", "consumer":
		return sideServer
	}
	return ""
}

func metricSide(name string) string {
	switch {
	case strings.Contains(name, ".client."):
		return sideClient
	case strings.Contains(name, ".server."):
		return sideServer
	}
	return ""
}

func oppositeSide(side string) string {
	switch side {
	case sideClient:
		return sideServer
	case sideServer:
		return sideClient
	}
	return ""
}

func upstreamRegistryPath(t *testing.T) string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(upstreamDeps, "upstream-v*"))
	require.NoError(t, err)
	require.Lenf(t, dirs, 1, "expected one upstream registry under %s", upstreamDeps)
	return "/obi-registry/.deps/" + filepath.Base(dirs[0]) + "/model"
}

type upstreamRegistry struct {
	spans      map[string]resolvedSignal
	metrics    map[string]resolvedSignal
	renamed    map[string]string
	attributes map[string]bool
	namespaces map[string]bool
	sides      map[string]map[string]bool
}

func resolveUpstreamRegistry(t *testing.T) upstreamRegistry {
	t.Helper()
	res := resolveRegistryAt(t, upstreamRegistryPath(t))

	reg := upstreamRegistry{
		spans:      map[string]resolvedSignal{},
		metrics:    map[string]resolvedSignal{},
		renamed:    map[string]string{},
		attributes: map[string]bool{},
		namespaces: map[string]bool{},
		sides:      map[string]map[string]bool{},
	}
	for _, a := range res.Registry.Attributes {
		reg.attributes[a.Key] = true
		reg.namespaces[namespaceOf(a.Key)] = true
		if a.Deprecated != nil && a.Deprecated.RenamedTo != "" {
			reg.renamed[a.Key] = a.Deprecated.RenamedTo
		}
	}
	for _, s := range res.Registry.Spans {
		reg.spans[s.Type] = s
		reg.recordSides(spanSide(s.Kind), s)
	}
	for _, s := range res.Refinements.Spans {
		if _, ok := reg.spans[s.ID]; !ok {
			reg.spans[s.ID] = s
		}
		reg.recordSides(spanSide(s.Kind), s)
	}
	for _, m := range res.Registry.Metrics {
		name := m.metricName(t)
		reg.metrics[name] = m
		reg.recordSides(metricSide(name), m)
	}
	return reg
}

func (reg upstreamRegistry) key(attribute string) string {
	if renamed, ok := reg.renamed[attribute]; ok {
		return renamed
	}
	return attribute
}

func (reg upstreamRegistry) recordSides(side string, s resolvedSignal) {
	if side == "" {
		return
	}
	for _, a := range s.Attributes {
		key := reg.key(a.Key)
		if reg.sides[key] == nil {
			reg.sides[key] = map[string]bool{}
		}
		reg.sides[key][side] = true
	}
}

func (reg upstreamRegistry) onlyOnSide(attribute, side string) bool {
	sides := reg.sides[attribute]
	return len(sides) == 1 && sides[side]
}

func (reg upstreamRegistry) levels(t *testing.T, s resolvedSignal) map[string]string {
	t.Helper()
	levels := map[string]string{}
	for _, a := range s.Attributes {
		levels[reg.key(a.Key)] = requirementLevel(t, a.RequirementLevel)
	}
	return levels
}

type paritySubject struct {
	signal   string
	upstream string
	side     string
	obi      resolvedSignal
	match    resolvedSignal
}

func (s resolvedSignal) upstreamSpanType() string {
	if s.Annotations.OBI.Upstream != "" {
		return s.Annotations.OBI.Upstream
	}
	return strings.TrimPrefix(s.Type, obiNamespace+".")
}

func paritySubjects(t *testing.T, obi resolveOutput, up upstreamRegistry) []paritySubject {
	t.Helper()
	var subjects []paritySubject
	for _, s := range obi.Registry.Spans {
		target := s.upstreamSpanType()
		if u, ok := up.spans[target]; ok && target != upstreamNone {
			subjects = append(subjects, paritySubject{s.Type, target, spanSide(s.Kind), s, u})
		}
	}
	for _, m := range obi.Registry.Metrics {
		name := m.metricName(t)
		if u, ok := up.metrics[name]; ok {
			subjects = append(subjects, paritySubject{name, name, metricSide(name), m, u})
		}
	}
	return subjects
}

func compareWithUpstream(t *testing.T, s paritySubject, up upstreamRegistry, invented map[string]bool) []parityFinding {
	t.Helper()
	var findings []parityFinding
	add := func(attribute string, problem parityProblem) {
		findings = append(findings, parityFinding{s.signal, s.upstream, attribute, problem})
	}

	upstream := up.levels(t, s.match)
	declared := map[string]string{}
	for _, a := range s.obi.Attributes {
		declared[a.Key] = requirementLevel(t, a.RequirementLevel)
	}

	for attribute, level := range upstream {
		if _, ok := declared[attribute]; ok {
			continue
		}
		switch level {
		case levelRequired:
			add(attribute, problemMissingRequired)
		case levelConditionallyRequired:
			add(attribute, problemMissingConditional)
		}
	}
	for attribute, level := range declared {
		upstreamLevel, listed := upstream[attribute]
		switch {
		case listed && upstreamLevel == levelOptIn && level != levelOptIn:
			add(attribute, problemMoreOnThanUpstream)
		case !listed && invented[attribute]:
			add(attribute, problemInventedUpstreamNS)
		case !listed && up.onlyOnSide(attribute, oppositeSide(s.side)):
			add(attribute, problemOppositeSide)
		}
	}
	return findings
}

func inventedInUpstreamNamespaces(obi resolveOutput, up upstreamRegistry) map[string]bool {
	invented := map[string]bool{}
	for _, a := range obi.Registry.Attributes {
		ns := namespaceOf(a.Key)
		if a.Provenance.local() && !up.attributes[a.Key] && ns != obiNamespace && up.namespaces[ns] {
			invented[a.Key] = true
		}
	}
	return invented
}

func definitionDeviations(obi resolveOutput) map[string]bool {
	deviations := map[string]bool{}
	for _, a := range obi.Registry.Attributes {
		if a.Annotations.OBI.UpstreamDeviation != "" {
			deviations[a.Key] = true
		}
	}
	return deviations
}

func justified(s paritySubject, f parityFinding, definitions map[string]bool) bool {
	switch f.problem {
	case problemMissingRequired, problemMissingConditional:
		_, ok := s.obi.Annotations.OBI.UpstreamOmits[f.attribute]
		return ok
	case problemInventedUpstreamNS:
		return definitions[f.attribute]
	}
	for _, a := range s.obi.Attributes {
		if a.Key == f.attribute {
			return a.Annotations.OBI.UpstreamDeviation != ""
		}
	}
	return false
}

func TestEverySpanNamesItsUpstreamSpan(t *testing.T) {
	obi := resolveRegistry(t)
	up := resolveUpstreamRegistry(t)

	for _, s := range obi.Registry.Spans {
		target := s.upstreamSpanType()
		if target == upstreamNone {
			assert.NotEmptyf(t, s.Annotations.OBI.UpstreamReason,
				"%s declares no upstream span, so annotations.obi.upstream_reason must say why", s.Type)
			continue
		}
		_, ok := up.spans[target]
		assert.Truef(t, ok,
			"%s maps to upstream span %q, which upstream does not define: name the span obi.<upstream type> "+
				"or set annotations.obi.upstream to the upstream type or to %q with an upstream_reason",
			s.Type, target, upstreamNone)
	}
}

func TestEveryMetricNamesItsUpstreamMetric(t *testing.T) {
	obi := resolveRegistry(t)
	up := resolveUpstreamRegistry(t)

	for _, m := range obi.Registry.Metrics {
		name := m.metricName(t)
		_, upstream := up.metrics[name]
		none := m.Annotations.OBI.Upstream == upstreamNone
		switch {
		case upstream:
			assert.Falsef(t, none, "%s exists upstream, so it cannot declare annotations.obi.upstream: %s", name, upstreamNone)
		case namespaceOf(name) == obiNamespace:
		default:
			assert.Truef(t, none && m.Annotations.OBI.UpstreamReason != "",
				"%s is not an upstream metric and not in the %s namespace: fix the name, or set "+
					"annotations.obi.upstream: %s with an upstream_reason", name, obiNamespace, upstreamNone)
		}
	}
}

func TestSignalsFollowUpstream(t *testing.T) {
	obi := resolveRegistry(t)
	up := resolveUpstreamRegistry(t)
	invented := inventedInUpstreamNamespaces(obi, up)
	definitions := definitionDeviations(obi)

	var violations, stale []string
	for key := range definitions {
		if !invented[key] {
			stale = append(stale, "attribute "+key+": upstream_deviation on its definition")
		}
	}
	for _, s := range paritySubjects(t, obi, up) {
		reported := map[string]bool{}
		for _, f := range compareWithUpstream(t, s, up, invented) {
			reported[f.attribute] = true
			if !justified(s, f, definitions) {
				violations = append(violations, f.String())
			}
		}
		for attribute := range s.obi.Annotations.OBI.UpstreamOmits {
			if !reported[attribute] {
				stale = append(stale, s.signal+": upstream_omits "+attribute)
			}
		}
		for _, a := range s.obi.Attributes {
			if a.Annotations.OBI.UpstreamDeviation != "" && !reported[a.Key] {
				stale = append(stale, s.signal+": upstream_deviation on "+a.Key)
			}
		}
	}
	slices.Sort(violations)
	slices.Sort(stale)

	assert.Emptyf(t, violations,
		"signals diverge from upstream semantic conventions; fix them, or record a justified deviation "+
			"with annotations.obi.upstream_deviation on the attribute or annotations.obi.upstream_omits "+
			"on the signal:\n%s", strings.Join(violations, "\n"))
	assert.Emptyf(t, stale, "these annotations justify a difference that no longer exists; remove them:\n%s",
		strings.Join(stale, "\n"))
}
