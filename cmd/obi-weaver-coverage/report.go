// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Report is the part of a `compact` live-check report coverage reads.
type Report struct {
	MatchedSignals        map[string]int                 `json:"matched_signals"`
	SignalAttributes      map[string][]string            `json:"signal_attributes"`
	SignalAttributeValues map[string]map[string][]string `json:"signal_attribute_values"`
}

type Observed struct {
	Signals          map[string]struct{}
	SignalAttributes map[string]map[string]struct{}
	// SignalAttributeValues holds, per signal and attribute key, the values seen.
	SignalAttributeValues map[string]map[string]map[string]struct{}
}

// Observe unions the reports. A matched signal counts only with a positive
// count.
func Observe(reports []Report) Observed {
	o := Observed{
		Signals:               map[string]struct{}{},
		SignalAttributes:      map[string]map[string]struct{}{},
		SignalAttributeValues: map[string]map[string]map[string]struct{}{},
	}
	for _, r := range reports {
		for signal, keys := range r.SignalAttributeValues {
			if o.SignalAttributeValues[signal] == nil {
				o.SignalAttributeValues[signal] = map[string]map[string]struct{}{}
			}
			for key, values := range keys {
				seen := o.SignalAttributeValues[signal][key]
				if seen == nil {
					seen = map[string]struct{}{}
					o.SignalAttributeValues[signal][key] = seen
				}
				for _, v := range values {
					seen[v] = struct{}{}
				}
			}
		}
		for name, count := range r.MatchedSignals {
			if count > 0 {
				o.Signals[name] = struct{}{}
			}
		}
		for signal, keys := range r.SignalAttributes {
			seen := o.SignalAttributes[signal]
			if seen == nil {
				seen = map[string]struct{}{}
				o.SignalAttributes[signal] = seen
			}
			for _, k := range keys {
				seen[k] = struct{}{}
			}
		}
	}
	return o
}

type SurfaceResult struct {
	Covered []string `json:"covered"`
	Gaps    []string `json:"gaps"`
}

type SignalAttributesResult struct {
	Signal  string              `json:"signal"`
	Kind    string              `json:"kind"`
	Covered []DeclaredAttribute `json:"covered"`
	Gaps    []DeclaredAttribute `json:"gaps"`
}

// EnumValuesResult is the coverage of the members of one enum attribute on one
// signal.
type EnumValuesResult struct {
	Signal    string   `json:"signal"`
	Kind      string   `json:"kind"`
	Attribute string   `json:"attribute"`
	Covered   []string `json:"covered"`
	Gaps      []string `json:"gaps"`
}

// EnumAttributeResult is the coverage of the members of one enum attribute
// across every signal that emitted it: a gap here was seen on no signal.
type EnumAttributeResult struct {
	Attribute string   `json:"attribute"`
	Covered   []string `json:"covered"`
	Gaps      []string `json:"gaps"`
}

type Result struct {
	Reports          int                      `json:"reports"`
	Metrics          SurfaceResult            `json:"metrics"`
	Spans            SurfaceResult            `json:"spans"`
	SignalAttributes []SignalAttributesResult `json:"signal_attributes"`
	EnumValues       []EnumValuesResult       `json:"enum_values"`
	EnumAttributes   []EnumAttributeResult    `json:"enum_attributes"`
}

// Aggregate measures the reports against the declared signals. Attribute
// coverage is measured only on signals some suite observed, and enum member
// coverage only on attributes some suite emitted: an unobserved signal or
// attribute is already a gap, and counting what it contains would only repeat
// it.
func Aggregate(signals []Signal, reports []Report) Result {
	o := Observe(reports)
	res := Result{
		Reports:          len(reports),
		Metrics:          SurfaceResult{Covered: []string{}, Gaps: []string{}},
		Spans:            SurfaceResult{Covered: []string{}, Gaps: []string{}},
		SignalAttributes: []SignalAttributesResult{},
		EnumValues:       []EnumValuesResult{},
	}

	for _, s := range signals {
		surface := &res.Metrics
		if s.Kind == kindSpan {
			surface = &res.Spans
		}
		if _, ok := o.Signals[s.Name]; !ok {
			surface.Gaps = append(surface.Gaps, s.Name)
			continue
		}
		surface.Covered = append(surface.Covered, s.Name)
		if len(s.Attributes) == 0 {
			continue
		}

		sr := SignalAttributesResult{Signal: s.Name, Kind: s.Kind, Covered: []DeclaredAttribute{}, Gaps: []DeclaredAttribute{}}
		for _, a := range s.Attributes {
			if !a.observedIn(o.SignalAttributes[s.Name]) {
				sr.Gaps = append(sr.Gaps, a)
				continue
			}
			sr.Covered = append(sr.Covered, a)
			if len(a.Members) > 0 {
				res.EnumValues = append(res.EnumValues, enumValues(s, a, o.SignalAttributeValues[s.Name][a.Key]))
			}
		}
		res.SignalAttributes = append(res.SignalAttributes, sr)
	}
	res.EnumAttributes = enumAttributes(res.EnumValues)
	return res
}

// enumAttributes rolls the per-signal enum coverage up per attribute. The
// registry declares one member list per attribute, so a member a signal can
// never emit is a per-signal gap; a member no signal emitted is a real one.
func enumAttributes(values []EnumValuesResult) []EnumAttributeResult {
	members := map[string]map[string]struct{}{}
	seen := map[string]map[string]struct{}{}
	for _, v := range values {
		if members[v.Attribute] == nil {
			members[v.Attribute] = map[string]struct{}{}
			seen[v.Attribute] = map[string]struct{}{}
		}
		for _, m := range v.Covered {
			members[v.Attribute][m] = struct{}{}
			seen[v.Attribute][m] = struct{}{}
		}
		for _, m := range v.Gaps {
			members[v.Attribute][m] = struct{}{}
		}
	}

	out := []EnumAttributeResult{}
	for _, attr := range sortedKeys(members) {
		res := EnumAttributeResult{Attribute: attr, Covered: []string{}, Gaps: []string{}}
		for _, m := range sortedKeys(members[attr]) {
			if _, ok := seen[attr][m]; ok {
				res.Covered = append(res.Covered, m)
			} else {
				res.Gaps = append(res.Gaps, m)
			}
		}
		out = append(out, res)
	}
	return out
}

func sortedKeys[V any](set map[string]V) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func enumValues(s Signal, a DeclaredAttribute, seen map[string]struct{}) EnumValuesResult {
	res := EnumValuesResult{Signal: s.Name, Kind: s.Kind, Attribute: a.Key, Covered: []string{}, Gaps: []string{}}
	for _, m := range a.Members {
		if _, ok := seen[m]; ok {
			res.Covered = append(res.Covered, m)
		} else {
			res.Gaps = append(res.Gaps, m)
		}
	}
	return res
}

// isMandatory reports whether attributes of a requirement level must be on
// every matching sample, which the report lists ahead of the optional ones.
func isMandatory(level string) bool {
	return level == levelRequired || level == levelConditionallyRequired
}

// FailingGaps counts the gaps --fail-on-gap fails on: signals no suite
// observed. Attribute and enum member gaps are reported but never fail: some
// conditions, such as error paths, are not reached by every suite, and an enum
// imported from upstream lists members OBI may never emit.
func (r Result) FailingGaps() int {
	return len(r.Metrics.Gaps) + len(r.Spans.Gaps)
}

func pct(covered, total int) string {
	if total == 0 {
		return "100.0"
	}
	return fmt.Sprintf("%.1f", float64(covered)/float64(total)*100)
}

func (r Result) attributeCountsByLevel() (covered, total map[string]int) {
	covered, total = map[string]int{}, map[string]int{}
	for _, s := range r.SignalAttributes {
		for _, a := range s.Covered {
			covered[a.RequirementLevel]++
			total[a.RequirementLevel]++
		}
		for _, a := range s.Gaps {
			total[a.RequirementLevel]++
		}
	}
	return covered, total
}

func writeGapList(b *strings.Builder, label string, gaps []string) {
	if len(gaps) == 0 {
		fmt.Fprintf(b, "**%s:** all covered\n\n", label)
		return
	}
	fmt.Fprintf(b, "**%s: %d never observed**\n\n", label, len(gaps))
	for _, name := range gaps {
		fmt.Fprintf(b, "- `%s`\n", name)
	}
	b.WriteString("\n")
}

// writeAttributeGaps lists, per signal, the gaps the keep predicate selects.
func (r Result) writeAttributeGaps(b *strings.Builder, keep func(level string) bool) int {
	listed := 0
	for _, s := range r.SignalAttributes {
		var names []string
		for _, g := range s.Gaps {
			if keep(g.RequirementLevel) {
				names = append(names, fmt.Sprintf("`%s` (%s)", g.Key, g.RequirementLevel))
			}
		}
		if len(names) == 0 {
			continue
		}
		fmt.Fprintf(b, "- %s `%s`: %s\n", s.Kind, s.Signal, strings.Join(names, ", "))
		listed++
	}
	return listed
}

func (r Result) Markdown() string {
	var b strings.Builder
	b.WriteString("## Weaver telemetry coverage\n\n")
	fmt.Fprintf(&b, "_Union of %d per-suite weaver report(s). An item is covered when at least one suite emitted it. "+
		"Signal attributes are measured on the signals some suite emitted. Only an uncovered signal fails `--fail-on-gap`._\n\n", r.Reports)

	b.WriteString("| surface | covered | total | coverage |\n| --- | ---: | ---: | ---: |\n")
	row := func(label string, covered, total int) {
		fmt.Fprintf(&b, "| %s | %d | %d | %s%% |\n", label, covered, total, pct(covered, total))
	}
	row("metrics", len(r.Metrics.Covered), len(r.Metrics.Covered)+len(r.Metrics.Gaps))
	row("spans", len(r.Spans.Covered), len(r.Spans.Covered)+len(r.Spans.Gaps))
	covered, total := r.attributeCountsByLevel()
	for _, level := range requirementLevels {
		row("signal attributes, "+level, covered[level], total[level])
	}
	enumCovered, enumTotal := 0, 0
	for _, e := range r.EnumAttributes {
		enumCovered += len(e.Covered)
		enumTotal += len(e.Covered) + len(e.Gaps)
	}
	row("enum members, any signal", enumCovered, enumTotal)
	enumCovered, enumTotal = 0, 0
	for _, e := range r.EnumValues {
		enumCovered += len(e.Covered)
		enumTotal += len(e.Covered) + len(e.Gaps)
	}
	row("enum members, per signal", enumCovered, enumTotal)
	b.WriteString("\n")

	writeGapList(&b, "Uncovered metrics", r.Metrics.Gaps)
	writeGapList(&b, "Uncovered spans", r.Spans.Gaps)

	var attrs strings.Builder
	if n := r.writeAttributeGaps(&attrs, isMandatory); n == 0 {
		b.WriteString("**Required and conditionally required signal attributes:** all covered\n\n")
	} else {
		fmt.Fprintf(&b, "**Required and conditionally required signal attributes: %d signal(s) with gaps**\n\n%s\n", n, attrs.String())
	}

	var informational strings.Builder
	if n := r.writeAttributeGaps(&informational, func(level string) bool { return !isMandatory(level) }); n > 0 {
		fmt.Fprintf(&b, "<details><summary>Recommended and opt-in signal attributes never observed (%d signal(s))</summary>\n\n%s\n</details>\n\n",
			n, informational.String())
	}

	r.writeEnumGaps(&b)
	return b.String()
}

// writeEnumGaps lists the enum members no signal emitted, then, collapsed, the
// members never seen per signal.
func (r Result) writeEnumGaps(b *strings.Builder) {
	var gaps strings.Builder
	listed := 0
	for _, e := range r.EnumAttributes {
		if len(e.Gaps) == 0 {
			continue
		}
		fmt.Fprintf(&gaps, "- `%s`: `%s`\n", e.Attribute, strings.Join(e.Gaps, "`, `"))
		listed++
	}
	if listed == 0 {
		b.WriteString("**Enum members on any signal:** all covered\n\n")
	} else {
		fmt.Fprintf(b, "**Enum members never observed on any signal: %d attribute(s)**\n\n%s\n", listed, gaps.String())
	}

	var perSignal strings.Builder
	listed = 0
	for _, e := range r.EnumValues {
		if len(e.Gaps) == 0 {
			continue
		}
		fmt.Fprintf(&perSignal, "- %s `%s` `%s`: `%s`\n", e.Kind, e.Signal, e.Attribute, strings.Join(e.Gaps, "`, `"))
		listed++
	}
	if listed > 0 {
		fmt.Fprintf(b, "<details><summary>Enum members never observed, per signal (%d signal attribute(s))</summary>\n\n%s\n</details>\n\n",
			listed, perSignal.String())
	}
}

// LoadReports reads every weaver-report-*.json under dir. A report that does
// not parse is skipped with a warning, so one broken suite does not discard the
// others; a missing dir yields no reports.
func LoadReports(dir string) ([]Report, error) {
	var reports []Report
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "weaver-report-") || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var r Report
		if err := json.Unmarshal(raw, &r); err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", path, err)
			return nil
		}
		reports = append(reports, r)
		return nil
	})
	return reports, err
}
