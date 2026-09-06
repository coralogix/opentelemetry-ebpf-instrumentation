// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
)

func Markdown(m *Model, r *Result, g *Gate) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## OBI telemetry coverage\n\n")
	reports := "reports"
	if r.Reports == 1 {
		reports = "report"
	}
	fmt.Fprintf(&b, "Registry `%s`, unioned over %d live-check %s.\n\n", r.SchemaURL, r.Reports, reports)

	fmt.Fprintf(&b, "| Surface | Observed | Declared | Attributes covered |\n")
	fmt.Fprintf(&b, "| --- | --- | --- | --- |\n")
	writeSurface(&b, "Span types", r.Spans)
	writeSurface(&b, "Metrics", r.Metrics)

	observedEntities := 0
	for _, e := range r.Entities {
		if e.Observed {
			observedEntities++
		}
	}
	fmt.Fprintf(&b, "| Entities | %d/%d | %d | - |\n\n", observedEntities, len(r.Entities), len(r.Entities))

	if g.Failed() {
		fmt.Fprintf(&b, "### Gate: failing\n\n")
	} else {
		fmt.Fprintf(&b, "### Gate: passing\n\n")
	}

	writeList(&b, "Declared span types never observed", g.UnobservedSpans)
	writeList(&b, "Declared metrics never observed", g.UnobservedMetrics)
	writeList(&b, "Required attributes never observed", g.MissingRequired)
	writeList(&b, "Metrics emitted but not declared", r.UndeclaredMetrics)

	if len(r.UnclassifiedShapes) > 0 {
		fmt.Fprintf(&b, "**Span shapes matching no declared span type (%d)**\n\n", len(r.UnclassifiedShapes))
		for _, s := range r.UnclassifiedShapes {
			fmt.Fprintf(&b, "- kind `%s`: %s\n", s.Kind, strings.Join(s.Attributes, ", "))
		}
		b.WriteString("\n")
	}

	writeGaps(&b, "Conditionally required attributes never observed", m, r, LevelConditionallyRequired)
	writeGaps(&b, "Recommended attributes never observed", m, r, LevelRecommended)
	writeGaps(&b, "Opt-in attributes never observed", m, r, LevelOptIn)

	return b.String()
}

func writeSurface(b *strings.Builder, label string, sigs []SignalCoverage) {
	observed, declaredAttrs, coveredAttrs := 0, 0, 0
	for _, s := range sigs {
		if s.Observed {
			observed++
		}
		declaredAttrs += s.Declared
		coveredAttrs += len(s.Covered)
	}
	fmt.Fprintf(b, "| %s | %d/%d | %d | %d/%d (%s) |\n",
		label, observed, len(sigs), len(sigs), coveredAttrs, declaredAttrs, percent(coveredAttrs, declaredAttrs))
}

func writeList(b *strings.Builder, label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "**%s (%d)**\n\n", label, len(items))
	for _, i := range items {
		fmt.Fprintf(b, "- `%s`\n", i)
	}
	b.WriteString("\n")
}

func writeGaps(b *strings.Builder, label string, m *Model, r *Result, level string) {
	type gap struct {
		signal string
		attrs  []string
	}
	var gaps []gap
	total := 0
	for _, group := range [][]SignalCoverage{r.Spans, r.Metrics} {
		for _, s := range group {
			if !s.Observed || len(s.Missing[level]) == 0 {
				continue
			}
			gaps = append(gaps, gap{signal: s.Name, attrs: s.Missing[level]})
			total += len(s.Missing[level])
		}
	}
	if total == 0 {
		return
	}
	fmt.Fprintf(b, "<details><summary>%s (%d)</summary>\n\n", label, total)
	for _, gp := range gaps {
		fmt.Fprintf(b, "- `%s`\n", gp.signal)
		for _, a := range gp.attrs {
			if cond := conditionFor(m, gp.signal, a); cond != "" {
				fmt.Fprintf(b, "  - `%s` — %s\n", a, cond)
				continue
			}
			fmt.Fprintf(b, "  - `%s`\n", a)
		}
	}
	b.WriteString("\n</details>\n\n")
}

func percent(covered, declared int) string {
	if declared == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(covered)/float64(declared))
}

func conditionFor(m *Model, signal, attr string) string {
	if s, ok := m.Spans[signal]; ok {
		return s.Attributes[attr].Condition
	}
	if mt, ok := m.Metrics[signal]; ok {
		return mt.Attributes[attr].Condition
	}
	return ""
}
