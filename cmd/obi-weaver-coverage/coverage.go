// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "sort"

type SignalCoverage struct {
	Name     string              `json:"name"`
	Observed bool                `json:"observed"`
	Declared int                 `json:"declared"`
	Covered  []string            `json:"covered"`
	Missing  map[string][]string `json:"missing"`
}

type EntityCoverage struct {
	Name        string   `json:"name"`
	Observed    bool     `json:"observed"`
	Identity    []string `json:"identity"`
	Description []string `json:"description"`
	Missing     []string `json:"missing"`
}

type Result struct {
	SchemaURL          string           `json:"schema_url"`
	Reports            int              `json:"reports"`
	Spans              []SignalCoverage `json:"spans"`
	Metrics            []SignalCoverage `json:"metrics"`
	Entities           []EntityCoverage `json:"entities"`
	UnclassifiedShapes []SpanShape      `json:"unclassified_span_shapes"`
	UndeclaredMetrics  []string         `json:"undeclared_metrics"`
}

func Aggregate(m *Model, u *Union) *Result {
	r := &Result{
		SchemaURL:          m.SchemaURL,
		Reports:            u.Reports,
		Spans:              []SignalCoverage{},
		Metrics:            []SignalCoverage{},
		Entities:           []EntityCoverage{},
		UnclassifiedShapes: []SpanShape{},
		UndeclaredMetrics:  []string{},
	}

	spanAttrs := map[string]map[string]struct{}{}
	for _, s := range u.SpanShapes {
		t := Classify(s)
		if t == Unclassified {
			r.UnclassifiedShapes = append(r.UnclassifiedShapes, s)
			continue
		}
		if spanAttrs[t] == nil {
			spanAttrs[t] = map[string]struct{}{}
		}
		for _, a := range s.Attributes {
			spanAttrs[t][a] = struct{}{}
		}
	}

	for _, name := range sortedKeys(m.Spans) {
		observed, seen := spanAttrs[name]
		r.Spans = append(r.Spans, signalCoverage(name, m.Spans[name].Attributes, observed, seen))
	}

	for _, name := range sortedKeys(m.Metrics) {
		observed, seen := u.Metrics[name]
		r.Metrics = append(r.Metrics, signalCoverage(name, m.Metrics[name].Attributes, observed, seen))
	}

	for name := range u.Metrics {
		if _, declared := m.Metrics[name]; !declared {
			r.UndeclaredMetrics = append(r.UndeclaredMetrics, name)
		}
	}
	sort.Strings(r.UndeclaredMetrics)

	for _, name := range sortedKeys(m.Entities) {
		r.Entities = append(r.Entities, entityCoverage(name, m.Entities[name], u.Resource))
	}

	return r
}

func signalCoverage(name string, declared Attributes, observed map[string]struct{}, seen bool) SignalCoverage {
	c := SignalCoverage{
		Name:     name,
		Observed: seen,
		Declared: len(declared),
		Covered:  []string{},
		Missing:  map[string][]string{},
	}
	for _, attr := range sortedKeys(declared) {
		if _, ok := observed[attr]; ok {
			c.Covered = append(c.Covered, attr)
			continue
		}
		level := declared[attr].Level
		c.Missing[level] = append(c.Missing[level], attr)
	}
	return c
}

func entityCoverage(name string, e ModelEntity, resource map[string]struct{}) EntityCoverage {
	c := EntityCoverage{Name: name, Identity: []string{}, Description: []string{}, Missing: []string{}}
	c.Observed = len(e.Identity) > 0
	for _, attr := range sortedKeys(e.Identity) {
		if _, ok := resource[attr]; ok {
			c.Identity = append(c.Identity, attr)
			continue
		}
		c.Observed = false
		c.Missing = append(c.Missing, attr)
	}
	// A descriptive entity declares no identifying attributes, so there is
	// nothing to recognize it by; any of its described attributes appearing on
	// a resource is what it means for the run to have covered it.
	if len(e.Identity) == 0 {
		for attr := range e.Description {
			if _, ok := resource[attr]; ok {
				c.Observed = true
				break
			}
		}
	}
	if !c.Observed {
		return c
	}
	for _, attr := range sortedKeys(e.Description) {
		if _, ok := resource[attr]; ok {
			c.Description = append(c.Description, attr)
			continue
		}
		c.Missing = append(c.Missing, attr)
	}
	return c
}

type Gate struct {
	UnobservedSpans   []string
	UnobservedMetrics []string
	MissingRequired   []string
	Unclassified      int
}

func (g *Gate) Failed() bool {
	return len(g.UnobservedSpans) > 0 ||
		len(g.UnobservedMetrics) > 0 ||
		len(g.MissingRequired) > 0 ||
		g.Unclassified > 0
}

func Evaluate(r *Result) *Gate {
	g := &Gate{Unclassified: len(r.UnclassifiedShapes)}
	for _, s := range r.Spans {
		if !s.Observed {
			g.UnobservedSpans = append(g.UnobservedSpans, s.Name)
			continue
		}
		for _, a := range s.Missing[LevelRequired] {
			g.MissingRequired = append(g.MissingRequired, "span "+s.Name+": "+a)
		}
	}
	for _, m := range r.Metrics {
		if !m.Observed {
			g.UnobservedMetrics = append(g.UnobservedMetrics, m.Name)
			continue
		}
		for _, a := range m.Missing[LevelRequired] {
			g.MissingRequired = append(g.MissingRequired, "metric "+m.Name+": "+a)
		}
	}
	return g
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
