// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// obi-weaver-coverage aggregates the per-suite weaver live-check reports
// produced across the sharded test matrix into a single telemetry coverage
// verdict. The denominator is resolved from the OBI schema itself (weaver
// registry resolve --v2): every metric and span definition with its declared
// attributes, and the resource attributes. The observed set is the union,
// across every report, of the signals live-check matched samples to, the
// attribute keys seen on the samples of each signal, and the seen_* statistics.
// Every declared item no suite observed is reported as a gap.
//
// All of the aggregation logic lives here rather than in the workflow: the CI
// job is `make weaver-coverage`, nothing more.
//
// Usage:
//
//	obi-weaver-coverage --schema <dir> --oci-bin docker --weaver-image <img> --in <dir> [--out-md f] [--out-json f] [--fail-on-gap]
//	obi-weaver-coverage --intended <file> --in <dir>   # denominator from a file instead of resolving
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

const (
	kindMetric = "metric"
	kindSpan   = "span"

	levelRequired              = "required"
	levelConditionallyRequired = "conditionally_required"
	levelRecommended           = "recommended"
	levelOptIn                 = "opt_in"

	resolveTimeout = 5 * time.Minute
)

var requirementLevels = []string{levelRequired, levelConditionallyRequired, levelRecommended, levelOptIn}

// targetInfoCarriers are the meta-metrics whose data-point labels are the OTel
// resource attribute set (Prometheus/OpenMetrics target_info heritage), so their
// attributes also seed the resource surface.
var targetInfoCarriers = map[string]struct{}{
	"target.info":        {},
	"traces.target.info": {},
	"traces.host.info":   {},
}

type resolvedAttribute struct {
	Key              string          `json:"key"`
	Type             json.RawMessage `json:"type"`
	RequirementLevel json.RawMessage `json:"requirement_level"`
}

// template reports whether the attribute is a template: emitted as
// `<key>.<suffix>` keys rather than under its own key.
func (a resolvedAttribute) template() bool {
	var t string
	return json.Unmarshal(a.Type, &t) == nil && strings.HasPrefix(t, "template[")
}

type resolvedMetric struct {
	Name       string              `json:"name"`
	Attributes []resolvedAttribute `json:"attributes"`
}

type resolvedSpan struct {
	Type       string              `json:"type"`
	Attributes []resolvedAttribute `json:"attributes"`
}

type resolvedEntity struct {
	Identity    []resolvedAttribute `json:"identity"`
	Description []resolvedAttribute `json:"description"`
}

type resolvedRegistry struct {
	Registry struct {
		Metrics  []resolvedMetric `json:"metrics"`
		Spans    []resolvedSpan   `json:"spans"`
		Entities []resolvedEntity `json:"entities"`
	} `json:"registry"`
}

type DeclaredAttribute struct {
	Key              string `json:"key"`
	RequirementLevel string `json:"requirement_level"`
	Template         bool   `json:"template,omitempty"`
}

func (a DeclaredAttribute) observedIn(seen map[string]struct{}) bool {
	if _, ok := seen[a.Key]; ok {
		return true
	}
	if !a.Template {
		return false
	}
	for key := range seen {
		if strings.HasPrefix(key, a.Key+".") {
			return true
		}
	}
	return false
}

type Signal struct {
	Name       string              `json:"name"`
	Kind       string              `json:"kind"`
	Attributes []DeclaredAttribute `json:"attributes"`
}

type Denominator struct {
	Signals            []Signal `json:"signals"`
	ResourceAttributes []string `json:"resource_attributes"`
}

// requirementLevel reduces a resolved requirement level, either a bare word or
// a single-key object carrying the condition, to its word. Weaver defaults an
// unset level to recommended.
func requirementLevel(raw json.RawMessage) string {
	var word string
	if err := json.Unmarshal(raw, &word); err == nil && word != "" {
		return word
	}
	var conditional map[string]json.RawMessage
	if err := json.Unmarshal(raw, &conditional); err == nil {
		for level := range conditional {
			return level
		}
	}
	return levelRecommended
}

func declaredAttributes(attrs []resolvedAttribute) []DeclaredAttribute {
	out := make([]DeclaredAttribute, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, DeclaredAttribute{
			Key:              a.Key,
			RequirementLevel: requirementLevel(a.RequirementLevel),
			Template:         a.template(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// parseDenominator reads the v2 resolved registry. Live-check resolves without
// --include-unreferenced, so every metric and span in it is one OBI emits: its
// own, or an upstream definition it imports.
func parseDenominator(resolved []byte) (Denominator, error) {
	var reg resolvedRegistry
	if err := json.Unmarshal(resolved, &reg); err != nil {
		return Denominator{}, fmt.Errorf("parsing resolved registry: %w", err)
	}

	var d Denominator
	resourceAttrs := map[string]struct{}{}
	for _, m := range reg.Registry.Metrics {
		d.Signals = append(d.Signals, Signal{Name: m.Name, Kind: kindMetric, Attributes: declaredAttributes(m.Attributes)})
		if _, carrier := targetInfoCarriers[m.Name]; carrier {
			for _, a := range m.Attributes {
				resourceAttrs[a.Key] = struct{}{}
			}
		}
	}
	for _, s := range reg.Registry.Spans {
		d.Signals = append(d.Signals, Signal{Name: s.Type, Kind: kindSpan, Attributes: declaredAttributes(s.Attributes)})
	}
	for _, e := range reg.Registry.Entities {
		for _, a := range slices.Concat(e.Identity, e.Description) {
			resourceAttrs[a.Key] = struct{}{}
		}
	}
	sort.Slice(d.Signals, func(i, j int) bool { return d.Signals[i].Name < d.Signals[j].Name })
	d.ResourceAttributes = sortedKeys(resourceAttrs)

	if len(d.Signals) == 0 {
		return Denominator{}, errors.New("resolved registry declares no metric or span")
	}
	return d, nil
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resolveSchema runs `weaver registry resolve --v2`. Weaver can exit non-zero on
// a diagnostic while still writing the complete resolved registry, so the
// output is judged by parseDenominator rather than by the exit code.
func resolveSchema(ociBin, image, schemaPath string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, ociBin, "run", "--rm",
		"-v", schemaPath+":/obi-registry:ro",
		"-w", "/obi-registry",
		image, "registry", "resolve",
		"--registry", "/obi-registry",
		"--v2",
		"--format", "json")
	out, err := cmd.Output()
	if len(out) == 0 {
		return nil, fmt.Errorf("running weaver registry resolve: %w", err)
	}
	return out, nil
}

// driftWarnings reports OTLP metrics the code emits that the schema does not
// declare: a metric absent from the denominator can never show up as a gap, so
// coverage would silently over-report.
func driftWarnings(d Denominator) []string {
	declared := map[string]struct{}{}
	for _, s := range d.Signals {
		if s.Kind == kindMetric {
			declared[s.Name] = struct{}{}
		}
	}
	var missing []string
	for _, m := range attributes.EmittedMetricNames() {
		if _, ok := declared[m]; !ok {
			missing = append(missing, m)
		}
	}
	return missing
}

type Statistics struct {
	SeenRegistryMetrics       map[string]int `json:"seen_registry_metrics"`
	SeenRegistryAttributes    map[string]int `json:"seen_registry_attributes"`
	SeenNonRegistryAttributes map[string]int `json:"seen_non_registry_attributes"`
}

// Report is the part of a `compact` live-check report coverage reads.
type Report struct {
	Statistics       Statistics          `json:"statistics"`
	MatchedSignals   map[string]int      `json:"matched_signals"`
	SignalAttributes map[string][]string `json:"signal_attributes"`
}

type Observed struct {
	Signals          map[string]struct{}
	SignalAttributes map[string]map[string]struct{}
	Attributes       map[string]struct{}
}

// Observe unions the reports. A seen_* entry counts only with a positive count,
// because weaver lists every declared item, the unseen ones with zero.
func Observe(reports []Report) Observed {
	o := Observed{
		Signals:          map[string]struct{}{},
		SignalAttributes: map[string]map[string]struct{}{},
		Attributes:       map[string]struct{}{},
	}
	addCounted := func(dst map[string]struct{}, src map[string]int) {
		for name, count := range src {
			if count > 0 {
				dst[name] = struct{}{}
			}
		}
	}
	for _, r := range reports {
		addCounted(o.Signals, r.MatchedSignals)
		addCounted(o.Signals, r.Statistics.SeenRegistryMetrics)
		addCounted(o.Attributes, r.Statistics.SeenRegistryAttributes)
		addCounted(o.Attributes, r.Statistics.SeenNonRegistryAttributes)
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

func diff(intended []string, observed map[string]struct{}) SurfaceResult {
	res := SurfaceResult{Covered: []string{}, Gaps: []string{}}
	for _, name := range intended {
		if _, ok := observed[name]; ok {
			res.Covered = append(res.Covered, name)
		} else {
			res.Gaps = append(res.Gaps, name)
		}
	}
	return res
}

type SignalAttributesResult struct {
	Signal  string              `json:"signal"`
	Kind    string              `json:"kind"`
	Covered []DeclaredAttribute `json:"covered"`
	Gaps    []DeclaredAttribute `json:"gaps"`
}

type Result struct {
	Reports            int                      `json:"reports"`
	Metrics            SurfaceResult            `json:"metrics"`
	Spans              SurfaceResult            `json:"spans"`
	SignalAttributes   []SignalAttributesResult `json:"signal_attributes"`
	ResourceAttributes SurfaceResult            `json:"resource_attributes"`
}

// Aggregate measures the reports against the denominator. Attribute coverage is
// measured only on signals some suite observed: an unobserved signal is already
// a signal gap, and counting its attributes again would only repeat it.
func Aggregate(d Denominator, reports []Report) Result {
	o := Observe(reports)
	res := Result{Reports: len(reports), SignalAttributes: []SignalAttributesResult{}}

	var metrics, spans []string
	for _, s := range d.Signals {
		if s.Kind == kindSpan {
			spans = append(spans, s.Name)
		} else {
			metrics = append(metrics, s.Name)
		}
		if _, ok := o.Signals[s.Name]; !ok || len(s.Attributes) == 0 {
			continue
		}
		sr := SignalAttributesResult{Signal: s.Name, Kind: s.Kind, Covered: []DeclaredAttribute{}, Gaps: []DeclaredAttribute{}}
		seen := o.SignalAttributes[s.Name]
		for _, a := range s.Attributes {
			if a.observedIn(seen) {
				sr.Covered = append(sr.Covered, a)
			} else {
				sr.Gaps = append(sr.Gaps, a)
			}
		}
		res.SignalAttributes = append(res.SignalAttributes, sr)
	}
	res.Metrics = diff(metrics, o.Signals)
	res.Spans = diff(spans, o.Signals)
	res.ResourceAttributes = diff(d.ResourceAttributes, o.Attributes)
	return res
}

func failsOnGap(level string) bool {
	return level == levelRequired || level == levelConditionallyRequired
}

// FailingGaps counts the gaps --fail-on-gap fails on: unobserved signals, and
// required or conditionally required attributes missing from an observed
// signal. Recommended, opt-in and resource attribute gaps are informational.
func (r Result) FailingGaps() int {
	n := len(r.Metrics.Gaps) + len(r.Spans.Gaps)
	for _, s := range r.SignalAttributes {
		for _, g := range s.Gaps {
			if failsOnGap(g.RequirementLevel) {
				n++
			}
		}
	}
	return n
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
		"Signal attributes are measured on the signals some suite emitted._\n\n", r.Reports)

	b.WriteString("| surface | covered | total | coverage |\n| --- | ---: | ---: | ---: |\n")
	row := func(label string, covered, total int) {
		fmt.Fprintf(&b, "| %s | %d | %d | %s%% |\n", label, covered, total, pct(covered, total))
	}
	row("metrics", len(r.Metrics.Covered), len(r.Metrics.Covered)+len(r.Metrics.Gaps))
	row("spans", len(r.Spans.Covered), len(r.Spans.Covered)+len(r.Spans.Gaps))
	covered, total := r.attributeCountsByLevel()
	for _, level := range requirementLevels {
		label := "signal attributes, " + level
		if !failsOnGap(level) {
			label += " (informational)"
		}
		row(label, covered[level], total[level])
	}
	row("resource attributes (informational)", len(r.ResourceAttributes.Covered),
		len(r.ResourceAttributes.Covered)+len(r.ResourceAttributes.Gaps))
	b.WriteString("\n")

	writeGapList(&b, "Uncovered metrics", r.Metrics.Gaps)
	writeGapList(&b, "Uncovered spans", r.Spans.Gaps)

	var attrs strings.Builder
	if n := r.writeAttributeGaps(&attrs, failsOnGap); n == 0 {
		b.WriteString("**Required and conditionally required signal attributes:** all covered\n\n")
	} else {
		fmt.Fprintf(&b, "**Required and conditionally required signal attributes: %d signal(s) with gaps**\n\n%s\n", n, attrs.String())
	}

	var informational strings.Builder
	if n := r.writeAttributeGaps(&informational, func(level string) bool { return !failsOnGap(level) }); n > 0 {
		fmt.Fprintf(&b, "<details><summary>Recommended and opt-in signal attributes never observed (%d signal(s))</summary>\n\n%s\n</details>\n\n",
			n, informational.String())
	}

	writeGapList(&b, "Uncovered resource attributes", r.ResourceAttributes.Gaps)
	return b.String()
}

func LoadReports(dir string) ([]Report, error) {
	var reports []Report
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
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		reports = append(reports, r)
		return nil
	})
	return reports, err
}

func loadDenominator(path string) (Denominator, error) {
	var d Denominator
	raw, err := os.ReadFile(path)
	if err != nil {
		return d, err
	}
	return d, json.Unmarshal(raw, &d)
}

func emit(md, outMD string) {
	if outMD != "" {
		if err := os.WriteFile(outMD, []byte(md), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
		if f, err := os.OpenFile(summary, os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			if _, werr := f.WriteString(md); werr != nil {
				fmt.Fprintln(os.Stderr, werr)
			}
			_ = f.Close()
		}
	}
	fmt.Print(md)
}

func writeJSON(res Result, outJSON string) {
	if outJSON == "" {
		return
	}
	j, err := json.MarshalIndent(res, "", "  ")
	if err == nil {
		err = os.WriteFile(outJSON, append(j, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

func denominator(schema, ociBin, image, intendedPath string) (Denominator, error) {
	if intendedPath != "" {
		return loadDenominator(intendedPath)
	}
	resolved, err := resolveSchema(ociBin, image, schema)
	if err != nil {
		return Denominator{}, err
	}
	d, err := parseDenominator(resolved)
	if err != nil {
		return Denominator{}, err
	}
	if missing := driftWarnings(d); len(missing) > 0 {
		fmt.Printf("::warning title=Schema drift::code emits OTLP metrics the schema does not declare: %s\n",
			strings.Join(missing, ", "))
	}
	return d, nil
}

func main() {
	in := flag.String("in", "", "directory searched recursively for weaver-report-*.json")
	schema := flag.String("schema", "", "OBI registry path; resolved via weaver to derive the denominator")
	ociBin := flag.String("oci-bin", "docker", "container runtime used to run the weaver image")
	weaverImage := flag.String("weaver-image", "", "pinned weaver image used to resolve the schema")
	intendedPath := flag.String("intended", "", "denominator JSON, overriding --schema (for tests)")
	outMD := flag.String("out-md", "", "write the markdown summary to this file")
	outJSON := flag.String("out-json", "", "write the result JSON to this file")
	failOnGap := flag.Bool("fail-on-gap", false,
		"exit non-zero when a signal, or a required or conditionally required attribute of an observed signal, was never observed")
	flag.Parse()

	if *schema == "" && *intendedPath == "" {
		fatal("one of --schema or --intended is required")
	}
	if *schema != "" && *intendedPath == "" && *weaverImage == "" {
		fatal("--weaver-image is required with --schema")
	}
	intended, err := denominator(*schema, *ociBin, *weaverImage, *intendedPath)
	if err != nil {
		fatal(err.Error())
	}

	reports, err := LoadReports(*in)
	if err != nil {
		fatal(err.Error())
	}

	if len(reports) == 0 {
		emit(fmt.Sprintf("## Weaver telemetry coverage\n\n_No weaver reports (`weaver-report-*.json`) found under `%s`._\n", *in), *outMD)
		writeJSON(Result{SignalAttributes: []SignalAttributesResult{}}, *outJSON)
		return
	}

	res := Aggregate(intended, reports)
	emit(res.Markdown(), *outMD)
	writeJSON(res, *outJSON)

	if n := res.FailingGaps(); n > 0 && *failOnGap {
		fmt.Fprintf(os.Stderr, "weaver telemetry coverage: %d failing gap(s)\n", n)
		os.Exit(1)
	}
}
