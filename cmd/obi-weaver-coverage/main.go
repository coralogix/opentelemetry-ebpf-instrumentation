// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// obi-weaver-coverage aggregates the per-suite weaver live-check reports
// produced across the sharded integration matrix into a single telemetry
// coverage verdict. The denominator is the set of metrics and attributes OBI
// emits over OTLP, resolved from the OBI schema itself (weaver registry
// resolve, minus Prometheus-only signals); the observed set is the union,
// across every shard report, of the seen_* statistics maps. Every denominator
// entry never observed by any suite is reported as a gap.
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
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

type resolvedGroup struct {
	Type       string `json:"type"`
	MetricName string `json:"metric_name"`
	Attributes []struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		Ref  string `json:"ref"`
	} `json:"attributes"`
}

type resolvedRegistry struct {
	Groups   []resolvedGroup `json:"groups"`
	Registry struct {
		Groups []resolvedGroup `json:"groups"`
	} `json:"registry"`
}

// targetInfoCarriers are the meta-metrics whose data-point labels are the OTel
// resource attribute set (Prometheus/OpenMetrics target_info heritage). Their
// attributes describe the resource, not a metric data point, so they seed the
// resource surface rather than the metric-attribute surface.
var targetInfoCarriers = map[string]struct{}{
	"target.info":        {},
	"traces.target.info": {},
	"traces.host.info":   {},
}

// parseDenominator splits the resolved registry into three coverage surfaces:
// metric names, metric data-point attributes, and resource attributes. Span
// groups are intentionally excluded — weaver cannot match an emitted span to a
// span definition (OTEP #5233), so span attributes are not coverable. Bare
// attribute_group definitions are skipped too: they are resolved into the
// metric/span/entity groups that reference them, which is where they count.
func parseDenominator(resolved []byte) (Surface, error) {
	var reg resolvedRegistry
	if err := json.Unmarshal(resolved, &reg); err != nil {
		return Surface{}, fmt.Errorf("parsing resolved registry: %w", err)
	}
	groups := reg.Groups
	if len(groups) == 0 {
		groups = reg.Registry.Groups
	}
	metrics := map[string]struct{}{}
	metricAttrs := map[string]struct{}{}
	resourceAttrs := map[string]struct{}{}
	attrNames := func(g resolvedGroup) []string {
		var out []string
		for _, a := range g.Attributes {
			switch {
			case a.Name != "":
				out = append(out, a.Name)
			case a.ID != "":
				out = append(out, a.ID)
			case a.Ref != "":
				out = append(out, a.Ref)
			}
		}
		return out
	}
	add := func(dst map[string]struct{}, names []string) {
		for _, n := range names {
			dst[n] = struct{}{}
		}
	}
	for _, g := range groups {
		switch g.Type {
		case "metric":
			if g.MetricName != "" {
				metrics[g.MetricName] = struct{}{}
			}
			if _, carrier := targetInfoCarriers[g.MetricName]; carrier {
				add(resourceAttrs, attrNames(g))
			} else {
				add(metricAttrs, attrNames(g))
			}
		case "entity":
			add(resourceAttrs, attrNames(g))
		}
	}
	return Surface{
		MetricNames:        sortedKeys(metrics),
		MetricAttributes:   sortedKeys(metricAttrs),
		ResourceAttributes: sortedKeys(resourceAttrs),
	}, nil
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func resolveSchema(ociBin, image, schemaPath string) ([]byte, error) {
	cmd := exec.Command(ociBin, "run", "--rm",
		"-v", schemaPath+":/obi-registry:ro",
		"-w", "/obi-registry",
		image, "registry", "resolve",
		"--registry", "/obi-registry",
		"--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running weaver registry resolve: %w", err)
	}
	return out, nil
}

// driftWarnings reports OTLP metrics the code emits (attributes.AllMetrics) that
// the schema-resolved denominator does not declare — the schema drifting behind
// the code. Connector metrics live outside AllMetrics, so only the code→schema
// direction is checked.
func driftWarnings(denominator Surface) []string {
	declared := map[string]struct{}{}
	for _, m := range denominator.MetricNames {
		declared[m] = struct{}{}
	}
	var missing []string
	for _, m := range attributes.EmittedMetricNames() {
		if _, ok := declared[m]; !ok {
			missing = append(missing, m)
		}
	}
	sort.Strings(missing)
	return missing
}

type Surface struct {
	MetricNames        []string `json:"metric_names"`
	MetricAttributes   []string `json:"metric_attributes"`
	ResourceAttributes []string `json:"resource_attributes"`
}

type Statistics struct {
	SeenRegistryMetrics       map[string]int `json:"seen_registry_metrics"`
	SeenNonRegistryMetrics    map[string]int `json:"seen_non_registry_metrics"`
	SeenRegistryAttributes    map[string]int `json:"seen_registry_attributes"`
	SeenNonRegistryAttributes map[string]int `json:"seen_non_registry_attributes"`
}

type Report struct {
	Statistics Statistics `json:"statistics"`
}

func Observed(reports []Report) (metrics, attributes map[string]struct{}) {
	metrics = map[string]struct{}{}
	attributes = map[string]struct{}{}
	add := func(dst map[string]struct{}, src map[string]int) {
		for name, count := range src {
			if count > 0 {
				dst[name] = struct{}{}
			}
		}
	}
	for _, r := range reports {
		add(metrics, r.Statistics.SeenRegistryMetrics)
		add(metrics, r.Statistics.SeenNonRegistryMetrics)
		add(attributes, r.Statistics.SeenRegistryAttributes)
		add(attributes, r.Statistics.SeenNonRegistryAttributes)
	}
	return metrics, attributes
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
	sort.Strings(res.Covered)
	sort.Strings(res.Gaps)
	return res
}

type Result struct {
	Reports            int           `json:"reports"`
	MetricNames        SurfaceResult `json:"metric_names"`
	MetricAttributes   SurfaceResult `json:"metric_attributes"`
	ResourceAttributes SurfaceResult `json:"resource_attributes"`
}

func Aggregate(intended Surface, reports []Report) Result {
	metrics, attributes := Observed(reports)
	return Result{
		Reports:            len(reports),
		MetricNames:        diff(intended.MetricNames, metrics),
		MetricAttributes:   diff(intended.MetricAttributes, attributes),
		ResourceAttributes: diff(intended.ResourceAttributes, attributes),
	}
}

func (r Result) TotalGaps() int {
	return len(r.MetricNames.Gaps) + len(r.MetricAttributes.Gaps) + len(r.ResourceAttributes.Gaps)
}

func pct(covered, total int) string {
	if total == 0 {
		return "100.0"
	}
	return fmt.Sprintf("%.1f", float64(covered)/float64(total)*100)
}

func (r Result) Markdown() string {
	var b strings.Builder
	b.WriteString("## Weaver telemetry coverage\n\n")
	fmt.Fprintf(&b, "_Union of `seen_*` maps across %d per-suite weaver report(s). "+
		"A row is covered when at least one suite emitted it._\n\n", r.Reports)
	b.WriteString("| surface | covered | total | coverage |\n| --- | ---: | ---: | ---: |\n")
	row := func(label string, s SurfaceResult) {
		total := len(s.Covered) + len(s.Gaps)
		fmt.Fprintf(&b, "| %s | %d | %d | %s%% |\n", label, len(s.Covered), total, pct(len(s.Covered), total))
	}
	row("metric names", r.MetricNames)
	row("metric attributes", r.MetricAttributes)
	row("resource attributes", r.ResourceAttributes)
	b.WriteString("\n")
	gaps := func(label string, s SurfaceResult) {
		if len(s.Gaps) == 0 {
			fmt.Fprintf(&b, "**%s:** all covered ✅\n\n", label)
			return
		}
		fmt.Fprintf(&b, "**%s — %d never observed ❌**\n\n", label, len(s.Gaps))
		for _, name := range s.Gaps {
			fmt.Fprintf(&b, "- `%s`\n", name)
		}
		b.WriteString("\n")
	}
	gaps("Uncovered metric names", r.MetricNames)
	gaps("Uncovered metric attributes", r.MetricAttributes)
	gaps("Uncovered resource attributes", r.ResourceAttributes)
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

func loadSurface(path string) (Surface, error) {
	var s Surface
	raw, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(raw, &s)
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

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

func denominator(schema, ociBin, image, intendedPath string) (Surface, error) {
	if intendedPath != "" {
		return loadSurface(intendedPath)
	}
	resolved, err := resolveSchema(ociBin, image, schema)
	if err != nil {
		return Surface{}, err
	}
	surface, err := parseDenominator(resolved)
	if err != nil {
		return Surface{}, err
	}
	if missing := driftWarnings(surface); len(missing) > 0 {
		fmt.Printf("::warning title=Schema drift::code emits OTLP metrics the schema does not declare: %s\n",
			strings.Join(missing, ", "))
	}
	return surface, nil
}

func main() {
	in := flag.String("in", "", "directory searched recursively for weaver-report-*.json")
	schema := flag.String("schema", "", "OBI registry path; resolved via weaver to derive the denominator")
	ociBin := flag.String("oci-bin", "docker", "container runtime used to run the weaver image")
	weaverImage := flag.String("weaver-image", "", "pinned weaver image used to resolve the schema")
	intendedPath := flag.String("intended", "", "denominator JSON, overriding --schema (for tests)")
	outMD := flag.String("out-md", "", "write the markdown summary to this file")
	outJSON := flag.String("out-json", "", "write the result JSON to this file")
	failOnGap := flag.Bool("fail-on-gap", false, "exit non-zero when any denominator entry was never observed")
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
		if *outJSON != "" {
			empty := `{"reports":0,"metric_names":{"covered":[],"gaps":[]},"metric_attributes":{"covered":[],"gaps":[]},"resource_attributes":{"covered":[],"gaps":[]}}` + "\n"
			if err := os.WriteFile(*outJSON, []byte(empty), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
		return
	}

	res := Aggregate(intended, reports)
	emit(res.Markdown(), *outMD)
	if *outJSON != "" {
		j, _ := json.MarshalIndent(res, "", "  ")
		if err := os.WriteFile(*outJSON, append(j, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}

	if res.TotalGaps() > 0 && *failOnGap {
		fmt.Fprintf(os.Stderr, "weaver telemetry coverage: %d intended item(s) never observed\n", res.TotalGaps())
		os.Exit(1)
	}
}
