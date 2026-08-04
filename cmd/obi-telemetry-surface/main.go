// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// obi-telemetry-surface prints the code-derived set of telemetry OBI can emit:
// the metric names and metric attributes enumerated from the attribute-selection
// registry with every feature group enabled. The coverage denominator is
// resolved from the OBI schema (see scripts/weaver-schema-denominator.sh); this
// tool is the drift guard that keeps the schema honest — every OTLP metric the
// code emits must be declared in the schema, or the aggregate warns.
//
// Usage:
//
//	go run ./cmd/obi-telemetry-surface > code-emitted.json
//	go run ./cmd/obi-telemetry-surface -output code-emitted.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

type surface struct {
	MetricNames      []string `json:"metric_names"`
	MetricAttributes []string `json:"metric_attributes"`
}

func main() {
	output := flag.String("output", "", "write JSON to this file instead of stdout")
	flag.Parse()

	out, err := json.MarshalIndent(surface{
		MetricNames:      attributes.EmittedMetricNames(),
		MetricAttributes: attributes.EmittedMetricAttributes(),
	}, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out = append(out, '\n')

	if *output == "" {
		os.Stdout.Write(out)
		return
	}
	if err := os.WriteFile(*output, out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
