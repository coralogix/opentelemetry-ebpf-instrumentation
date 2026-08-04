// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// obi-telemetry-surface prints the code-derived set of telemetry OBI can emit:
// the metric names and metric attributes enumerated from the attribute-selection
// registry with every feature group enabled. It is the denominator for the
// weaver telemetry-coverage aggregate: every name it lists must be observed by
// at least one weaver live-check across the integration suite.
//
// Usage:
//
//	go run ./cmd/obi-telemetry-surface > intended-telemetry.json
//	go run ./cmd/obi-telemetry-surface -output intended-telemetry.json
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
