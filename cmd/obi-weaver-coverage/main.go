// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	model := flag.String("model", "", "path to the coverage model produced by `weaver registry generate coverage-model`")
	in := flag.String("in", "./all-weaver-reports", "directory holding the archived weaver-report-*.json files")
	outMD := flag.String("out-md", "", "path to write the markdown report to")
	outJSON := flag.String("out-json", "", "path to write the machine-readable report to")
	failOnGap := flag.Bool("fail-on-gap", false, "exit non-zero when the gate fails")
	flag.Parse()

	if *model == "" {
		fmt.Fprintln(os.Stderr, "obi-weaver-coverage: -model is required")
		os.Exit(2)
	}

	if err := run(*model, *in, *outMD, *outJSON, *failOnGap); err != nil {
		fmt.Fprintf(os.Stderr, "obi-weaver-coverage: %v\n", err)
		os.Exit(1)
	}
}

func run(modelPath, in, outMD, outJSON string, failOnGap bool) error {
	m, err := LoadModel(modelPath)
	if err != nil {
		return err
	}
	u, err := LoadReports(in)
	if err != nil {
		return err
	}

	result := Aggregate(m, u)
	gate := Evaluate(result)
	md := Markdown(m, result, gate)

	if outMD != "" {
		if err := os.WriteFile(outMD, []byte(md), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", outMD, err)
		}
	}
	if outJSON != "" {
		raw, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding report: %w", err)
		}
		if err := os.WriteFile(outJSON, append(raw, '\n'), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", outJSON, err)
		}
	}

	fmt.Print(md)

	if gate.Failed() && failOnGap {
		return errors.New("telemetry coverage gate failed")
	}
	return nil
}
