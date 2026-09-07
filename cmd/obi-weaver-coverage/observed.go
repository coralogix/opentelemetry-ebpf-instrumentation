// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Report struct {
	Observed Observed `json:"observed"`
}

type Observed struct {
	Spans    []SpanShape         `json:"spans"`
	Metrics  map[string][]string `json:"metrics"`
	Resource []string            `json:"resource"`
}

type SpanShape struct {
	Kind           string            `json:"kind"`
	Attributes     []string          `json:"attributes"`
	Discriminators map[string]string `json:"discriminators"`
}

type Union struct {
	SpanShapes []SpanShape
	Metrics    map[string]map[string]struct{}
	Resource   map[string]struct{}
	Reports    int
}

func LoadReports(dir string) (*Union, error) {
	u := &Union{
		Metrics:  map[string]map[string]struct{}{},
		Resource: map[string]struct{}{},
	}
	seen := map[string]struct{}{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "weaver-report-") || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		var r Report
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		u.Reports++
		u.add(&r.Observed, seen)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if u.Reports == 0 {
		return nil, fmt.Errorf("no weaver-report-*.json found under %s", dir)
	}
	sort.Slice(u.SpanShapes, func(i, j int) bool { return shapeKey(u.SpanShapes[i]) < shapeKey(u.SpanShapes[j]) })
	return u, nil
}

func (u *Union) add(o *Observed, seen map[string]struct{}) {
	for _, s := range o.Spans {
		k := shapeKey(s)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		u.SpanShapes = append(u.SpanShapes, s)
	}
	for name, attrs := range o.Metrics {
		if u.Metrics[name] == nil {
			u.Metrics[name] = map[string]struct{}{}
		}
		for _, a := range attrs {
			u.Metrics[name][a] = struct{}{}
		}
	}
	for _, a := range o.Resource {
		u.Resource[a] = struct{}{}
	}
}

func shapeKey(s SpanShape) string {
	attrs := append([]string(nil), s.Attributes...)
	sort.Strings(attrs)
	disc := make([]string, 0, len(s.Discriminators))
	for k, v := range s.Discriminators {
		disc = append(disc, k+"="+v)
	}
	sort.Strings(disc)
	return s.Kind + "|" + strings.Join(attrs, ",") + "|" + strings.Join(disc, ",")
}
