// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	LevelRequired              = "required"
	LevelConditionallyRequired = "conditionally_required"
	LevelRecommended           = "recommended"
	LevelOptIn                 = "opt_in"
)

type Model struct {
	Spans     map[string]ModelSpan   `json:"spans"`
	Metrics   map[string]ModelMetric `json:"metrics"`
	Events    map[string]ModelSignal `json:"events"`
	Entities  map[string]ModelEntity `json:"entities"`
	Enums     map[string][]string    `json:"enums"`
	SchemaURL string                 `json:"schema_url"`
}

type AttrLevel struct {
	Level     string `json:"level"`
	Condition string `json:"condition,omitempty"`
}

type Attributes map[string]AttrLevel

type ModelSpan struct {
	Kind       string     `json:"kind"`
	Attributes Attributes `json:"attributes"`
}

type ModelMetric struct {
	Instrument       string     `json:"instrument"`
	Unit             string     `json:"unit"`
	UpstreamOverride bool       `json:"upstream_override"`
	Attributes       Attributes `json:"attributes"`
}

type ModelSignal struct {
	Attributes Attributes `json:"attributes"`
}

type ModelEntity struct {
	Identity    Attributes `json:"identity"`
	Description Attributes `json:"description"`
}

func LoadModel(path string) (*Model, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading coverage model %s: %w", path, err)
	}
	var m Model
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parsing coverage model %s: %w", path, err)
	}
	if len(m.Spans) == 0 && len(m.Metrics) == 0 {
		return nil, fmt.Errorf("coverage model %s declares no spans and no metrics; regenerate it with an absolute --registry path", path)
	}
	return &m, nil
}
