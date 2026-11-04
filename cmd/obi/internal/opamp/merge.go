// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package opamp // import "go.opentelemetry.io/obi/cmd/obi/internal/opamp"

import (
	"bytes"
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"
)

const redacted = "<redacted>"

var localOnlyPath = []string{"extensions", "obi", "daemon", "opamp"}

func mergeOverlay(base, overlay []byte) ([]byte, error) {
	if len(bytes.TrimSpace(overlay)) == 0 {
		return base, nil
	}
	baseRoot, err := documentMapping(base)
	if err != nil {
		return nil, fmt.Errorf("parsing local configuration: %w", err)
	}
	overlayRoot, err := documentMapping(overlay)
	if err != nil {
		return nil, fmt.Errorf("parsing remote configuration: %w", err)
	}
	if lookup(overlayRoot, localOnlyPath...) != nil {
		return nil, errors.New("remote configuration can't set extensions.obi.daemon.opamp")
	}
	mergeMapping(baseRoot, overlayRoot)
	return yaml.Marshal(baseRoot)
}

func redactedConfig(data []byte) ([]byte, error) {
	root, err := documentMapping(data)
	if err != nil {
		return nil, err
	}
	redactHeaders(root)
	return yaml.Marshal(root)
}

func documentMapping(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("configuration root must be a mapping")
	}
	return root, nil
}

func mergeMapping(dst, src *yaml.Node) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, value := src.Content[i], src.Content[i+1]
		existing := mappingValue(dst, key.Value)
		switch {
		case existing == nil:
			dst.Content = append(dst.Content, key, value)
		case existing.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode:
			mergeMapping(existing, value)
		default:
			*existing = *value
		}
	}
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func lookup(node *yaml.Node, path ...string) *yaml.Node {
	for _, key := range path {
		if node == nil || node.Kind != yaml.MappingNode {
			return nil
		}
		node = mappingValue(node, key)
	}
	return node
}

func redactHeaders(node *yaml.Node) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Value == "headers" || key.Value == "headers_list" {
				redactValues(value)
				continue
			}
			redactHeaders(value)
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			redactHeaders(item)
		}
	}
}

func redactValues(node *yaml.Node) {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag != "!!null" {
			node.Value, node.Tag, node.Style = redacted, "!!str", 0
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value != "name" {
				redactValues(node.Content[i+1])
			}
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			redactValues(item)
		}
	}
}
