// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllMetricsMatchesDeclarations(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "metric.go", nil, 0)
	require.NoError(t, err)

	declared := 0
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				lit, ok := val.(*ast.CompositeLit)
				if !ok {
					continue
				}
				if id, ok := lit.Type.(*ast.Ident); ok && id.Name == "Name" {
					declared++
				}
			}
		}
	}

	assert.Equal(t, len(AllMetrics), declared,
		"every Name{...} declared in metric.go must be listed in AllMetrics")
}

func TestEmittedMetricNamesNonEmpty(t *testing.T) {
	names := EmittedMetricNames()
	require.NotEmpty(t, names)
	for _, n := range names {
		assert.NotEqual(t, "resource", n, "resource is an attribute-selection section, not a metric")
	}
}

func TestEmittedMetricAttributesNonEmpty(t *testing.T) {
	attrs := EmittedMetricAttributes()
	require.NotEmpty(t, attrs)
	assert.Contains(t, attrs, "http.request.method")
}
