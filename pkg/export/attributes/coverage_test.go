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

	declared := map[string]struct{}{}
	var listed []string
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
			for i, val := range vs.Values {
				lit, ok := val.(*ast.CompositeLit)
				if !ok {
					continue
				}
				switch typ := lit.Type.(type) {
				case *ast.Ident:
					if typ.Name == "Name" {
						declared[vs.Names[i].Name] = struct{}{}
					}
				case *ast.ArrayType:
					elt, ok := typ.Elt.(*ast.Ident)
					if !ok || elt.Name != "Name" || vs.Names[i].Name != "AllMetrics" {
						continue
					}
					for _, e := range lit.Elts {
						id, ok := e.(*ast.Ident)
						require.Truef(t, ok, "AllMetrics element is not a bare identifier: %T", e)
						listed = append(listed, id.Name)
					}
				}
			}
		}
	}

	require.NotEmpty(t, declared)
	require.NotEmpty(t, listed)

	inAllMetrics := map[string]struct{}{}
	for _, name := range listed {
		_, dup := inAllMetrics[name]
		assert.Falsef(t, dup, "%s is listed in AllMetrics more than once", name)
		inAllMetrics[name] = struct{}{}
	}

	for name := range declared {
		_, ok := inAllMetrics[name]
		assert.Truef(t, ok, "%s is declared as a Name{...} but missing from AllMetrics", name)
	}
	for name := range inAllMetrics {
		_, ok := declared[name]
		assert.Truef(t, ok, "%s is in AllMetrics but is not a declared Name{...}", name)
	}
}

func TestEmittedMetricNamesNonEmpty(t *testing.T) {
	names := EmittedMetricNames()
	require.NotEmpty(t, names)
	for _, n := range names {
		assert.NotEqual(t, "resource", n, "resource is an attribute-selection section, not a metric")
	}
}
