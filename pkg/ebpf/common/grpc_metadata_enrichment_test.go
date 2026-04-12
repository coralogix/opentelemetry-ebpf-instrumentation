// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
)

func grpcGlob(pattern string) services.GlobAttr {
	return services.NewGlob(pattern)
}

//nolint:unparam
func newGRPCEnricher(defaultAction config.ParsingAction, obfuscation string, rules []config.GRPCParsingRule) *GRPCMetadataEnricher {
	return NewGRPCMetadataEnricher(config.GRPCEnrichmentConfig{
		Policy: config.GRPCParsingPolicy{
			DefaultAction:     config.GRPCParsingDefaultAction{Metadata: defaultAction},
			ObfuscationString: obfuscation,
		},
		Rules: rules,
	})
}

func TestGRPCMetadataEnricher_IncludeByDefault(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionInclude, "***", nil)
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{"x-req-id": {"123"}, "authorization": {"Bearer tok"}}
	respMD := map[string][]string{"x-resp-id": {"456"}}

	ok := e.Enrich(span, reqMD, respMD)
	require.True(t, ok)
	assert.Equal(t, map[string][]string{"x-req-id": {"123"}, "authorization": {"Bearer tok"}}, span.RequestHeaders)
	assert.Equal(t, map[string][]string{"x-resp-id": {"456"}}, span.ResponseHeaders)
}

func TestGRPCMetadataEnricher_ExcludeByDefault(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionExclude, "***", nil)
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{"x-req-id": {"123"}}
	respMD := map[string][]string{"x-resp-id": {"456"}}

	ok := e.Enrich(span, reqMD, respMD)
	assert.False(t, ok)
	assert.Nil(t, span.RequestHeaders)
	assert.Nil(t, span.ResponseHeaders)
}

func TestGRPCMetadataEnricher_IncludeRule(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionExclude, "***", []config.GRPCParsingRule{
		{
			Action: config.ParsingActionInclude,
			Scope:  config.ParsingScopeAll,
			Match:  config.GRPCParsingMatch{Patterns: []services.GlobAttr{grpcGlob("x-custom-*")}},
		},
	})
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{
		"x-custom-foo":  {"val1"},
		"authorization": {"secret"},
	}

	ok := e.Enrich(span, reqMD, nil)
	require.True(t, ok)
	assert.Equal(t, map[string][]string{"x-custom-foo": {"val1"}}, span.RequestHeaders)
}

func TestGRPCMetadataEnricher_ObfuscateRule(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionExclude, "***", []config.GRPCParsingRule{
		{
			Action: config.ParsingActionObfuscate,
			Scope:  config.ParsingScopeAll,
			Match:  config.GRPCParsingMatch{Patterns: []services.GlobAttr{grpcGlob("authorization")}},
		},
	})
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{"authorization": {"Bearer secret-token"}}

	ok := e.Enrich(span, reqMD, nil)
	require.True(t, ok)
	assert.Equal(t, map[string][]string{"authorization": {"***"}}, span.RequestHeaders)
}

func TestGRPCMetadataEnricher_FirstMatchWins(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionExclude, "***", []config.GRPCParsingRule{
		{
			Action: config.ParsingActionObfuscate,
			Scope:  config.ParsingScopeAll,
			Match:  config.GRPCParsingMatch{Patterns: []services.GlobAttr{grpcGlob("authorization")}},
		},
		{
			Action: config.ParsingActionInclude,
			Scope:  config.ParsingScopeAll,
			Match:  config.GRPCParsingMatch{Patterns: []services.GlobAttr{grpcGlob("*")}},
		},
	})
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{
		"authorization": {"Bearer tok"},
		"x-custom":      {"val"},
	}

	ok := e.Enrich(span, reqMD, nil)
	require.True(t, ok)
	// authorization matched by obfuscate rule first
	assert.Equal(t, "***", span.RequestHeaders["authorization"][0])
	// x-custom matched by include-all rule second
	assert.Equal(t, "val", span.RequestHeaders["x-custom"][0])
}

func TestGRPCMetadataEnricher_ScopeRequest(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionExclude, "***", []config.GRPCParsingRule{
		{
			Action: config.ParsingActionInclude,
			Scope:  config.ParsingScopeRequest,
			Match:  config.GRPCParsingMatch{Patterns: []services.GlobAttr{grpcGlob("x-custom")}},
		},
	})
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{"x-custom": {"req-val"}}
	respMD := map[string][]string{"x-custom": {"resp-val"}}

	ok := e.Enrich(span, reqMD, respMD)
	require.True(t, ok)
	assert.Equal(t, map[string][]string{"x-custom": {"req-val"}}, span.RequestHeaders)
	// response excluded because rule scope is request-only
	assert.Nil(t, span.ResponseHeaders)
}

func TestGRPCMetadataEnricher_ScopeResponse(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionExclude, "***", []config.GRPCParsingRule{
		{
			Action: config.ParsingActionInclude,
			Scope:  config.ParsingScopeResponse,
			Match:  config.GRPCParsingMatch{Patterns: []services.GlobAttr{grpcGlob("x-custom")}},
		},
	})
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{"x-custom": {"req-val"}}
	respMD := map[string][]string{"x-custom": {"resp-val"}}

	ok := e.Enrich(span, reqMD, respMD)
	require.True(t, ok)
	assert.Nil(t, span.RequestHeaders)
	assert.Equal(t, map[string][]string{"x-custom": {"resp-val"}}, span.ResponseHeaders)
}

func TestGRPCMetadataEnricher_RPCMethodPattern(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionExclude, "***", []config.GRPCParsingRule{
		{
			Action: config.ParsingActionInclude,
			Scope:  config.ParsingScopeAll,
			Match: config.GRPCParsingMatch{
				Patterns:          []services.GlobAttr{grpcGlob("x-custom")},
				RPCMethodPatterns: []services.GlobAttr{grpcGlob("/routeguide.RouteGuide/*")},
			},
		},
	})

	// matching RPC method
	span1 := &request.Span{Path: "/routeguide.RouteGuide/GetFeature"}
	ok := e.Enrich(span1, map[string][]string{"x-custom": {"val"}}, nil)
	require.True(t, ok)
	assert.Equal(t, "val", span1.RequestHeaders["x-custom"][0])

	// non-matching RPC method
	span2 := &request.Span{Path: "/other.Service/Method"}
	ok = e.Enrich(span2, map[string][]string{"x-custom": {"val"}}, nil)
	assert.False(t, ok)
}

func TestGRPCMetadataEnricher_CaseInsensitive(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionExclude, "***", []config.GRPCParsingRule{
		{
			Action: config.ParsingActionInclude,
			Scope:  config.ParsingScopeAll,
			Match: config.GRPCParsingMatch{
				Patterns:      []services.GlobAttr{grpcGlob("x-custom-*")},
				CaseSensitive: false,
			},
		},
	})
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{
		"X-Custom-Foo": {"val1"},
		"x-custom-bar": {"val2"},
	}

	ok := e.Enrich(span, reqMD, nil)
	require.True(t, ok)
	assert.Contains(t, span.RequestHeaders, "X-Custom-Foo")
	assert.Contains(t, span.RequestHeaders, "x-custom-bar")
}

func TestGRPCMetadataEnricher_MultipleGlobsInRule(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionExclude, "***", []config.GRPCParsingRule{
		{
			Action: config.ParsingActionInclude,
			Scope:  config.ParsingScopeAll,
			Match: config.GRPCParsingMatch{
				Patterns: []services.GlobAttr{grpcGlob("x-req-*"), grpcGlob("x-trace-*")},
			},
		},
	})
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{
		"x-req-id":   {"123"},
		"x-trace-id": {"abc"},
		"x-other":    {"excluded"},
	}

	ok := e.Enrich(span, reqMD, nil)
	require.True(t, ok)
	assert.Contains(t, span.RequestHeaders, "x-req-id")
	assert.Contains(t, span.RequestHeaders, "x-trace-id")
	assert.NotContains(t, span.RequestHeaders, "x-other")
}

func TestGRPCMetadataEnricher_EmptyMetadata(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionInclude, "***", nil)
	span := &request.Span{Path: "/pkg.Svc/Method"}

	ok := e.Enrich(span, nil, nil)
	assert.False(t, ok)
	assert.Nil(t, span.RequestHeaders)
	assert.Nil(t, span.ResponseHeaders)
}

func TestGRPCMetadataEnricher_ExcludeBeforeInclude(t *testing.T) {
	e := newGRPCEnricher(config.ParsingActionInclude, "***", []config.GRPCParsingRule{
		{
			Action: config.ParsingActionExclude,
			Scope:  config.ParsingScopeAll,
			Match:  config.GRPCParsingMatch{Patterns: []services.GlobAttr{grpcGlob("authorization")}},
		},
		{
			Action: config.ParsingActionInclude,
			Scope:  config.ParsingScopeAll,
			Match:  config.GRPCParsingMatch{Patterns: []services.GlobAttr{grpcGlob("*")}},
		},
	})
	span := &request.Span{Path: "/pkg.Svc/Method"}
	reqMD := map[string][]string{
		"authorization": {"secret"},
		"x-custom":      {"val"},
	}

	ok := e.Enrich(span, reqMD, nil)
	require.True(t, ok)
	assert.NotContains(t, span.RequestHeaders, "authorization")
	assert.Contains(t, span.RequestHeaders, "x-custom")
}
