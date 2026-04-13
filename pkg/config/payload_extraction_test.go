// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestEnrichmentConfig_Validate_HeaderRules(t *testing.T) {
	tests := []struct {
		name    string
		rules   []ParsingRule
		wantErr string
	}{
		{
			name: "valid header rule",
			rules: []ParsingRule{
				{
					Action: ParsingActionInclude,
					Type:   ParsingRuleTypeHeaders,
					Scope:  ParsingScopeAll,
					Match: ParsingMatch{
						Patterns: []services.GlobAttr{services.NewGlob("Content-Type")},
					},
				},
			},
		},
		{
			name: "header rule without patterns",
			rules: []ParsingRule{
				{
					Action: ParsingActionInclude,
					Type:   ParsingRuleTypeHeaders,
					Scope:  ParsingScopeAll,
					Match:  ParsingMatch{},
				},
			},
			wantErr: "rule 0: header rules require at least one pattern",
		},
		{
			name: "header rule with obfuscation_json_paths",
			rules: []ParsingRule{
				{
					Action: ParsingActionObfuscate,
					Type:   ParsingRuleTypeHeaders,
					Scope:  ParsingScopeAll,
					Match: ParsingMatch{
						Patterns:             []services.GlobAttr{services.NewGlob("Authorization")},
						ObfuscationJSONPaths: []JSONPathExpr{{str: "$.password"}},
					},
				},
			},
			wantErr: "rule 0: header rules cannot use obfuscation_json_paths",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := EnrichmentConfig{Rules: tt.rules}
			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestEnrichmentConfig_Validate_BodyRules(t *testing.T) {
	jsonPath, _ := NewJSONPathExpr("$.password")

	tests := []struct {
		name    string
		rules   []ParsingRule
		wantErr string
	}{
		{
			name: "valid body include rule",
			rules: []ParsingRule{
				{
					Action: ParsingActionInclude,
					Type:   ParsingRuleTypeBody,
					Scope:  ParsingScopeRequest,
					Match:  ParsingMatch{},
				},
			},
		},
		{
			name: "valid body obfuscate rule",
			rules: []ParsingRule{
				{
					Action: ParsingActionObfuscate,
					Type:   ParsingRuleTypeBody,
					Scope:  ParsingScopeAll,
					Match: ParsingMatch{
						ObfuscationJSONPaths: []JSONPathExpr{jsonPath},
					},
				},
			},
		},
		{
			name: "body rule with patterns",
			rules: []ParsingRule{
				{
					Action: ParsingActionInclude,
					Type:   ParsingRuleTypeBody,
					Scope:  ParsingScopeAll,
					Match: ParsingMatch{
						Patterns: []services.GlobAttr{services.NewGlob("Content-Type")},
					},
				},
			},
			wantErr: "rule 0: body rules cannot use patterns",
		},
		{
			name: "body rule with case_sensitive",
			rules: []ParsingRule{
				{
					Action: ParsingActionInclude,
					Type:   ParsingRuleTypeBody,
					Scope:  ParsingScopeAll,
					Match: ParsingMatch{
						CaseSensitive: true,
					},
				},
			},
			wantErr: "rule 0: body rules cannot use case_sensitive",
		},
		{
			name: "body obfuscate without json paths",
			rules: []ParsingRule{
				{
					Action: ParsingActionObfuscate,
					Type:   ParsingRuleTypeBody,
					Scope:  ParsingScopeAll,
					Match:  ParsingMatch{},
				},
			},
			wantErr: "rule 0: action \"obfuscate\" on body rule requires obfuscation_json_paths",
		},
		{
			name: "body include with json paths",
			rules: []ParsingRule{
				{
					Action: ParsingActionInclude,
					Type:   ParsingRuleTypeBody,
					Scope:  ParsingScopeAll,
					Match: ParsingMatch{
						ObfuscationJSONPaths: []JSONPathExpr{jsonPath},
					},
				},
			},
			wantErr: "rule 0: obfuscation_json_paths can only be used with action \"obfuscate\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := EnrichmentConfig{Rules: tt.rules}
			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestEnrichmentConfig_Validate_MultipleRules(t *testing.T) {
	jsonPath, _ := NewJSONPathExpr("$.secret")

	cfg := EnrichmentConfig{
		Rules: []ParsingRule{
			{
				Action: ParsingActionInclude,
				Type:   ParsingRuleTypeHeaders,
				Scope:  ParsingScopeAll,
				Match: ParsingMatch{
					Patterns: []services.GlobAttr{services.NewGlob("Content-Type")},
				},
			},
			{
				Action: ParsingActionObfuscate,
				Type:   ParsingRuleTypeBody,
				Scope:  ParsingScopeRequest,
				Match: ParsingMatch{
					ObfuscationJSONPaths: []JSONPathExpr{jsonPath},
				},
			},
		},
	}
	assert.NoError(t, cfg.Validate())
}

func TestEnrichmentConfig_Validate_SecondRuleInvalid(t *testing.T) {
	cfg := EnrichmentConfig{
		Rules: []ParsingRule{
			{
				Action: ParsingActionInclude,
				Type:   ParsingRuleTypeHeaders,
				Scope:  ParsingScopeAll,
				Match: ParsingMatch{
					Patterns: []services.GlobAttr{services.NewGlob("Content-Type")},
				},
			},
			{
				Action: ParsingActionInclude,
				Type:   ParsingRuleTypeHeaders,
				Scope:  ParsingScopeAll,
				Match:  ParsingMatch{},
			},
		},
	}
	assert.EqualError(t, cfg.Validate(), "rule 1: header rules require at least one pattern")
}

func TestEnrichmentConfig_Validate_EmptyRules(t *testing.T) {
	cfg := EnrichmentConfig{}
	assert.NoError(t, cfg.Validate())
}

func TestGRPCEnrichmentConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rules   []GRPCParsingRule
		wantErr string
	}{
		{
			name: "valid rule with patterns",
			rules: []GRPCParsingRule{
				{
					Action: ParsingActionInclude,
					Scope:  ParsingScopeAll,
					Match: GRPCParsingMatch{
						Patterns: []services.GlobAttr{services.NewGlob("x-custom-*")},
					},
				},
			},
		},
		{
			name: "rule without patterns",
			rules: []GRPCParsingRule{
				{
					Action: ParsingActionInclude,
					Scope:  ParsingScopeAll,
					Match:  GRPCParsingMatch{},
				},
			},
			wantErr: "rule 0: gRPC metadata rules require at least one pattern",
		},
		{
			name: "second rule invalid",
			rules: []GRPCParsingRule{
				{
					Action: ParsingActionInclude,
					Scope:  ParsingScopeAll,
					Match: GRPCParsingMatch{
						Patterns: []services.GlobAttr{services.NewGlob("authorization")},
					},
				},
				{
					Action: ParsingActionObfuscate,
					Scope:  ParsingScopeRequest,
					Match:  GRPCParsingMatch{},
				},
			},
			wantErr: "rule 1: gRPC metadata rules require at least one pattern",
		},
		{
			name:  "empty rules",
			rules: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := GRPCEnrichmentConfig{Rules: tt.rules}
			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}
