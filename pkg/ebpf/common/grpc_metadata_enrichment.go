// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
)

// GRPCMetadataEnricher applies gRPC metadata enrichment rules to extract
// metadata key-value pairs into spans. Rules are evaluated in order with
// first-match-wins semantics.
type GRPCMetadataEnricher struct {
	rules             []config.GRPCParsingRule
	defaultAction     config.HTTPParsingAction
	obfuscationString string
}

// NewGRPCMetadataEnricher creates an enricher from the given gRPC enrichment config.
func NewGRPCMetadataEnricher(cfg config.GRPCEnrichmentConfig) *GRPCMetadataEnricher {
	return &GRPCMetadataEnricher{
		rules:             cfg.Rules,
		defaultAction:     cfg.Policy.DefaultAction.Metadata,
		obfuscationString: cfg.Policy.ObfuscationString,
	}
}

// Enrich applies metadata extraction rules to the span.
// Returns true if any metadata was extracted.
func (e *GRPCMetadataEnricher) Enrich(
	span *request.Span,
	requestMetadata map[string][]string,
	responseMetadata map[string][]string,
) bool {
	reqMD := e.processMetadata(requestMetadata, config.HTTPParsingScopeRequest, span)
	respMD := e.processMetadata(responseMetadata, config.HTTPParsingScopeResponse, span)

	hasContent := len(reqMD) > 0 || len(respMD) > 0
	if !hasContent {
		return false
	}

	if len(reqMD) > 0 {
		span.RequestHeaders = reqMD
	}
	if len(respMD) > 0 {
		span.ResponseHeaders = respMD
	}
	return true
}

// processMetadata evaluates rules against metadata entries and returns a
// filtered map. The map is allocated lazily.
func (e *GRPCMetadataEnricher) processMetadata(
	metadata map[string][]string,
	scope config.HTTPParsingScope,
	span *request.Span,
) map[string][]string {
	var result map[string][]string
	for name, values := range metadata {
		action := e.resolveMetadataAction(name, scope, span)
		if action == config.HTTPParsingActionExclude {
			continue
		}
		if result == nil {
			result = make(map[string][]string)
		}
		grpcApplyMetadataAction(action, name, values, result, e.obfuscationString)
	}
	return result
}

// resolveMetadataAction determines the action for a given metadata key
// by evaluating rules in order (first match wins).
func (e *GRPCMetadataEnricher) resolveMetadataAction(
	metadataKey string,
	scope config.HTTPParsingScope,
	span *request.Span,
) config.HTTPParsingAction {
	var lowerName string

	for _, rule := range e.rules {
		if !grpcRuleApplies(rule, scope, span) {
			continue
		}
		matchName := metadataKey
		if !rule.Match.CaseSensitive {
			if lowerName == "" {
				lowerName = strings.ToLower(metadataKey)
			}
			matchName = lowerName
		}
		for i := range rule.Match.Patterns {
			if rule.Match.Patterns[i].MatchString(matchName) {
				return rule.Action
			}
		}
	}
	return e.defaultAction
}

// grpcRuleApplies returns true if the rule's scope and RPC method patterns match.
func grpcRuleApplies(rule config.GRPCParsingRule, scope config.HTTPParsingScope, span *request.Span) bool {
	return grpcScopeApplies(rule.Scope, scope) &&
		rpcMethodMatches(rule.Match.RPCMethodPatterns, span.Path)
}

// grpcScopeApplies returns true if the rule scope covers the given metadata source.
func grpcScopeApplies(ruleScope config.HTTPParsingScope, metadataSource config.HTTPParsingScope) bool {
	return ruleScope == config.HTTPParsingScopeAll || ruleScope == metadataSource
}

// rpcMethodMatches returns true if the RPC method path matches any of the patterns.
// If no patterns are specified, all methods match.
func rpcMethodMatches(patterns []services.GlobAttr, rpcMethod string) bool {
	if len(patterns) == 0 {
		return true
	}
	for i := range patterns {
		if patterns[i].MatchString(rpcMethod) {
			return true
		}
	}
	return false
}

// grpcApplyMetadataAction adds the metadata entry to the map based on the resolved action.
func grpcApplyMetadataAction(
	action config.HTTPParsingAction,
	name string,
	values []string,
	metadata map[string][]string,
	obfuscationString string,
) {
	switch action {
	case config.HTTPParsingActionInclude:
		metadata[name] = append(metadata[name], values...)
	case config.HTTPParsingActionObfuscate:
		metadata[name] = []string{obfuscationString}
	case config.HTTPParsingActionExclude:
		// do nothing
	}
}
