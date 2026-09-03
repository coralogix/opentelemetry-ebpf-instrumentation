// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

const Unclassified = ""

type shape struct {
	kind  string
	attrs map[string]struct{}
	disc  map[string]string
}

func (s shape) has(name string) bool {
	_, ok := s.attrs[name]
	return ok
}

func (s shape) hasPrefix(prefixes ...string) bool {
	for a := range s.attrs {
		for _, p := range prefixes {
			if strings.HasPrefix(a, p) {
				return true
			}
		}
	}
	return false
}

func (s shape) discIs(name, value string) bool {
	return s.disc[name] == value
}

func (s shape) protocolMarked() bool {
	return s.has("http.request.method") ||
		s.has("db.system.name") ||
		s.has("rpc.system.name") ||
		s.has("messaging.system") ||
		s.hasPrefix("gen_ai.", "mcp.", "openai.", "aws.", "onc_rpc.", "dns.", "elasticsearch.")
}

type rule struct {
	types []string
	match func(shape) string
}

var rules = []rule{
	// The timing children createSubSpans attaches to every request span are
	// internal and carry no attributes at all. Matched before DNS, which is
	// the other internal-kind type and is recognized by having any attribute
	// — dns.question.name is opt_in, so a DNS span may carry only its
	// connection attributes.
	{
		types: []string{"obi.subspan"},
		match: func(s shape) string {
			if s.kind == "internal" && len(s.attrs) == 0 {
				return "obi.subspan"
			}
			return Unclassified
		},
	},
	// DNS is the only internal-kind declared type, but matching on kind alone
	// would also swallow any other span that reaches internal kind — a
	// messaging span whose operation type did not map, for instance. A DNS
	// span carries its connection attributes and no other protocol's marker;
	// dns.question.name itself is opt_in, so it cannot be required here.
	{
		types: []string{"obi.dns"},
		match: func(s shape) string {
			if s.kind != "internal" || len(s.attrs) == 0 {
				return Unclassified
			}
			if s.hasPrefix("dns.") || !s.protocolMarked() {
				return "obi.dns"
			}
			return Unclassified
		},
	},
	// A server-kind span carrying messaging attributes is deliberately left
	// unclassified. Semantic conventions define messaging spans as producer or
	// consumer only, and OBI reaches server kind for them by inferring
	// direction from whether the first operation it observed on the connection
	// was a receive — which mislabels a messaging client whose connection
	// predates the agent. Declaring a span type for it would write that into
	// the contract; failing it keeps the emitter bug visible.
	{
		types: []string{"obi.messaging.producer", "obi.messaging.consumer"},
		match: func(s shape) string {
			switch s.kind {
			case "producer":
				return "obi.messaging.producer"
			case "consumer":
				return "obi.messaging.consumer"
			}
			return Unclassified
		},
	},
	// MCP is its own span type upstream rather than a GenAI operation, and it
	// is matched first because an MCP call also carries gen_ai attributes.
	{
		types: []string{"obi.mcp.client"},
		match: func(s shape) string {
			if s.kind == "client" && s.hasPrefix("mcp.") {
				return "obi.mcp.client"
			}
			return Unclassified
		},
	},
	// GenAI operations are split the way upstream splits them, keyed on the
	// operation name OBI already emits. An unrecognized operation is inference
	// rather than unclassified: chat and text completion are the default
	// shape, and a new operation name should read as an under-declared
	// inference span rather than vanish from coverage.
	{
		types: []string{
			"obi.gen_ai.inference.client",
			"obi.gen_ai.embeddings.client",
			"obi.gen_ai.retrieval.client",
		},
		match: func(s shape) string {
			if s.kind != "client" || !s.hasPrefix("gen_ai.", "openai.") {
				return Unclassified
			}
			switch s.disc["gen_ai.operation.name"] {
			case "embeddings":
				return "obi.gen_ai.embeddings.client"
			case "retrieval", "rerank":
				return "obi.gen_ai.retrieval.client"
			}
			return "obi.gen_ai.inference.client"
		},
	},
	{
		types: []string{"obi.aws.client"},
		match: func(s shape) string {
			if s.kind != "client" {
				return Unclassified
			}
			if s.discIs("rpc.system.name", "aws-api") || s.hasPrefix("aws.") {
				return "obi.aws.client"
			}
			return Unclassified
		},
	},
	{
		types: []string{"obi.elasticsearch.client"},
		match: func(s shape) string {
			if s.kind != "client" {
				return Unclassified
			}
			if s.has("elasticsearch.node.name") || s.discIs("db.system.name", "elasticsearch") {
				return "obi.elasticsearch.client"
			}
			return Unclassified
		},
	},
	{
		types: []string{"obi.db.client", "obi.db.server"},
		match: func(s shape) string {
			if !s.has("db.system.name") {
				return Unclassified
			}
			switch s.kind {
			case "client":
				return "obi.db.client"
			case "server":
				return "obi.db.server"
			}
			return Unclassified
		},
	},
	// HTTP is matched before RPC. An OBI HTTP server span keeps the HTTP
	// attributes even when it also carries the JSON-RPC, MCP or GraphQL
	// attributes OBI enriches it with in place, and it is still an HTTP server
	// request. A real RPC span carries no http.request.method, so it cannot be
	// caught here.
	{
		types: []string{"obi.http.client", "obi.http.server"},
		match: func(s shape) string {
			if !s.has("http.request.method") {
				return Unclassified
			}
			switch s.kind {
			case "client":
				return "obi.http.client"
			case "server":
				return "obi.http.server"
			}
			return Unclassified
		},
	},
	{
		types: []string{"obi.rpc.client", "obi.rpc.server"},
		match: func(s shape) string {
			if !s.has("rpc.system.name") && !s.hasPrefix("onc_rpc.") {
				return Unclassified
			}
			switch s.kind {
			case "client":
				return "obi.rpc.client"
			case "server":
				return "obi.rpc.server"
			}
			return Unclassified
		},
	},
	{
		types: []string{"obi.failed_connect"},
		match: func(s shape) string {
			if s.kind == "client" && (s.has("network.tcp.handshake.role") || !s.protocolMarked()) {
				return "obi.failed_connect"
			}
			return Unclassified
		},
	},
}

func Classify(s SpanShape) string {
	sh := shape{kind: s.Kind, attrs: make(map[string]struct{}, len(s.Attributes)), disc: s.Discriminators}
	for _, a := range s.Attributes {
		sh.attrs[a] = struct{}{}
	}
	for _, r := range rules {
		if t := r.match(sh); t != Unclassified {
			return t
		}
	}
	return Unclassified
}

func RuleTypes() []string {
	var out []string
	for _, r := range rules {
		out = append(out, r.types...)
	}
	return out
}
