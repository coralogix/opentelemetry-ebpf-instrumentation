// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const registryGroups = "../../schemas/obi/groups"

type groupFile struct {
	Groups []struct {
		ID   string `yaml:"id"`
		Type string `yaml:"type"`
	} `yaml:"groups"`
}

func declaredSpanTypes(t *testing.T) []string {
	t.Helper()
	var types []string
	err := filepath.WalkDir(registryGroups, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var gf groupFile
		if err := yaml.Unmarshal(raw, &gf); err != nil {
			return err
		}
		for _, g := range gf.Groups {
			if g.Type == "span" {
				types = append(types, strings.TrimPrefix(g.ID, "span."))
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, types, "found no span groups under %s", registryGroups)
	return types
}

func TestEveryDeclaredSpanTypeHasAClassifierRule(t *testing.T) {
	ruled := map[string]struct{}{}
	for _, ty := range RuleTypes() {
		ruled[ty] = struct{}{}
	}
	for _, declared := range declaredSpanTypes(t) {
		assert.Containsf(t, ruled, declared,
			"span type %q is declared in the registry but no classifier rule can produce it, so its coverage would always read as zero", declared)
	}
}

func TestEveryClassifierRuleNamesADeclaredSpanType(t *testing.T) {
	declared := map[string]struct{}{}
	for _, ty := range declaredSpanTypes(t) {
		declared[ty] = struct{}{}
	}
	for _, ty := range RuleTypes() {
		assert.Containsf(t, declared, ty,
			"classifier rule produces span type %q, which the registry does not declare", ty)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name  string
		shape SpanShape
		want  string
	}{
		{
			name:  "http server",
			shape: SpanShape{Kind: "server", Attributes: []string{"http.request.method", "url.path", "server.address"}},
			want:  "obi.http.server",
		},
		{
			name:  "http client",
			shape: SpanShape{Kind: "client", Attributes: []string{"http.request.method", "url.full"}},
			want:  "obi.http.client",
		},
		{
			name:  "graphql stays an http server span",
			shape: SpanShape{Kind: "server", Attributes: []string{"http.request.method", "graphql.operation.name"}},
			want:  "obi.http.server",
		},
		{
			name:  "mcp on the server span stays http",
			shape: SpanShape{Kind: "server", Attributes: []string{"http.request.method", "mcp.method.name"}},
			want:  "obi.http.server",
		},
		{
			name: "aws s3 client",
			shape: SpanShape{
				Kind:           "client",
				Attributes:     []string{"rpc.system.name", "rpc.method", "aws.s3.bucket"},
				Discriminators: map[string]string{"rpc.system.name": "aws-api"},
			},
			want: "obi.aws.client",
		},
		{
			name: "aws sqs carries messaging attributes but is still an aws span",
			shape: SpanShape{
				Kind:           "client",
				Attributes:     []string{"aws.sqs.queue.url", "messaging.destination.name", "messaging.operation.type", "rpc.system.name"},
				Discriminators: map[string]string{"rpc.system.name": "aws-api", "messaging.system": "aws_sqs"},
			},
			want: "obi.aws.client",
		},
		{
			name: "bedrock carries an aws attribute but is a gen_ai inference span",
			shape: SpanShape{
				Kind:           "client",
				Attributes:     []string{"aws.bedrock.guardrail.id", "gen_ai.request.model", "gen_ai.provider.name"},
				Discriminators: map[string]string{"gen_ai.operation.name": "chat"},
			},
			want: "obi.gen_ai.inference.client",
		},
		{
			name:  "mcp client is its own span type, not a gen_ai operation",
			shape: SpanShape{Kind: "client", Attributes: []string{"mcp.method.name", "mcp.session.id", "gen_ai.operation.name"}, Discriminators: map[string]string{"gen_ai.operation.name": "execute_tool"}},
			want:  "obi.mcp.client",
		},
		{
			name:  "embeddings operation selects the embeddings span type",
			shape: SpanShape{Kind: "client", Attributes: []string{"gen_ai.operation.name", "gen_ai.request.model"}, Discriminators: map[string]string{"gen_ai.operation.name": "embeddings"}},
			want:  "obi.gen_ai.embeddings.client",
		},
		{
			name:  "rerank operation selects the retrieval span type",
			shape: SpanShape{Kind: "client", Attributes: []string{"gen_ai.operation.name", "gen_ai.rerank.top_n"}, Discriminators: map[string]string{"gen_ai.operation.name": "rerank"}},
			want:  "obi.gen_ai.retrieval.client",
		},
		{
			name:  "an unrecognized gen_ai operation falls back to inference",
			shape: SpanShape{Kind: "client", Attributes: []string{"gen_ai.operation.name", "gen_ai.provider.name"}, Discriminators: map[string]string{"gen_ai.operation.name": "invoke_agent"}},
			want:  "obi.gen_ai.inference.client",
		},
		{
			name: "elasticsearch wins over the generic db client",
			shape: SpanShape{
				Kind:           "client",
				Attributes:     []string{"db.system.name", "db.operation.name", "elasticsearch.node.name"},
				Discriminators: map[string]string{"db.system.name": "elasticsearch"},
			},
			want: "obi.elasticsearch.client",
		},
		{
			name: "generic db client",
			shape: SpanShape{
				Kind:           "client",
				Attributes:     []string{"db.system.name", "db.query.text"},
				Discriminators: map[string]string{"db.system.name": "postgresql"},
			},
			want: "obi.db.client",
		},
		{
			name: "db server",
			shape: SpanShape{
				Kind:           "server",
				Attributes:     []string{"db.system.name", "db.operation.name"},
				Discriminators: map[string]string{"db.system.name": "redis"},
			},
			want: "obi.db.server",
		},
		{
			name:  "messaging producer by kind",
			shape: SpanShape{Kind: "producer", Attributes: []string{"messaging.system", "messaging.destination.name"}},
			want:  "obi.messaging.producer",
		},
		{
			name:  "messaging consumer by kind",
			shape: SpanShape{Kind: "consumer", Attributes: []string{"messaging.system", "messaging.kafka.offset"}},
			want:  "obi.messaging.consumer",
		},
		{
			name:  "grpc client",
			shape: SpanShape{Kind: "client", Attributes: []string{"rpc.system.name", "rpc.method"}, Discriminators: map[string]string{"rpc.system.name": "grpc"}},
			want:  "obi.rpc.client",
		},
		{
			name:  "sunrpc server",
			shape: SpanShape{Kind: "server", Attributes: []string{"onc_rpc.procedure.name", "onc_rpc.program.name"}},
			want:  "obi.rpc.server",
		},
		{
			name:  "dns by kind",
			shape: SpanShape{Kind: "internal", Attributes: []string{"dns.question.name", "server.address"}},
			want:  "obi.dns",
		},
		{
			name:  "dns without its optional question attribute",
			shape: SpanShape{Kind: "internal", Attributes: []string{"server.address", "server.port"}},
			want:  "obi.dns",
		},
		{
			name:  "failed connect by handshake role",
			shape: SpanShape{Kind: "client", Attributes: []string{"network.tcp.handshake.role", "error.type", "server.address"}},
			want:  "obi.failed_connect",
		},
		{
			name:  "failed connect by absence of any protocol attribute",
			shape: SpanShape{Kind: "client", Attributes: []string{"server.address", "server.port", "error.type"}},
			want:  "obi.failed_connect",
		},
		{
			name:  "a server span with no protocol attribute matches nothing",
			shape: SpanShape{Kind: "server", Attributes: []string{"server.address"}},
			want:  Unclassified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Classify(tt.shape))
		})
	}
}

func TestClassifyIsExhaustiveOverDeclaredTypes(t *testing.T) {
	produced := map[string]struct{}{}
	for _, tt := range classifierFixtures() {
		if ty := Classify(tt); ty != Unclassified {
			produced[ty] = struct{}{}
		}
	}
	for _, declared := range declaredSpanTypes(t) {
		assert.Containsf(t, produced, declared,
			"no fixture in this test file classifies as %q, so the rule that produces it is unexercised", declared)
	}
}

func classifierFixtures() []SpanShape {
	return []SpanShape{
		{Kind: "server", Attributes: []string{"http.request.method"}},
		{Kind: "client", Attributes: []string{"http.request.method"}},
		{Kind: "client", Attributes: []string{"aws.s3.bucket"}},
		{Kind: "client", Attributes: []string{"gen_ai.request.model"}},
		{Kind: "client", Attributes: []string{"gen_ai.operation.name"}, Discriminators: map[string]string{"gen_ai.operation.name": "embeddings"}},
		{Kind: "client", Attributes: []string{"gen_ai.operation.name"}, Discriminators: map[string]string{"gen_ai.operation.name": "retrieval"}},
		{Kind: "client", Attributes: []string{"mcp.method.name"}},
		{Kind: "client", Attributes: []string{"db.system.name", "elasticsearch.node.name"}},
		{Kind: "client", Attributes: []string{"db.system.name"}},
		{Kind: "server", Attributes: []string{"db.system.name"}},
		{Kind: "producer", Attributes: []string{"messaging.system"}},
		{Kind: "consumer", Attributes: []string{"messaging.system"}},
		{Kind: "client", Attributes: []string{"rpc.system.name"}},
		{Kind: "server", Attributes: []string{"rpc.system.name"}},
		{Kind: "internal", Attributes: []string{"dns.question.name"}},
		{Kind: "client", Attributes: []string{"network.tcp.handshake.role"}},
	}
}
