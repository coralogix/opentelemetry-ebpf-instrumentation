// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

const liveCheckTimeout = 3 * time.Minute

var defaultSpanOptional = []attr.Name{
	attr.NetworkPeerAddress,
	attr.NetworkPeerPort,
	attr.NetworkProtocolVersion,
	attr.ErrorType,
}

// matchOnlySpanCases complete emittedSpanCases so that every span definition
// has a span to match: live-check pairs them by matcher, which this test
// checks, while the exact attribute set of these is not pinned.
func matchOnlySpanCases() []emittedSpanCase {
	return []emittedSpanCase{
		{
			name:     "aws sns client",
			spanType: "obi.aws.sns.client",
			span: &request.Span{
				Type:         request.EventTypeHTTPClient,
				SubType:      request.HTTPSubtypeAWSSNS,
				Host:         "10.0.0.1",
				HostPort:     443,
				Status:       200,
				ProtoVersion: request.ProtoVersionHTTP11,
				AWS: &request.AWS{SNS: request.AWSSNS{
					Meta:          request.AWSMeta{RequestID: "req-3", Region: "us-east-1"},
					OperationName: "Publish",
					OperationType: "send",
					Destination:   "my-topic",
					TopicARN:      "arn:aws:sns:us-east-1:1:my-topic",
					MessageID:     "msg-2",
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "redis client",
			spanType: "obi.db.client",
			span: &request.Span{
				Type:     request.EventTypeRedisClient,
				Method:   "GET",
				Path:     "GET my-key",
				Host:     "10.0.0.1",
				HostPort: 6379,
				Peer:     "10.0.0.2",
				PeerPort: 54321,
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "redis server",
			spanType: "obi.db.server",
			span: &request.Span{
				Type:     request.EventTypeRedisServer,
				Method:   "SET",
				Host:     "10.0.0.1",
				HostPort: 6379,
				Peer:     "10.0.0.2",
				PeerPort: 54321,
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "dns",
			spanType: "obi.dns",
			span: &request.Span{
				Type:      request.EventTypeDNS,
				Method:    "A",
				Path:      "example.com",
				Statement: "93.184.216.34",
				Host:      "10.0.0.2",
				HostPort:  53,
				Peer:      "10.0.0.53",
			},
			optional: append([]attr.Name{attr.DNSQuestionName}, defaultSpanOptional...),
		},
		{
			name:     "failed connect",
			spanType: "obi.failed_connect",
			span: &request.Span{
				Type:     request.EventTypeFailedConnect,
				Host:     "10.0.0.1",
				HostPort: 8080,
				Peer:     "10.0.0.2",
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "gen_ai inference client",
			spanType: "obi.gen_ai.inference.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeOpenAI,
				Host:     "10.0.0.1",
				HostPort: 443,
				Status:   200,
				GenAI: &request.GenAI{OpenAI: &request.VendorOpenAI{
					OperationName: "chat.completion",
					ResponseModel: "gpt-4o-2024-08-06",
					ID:            "chatcmpl-1",
					Request:       request.OpenAIInput{Model: "gpt-4o"},
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "gen_ai embeddings client",
			spanType: "obi.gen_ai.embeddings.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeEmbedding,
				Host:     "10.0.0.1",
				HostPort: 443,
				Status:   200,
				GenAI: &request.GenAI{Embedding: &request.VendorEmbedding{
					Provider: "voyage",
					Model:    "voyage-3",
					Input:    request.EmbeddingRequest{Model: "voyage-3"},
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "gen_ai retrieval client",
			spanType: "obi.gen_ai.retrieval.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeRetrieval,
				Host:     "10.0.0.1",
				HostPort: 443,
				Status:   200,
				GenAI: &request.GenAI{Retrieval: &request.VendorRetrieval{
					Provider: "pinecone",
					Input:    request.RetrievalRequest{Namespace: "docs", TopK: 5},
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "gen_ai rerank client",
			spanType: "obi.gen_ai.rerank.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeRerank,
				Host:     "10.0.0.1",
				HostPort: 443,
				Status:   200,
				GenAI: &request.GenAI{Rerank: &request.VendorRerank{
					Provider: "cohere",
					Input:    request.RerankRequest{Model: "rerank-v3.5", TopN: 3},
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "mcp client",
			spanType: "obi.mcp.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeMCP,
				Host:     "10.0.0.1",
				HostPort: 8000,
				Status:   200,
				GenAI: &request.GenAI{MCP: &request.MCPCall{
					Method:      request.MCPMethodToolsCall,
					ToolName:    "search",
					SessionID:   "s-1",
					ProtocolVer: "2025-06-18",
					RequestID:   "1",
				}},
			},
			optional: defaultSpanOptional,
		},
	}
}

type liveCheckAttribute struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

type liveCheckSpan struct {
	Name       string               `json:"name"`
	Kind       string               `json:"kind"`
	Attributes []liveCheckAttribute `json:"attributes"`
}

type liveCheckSample struct {
	Span liveCheckSpan `json:"span"`
}

// exportedSpan renders a span through the trace exporter and returns it as a
// live-check sample: the name, kind and attributes OTLP carries.
func exportedSpan(t *testing.T, span *request.Span, optional []attr.Name) liveCheckSample {
	t.Helper()

	selected := make(map[attr.Name]struct{}, len(optional))
	for _, name := range optional {
		selected[name] = struct{}{}
	}

	cache := expirable.NewLRU[svc.UID, []attribute.KeyValue](1, nil, time.Minute)
	traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, nil, &meta.NodeMeta{},
		[]tracesgen.TraceSpanAndAttributes{{Span: span, Attributes: tracesgen.TraceAttributesSelector(span, selected)}},
		"obi")
	require.Equal(t, 1, traces.SpanCount(), "the exporter should produce exactly one span")

	return liveCheckSampleOf(traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0))
}

// exportedRequestPhases renders a server span whose request waited before it
// was processed and returns the "in queue" and "processing" children the
// exporter adds under it.
func exportedRequestPhases(t *testing.T) []liveCheckSample {
	t.Helper()

	start := time.Now()
	span := &request.Span{
		Type:         request.EventTypeHTTP,
		Method:       "GET",
		Path:         "/users",
		Host:         "10.0.0.1",
		HostPort:     8080,
		Status:       200,
		RequestStart: start.UnixNano(),
		Start:        start.Add(time.Millisecond).UnixNano(),
		End:          start.Add(2 * time.Millisecond).UnixNano(),
	}

	cache := expirable.NewLRU[svc.UID, []attribute.KeyValue](1, nil, time.Minute)
	traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, nil, &meta.NodeMeta{},
		[]tracesgen.TraceSpanAndAttributes{{Span: span, Attributes: tracesgen.TraceAttributesSelector(span, nil)}},
		"obi")

	spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	var phases []liveCheckSample
	for i := range spans.Len() {
		if s := spans.At(i); s.Kind() == ptrace.SpanKindInternal {
			phases = append(phases, liveCheckSampleOf(s))
		}
	}
	require.Len(t, phases, 2, "the exporter should add an in-queue and a processing span")
	return phases
}

func liveCheckSampleOf(exported ptrace.Span) liveCheckSample {
	sample := liveCheckSpan{
		Name:       exported.Name(),
		Kind:       strings.ToLower(exported.Kind().String()),
		Attributes: []liveCheckAttribute{},
	}
	for key, value := range exported.Attributes().All() {
		sample.Attributes = append(sample.Attributes, liveCheckAttribute{Name: key, Value: value.AsRaw()})
	}
	return liveCheckSample{Span: sample}
}

type liveCheckFinding struct {
	ID      string `json:"id"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type liveCheckResult struct {
	AllAdvice []liveCheckFinding `json:"all_advice"`
	MatchInfo *struct {
		Signal  string `json:"signal"`
		Entries []struct {
			Matcher string `json:"matcher"`
			Ignored bool   `json:"ignored"`
		} `json:"entries"`
	} `json:"match_info"`
}

type liveCheckReport struct {
	Samples []struct {
		Span *struct {
			Name             string          `json:"name"`
			LiveCheckResult  liveCheckResult `json:"live_check_result"`
			AttributeResults []struct {
				Name            string          `json:"name"`
				LiveCheckResult liveCheckResult `json:"live_check_result"`
			} `json:"attributes"`
		} `json:"span"`
	} `json:"samples"`
}

// liveCheck feeds the samples to `weaver registry live-check`, configured by
// schemas/obi/.weaver.toml, and returns its JSON report.
func liveCheck(t *testing.T, samples []liveCheckSample) liveCheckReport {
	t.Helper()
	ociBin := requireWeaverRuntime(t)

	input, err := json.Marshal(samples)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), liveCheckTimeout)
	defer cancel()

	cmd := weaverCommand(ctx, t, ociBin,
		"registry", "live-check", "--registry", "/obi-registry",
		"--input-source", "stdin", "--input-format", "json",
		"--format", "json", "--no-stream")
	cmd.Stdin = bytes.NewReader(input)

	// live-check exits non-zero when it reports a violation, which the
	// assertions below surface in detail; only a missing report is fatal here.
	out, runErr := cmd.Output()
	var report liveCheckReport
	if jsonErr := json.Unmarshal(out, &report); jsonErr != nil {
		var stderr []byte
		if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
			stderr = exitErr.Stderr
		}
		require.NoErrorf(t, jsonErr, "weaver live-check produced no parseable report (run error: %v)\n%s", runErr, stderr)
	}
	return report
}

// Live-check pairs a span with its span definition only through the matchers
// in schemas/obi/.weaver.toml. Every span the exporter builds must be paired by
// exactly one matcher with the definition that describes it, with the kind that
// definition declares and a name its templates render. Other findings are the
// weaver-validated suites' to enforce, so they are only logged here.
func TestEmittedSpansMatchTheirDeclaredSpan(t *testing.T) {
	cases := append(emittedSpanCases(), matchOnlySpanCases()...)

	samples := make([]liveCheckSample, 0, len(cases))
	spanTypes := make([]string, 0, len(cases))
	names := make([]string, 0, len(cases))
	for _, tc := range cases {
		samples = append(samples, exportedSpan(t, tc.span, tc.optional))
		spanTypes = append(spanTypes, tc.spanType)
		names = append(names, tc.name)
	}
	for _, phase := range exportedRequestPhases(t) {
		samples = append(samples, phase)
		spanTypes = append(spanTypes, "obi.request.phase")
		names = append(names, "request phase "+phase.Span.Name)
	}

	report := liveCheck(t, samples)
	require.Len(t, report.Samples, len(samples), "live-check should report one sample per span")

	covered := map[string]struct{}{}
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			span := report.Samples[i].Span
			require.NotNil(t, span, "sample %d is not a span", i)
			result := span.LiveCheckResult
			require.NotNil(t, result.MatchInfo, "span %q has no match info", span.Name)

			assert.Equalf(t, spanTypes[i], result.MatchInfo.Signal,
				"span %q was compared with %q", span.Name, result.MatchInfo.Signal)
			assert.Lenf(t, result.MatchInfo.Entries, 1,
				"span %q should be selected by exactly one matcher, got %+v", span.Name, result.MatchInfo.Entries)

			findings := result.AllAdvice
			for _, a := range span.AttributeResults {
				findings = append(findings, a.LiveCheckResult.AllAdvice...)
			}
			for _, f := range findings {
				assert.NotContainsf(t, []string{"kind_mismatch", "span_name_mismatch"}, f.ID,
					"span %q: %s", span.Name, f.Message)
				assert.NotEqualf(t, "violation", f.Level, "span %q: [%s] %s", span.Name, f.ID, f.Message)
			}
			covered[spanTypes[i]] = struct{}{}
		})
	}

	for _, f := range registryFiles(t) {
		for _, s := range f.Spans {
			assert.Containsf(t, covered, s.Type, "no span case covers span definition %q", s.Type)
		}
	}
}
