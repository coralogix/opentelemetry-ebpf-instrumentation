// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func fixtureGroups() map[string]spanGroup {
	return map[string]spanGroup{
		"common.base": {
			attrs: []string{"error.type", "network.transport"},
		},
		"common.trace": {
			extends: "common.base",
			attrs:   []string{"mcp.method.name"},
		},
		"span.mcp.client": {
			extends: "common.trace",
			attrs:   []string{"server.address", "jsonrpc.protocol.version"},
			isSpan:  true,
		},
		"span.obi.mcp.client": {
			attrs:  []string{"error.type", "mcp.method.name", "server.address", "obi.extra"},
			isSpan: true,
		},
	}
}

// TestResolveSpanAttributesFollowsExtends pins the behavior the whole span
// comparison depends on: upstream shares attributes through `extends`, so a
// comparison that reads only a group's own list understates it.
func TestResolveSpanAttributesFollowsExtends(t *testing.T) {
	got := resolveSpanAttributes(fixtureGroups(), "span.mcp.client")

	assert.True(t, got["error.type"], "inherited two levels up")
	assert.True(t, got["network.transport"], "inherited two levels up")
	assert.True(t, got["mcp.method.name"], "inherited one level up")
	assert.True(t, got["server.address"], "declared directly")
	assert.Len(t, got, 5)
}

func TestOmittedAttributesReportsUpstreamOnly(t *testing.T) {
	got := omittedAttributes(fixtureGroups(), "span.obi.mcp.client", "span.mcp.client", nil)

	assert.Equal(t, []string{"jsonrpc.protocol.version", "network.transport"}, got)
}

func TestExtraAttributesReportsOBIExtensions(t *testing.T) {
	got := extraAttributes(fixtureGroups(), "span.obi.mcp.client", "span.mcp.client")

	assert.Equal(t, []string{"obi.extra"}, got)
}

func TestOmittedAttributesEmptyWhenOBICarriesEverything(t *testing.T) {
	groups := fixtureGroups()
	groups["span.obi.mcp.client"] = spanGroup{
		extends: "common.trace",
		attrs:   []string{"server.address", "jsonrpc.protocol.version"},
		isSpan:  true,
	}

	assert.Empty(t, omittedAttributes(groups, "span.obi.mcp.client", "span.mcp.client", nil))
}

func TestOBISpanTypesFindsOnlyOBISpans(t *testing.T) {
	groups := fixtureGroups()
	groups["registry.obi.network"] = spanGroup{attrs: []string{"obi.network.flow.bytes"}}

	assert.Equal(t, []string{"span.obi.mcp.client"}, obiSpanTypes(groups))
}

// TestSpanGroupsFileParsesOBIAnnotations pins the annotation shape the span
// guards read. The divergence record lives in the schema now, so a change to
// how it is spelled has to break here rather than quietly resolve to an empty
// decision.
func TestSpanGroupsFileParsesOBIAnnotations(t *testing.T) {
	const doc = `
groups:
  - id: span.obi.http.server
    type: span
    annotations:
      obi:
        upstream_span: span.http.server
        upstream_omits:
          - client.port
          - network.transport
        upstream_absorbs:
          - id: span.mcp.server
            reason: >-
              enriched onto this span in place
    brief: OBI inbound HTTP server span.
  - id: span.obi.dns
    type: span
    annotations:
      obi:
        upstream_span: none
        upstream_absent_reason: >-
          upstream models no DNS resolution span
    brief: OBI DNS resolution span.
`

	var f spanGroupsFile
	require.NoError(t, yaml.Unmarshal([]byte(doc), &f))
	require.Len(t, f.Groups, 2)

	srv := f.Groups[0].Annotations.OBI
	assert.Equal(t, "span.http.server", srv.UpstreamSpan)
	assert.Equal(t, []string{"client.port", "network.transport"}, srv.UpstreamOmits)
	require.Len(t, srv.UpstreamAbsorbs, 1)
	assert.Equal(t, "span.mcp.server", srv.UpstreamAbsorbs[0].ID)
	assert.Equal(t, "enriched onto this span in place", srv.UpstreamAbsorbs[0].Reason)

	dns := f.Groups[1].Annotations.OBI
	assert.Equal(t, spanUpstreamNone, dns.UpstreamSpan)
	assert.Equal(t, "upstream models no DNS resolution span", dns.UpstreamAbsentReason)
	assert.Empty(t, dns.UpstreamOmits)
}

func TestComparedOBISpansSkipsOBIOnlyAndUnannotated(t *testing.T) {
	groups := fixtureGroups()

	annotated := groups["span.obi.mcp.client"]
	annotated.upstream = "span.mcp.client"
	groups["span.obi.mcp.client"] = annotated

	groups["span.obi.dns"] = spanGroup{isSpan: true, upstream: spanUpstreamNone}
	groups["span.obi.unannotated"] = spanGroup{isSpan: true}

	assert.Equal(t, []string{"span.obi.mcp.client"}, comparedOBISpans(groups))
}

func TestAcceptedOmissionsReadsUpstreamOmits(t *testing.T) {
	got := acceptedOmissions(spanGroup{omits: []string{"client.port", "network.transport"}})

	assert.Equal(t, map[string]bool{"client.port": true, "network.transport": true}, got)
	assert.Empty(t, acceptedOmissions(spanGroup{}))
}
