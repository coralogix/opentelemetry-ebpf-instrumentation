// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package opamp

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestMergeOverlay(t *testing.T) {
	base := []byte(`file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      rules:
        - action: include
          match:
            process:
              open_ports: 8080
        - action: include
          match:
            process:
              open_ports: 8081
    daemon:
      logging:
        debug_trace_output: text
`)
	overlay := []byte(`extensions:
  obi:
    capture:
      rules:
        - action: include
          match:
            process:
              open_ports: 9090
    daemon:
      shutdown:
        timeout: 10s
`)

	merged, err := mergeOverlay(base, overlay)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, yaml.Unmarshal(merged, &got))
	obi := got["extensions"].(map[string]any)["obi"].(map[string]any)
	require.Equal(t, "2.0", obi["version"])
	rules := obi["capture"].(map[string]any)["rules"].([]any)
	require.Len(t, rules, 1)
	require.Equal(t, 9090, rules[0].(map[string]any)["match"].(map[string]any)["process"].(map[string]any)["open_ports"])
	daemon := obi["daemon"].(map[string]any)
	require.Equal(t, "text", daemon["logging"].(map[string]any)["debug_trace_output"])
	require.Equal(t, "10s", daemon["shutdown"].(map[string]any)["timeout"])
}

func TestMergeOverlayEmptyKeepsBase(t *testing.T) {
	base := []byte("file_format: \"1.0\"\n")
	for _, overlay := range [][]byte{nil, []byte(""), []byte("  \n")} {
		merged, err := mergeOverlay(base, overlay)
		require.NoError(t, err)
		require.Equal(t, base, merged)
	}
}

func TestMergeOverlayRejects(t *testing.T) {
	base := []byte("file_format: \"1.0\"\n")
	for name, overlay := range map[string]string{
		"local-only opamp settings": "extensions:\n  obi:\n    daemon:\n      opamp:\n        endpoint: ws://evil\n",
		"non-mapping root":          "- a\n- b\n",
		"invalid yaml":              "a: [\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := mergeOverlay(base, []byte(overlay))
			require.Error(t, err)
		})
	}
}

func TestRedactedConfig(t *testing.T) {
	data := []byte(`tracer_provider:
  processors:
    - batch:
        exporter:
          otlp_http:
            endpoint: http://collector:4318
            headers:
              - name: authorization
                value: Bearer secret
            headers_list: "api-key=secret"
extensions:
  obi:
    daemon:
      opamp:
        endpoint: ws://server
        headers:
          Authorization: secret
`)
	redactedData, err := redactedConfig(data)
	require.NoError(t, err)
	require.NotContains(t, string(redactedData), "secret")
	require.Contains(t, string(redactedData), "name: authorization")
	require.Contains(t, string(redactedData), "http://collector:4318")
	require.Contains(t, string(redactedData), "ws://server")
}
