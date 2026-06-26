// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	customSpanCPort      = "8390"
	customSpanPythonPort = "8392"
	customSpanRubyPort   = "8393"
	customSpanGoPort     = "8394"
	customSpanJavaPort   = "8395"
	customSpanNodejsPort = "8396"
	customSpanCppPort    = "8397"
	customSpanRustPort   = "8398"
)

// TestCustomSpan asserts OBI emits user-declared spans for every supported
// language flavor:
//   - C (static .note.stapsdt via <sys/sdt.h>) — paired, single, function-mode (both shapes), match-filter
//   - Python (libstapsdt-backed runtime probes via python-stapsdt)
//   - Ruby (libstapsdt via ruby-stapsdt)
//   - Go (salp runtime-registered USDT). Go binaries route to gotracer;
//     finder.newGoTracersGroup additionally attaches generictracer when
//     custom_span is configured so probes register, and gotracer routes
//     EVENT_CUSTOM_SPAN records via EBPFEventContext.CustomSpanHandler.
//   - Java (JNI bridge to libstapsdt). HotSpot's built-in
//     hotspot:method__entry requires DTraceMethodProbes which is develop-only
//     in distro JDKs; the JNI path mirrors python-stapsdt / ruby-stapsdt /
//     salp and registers custom_span_java:order probes at runtime.
//   - Node.js (Node-API addon over libstapsdt). dtrace-provider relies on
//     libusdt which has no arm64 path; the N-API addon reuses our vendored
//     libstapsdt-arm64 fork the same way the JNI bridge does.
//   - C++ with folly's FOLLY_SDT_WITH_SEMAPHORE macro. The only sample that
//     exercises the semaphore-gated probe path — OBI bumps a u16 semaphore
//     via link.UprobeOptions.RefCtrOffset at attach time so the probe's
//     inline-asm body skips its body when no consumer is attached.
//   - Rust via the `usdt` crate (oxidecomputer). Stable inline-asm-emitted
//     .note.stapsdt notes in the binary; covers usdt_span + usdt_noret.
func TestCustomSpan(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-custom-span.yml", path.Join(pathOutput, "test-suite-custom-span.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Cleanup(func() { require.NoError(t, compose.Close()) })

	waitForCustomSpanServices(t)

	tracesPath := path.Join(pathOutput, "custom-span-traces.json")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for i := 1; i <= 5; i++ {
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/order?id=%d&customer=alice%d", customSpanCPort, i, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/cache?key=user:%d", customSpanCPort, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/order?id=%d&customer=bob%d", customSpanPythonPort, 100+i, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/cache?key=cart:%d", customSpanPythonPort, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/order?id=%d&customer=carol%d", customSpanRubyPort, 200+i, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/cache?key=stock:%d", customSpanRubyPort, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/order?id=%d&customer=dave%d", customSpanGoPort, 300+i, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/cache?key=sku:%d", customSpanGoPort, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/order?id=%d&customer=eve%d", customSpanJavaPort, 400+i, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/cache?key=jdk:%d", customSpanJavaPort, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/order?id=%d&customer=frank%d", customSpanNodejsPort, 500+i, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/cache?key=node:%d", customSpanNodejsPort, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/order?id=%d&customer=grace%d", customSpanCppPort, 600+i, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/cache?key=cpp:%d", customSpanCppPort, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/order?id=%d&customer=heidi%d", customSpanRustPort, 700+i, i), http.StatusOK)
			ti.DoHTTPGet(ct, fmt.Sprintf("http://localhost:%s/cache?key=rust:%d", customSpanRustPort, i), http.StatusOK)
		}
		spans := readCustomSpanSpecs(ct, tracesPath)
		assert.NotEmpty(ct, spansByName(spans, "order.process"), "expected C paired spans")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit"), "expected C single-shot spans")
		assert.NotEmpty(ct, spansByName(spans, "order.process.py"), "expected Python paired spans")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.py"), "expected Python single-shot spans")
		assert.NotEmpty(ct, spansByName(spans, "order.process.rb"), "expected Ruby paired spans")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.rb"), "expected Ruby single-shot spans")
		assert.NotEmpty(ct, spansByName(spans, "order.process.go"), "expected Go paired spans")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.go"), "expected Go single-shot spans")
		assert.NotEmpty(ct, spansByName(spans, "order.process.java"), "expected Java paired spans (libstapsdt via JNI)")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.java"), "expected Java single-shot spans (libstapsdt via JNI)")
		assert.NotEmpty(ct, spansByName(spans, "order.process.nodejs"), "expected Node.js paired spans (libstapsdt via N-API)")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.nodejs"), "expected Node.js single-shot spans (libstapsdt via N-API)")
		assert.NotEmpty(ct, spansByName(spans, "order.process.cpp"), "expected C++ folly SDT paired spans (semaphored)")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.cpp"), "expected C++ folly SDT single-shot spans (semaphored)")
		assert.NotEmpty(ct, spansByName(spans, "order.process.rust"), "expected Rust paired spans (usdt crate)")
		assert.NotEmpty(ct, spansByName(spans, "cache.hit.rust"), "expected Rust single-shot spans (usdt crate)")
		assert.NotEmpty(ct, spansByName(spans, "order.func.go"), "expected Go function-mode paired spans (per-RET uprobes)")
		goMatch := spansByName(spans, "cache.match.go")
		assert.NotEmpty(ct, goMatch, "expected Go match-filter span on key=sku:3")
		for _, s := range goMatch {
			for _, a := range s.Attributes {
				if a.Key == "key" {
					assert.Equal(ct, "sku:3", a.Value.StringValue, "Go match-filter should only emit for sku:3")
				}
			}
		}
		pyMatch := spansByName(spans, "cache.match.py")
		assert.NotEmpty(ct, pyMatch, "expected Python match-filter span on key=cart:3")
		for _, s := range pyMatch {
			for _, a := range s.Attributes {
				if a.Key == "key" {
					assert.Equal(ct, "cart:3", a.Value.StringValue, "Python match-filter should only emit for cart:3")
				}
			}
		}
		assert.NotEmpty(ct, spansByName(spans, "order.func.c"), "expected C function-mode spans (P1)")
		assert.NotEmpty(ct, spansByName(spans, "cache.func.c"), "expected C paired function spans")
		matchSpans := spansByName(spans, "cache.match.c")
		assert.NotEmpty(ct, matchSpans, "expected C match-filter spans to emit on user:3")
		for _, s := range matchSpans {
			for _, a := range s.Attributes {
				if a.Key == "key" {
					assert.Equal(ct, "user:3", a.Value.StringValue, "match-filter span should only emit for user:3")
				}
			}
		}
		for _, n := range []string{"order.process", "order.process.py", "order.process.rb", "order.process.go", "order.process.java", "order.process.nodejs", "order.process.cpp", "order.process.rust", "order.func.c", "order.func.go"} {
			assertAnyAttr(ct, spansByName(spans, n), "order_id")
			assertAnyAttr(ct, spansByName(spans, n), "customer")
		}
	}, 120*time.Second, 2*time.Second)
}

func waitForCustomSpanServices(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, port := range []string{customSpanCPort, customSpanPythonPort, customSpanRubyPort, customSpanGoPort, customSpanJavaPort, customSpanNodejsPort, customSpanCppPort, customSpanRustPort} {
			ti.DoHTTPGet(ct, "http://localhost:"+port+"/smoke", http.StatusOK)
		}
	}, testTimeout, time.Second)
}

type otlpSpan struct {
	Name       string         `json:"name"`
	Attributes []otlpAttr     `json:"attributes"`
	StartUnix  string         `json:"startTimeUnixNano"`
	EndUnix    string         `json:"endTimeUnixNano"`
	Parent     string         `json:"parentSpanId"`
	TraceID    string         `json:"traceId"`
	SpanID     string         `json:"spanId"`
	Extra      map[string]any `json:"-"`
}

type otlpAttr struct {
	Key   string `json:"key"`
	Value struct {
		StringValue string `json:"stringValue,omitempty"`
		IntValue    string `json:"intValue,omitempty"`
	} `json:"value"`
}

func readCustomSpanSpecs(t assert.TestingT, p string) []otlpSpan {
	raw, err := os.ReadFile(p)
	if err != nil {
		assert.NoError(t, err, "trace export file not present yet")
		return nil
	}
	var spans []otlpSpan
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var batch struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []otlpSpan `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal([]byte(line), &batch); err != nil {
			continue
		}
		for _, rs := range batch.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				spans = append(spans, ss.Spans...)
			}
		}
	}
	return spans
}

func spansByName(all []otlpSpan, name string) []otlpSpan {
	var out []otlpSpan
	for _, s := range all {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

func assertAnyAttr(t assert.TestingT, spans []otlpSpan, key string) {
	for _, s := range spans {
		for _, a := range s.Attributes {
			if a.Key == key && (a.Value.StringValue != "" || a.Value.IntValue != "") {
				return
			}
		}
	}
	assert.Failf(t, "missing attribute", "expected at least one span with attribute %q across %d spans", key, len(spans))
}
