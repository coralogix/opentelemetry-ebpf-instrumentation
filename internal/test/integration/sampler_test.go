// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testSampler(t *testing.T) {
	waitForTestComponents(t, "http://localhost:5000")
	waitForTestComponents(t, "http://localhost:5002")
	waitForTestComponents(t, "http://localhost:5003")

	// give enough time for the NodeJS injector to finish
	// TODO: once we implement the instrumentation status query API, replace
	// this with  a proper check to see if the target process has finished
	// being instrumented
	time.Sleep(60 * time.Second)

	// Add and check for specific trace ID
	// Run couple of requests to make sure we flush out any transactions that might be
	// stuck because of our tracking of full request times
	for i := 0; i < 10; i++ {
		ti.DoHTTPGet(t, "http://localhost:5000/a", 200)
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=service-a&operation=GET%20%2Fa")

		require.NoError(ct, err)

		if resp == nil {
			return
		}

		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery

		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/a"})

		lenA := len(traces)

		require.LessOrEqual(ct, 10, lenA)

		resp, err = http.Get(jaegerQueryURL + "?service=service-c&operation=GET%20%2Fc")

		require.NoError(ct, err)

		if resp == nil {
			return
		}

		require.Equal(ct, http.StatusOK, resp.StatusCode)

		traces = tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/c"})

		lenC := len(traces)

		require.NotZero(ct, lenC)
		require.Less(ct, lenC, lenA)
	}, testTimeout, 1500*time.Millisecond)
}

func TestSampler(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Pid:     "host",
			Command: []string{"--config=/configs/${OBI_CONFIG}"},
			Ports:   []string{"8999:8999"},
			RunDir:  "run-multi",
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PATH": "/metrics",
				"OTEL_EBPF_OPEN_PORT":                        "",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresAppSpan,
			},
		}),
	}), "docker-compose-sampler.yml")
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OBI_CONFIG=obi-config-sampler.yml`)
	require.NoError(t, compose.Up())

	t.Run("Sampler", testSampler)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}
