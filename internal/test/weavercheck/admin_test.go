// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

const testReport = `{"statistics":{"total_entities":1}}`

type fakeWeaverAdmin struct {
	calls   []string
	stopped bool
}

func (f *fakeWeaverAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	switch r.Method + " " + r.URL.Path {
	case "POST /stop":
		f.stopped = true
		_, _ = w.Write([]byte(`{"state":"stopped","report":true}`))
	case "GET /report":
		if !f.stopped {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"still receiving; POST /stop first"}`))
			return
		}
		_, _ = w.Write([]byte(testReport))
	case "POST /shutdown":
		_, _ = w.Write([]byte(`{"state":"shutting_down"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestFetchRawReportStopsReadsThenShutsDown(t *testing.T) {
	admin := &fakeWeaverAdmin{}
	server := httptest.NewServer(admin)
	defer server.Close()

	raw, err := FetchRawReport(t.Context(), server.URL)

	require.NoError(t, err)
	require.JSONEq(t, testReport, string(raw))
	require.Equal(t, []string{"POST /stop", "GET /report", "POST /shutdown"}, admin.calls)
}

func TestFetchRawReportFailsOnAdminError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	_, err := FetchRawReport(t.Context(), server.URL)

	require.ErrorContains(t, err, "weaver /stop returned HTTP 409")
}
