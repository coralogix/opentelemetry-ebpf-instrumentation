// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
)

func TestInjectReportsTheScriptSentOnlyOnceWritten(t *testing.T) {
	t.Run("no debugging target: nothing was written", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("[]"))
		}))
		t.Cleanup(srv.Close)

		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		require.NoError(t, err)

		cfg := obi.DefaultConfig
		i := NewNodeInjector(&cfg)

		sent, err := i.injectViaConn(conn, "1+1", time.Time{}, true)

		require.Error(t, err)
		require.False(t, sent, "the inspector offered no target, so no script was written")
	})

	t.Run("the write itself fails: nothing reached the target", func(t *testing.T) {
		wsConn := newTestInspectorConn(t, func(c *websocket.Conn) {
			_ = c.Close()
		})

		// Closed under the writer, so WriteMessage cannot land.
		require.NoError(t, wsConn.Close())

		payload, err := evaluateRequest("1+1", 1)
		require.NoError(t, err)

		cfg := obi.DefaultConfig
		i := NewNodeInjector(&cfg)

		sent, err := i.injectFileWS(wsConn, payload, time.Time{}, true)

		require.Error(t, err)
		require.False(t, sent, "the write failed, so no script reached the target")
	})

	t.Run("reply never arrives: the script is already out", func(t *testing.T) {
		wsConn := newTestInspectorConn(t, func(c *websocket.Conn) {
			// Read the payload, then hang up without answering.
			_, _, _ = c.ReadMessage()
			_ = c.Close()
		})

		payload, err := evaluateRequest("1+1", 1)
		require.NoError(t, err)

		sent, err := sendMessageWithTimeout(wsConn, payload, testInspectorTimeout)

		require.Error(t, err, "the exchange fails without a reply")
		require.True(t, sent, "the payload was written, so the target may have evaluated it")
	})
}

func TestConnectWaitStaysInsideItsTimeout(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := probe.Addr().(*net.TCPAddr).Port
	require.NoError(t, probe.Close())

	const (
		timeout  = 300 * time.Millisecond
		interval = 200 * time.Millisecond
	)

	begin := time.Now()
	_, err = connectWait("127.0.0.1", port, timeout, interval)
	elapsed := time.Since(begin)

	require.Error(t, err, "nothing is listening, so the wait must time out")
	require.LessOrEqual(t, elapsed, timeout+100*time.Millisecond,
		"connectWait slept past the timeout it was given")
}
