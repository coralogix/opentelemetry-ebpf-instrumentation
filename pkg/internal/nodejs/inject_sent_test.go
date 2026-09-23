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

// Whether the script reached the target decides whether the process is
// recorded for the shutdown pass, and a recorded process is signaled again on
// the way out. Reporting it too early costs a live application a second
// SIGUSR1 and a reopened debugger port to remove a script it never received;
// reporting it too late leaves a resident script nothing will ever remove. The
// line is the write itself.
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

// The uninstall pass sizes the rest of a target's budget on this returning
// within the timeout it was given: the evaluate that closes the reopened
// inspector gets what is left. Sleeping a whole interval past the deadline
// pushes that close past the point where the pass has already returned.
func TestConnectWaitStaysInsideItsTimeout(t *testing.T) {
	// A port nothing listens on: every attempt is refused immediately, so the
	// elapsed time is the sleeping.
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
