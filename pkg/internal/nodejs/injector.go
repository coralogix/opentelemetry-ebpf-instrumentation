// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

type inspectorTarget struct {
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

type cdpRequest struct {
	ID     int    `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

type cdpResponse struct {
	ID     int            `json:"id"`
	Result map[string]any `json:"result,omitempty"`
	Error  map[string]any `json:"error,omitempty"`
}

type evalParams struct {
	Expression            string `json:"expression"`
	IncludeCommandLineAPI bool   `json:"includeCommandLineAPI"`
}

const inspectorRequestTimeout = 5 * time.Second

// debugEndBudget is what the evaluate that closes the inspector again gets. It
// is held back from the handshake deadline rather than shared with it: a
// conversation that ran out of time still has to close the port it opened.
const debugEndBudget = 500 * time.Millisecond

// stepTimeout bounds one step of an inspector conversation. The zero deadline
// means the caller works against no deadline of its own, and every step gets
// the full inspectorRequestTimeout.
func stepTimeout(deadline time.Time) time.Duration {
	if deadline.IsZero() {
		return inspectorRequestTimeout
	}

	return min(time.Until(deadline), inspectorRequestTimeout)
}

// debugEndTimeout never derives from what is left of the handshake deadline.
// Closing the inspector is what keeps a signaled application from being left
// with an open debugger port, so it keeps its budget even when the handshake
// has already overrun.
func debugEndTimeout(deadline time.Time) time.Duration {
	if deadline.IsZero() {
		return inspectorRequestTimeout
	}

	return debugEndBudget
}

// IMPORTANT: the code in this file needs to run in the network namespace of the
// target process in order to be able to connect to its inspector port - the
// network namespace switching is done by the withNetNS function, which locks
// the current go routine to the current thread, ensuring the current thread
// runs in the right network namespace - as a result, we need to manually
// initiate the connection, as net/http and gorilla/websocket dialers may
// spawn go routines of their own, which can potentially end up on a different
// thread (and consequently, in the wrong namespace)

func connect(addr string, port int) (net.Conn, error) {
	ip := net.ParseIP(addr).To4()

	if ip == nil {
		return nil, fmt.Errorf("only IPv4 supported, got: %s", addr)
	}

	sa := &syscall.SockaddrInet4{
		Port: port,
	}

	copy(sa.Addr[:], ip)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	if err := syscall.Connect(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("connect: %w", err)
	}

	file := os.NewFile(uintptr(fd), fmt.Sprintf("tcp:%s:%d", addr, port))

	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("failed to create os.File from fd")
	}

	conn, err := net.FileConn(file)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("fileconn: %w", err)
	}

	file.Close()

	return conn, nil
}

func connectWait(ip string, port int, timeout time.Duration, interval time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)

	for {
		conn, err := connect(ip, port)

		if err == nil {
			return conn, nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("timed out waiting for %s:%d", ip, port)
		}

		// Clamped: a full interval here would overrun the timeout, and callers
		// size the rest of their budget on this returning within it.
		time.Sleep(min(interval, remaining))
	}
}

func httpGetWithTimeout(conn net.Conn, path string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("request error: %w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return []byte{}, fmt.Errorf("connection deadline error: %w", err)
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	if err = req.Write(conn); err != nil {
		return []byte{}, fmt.Errorf("error writing request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return []byte{}, fmt.Errorf("error reading response: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("response body error: %w", err)
	}

	return body, nil
}

func (i *NodeInjector) requestDebuggerURL(conn net.Conn, deadline time.Time) (string, error) {
	res, err := httpGetWithTimeout(conn, "/json/list", stepTimeout(deadline))
	if err != nil {
		return "", err
	}

	i.log.Debug("received response", "response", res)

	var targets []inspectorTarget

	if err := json.Unmarshal(res, &targets); err != nil {
		return "", fmt.Errorf("invalid JSON %w", err)
	}

	if len(targets) == 0 {
		return "", errors.New("no debugging targets available")
	}

	return targets[0].WebSocketDebuggerURL, nil
}

func upgradeConnWithTimeout(conn net.Conn, wsURL string, writeBufferSize int, timeout time.Duration) (*websocket.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("connection deadline error: %w", err)
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
		// Messages larger than the write buffer are sent as fragmented
		// websocket frames, which the Node.js inspector does not support
		// (it abruptly closes the connection). The caller sizes writeBufferSize
		// to the payload so every message is sent as a single frame.
		WriteBufferSize: writeBufferSize,
		ReadBufferSize:  64 * 1024,
		NetDial: func(_, _ string) (net.Conn, error) {
			return conn, nil
		},
	}

	wsConn, _, err := dialer.Dial(wsURL, nil)

	return wsConn, err
}

func evaluateRequest(exp string, id int) ([]byte, error) {
	req := cdpRequest{
		ID:     id,
		Method: "Runtime.evaluate",
		Params: evalParams{
			Expression:            exp,
			IncludeCommandLineAPI: true,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}
	return data, nil
}

func sendEvaluateWithTimeout(wsConn *websocket.Conn, exp string, id int, timeout time.Duration) error {
	data, err := evaluateRequest(exp, id)
	if err != nil {
		return err
	}

	_, err = sendMessageWithTimeout(wsConn, data, timeout)

	return err
}

// sendMessageWithTimeout reports whether the message was written, separately
// from whether the exchange succeeded: a reply that never arrives does not undo
// a script the target has already evaluated.
func sendMessageWithTimeout(wsConn *websocket.Conn, data []byte, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)

	if err := wsConn.SetWriteDeadline(deadline); err != nil {
		return false, fmt.Errorf("websocket write deadline error: %w", err)
	}
	defer func() {
		_ = wsConn.SetWriteDeadline(time.Time{})
		_ = wsConn.SetReadDeadline(time.Time{})
	}()

	if err := wsConn.SetReadDeadline(deadline); err != nil {
		return false, fmt.Errorf("websocket read deadline error: %w", err)
	}

	if err := wsConn.WriteMessage(websocket.TextMessage, data); err != nil {
		return false, fmt.Errorf("websocket write error: %w", err)
	}

	// NOTE: the next message is assumed to be the response to `data`: valid as
	// long as no CDP event domain is enabled on this session (e.g.
	// Runtime.enable), since events would interleave before the response
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		return true, fmt.Errorf("websocket read error: %w", err)
	}

	var resp cdpResponse

	if err := json.Unmarshal(msg, &resp); err != nil {
		return true, fmt.Errorf("response unmarshal error: %w", err)
	}

	if resp.Error != nil {
		return true, fmt.Errorf("protocol error: %+v", resp.Error)
	}

	result := resp.Result["result"]

	if resultMap, ok := result.(map[string]any); ok {
		if subtype, ok := resultMap["subtype"]; ok && subtype == "error" {
			return true, fmt.Errorf("exception: %v", resultMap["description"])
		}
	}

	if ed, ok := resp.Result["exceptionDetails"]; ok {
		return true, fmt.Errorf("uncaught exception: %v", ed)
	}

	return true, nil
}

// injectFileWS evaluates the agent over an established inspector session and
// reports whether the script reached the target. That is true from the moment
// the message is written: a failure reading the reply leaves a script that may
// already have been evaluated, and one that is resident but unrecorded is never
// removed.
//
// closeInspector says whether this injection is what opened the debugger port.
// When it is, the port is closed again on the way out; when the application was
// already listening — it was started with --inspect — the port is left as the
// operator configured it. Closing it would drop any attached debugger and leave
// no way to reattach short of restarting the process.
func (i *NodeInjector) injectFileWS(wsConn *websocket.Conn, payload []byte, deadline time.Time, closeInspector bool) (bool, error) {
	defer wsConn.Close()

	defer func() {
		if !closeInspector {
			return
		}

		_ = sendEvaluateWithTimeout(wsConn, "process._debugEnd();", 2, debugEndTimeout(deadline))
	}()

	sent, err := sendMessageWithTimeout(wsConn, payload, stepTimeout(deadline))
	if err != nil {
		return sent, err
	}

	i.log.Info("Script successfully injected")

	return true, nil
}

// injectViaConn runs the whole inspector conversation. The zero deadline leaves
// every step its own timeout; a caller working against a deadline passes it so
// the conversation cannot outlive the budget that allowed it to start.
func (i *NodeInjector) injectViaConn(conn net.Conn, code string, deadline time.Time, closeInspector bool) (bool, error) {
	wsURL, err := i.requestDebuggerURL(conn, deadline)
	if err != nil {
		conn.Close()
		return false, err
	}

	i.log.Debug("found debugger url", "url", wsURL)

	payload, err := evaluateRequest(code, 1)
	if err != nil {
		conn.Close()
		return false, err
	}

	// buffer sized to the payload: the inspector rejects fragmented messages
	wsConn, err := upgradeConnWithTimeout(conn, wsURL, len(payload), stepTimeout(deadline))
	if err != nil {
		conn.Close()
		return false, fmt.Errorf("failed to connect to inspector WebSocket: %w", err)
	}

	return i.injectFileWS(wsConn, payload, deadline, closeInspector)
}
