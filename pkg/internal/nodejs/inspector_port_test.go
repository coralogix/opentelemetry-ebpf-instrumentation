// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectPortFromArg(t *testing.T) {
	for _, tc := range []struct {
		arg      string
		expected int
		ok       bool
	}{
		{arg: "--inspect-port=9300", expected: 9300, ok: true},
		{arg: "--inspect=9301", expected: 9301, ok: true},
		{arg: "--inspect=127.0.0.1:9302", expected: 9302, ok: true},
		{arg: "--inspect=0.0.0.0:9303", expected: 9303, ok: true},
		{arg: "--inspect-brk=9304", expected: 9304, ok: true},
		{arg: "--inspect-wait=9305", expected: 9305, ok: true},
		{arg: "--inspect-port=0", expected: 0, ok: true},
		{arg: "--inspect=[::1]:9306", expected: 9306, ok: true},
		// A bare flag carries no port; the default is added separately.
		{arg: "--inspect", ok: false},
		{arg: "--inspect-brk", ok: false},
		// Shares the --inspect prefix but is not a port.
		{arg: "--inspect-publish-uid=stderr", ok: false},
		{arg: "--inspect=notaport", ok: false},
		{arg: "--max-old-space-size=4096", ok: false},
		{arg: "server.js", ok: false},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			port, ok := inspectPortFromArg(tc.arg)
			assert.Equal(t, tc.ok, ok)

			if tc.ok {
				assert.Equal(t, tc.expected, port)
			}
		})
	}
}

func TestCandidateInspectorPortsAlwaysIncludesDefault(t *testing.T) {
	// The current test process has no --inspect flags, so only the Node.js
	// default should be offered.
	assert.Equal(t, []int{defaultInspectorPort}, candidateInspectorPorts(os.Getpid()))
}

func TestCandidateInspectorPortsIgnoresUnknownPid(t *testing.T) {
	// An exited process must not panic or invent ports beyond the default.
	assert.Equal(t, []int{defaultInspectorPort}, candidateInspectorPorts(-1))
}

func TestLocalPort(t *testing.T) {
	port, ok := localPort("0100007F:2445")
	require.True(t, ok)
	assert.Equal(t, 9285, port)

	_, ok = localPort("nocolon")
	assert.False(t, ok)
}

func TestForEachListeningSocketOnlyReportsListenState(t *testing.T) {
	// Columns match /proc/<pid>/net/tcp: the first row listens on 0x2445
	// (9285) with inode 1836325, the second is ESTABLISHED and must be skipped.
	table := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:2445 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1836325 1 0000\n" +
		"   1: 0100007F:2446 0100007F:9999 01 00000000:00000000 00:00000000 00000000  1000        0 1836326 1 0000\n"

	path := filepath.Join(t.TempDir(), "tcp")
	require.NoError(t, os.WriteFile(path, []byte(table), 0o600))

	found := map[int]uint64{}
	require.NoError(t, forEachListeningSocket(path, func(port int, inode uint64) {
		found[port] = inode
	}))

	assert.Equal(t, map[int]uint64{9285: 1836325}, found)
}

func TestForEachListeningSocketMissingTableIsAnError(t *testing.T) {
	assert.Error(t, forEachListeningSocket(filepath.Join(t.TempDir(), "absent"), func(int, uint64) {}))
}

func TestListeningTCPPortsFindsThisProcessListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	ports, err := listeningTCPPorts(os.Getpid())
	require.NoError(t, err)

	assert.Contains(t, ports, port, "listener on %d should be attributed to this pid", port)
}

func TestListeningTCPPortsExcludesForeignSockets(t *testing.T) {
	// This is the property that makes per-pid discovery trustworthy: a listener
	// shares its network namespace with every other process there - in
	// Kubernetes, every container in the pod - and so shows up in their
	// /proc/<pid>/net/tcp too. It must only be attributed to the pid whose file
	// descriptors actually hold it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// A child we own, so its /proc entries are readable, and which listens on
	// nothing itself.
	child := exec.Command("sleep", "30")
	require.NoError(t, child.Start())

	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()

	ports, err := listeningTCPPorts(child.Process.Pid)
	require.NoError(t, err)

	assert.NotContains(t, ports, port, "port %d belongs to this process, not to the child", port)

	// Same table, opposite verdict, for the pid that does own the socket.
	own, err := listeningTCPPorts(os.Getpid())
	require.NoError(t, err)
	assert.Contains(t, own, port)
}

func TestListeningTCPPortsUnknownPid(t *testing.T) {
	_, err := listeningTCPPorts(-1)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "/proc"), "error should name the path: %v", err)
}

func TestSocketInodesIncludesListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close()

	inodes, err := socketInodes(os.Getpid())
	require.NoError(t, err)
	assert.NotEmpty(t, inodes, "a process with an open listener holds at least one socket inode")
}

func TestReadNulSeparatedSkipsEmptyEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmdline")
	require.NoError(t, os.WriteFile(path, []byte("node\x00--inspect=9300\x00server.js\x00"), 0o600))

	assert.Equal(t, []string{"node", "--inspect=9300", "server.js"}, readNulSeparated(path))
}

func TestReadNulSeparatedMissingFile(t *testing.T) {
	assert.Nil(t, readNulSeparated(fmt.Sprintf("%s/absent", t.TempDir())))
}
