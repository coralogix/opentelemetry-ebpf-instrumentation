// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultInspectorPort = 9229
	tcpStateListen       = "0A"
)

// listeningTCPPorts returns the TCP ports the given process listens on. The
// socket tables under /proc/<pid>/net are scoped to the network namespace, which
// in Kubernetes is shared by every container in the pod, so they are intersected
// with the socket inodes held by the process's own file descriptors.
func listeningTCPPorts(pid int) (map[int]struct{}, error) {
	inodes, err := socketInodes(pid)
	if err != nil {
		return nil, err
	}

	ports := map[int]struct{}{}

	if len(inodes) == 0 {
		return ports, nil
	}

	for _, table := range []string{"tcp", "tcp6"} {
		path := fmt.Sprintf("/proc/%d/net/%s", pid, table)

		_ = forEachListeningSocket(path, func(port int, inode uint64) {
			if _, ok := inodes[inode]; ok {
				ports[port] = struct{}{}
			}
		})
	}

	return ports, nil
}

func socketInodes(pid int) (map[uint64]struct{}, error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	const prefix = "socket:["

	inodes := make(map[uint64]struct{}, len(entries))

	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}

		if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
			continue
		}

		inode, err := strconv.ParseUint(target[len(prefix):len(target)-1], 10, 64)
		if err != nil {
			continue
		}

		inodes[inode] = struct{}{}
	}

	return inodes, nil
}

func forEachListeningSocket(path string, fn func(port int, inode uint64)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		if len(fields) < 10 || fields[3] != tcpStateListen {
			continue
		}

		port, ok := localPort(fields[1])
		if !ok {
			continue
		}

		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		fn(port, inode)
	}

	return scanner.Err()
}

func localPort(address string) (int, bool) {
	colon := strings.LastIndex(address, ":")
	if colon < 0 {
		return 0, false
	}

	port, err := strconv.ParseUint(address[colon+1:], 16, 32)
	if err != nil {
		return 0, false
	}

	return int(port), true
}

// candidateInspectorPorts returns the ports this process's inspector could
// already be listening on, from --inspect flags on the command line or in
// NODE_OPTIONS, plus the Node.js default.
func candidateInspectorPorts(pid int) []int {
	ports := make([]int, 0, 2)
	seen := map[int]struct{}{}

	add := func(port int) {
		if port <= 0 || port > 65535 {
			return
		}

		if _, ok := seen[port]; ok {
			return
		}

		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	for _, arg := range append(procCmdline(pid), procNodeOptions(pid)...) {
		if port, ok := inspectPortFromArg(arg); ok {
			add(port)
		}
	}

	add(defaultInspectorPort)

	return ports
}

func inspectPortFromArg(arg string) (int, bool) {
	// Longest first, so --inspect does not swallow --inspect-port.
	for _, flag := range []string{"--inspect-port", "--inspect-brk", "--inspect-wait", "--inspect"} {
		if !strings.HasPrefix(arg, flag) {
			continue
		}

		rest := arg[len(flag):]

		if rest == "" || rest[0] != '=' {
			return 0, false
		}

		value := rest[1:]

		if colon := strings.LastIndex(value, ":"); colon >= 0 {
			value = value[colon+1:]
		}

		port, err := strconv.Atoi(value)
		if err != nil {
			return 0, false
		}

		return port, true
	}

	return 0, false
}

func procCmdline(pid int) []string {
	return readNulSeparated(fmt.Sprintf("/proc/%d/cmdline", pid))
}

func procNodeOptions(pid int) []string {
	for _, entry := range readNulSeparated(fmt.Sprintf("/proc/%d/environ", pid)) {
		if value, ok := strings.CutPrefix(entry, "NODE_OPTIONS="); ok {
			return strings.Fields(value)
		}
	}

	return nil
}

func readNulSeparated(path string) []string {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	parts := strings.Split(string(content), "\x00")

	out := make([]string, 0, len(parts))

	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}

	return out
}
