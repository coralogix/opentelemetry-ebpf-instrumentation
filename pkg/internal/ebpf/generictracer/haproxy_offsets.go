// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// haproxyOffsets holds the per-version struct member offsets the BPF
// uprobes need to walk a HAProxy `struct stream` to its backend FD and
// frontend peer address. Pushed into BPF as `volatile const u32` values
// at LoadSpec time (see RewriteConstants in convenience.go).
//
// All offsets are in bytes from the start of the containing struct.
// Offsets do not differ between amd64 and aarch64 (verified against
// haproxy:2.8.5-alpine on both platforms — the structs use only fixed-
// width types and pointers, so layout is identical across both archs).
type haproxyOffsets struct {
	StreamScf    uint32 // struct stream:    scf  (struct stconn *)
	StreamScb    uint32 // struct stream:    scb  (struct stconn *)
	StconnSedesc uint32 // struct stconn:    sedesc (struct sedesc *)
	SedescConn   uint32 // struct sedesc:    conn (struct connection *)
	ConnHandleFd uint32 // struct connection: handle.fd (int) — fd at union offset 0
	ConnSrc      uint32 // struct connection: src (struct sockaddr_storage *)
}

// haproxyOffsetTable holds offsets for every supported HAProxy LTS branch.
// Keyed by "MAJOR.MINOR" — match against the major.minor of the detected
// version (the patch level doesn't affect struct layout within an LTS).
//
// Extracted from official `haproxy:{2.6,2.8,3.0,3.2}-alpine` binaries via
// DWARF (.debug_info), see /tmp/extract_haproxy_offsets.py for the script.
// Verified across both aarch64 and amd64 builds of 2.8.5 — identical.
var haproxyOffsetTable = map[string]haproxyOffsets{
	"2.6": {StreamScf: 688, StreamScb: 696, StconnSedesc: 32, SedescConn: 8, ConnHandleFd: 104, ConnSrc: 128},
	"2.8": {StreamScf: 632, StreamScb: 640, StconnSedesc: 40, SedescConn: 8, ConnHandleFd: 104, ConnSrc: 128},
	"3.0": {StreamScf: 624, StreamScb: 632, StconnSedesc: 40, SedescConn: 8, ConnHandleFd: 120, ConnSrc: 144},
	"3.2": {StreamScf: 696, StreamScb: 704, StconnSedesc: 40, SedescConn: 8, ConnHandleFd: 120, ConnSrc: 144},
}

// defaultHAProxyOffsets are used when no HAProxy process is running at
// agent startup. Matches the most recent LTS at the time of writing — if
// HAProxy starts later with a different LTS, correlation will fall back
// to producing detached spans (the test will surface this).
var defaultHAProxyOffsets = haproxyOffsetTable["3.2"]

// offsetsForVersion returns the struct offsets for a given HAProxy
// semver string (e.g. "2.8.5"). Falls back to the closest supported LTS
// branch using semver comparison if the exact major.minor isn't in the
// table — useful for previewing offsets against patch releases that
// post-date this build of OBI.
func offsetsForVersion(version string) (haproxyOffsets, error) {
	mm, err := majorMinor(version)
	if err != nil {
		return haproxyOffsets{}, err
	}
	if off, ok := haproxyOffsetTable[mm]; ok {
		return off, nil
	}
	// Walk the table in reverse semver order, return the highest known
	// branch <= the requested version.
	branches := make([]string, 0, len(haproxyOffsetTable))
	for k := range haproxyOffsetTable {
		branches = append(branches, k)
	}
	semverSortDesc(branches)
	for _, b := range branches {
		if semver.Compare("v"+b, "v"+mm) <= 0 {
			return haproxyOffsetTable[b], nil
		}
	}
	return haproxyOffsets{}, fmt.Errorf("no offsets for HAProxy %s (closest known: %v)", version, branches)
}

// majorMinor extracts "MAJOR.MINOR" from a semver-ish string.
func majorMinor(v string) (string, error) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return "", fmt.Errorf("not a major.minor[.patch] version: %q", v)
	}
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return "", fmt.Errorf("invalid major: %q", parts[0])
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", fmt.Errorf("invalid minor: %q", parts[1])
	}
	return parts[0] + "." + parts[1], nil
}

func semverSortDesc(s []string) {
	// Tiny insertion sort — the slice is bounded by len(haproxyOffsetTable).
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && semver.Compare("v"+s[j-1], "v"+s[j]) < 0; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// detectRunningHAProxyOffsets scans /proc for a running HAProxy process,
// reads its version from .symtab, and returns the matching offset set.
// Returns (offsets, true) on success and (defaults, false) on failure.
//
// Limitation: only one HAProxy version is supported per OBI agent (the
// BPF constants are baked at load time). If multiple versions run
// simultaneously, the first one found wins.
func detectRunningHAProxyOffsets() (haproxyOffsets, bool) {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return defaultHAProxyOffsets, false
	}
	for _, e := range procEntries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		exePath := filepath.Join("/proc", e.Name(), "exe")
		target, err := os.Readlink(exePath)
		if err != nil {
			continue
		}
		// Cheap pre-filter — avoid opening the ELF for every process.
		if !strings.Contains(filepath.Base(target), "haproxy") {
			continue
		}
		off, err := offsetsFromBinary(exePath)
		if err != nil {
			continue
		}
		return off, true
	}
	return defaultHAProxyOffsets, false
}

// offsetsFromBinary opens the ELF at the given path, reads the HAProxy
// version, and returns the corresponding offset set.
func offsetsFromBinary(path string) (haproxyOffsets, error) {
	f, err := elf.Open(path)
	if err != nil {
		return haproxyOffsets{}, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	version, err := detectHAProxyVersion(f)
	if err != nil {
		return haproxyOffsets{}, fmt.Errorf("detecting version: %w", err)
	}
	off, err := offsetsForVersion(version)
	if err != nil {
		return haproxyOffsets{}, err
	}
	return off, nil
}

// haproxyConstants returns the BPF constants that select the HAProxy
// struct offsets to use. Names must match the `volatile const s32`
// declarations in bpf/generictracer/haproxy.c.
func haproxyConstants(off haproxyOffsets) map[string]any {
	return map[string]any{
		"haproxy_stream_scf":     int32(off.StreamScf),
		"haproxy_stream_scb":     int32(off.StreamScb),
		"haproxy_stconn_sedesc":  int32(off.StconnSedesc),
		"haproxy_sedesc_conn":    int32(off.SedescConn),
		"haproxy_conn_handle_fd": int32(off.ConnHandleFd),
		"haproxy_conn_src":       int32(off.ConnSrc),
	}
}
