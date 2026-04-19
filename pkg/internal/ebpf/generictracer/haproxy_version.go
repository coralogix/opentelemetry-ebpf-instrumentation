// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	"errors"
	"fmt"
	"strings"
)

// haproxyVersionSymbol is the name of the global char[] HAProxy uses to
// store its build version. It has been present in HAProxy since the 1.x
// era and is exported in the binary's symbol table (verified across LTS
// 2.6 / 2.8 / 3.0 / 3.2). Reading it directly from the ELF avoids forking
// the target binary just to get a version string.
const haproxyVersionSymbol = "haproxy_version"

// detectHAProxyVersion reads the haproxy_version symbol from the given
// ELF file and returns a semver-clean version string (e.g. "2.8.5").
//
// HAProxy declares the symbol as a `char[]` literal — bytes at the symbol
// address are the version string itself, no pointer dereference needed.
// Example raw value: "2.8.5-aaba8d0\0" — the git-hash suffix is stripped.
//
// Mirrors getGoDetails() in pkg/internal/goexec/gofile.go but simpler:
// HAProxy hands us a named symbol, so no magic-prefix scan is required.
func detectHAProxyVersion(f *elf.File) (string, error) {
	syms, err := f.Symbols()
	if err != nil {
		// Fall back to dynamic symbols — Alpine-built haproxy keeps
		// its globals in .symtab, but we want this to remain robust
		// if a downstream rebuild strips it down to .dynsym.
		dyn, dynErr := f.DynamicSymbols()
		if dynErr != nil {
			return "", fmt.Errorf("reading symbols: %w", err)
		}
		syms = dyn
	}

	var sym *elf.Symbol
	for i := range syms {
		if syms[i].Name == haproxyVersionSymbol {
			sym = &syms[i]
			break
		}
	}
	if sym == nil {
		return "", fmt.Errorf("symbol %q not found", haproxyVersionSymbol)
	}
	if sym.Size == 0 {
		return "", fmt.Errorf("symbol %q has zero size", haproxyVersionSymbol)
	}

	// Locate the section that contains the symbol's virtual address, then
	// translate to file offset.
	var sect *elf.Section
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NULL || s.Type == elf.SHT_NOBITS {
			continue
		}
		if sym.Value >= s.Addr && sym.Value < s.Addr+s.Size {
			sect = s
			break
		}
	}
	if sect == nil {
		return "", fmt.Errorf("symbol %q not in any loadable section", haproxyVersionSymbol)
	}

	raw := make([]byte, sym.Size)
	if _, err := sect.ReadAt(raw, int64(sym.Value-sect.Addr)); err != nil {
		return "", fmt.Errorf("reading %q: %w", haproxyVersionSymbol, err)
	}

	return parseHAProxyVersion(string(raw))
}

// parseHAProxyVersion turns a raw symbol payload like "2.8.5-aaba8d0\x00"
// into a clean "2.8.5". Returns an error for anything that doesn't look
// like a major.minor[.patch] version.
func parseHAProxyVersion(raw string) (string, error) {
	// Strip trailing NUL and any whitespace.
	s := strings.TrimRight(raw, "\x00")
	s = strings.TrimSpace(s)
	// Strip git/build suffix: "-aaba8d0", "+something", "-dev", etc.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	// Sanity-check shape: must start with a digit, contain at least one dot.
	if len(s) < 3 || s[0] < '0' || s[0] > '9' || !strings.Contains(s, ".") {
		return "", errors.New("not a valid HAProxy version string")
	}
	return s, nil
}
