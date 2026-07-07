//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/fastelf"
)

func TestMatchExeSymbols_InvalidStringOffset(t *testing.T) {
	const symSize = 24

	data := make([]byte, symSize+4)
	binary.LittleEndian.PutUint32(data[0:4], 128)
	data[4] = 0x02
	binary.LittleEndian.PutUint64(data[8:16], 1)
	binary.LittleEndian.PutUint64(data[16:24], 1)
	copy(data[symSize:], []byte("x\x00"))

	ctx := &fastelf.ElfContext{
		Data: data,
		Sections: []*fastelf.Elf64_Shdr{
			{
				Type:    fastelf.SHT_SYMTAB,
				Link:    1,
				Offset:  0,
				Size:    symSize,
				Entsize: symSize,
			},
			{
				Offset: symSize,
			},
		},
	}

	assert.Equal(t, svc.InstrumentableGeneric, matchExeSymbols(ctx))
}

func TestMatchExeSymbols_InvalidStringTableOffset(t *testing.T) {
	const symSize = 24

	ctx := &fastelf.ElfContext{
		Data: make([]byte, symSize),
		Sections: []*fastelf.Elf64_Shdr{
			{
				Type:    fastelf.SHT_SYMTAB,
				Link:    1,
				Size:    symSize,
				Entsize: symSize,
			},
			{
				Offset: ^uint64(0),
				Size:   1,
			},
		},
	}

	assert.Equal(t, svc.InstrumentableGeneric, matchExeSymbols(ctx))
}

func TestFindExeSymbolsExactLookup(t *testing.T) {
	const symbolName = "main.exactLookupTarget"

	f := openSymbolFixtureELF(t)
	defer f.Close()

	syms, err := FindExeSymbols(f, []string{symbolName})
	require.NoError(t, err)

	sym, ok := syms[symbolName]
	require.True(t, ok)
	assert.Equal(t, symbolName, sym.Name)
	assert.NotZero(t, sym.Off)
	assert.NotZero(t, sym.Len)
	assert.NotNil(t, sym.Prog)
}

func TestFindExeSymbolsSubstringLookup(t *testing.T) {
	const (
		symbolName = "main.substringLookupTarget"
		substring  = "substringLookup"
	)

	f := openSymbolFixtureELF(t)
	defer f.Close()

	syms, err := FindExeSymbolsBySubstring(f, []string{substring})
	require.NoError(t, err)

	sym, ok := syms[substring]
	require.True(t, ok)
	assert.Equal(t, symbolName, sym.Name)
	assert.NotZero(t, sym.Off)
	assert.NotZero(t, sym.Len)
	assert.NotNil(t, sym.Prog)
}

func TestFindExeSymbolsByNameAndSubstring(t *testing.T) {
	const (
		exactSymbolName    = "main.exactLookupTarget"
		substringSymbol    = "main.substringLookupTarget"
		symbolNameFragment = "substringLookup"
	)

	f := openSymbolFixtureELF(t)
	defer f.Close()

	exactSyms, substringSyms, err := FindExeSymbolsByNameAndSubstring(
		f,
		[]string{exactSymbolName},
		[]string{symbolNameFragment},
	)
	require.NoError(t, err)

	exactSym, ok := exactSyms[exactSymbolName]
	require.True(t, ok)
	assert.Equal(t, exactSymbolName, exactSym.Name)
	assert.NotZero(t, exactSym.Off)
	assert.NotZero(t, exactSym.Len)
	assert.NotNil(t, exactSym.Prog)

	substringSym, ok := substringSyms[symbolNameFragment]
	require.True(t, ok)
	assert.Equal(t, substringSymbol, substringSym.Name)
	assert.NotZero(t, substringSym.Off)
	assert.NotZero(t, substringSym.Len)
	assert.NotNil(t, substringSym.Prog)
}

func TestStripDollarBrackets(t *testing.T) {
	cases := []struct{ in, want string }{
		{"LocalOwnedTasks$LT$S$GT$", "LocalOwnedTasks"},
		{"OwnedTasks$LT$S$GT$", "OwnedTasks"},
		{"Foo$LT$Bar$LT$X$GT$$GT$", "Foo"},        // nested
		{"noGenerics", "noGenerics"},              // no-op
		{"prefix$LT$X$GT$suffix", "prefixsuffix"}, // mid-ident
		{"$LT$unclosed", "$LT$unclosed"},          // malformed — unchanged
	}
	for _, c := range cases {
		assert.Equal(t, c.want, stripDollarBrackets(c.in), c.in)
	}
}

func TestRustDemangle_Legacy(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string // exact expected demangled prefix path
	}{
		// Real samples (debug build) with $LT$S$GT$ generics + 17h<hash> build hash.
		{"LocalOwnedTasks::bind",
			"_ZN5tokio7runtime4task4list24LocalOwnedTasks$LT$S$GT$4bind17he45315048f19b0faE",
			"tokio::runtime::task::list::LocalOwnedTasks::bind"},
		{"OwnedTasks::bind_inner",
			"_ZN5tokio7runtime4task4list19OwnedTasks$LT$S$GT$10bind_inner17h69552d27e517e78cE",
			"tokio::runtime::task::list::OwnedTasks::bind_inner"},
		// Non-generic methods (no $LT$): RawTask::poll and the spawn_blocking free fn.
		{"RawTask::poll",
			"_ZN5tokio7runtime4task3raw7RawTask4poll17h0123456789abcdefE",
			"tokio::runtime::task::raw::RawTask::poll"},
		{"pool::spawn_blocking",
			"_ZN5tokio7runtime8blocking4pool14spawn_blocking17hfedcba9876543210E",
			"tokio::runtime::blocking::pool::spawn_blocking"},
		// A trailing Itanium template block (…IiEE) does not occur in real Rust
		// legacy symbols; the bare 'I' is a non-digit that just terminates the
		// scan, leaving the already-collected prefix intact.
		{"trailing template block terminates scan",
			"_ZN3foo3barIiEE",
			"foo::bar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, rustDemangle(c.raw))
		})
	}
}

func TestRustDemangle_BuildHashStripped(t *testing.T) {
	// The trailing 17h<16 hex> component must never appear in the output.
	got := rustDemangle("_ZN3foo3bar17h0123456789abcdefE")
	assert.Equal(t, "foo::bar", got)
	assert.NotContains(t, got, "h0123456789abcdef")
}

func TestRustDemangle_NonLegacyReturnsEmpty(t *testing.T) {
	// rustDemangle only handles the legacy _ZN…E scheme; everything else returns "".
	for _, in := range []string{
		"",
		"main.someGoSymbol",
		"plain_c_symbol",
		// a v0 (_R) symbol must NOT be parsed by the legacy demangler
		"_RNvMNtNtNtCsec06QdWoQn_5tokio7runtime4task4listINtB2_10OwnedTasksE10bind_inner",
	} {
		assert.Empty(t, rustDemangle(in), "input %q", in)
	}
}

func TestRustDemangleV0_Tokio(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantPrefix string
	}{
		// Real v0 samples (RUSTFLAGS="-C symbol-mangling-version=v0" build).
		{"LocalOwnedTasks::bind",
			"_RINvMs_NtNtNtCsec06QdWoQn_5tokio7runtime4task4listINtB5_15LocalOwnedTasksINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtBb_4task5local6SharedEE4bindINtNtCsjCd2fZ6KadX_4core3pin3PinINtNtB1e_5boxed3BoxDNtNtNtB2k_6future6future6Futurep6OutputuNtNtB2k_6marker4SendEL_EEECsjqY7L67gDVE_8actix_rt",
			"tokio::runtime::task::list::LocalOwnedTasks::bind"},
		{"OwnedTasks::bind_inner",
			"_RNvMNtNtNtCsec06QdWoQn_5tokio7runtime4task4listINtB2_10OwnedTasksINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtB6_9scheduler14current_thread6HandleEE10bind_innerCsjqY7L67gDVE_8actix_rt",
			"tokio::runtime::task::list::OwnedTasks::bind_inner"},
		// pool::spawn_blocking — Real v0 sample (free fn, instantiated with the multi-thread worker Launch closure).
		// Generic args (I…E) and the trailing instantiation are dropped by the parser.
		{"pool::spawn_blocking",
			"_RINvNtNtNtCshFZRMeAqrSd_5tokio7runtime8blocking4pool14spawn_blockingNCNvMNtNtNtB6_9scheduler12multi_thread6workerNtB19_6Launch6launch0uEB8_",
			"tokio::runtime::blocking::pool::spawn_blocking"},
		// macOS prepends an extra leading underscore (__R…); rustDemangleV0 strips it
		// and must produce the same result as the _R… form above.
		{"OwnedTasks::bind_inner (macOS __R)",
			"__RNvMNtNtNtCsec06QdWoQn_5tokio7runtime4task4listINtB2_10OwnedTasksINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtB6_9scheduler14current_thread6HandleEE10bind_innerCsjqY7L67gDVE_8actix_rt",
			"tokio::runtime::task::list::OwnedTasks::bind_inner"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rustDemangleV0(c.raw)
			assert.True(t, strings.HasPrefix(got, c.wantPrefix), "got %q", got)
		})
	}
}

func TestRustDemangleV0_NonV0ReturnsEmpty(t *testing.T) {
	for _, in := range []string{
		"",
		"main.someGoSymbol",
		// a legacy (_ZN) symbol must NOT be parsed by the v0 demangler
		"_ZN5tokio7runtime4task3raw7RawTask4poll17h0123456789abcdefE",
	} {
		assert.Empty(t, rustDemangleV0(in), "input %q", in)
	}
}

// TestV0Base62StopsWithoutConsuming locks the base62 terminator fix: a non-base62
// byte must end the number WITHOUT being consumed. (A plain `break` inside the
// switch previously only left the switch and then swallowed the byte as a 0 digit.)
// The terminator must be a genuinely non-base62 byte — '.' here, not a letter like
// 'x' which is itself a valid base62 digit — and the value must stay <= len(sym) so
// the overflow clamp doesn't mask the terminator behavior we're checking.
func TestV0Base62StopsWithoutConsuming(t *testing.T) {
	p := &v0Parser{sym: "1."}
	got := p.base62()
	assert.Equal(t, 2, got, "raw value 1, encoded +1")
	assert.Equal(t, 1, p.pos, "must stop at '.' without consuming it")
}

// TestV0Base62DoesNotOverflowNegative locks a crash fix AND its terminator
// invariant: a base62 run long enough to overflow int must (1) never wrap n
// negative — which would defeat the ">= len(p.sym)" bounds checks callers rely on
// and panic on a negative index — and (2) still consume the entire digit run plus
// the trailing '_'. The value is clamped, but scanning must NOT bail mid-number:
// real disambiguator hashes are long base62 runs, and stranding pos inside one
// derails all subsequent parsing (the v0 tokio demangling bug).
func TestV0Base62DoesNotOverflowNegative(t *testing.T) {
	sym := strings.Repeat("Z", 20) + "_" // 20 base62 digits, well past int64 overflow if uncapped
	p := &v0Parser{sym: sym}
	got := p.base62()
	assert.GreaterOrEqual(t, got, 0, "must not overflow negative")
	assert.Equal(t, len(sym), p.pos, "must consume the whole run and the trailing '_'")
}

// TestRustPrefix_SelectsPollNotRawTaskPoll validates the v0.2.0 probe re-target: the
// prefix must match the monomorphized vtable free fn raw::poll but NOT the
// RawTask::poll thunk (whose demangled name has "RawTask::" between "raw::" and
// "poll"). Matching RawTask::poll would probe the inlinable thunk (the original bug)
// or double-fire.
func TestRustPrefix_SelectsPollNotRawTaskPoll(t *testing.T) {
	const prefix = "tokio::runtime::task::raw::poll"
	rawPoll := rustDemangle("_ZN5tokio7runtime4task3raw4poll17h0123456789abcdefE")
	rawTaskPoll := rustDemangle("_ZN5tokio7runtime4task3raw7RawTask4poll17h0123456789abcdefE")

	assert.Equal(t, "tokio::runtime::task::raw::poll", rawPoll)
	assert.Equal(t, "tokio::runtime::task::raw::RawTask::poll", rawTaskPoll)
	assert.True(t, strings.HasPrefix(rawPoll, prefix), "raw::poll (vtable target) must match the probe prefix")
	assert.False(t, strings.HasPrefix(rawTaskPoll, prefix), "RawTask::poll (thunk) must NOT match the probe prefix")
}

// TestFindExeSymbolsByPrefix_NoFalseMatchOnNonRust confirms a Rust prefix matches
// nothing in a non-Rust (Go) binary — symbols that don't demangle as Rust are
// skipped, so the prefix machinery never produces spurious attachments.
func TestFindExeSymbolsByPrefix_NoFalseMatchOnNonRust(t *testing.T) {
	f := openSymbolFixtureELF(t)
	defer f.Close()

	out, err := FindExeSymbolsByPrefix(f, []string{"tokio::runtime::task::raw::poll"})
	require.NoError(t, err)
	assert.Empty(t, out["tokio::runtime::task::raw::poll"])
}

func openSymbolFixtureELF(t *testing.T) *elf.File {
	t.Helper()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "main.go")
	exePath := filepath.Join(dir, "symbol-fixture")

	require.NoError(t, os.WriteFile(sourcePath, []byte(`package main

//go:noinline
func exactLookupTarget() {}

//go:noinline
func substringLookupTarget() {}

func main() {
	exactLookupTarget()
	substringLookupTarget()
}
`), 0o600))

	cmd := exec.Command("go", "build", "-gcflags=all=-l", "-o", exePath, sourcePath)
	cmd.Env = append(os.Environ(), "GO111MODULE=off")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	require.NoError(t, cmd.Run(), out.String())

	f, err := elf.Open(exePath)
	require.NoError(t, err)

	return f
}
