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

// symbolTablesContext builds an ELF context with one symbol table per entry of
// tables, each holding defined, sized STT_FUNC symbols with the given names in
// the given order, as matchExeSymbols sees them in .dynsym or .symtab.
func symbolTablesContext(tables ...[]string) *fastelf.ElfContext {
	const symSize = 24

	ctx := &fastelf.ElfContext{}
	for _, names := range tables {
		var strtab []byte
		strtab = append(strtab, 0)
		symtab := make([]byte, symSize*len(names))
		for i, name := range names {
			sym := symtab[i*symSize : (i+1)*symSize]
			binary.NativeEndian.PutUint32(sym[0:4], uint32(len(strtab)))
			sym[4] = byte(elf.STT_FUNC)
			binary.NativeEndian.PutUint64(sym[8:16], 0x1000)
			binary.NativeEndian.PutUint64(sym[16:24], 16)
			strtab = append(strtab, name...)
			strtab = append(strtab, 0)
		}

		symtabIndex := uint32(len(ctx.Sections))
		ctx.Sections = append(ctx.Sections,
			&fastelf.Elf64_Shdr{
				Type:    fastelf.SHT_DYNSYM,
				Link:    symtabIndex + 1,
				Offset:  uint64(len(ctx.Data)),
				Size:    uint64(len(symtab)),
				Entsize: symSize,
			},
			&fastelf.Elf64_Shdr{
				Offset: uint64(len(ctx.Data) + len(symtab)),
				Size:   uint64(len(strtab)),
			},
		)
		ctx.Data = append(ctx.Data, symtab...)
		ctx.Data = append(ctx.Data, strtab...)
	}

	return ctx
}

func TestMatchExeSymbols_RustMarkerRanksLast(t *testing.T) {
	const (
		nodeSymbol = "_ZN4node5StartEiPPc"
		rustSymbol = "_RNvCs2ZxxKbmjnch_7___rustc20___rust_panic_cleanup"
		jvmSymbol  = "JVM_GetVersion"
		// Bun re-exports node:: API symbols such as MakeCallback; they are
		// not Node.js runtime symbols, so they must not override a Rust marker.
		bunReexport = "_ZN4node12MakeCallbackEPN2v87IsolateENS0_5LocalINS0_6ObjectEEEPKciPNS3_INS0_5ValueEEENS_13async_contextE"
		graalSymbol = "graal_create_isolate"
	)

	tests := []struct {
		name   string
		tables [][]string
		want   svc.InstrumentableType
	}{
		{"node only", [][]string{{"main", nodeSymbol}}, svc.InstrumentableNodejs},
		{"node before rust", [][]string{{nodeSymbol, rustSymbol}}, svc.InstrumentableNodejs},
		{"rust before node", [][]string{{rustSymbol, nodeSymbol}}, svc.InstrumentableNodejs},
		{"rust in the first table, node in the second", [][]string{{rustSymbol}, {nodeSymbol}}, svc.InstrumentableNodejs},
		{"rust in the first table, no marker in the second", [][]string{{rustSymbol}, {"main"}}, svc.InstrumentableRust},
		{"rust only", [][]string{{"main", rustSymbol}}, svc.InstrumentableRust},
		{"java before rust", [][]string{{jvmSymbol, rustSymbol}}, svc.InstrumentableJavaNative},
		{"rust before java", [][]string{{rustSymbol, jvmSymbol}}, svc.InstrumentableJavaNative},
		{"graal before rust", [][]string{{graalSymbol, rustSymbol}}, svc.InstrumentableJavaNative},
		{"rust in the first table, graal in the second", [][]string{{rustSymbol}, {graalSymbol}}, svc.InstrumentableJavaNative},
		{"rust with a bun-style node re-export", [][]string{{rustSymbol, bunReexport}}, svc.InstrumentableRust},
		{"node in the first table, rust in the second", [][]string{{nodeSymbol}, {rustSymbol}}, svc.InstrumentableNodejs},
		{"no marker", [][]string{{"main", "napi_create_function"}}, svc.InstrumentableGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchExeSymbols(symbolTablesContext(tt.tables...)))
		})
	}
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
	assert.NotZero(t, sym.Value)
	assert.NotZero(t, sym.Len)
	assert.NotNil(t, sym.Prog)
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
		want string // exact expected demangled path
	}{
		// Real samples (debug build) with $LT$S$GT$ generics + 17h<hash> build hash.
		{
			"LocalOwnedTasks::bind",
			"_ZN5tokio7runtime4task4list24LocalOwnedTasks$LT$S$GT$4bind17he45315048f19b0faE",
			"tokio::runtime::task::list::LocalOwnedTasks::bind",
		},
		{
			"OwnedTasks::bind_inner",
			"_ZN5tokio7runtime4task4list19OwnedTasks$LT$S$GT$10bind_inner17h69552d27e517e78cE",
			"tokio::runtime::task::list::OwnedTasks::bind_inner",
		},
		// Non-generic methods (no $LT$): RawTask::poll and the spawn_blocking free fn.
		{
			"RawTask::poll",
			"_ZN5tokio7runtime4task3raw7RawTask4poll17h0123456789abcdefE",
			"tokio::runtime::task::raw::RawTask::poll",
		},
		{
			"pool::spawn_blocking",
			"_ZN5tokio7runtime8blocking4pool14spawn_blocking17hfedcba9876543210E",
			"tokio::runtime::blocking::pool::spawn_blocking",
		},
		// A trailing Itanium template block (…IiEE) does not occur in real Rust
		// legacy symbols; the bare 'I' is a non-digit that just terminates the
		// scan, leaving the already-collected prefix intact.
		{
			"trailing template block terminates scan",
			"_ZN3foo3barIiEE",
			"foo::bar",
		},
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
		{
			"LocalOwnedTasks::bind",
			"_RINvMs_NtNtNtCsec06QdWoQn_5tokio7runtime4task4listINtB5_15LocalOwnedTasksINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtBb_4task5local6SharedEE4bindINtNtCsjCd2fZ6KadX_4core3pin3PinINtNtB1e_5boxed3BoxDNtNtNtB2k_6future6future6Futurep6OutputuNtNtB2k_6marker4SendEL_EEECsjqY7L67gDVE_8actix_rt",
			"tokio::runtime::task::list::LocalOwnedTasks::bind",
		},
		{
			"OwnedTasks::bind_inner",
			"_RNvMNtNtNtCsec06QdWoQn_5tokio7runtime4task4listINtB2_10OwnedTasksINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtB6_9scheduler14current_thread6HandleEE10bind_innerCsjqY7L67gDVE_8actix_rt",
			"tokio::runtime::task::list::OwnedTasks::bind_inner",
		},
		// pool::spawn_blocking — Real v0 sample (free fn, instantiated with the multi-thread worker Launch closure).
		// Generic args (I…E) and the trailing instantiation are dropped by the parser.
		{
			"pool::spawn_blocking",
			"_RINvNtNtNtCshFZRMeAqrSd_5tokio7runtime8blocking4pool14spawn_blockingNCNvMNtNtNtB6_9scheduler12multi_thread6workerNtB19_6Launch6launch0uEB8_",
			"tokio::runtime::blocking::pool::spawn_blocking",
		},
		// macOS prepends an extra leading underscore (__R…); rustDemangleV0 strips it
		// and must produce the same result as the _R… form above.
		{
			"OwnedTasks::bind_inner (macOS __R)",
			"__RNvMNtNtNtCsec06QdWoQn_5tokio7runtime4task4listINtB2_10OwnedTasksINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtB6_9scheduler14current_thread6HandleEE10bind_innerCsjqY7L67gDVE_8actix_rt",
			"tokio::runtime::task::list::OwnedTasks::bind_inner",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rustDemangleV0(c.raw)
			assert.True(t, strings.HasPrefix(got, c.wantPrefix), "got %q", got)
		})
	}
}

// TestRustDemangleV0_ComplexGenericArgs locks the structural generic-arg skip.
// These are real v0 Harness::<T,S>::poll monomorphizations whose generic args
// contain constructs that a naive I/E byte scan miscounts — a D…E dyn bound,
// deeply nested I…E, and type names whose bytes include capital 'I'/'E'
// (IntoFuture, Executor, Incoming). Before the fix, skipUntilE stopped short and
// the enclosing N mis-read the trailing method, dropping "::poll" (the whole v0
// under-resolution: ~20/27 copies attached instead of 27). All must now resolve
// to the full path so every monomorphization is instrumented.
func TestRustDemangleV0_ComplexGenericArgs(t *testing.T) {
	const wantPrefix = "tokio::runtime::task::harness::Harness::poll"
	cases := []struct{ name, raw string }{
		{
			"Pin<Box<dyn Future>> (D…E dyn bound)",
			"_RNvMs0_NtNtNtCs9jSgvtFl8W9_5tokio7runtime4task7harnessINtB5_7HarnessINtNtCsjCd2fZ6KadX_4core3pin3PinINtNtCseexLZiveblW_5alloc5boxed3BoxDNtNtNtB19_6future6future6Futurep6OutputuNtNtB19_6marker4SendEL_EEINtNtB1F_4sync3ArcNtNtNtB9_9scheduler14current_thread6HandleEE4pollCslgrtaP4xVX1_7reqwest",
		},
		{
			"H2Stream (deep nested I…E + IntoFuture/Incoming/Executor idents)",
			"_RNvMs0_NtNtNtCs9jSgvtFl8W9_5tokio7runtime4task7harnessINtB5_7HarnessINtNtNtNtCsiWqk3PIG25g_5hyper5proto2h26server8H2StreamINtNtNtCslucI2pHvjt9_10hyper_util7service4glue25TowerToHyperServiceFutureINtNtNtCs2X6c5HaYEso_5tower4util11map_request10MapRequestNtNtCshMmHa2FyZAo_4axum7routing6RouterNCNCNvXs0_NtB46_5serveINtB4O_5ServeB42_B42_ENtNtNtCsjCd2fZ6KadX_4core6future11into_future10IntoFuture11into_future0s1_0EINtNtCsi3ewrsuCVNV_4http7request7RequestNtNtNtB1d_4body8incoming8IncomingEENtNtCs5zVckKwpyv3_9axum_core4body4BodyNtNtNtB23_2rt5tokio13TokioExecutorEINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtB9_9scheduler14current_thread6HandleEE4pollCskAyKhQTcune_6server",
		},
		{
			"UpgradedSendStreamTask<Bytes>",
			"_RNvMs0_NtNtNtCs9jSgvtFl8W9_5tokio7runtime4task7harnessINtB5_7HarnessINtNtNtNtCsiWqk3PIG25g_5hyper5proto2h27upgrade22UpgradedSendStreamTaskNtNtCs10P6c5Uqsip_5bytes5bytes5BytesEINtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtB9_9scheduler14current_thread6HandleEE4pollCskAyKhQTcune_6server",
		},
		{
			"BlockingTask<trait-impl-method closure> (nested I…E in X trait path)",
			"_RNvMs0_NtNtNtCs9jSgvtFl8W9_5tokio7runtime4task7harnessINtB5_7HarnessINtNtNtB9_8blocking4task12BlockingTaskNCNvXs5_NtNtNtNtCslucI2pHvjt9_10hyper_util6client6legacy7connect3dnsNtB1O_11GaiResolverINtCsjabPfDUFD8q_13tower_service7ServiceNtB1O_4NameE4call0ENtNtB19_8schedule16BlockingScheduleE4pollB1W_",
		},
		{
			"axum serve IntoFuture (X trait method + nested I…E)",
			"_RNvMs0_NtNtNtCs9jSgvtFl8W9_5tokio7runtime4task7harnessINtB5_7HarnessNCNCNvXs0_NtCshMmHa2FyZAo_4axum5serveINtB1e_5ServeNtNtB1g_7routing6RouterB1S_ENtNtNtCsjCd2fZ6KadX_4core6future11into_future10IntoFuture11into_future0s2_0INtNtCseexLZiveblW_5alloc4sync3ArcNtNtNtB9_9scheduler14current_thread6HandleEE4pollCskAyKhQTcune_6server",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rustDemangleV0(c.raw)
			assert.True(t, strings.HasPrefix(got, wantPrefix), "got %q", got)
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

// TestRustPath_SelectsPollNotRawTaskPoll: the probe path raw::poll must equal the
// demangled vtable free fn raw::poll and NOT the RawTask::poll thunk (whose path has
// "RawTask::" between "raw::" and "poll"). Matching the thunk would probe an inlinable
// function or double-fire.
func TestRustPath_SelectsPollNotRawTaskPoll(t *testing.T) {
	const path = "tokio::runtime::task::raw::poll"
	rawPoll := rustDemangle("_ZN5tokio7runtime4task3raw4poll17h0123456789abcdefE")
	rawTaskPoll := rustDemangle("_ZN5tokio7runtime4task3raw7RawTask4poll17h0123456789abcdefE")

	assert.Equal(t, path, rawPoll, "raw::poll (vtable target) must match the probe path")
	assert.Equal(t, "tokio::runtime::task::raw::RawTask::poll", rawTaskPoll)
	assert.NotEqual(t, path, rawTaskPoll, "RawTask::poll (thunk) must NOT match the probe path")
}

// TestRustPath_NestedItemsAreNotCopies: a probe path matches a symbol only when the
// whole demangled path is equal. The nested helpers of Cell::new (new_header, check) and
// of Harness::poll (poll_inner) start with the parent's path but are different functions;
// they are inlined in release and out-of-line in debug builds, where a prefix match used
// to attach the parent's uretprobe to them (one bogus Header entry per spawn in debug).
// Real symbols from the debug test server (v0, rust 1.96 / tokio 1.52) and legacy-mangled
// equivalents.
func TestRustPath_NestedItemsAreNotCopies(t *testing.T) {
	const cellNew = "tokio::runtime::task::core::Cell::new"
	const harnessPoll = "tokio::runtime::task::harness::Harness::poll"

	copies := map[string]string{
		"_ZN5tokio7runtime4task4core17Cell$LT$T$C$S$GT$3new17h0123456789abcdefE": cellNew,
		"_RNvMs0_NtNtNtCscQKylqqyKjT_5tokio7runtime4task4coreINtB5_4CellINtNtCsjemqvGMJH9i_4core3pin3PinINtNtCsbSVVNPxiylx_5alloc5boxed3BoxNCNCNvCs388xbHJbcbW_6server11ws_direct_b00EEINtNtB1z_4sync3ArcNtNtNtNtB9_9scheduler12multi_thread6handle6HandleEE3newB29_": cellNew,
		"_RNvMs0_NtNtNtCscQKylqqyKjT_5tokio7runtime4task7harnessINtB5_7HarnessNCNCNvCs388xbHJbcbW_6server7chan_tx00INtNtCsbSVVNPxiylx_5alloc4sync3ArcNtNtNtNtB9_9scheduler12multi_thread6handle6HandleEE4pollB1a_":                                                    harnessPoll,
		"_ZN5tokio7runtime4task7harness20Harness$LT$T$C$S$GT$4poll17h0123456789abcdefE": harnessPoll,
	}
	for mangled, want := range copies {
		got := rustDemangle(mangled)
		if got == "" {
			got = rustDemangleV0(mangled)
		}
		assert.Equal(t, want, got, "monomorphized copy must demangle to the probe path: %s", mangled)
	}

	nested := map[string]string{
		"_RNvNvMs0_NtNtNtCscQKylqqyKjT_5tokio7runtime4task4coreINtB7_4CellppE3new10new_header":                                                                                                                   cellNew,
		"_RINvNvMs0_NtNtNtCscQKylqqyKjT_5tokio7runtime4task4coreINtB8_4CellppE3new5checkNtNtNtBc_8blocking8schedule16BlockingScheduleEBe_":                                                                       cellNew,
		"_ZN5tokio7runtime4task4core17Cell$LT$T$C$S$GT$3new10new_header17h0123456789abcdefE":                                                                                                                     cellNew,
		"_ZN5tokio7runtime4task4core17Cell$LT$T$C$S$GT$3new5check17h0123456789abcdefE":                                                                                                                           cellNew,
		"_ZN5tokio7runtime4task7harness20Harness$LT$T$C$S$GT$10poll_inner17h0123456789abcdefE":                                                                                                                   harnessPoll,
		"_RNvMs0_NtNtNtCscQKylqqyKjT_5tokio7runtime4task7harnessINtB5_7HarnessINtNtNtB9_8blocking4task12BlockingTaskNCNCNvCs388xbHJbcbW_6server8blocking00ENtNtB19_8schedule16BlockingScheduleE10poll_innerB1M_": harnessPoll,
	}
	for mangled, parent := range nested {
		got := rustDemangle(mangled)
		if got == "" {
			got = rustDemangleV0(mangled)
		}
		require.NotEmpty(t, got, "must demangle: %s", mangled)
		assert.True(t, strings.HasPrefix(got, parent), "nested item starts with the parent path: %s", got)
		assert.NotEqual(t, parent, got, "nested item must NOT be taken as a copy of the parent: %s", got)
	}
}

// TestFindRustSymbols_NoFalseMatchOnNonRust confirms a Rust path matches
// nothing in a non-Rust (Go) binary — symbols that don't demangle as Rust are
// skipped, so the path machinery never produces spurious attachments.
func TestFindRustSymbols_NoFalseMatchOnNonRust(t *testing.T) {
	f := openSymbolFixtureELF(t)
	defer f.Close()

	out, err := FindRustSymbols(f, []string{"tokio::runtime::task::raw::poll"})
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

func main() {
	exactLookupTarget()
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

// The symbols are matched through the same fastelf scan that runs in
// production, which admits only defined, sized STT_FUNC entries in .symtab or
// .dynsym. A table of hand-written mangled names cannot catch a Node build
// whose node:: symbols are undefined imports or STT_OBJECT, so the real
// executable is typed here rather than the strings it is expected to contain.
func TestFindLanguageFromElf_NodeBinary(t *testing.T) {
	path, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found in PATH")
	}

	resolved, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)

	if isLauncherForSharedRuntime(t, resolved) {
		t.Skip("this node links the runtime as libnode.so, which the shared-library pass types")
	}

	assert.Equal(t, svc.InstrumentableNodejs, findLanguageFromElf(resolved))
}

func TestFindLanguageFromElf_NonNodeExecutable(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)

	assert.NotEqual(t, svc.InstrumentableNodejs, findLanguageFromElf(self))
}

func isLauncherForSharedRuntime(t *testing.T, path string) bool {
	t.Helper()

	f, err := elf.Open(path)
	require.NoError(t, err)
	defer f.Close()

	libs, err := f.ImportedLibraries()
	if err != nil {
		return false
	}

	for _, lib := range libs {
		if strings.Contains(lib, "libnode.so") {
			return true
		}
	}

	return false
}

func TestPopulateRangeIsBestEffort(t *testing.T) {
	page := os.Getpagesize()
	data := make([]byte, 4*page)

	assert.NotPanics(t, func() {
		populateRange(data, 0, 0)
		populateRange(data, uint64(page)+7, uint64(page))
		populateRange(data, uint64(len(data)), 1)
		populateRange(data, 1, ^uint64(0))
	})
}

// Closure bodies must never be probed: legacy encodes them as a
// $u7b$$u7b$closure$u7d$$u7d$ segment; v0 as a root NC element that our simplified
// demangler renders identically to the parent fn (so it can only be told apart on the
// mangled form). All samples below are real symbols from the rusttokiostudy binary.
func TestIsRustClosureSymbol(t *testing.T) {
	closures := []string{
		// legacy {{closure}} inside Sender::try_send
		"_ZN5hyper6client8dispatch19Sender$LT$T$C$U$GT$8try_send28_$u7b$$u7b$closure$u7d$$u7d$17h4e845f50370058e4E",
		// legacy {{closure}} inside Dispatcher::poll_catch
		"_ZN5hyper5proto2h18dispatch32Dispatcher$LT$D$C$Bs$C$I$C$T$GT$10poll_catch28_$u7b$$u7b$closure$u7d$$u7d$17h2e4870ad20ac4d6aE",
		// v0 root closure of Sender::try_send (NC element right after _R)
		"_RNCNvMNtNtCsiYXsGep02p_5hyper6client8dispatchINtB4_6SenderINtNtCs6kuRhDqI2rp_4http7request7RequestNtNtNtCsbey0SzD3JOC_7reqwest10async_impl4body4BodyEINtNtBZ_8response8ResponseNtNtNtB8_4body8incoming8IncomingEE8try_send0B1E_",
		// v0 root closure, macOS __R prefix variant
		"__RNCNvMNtNtCsiYXsGep02p_5hyper6client8dispatchINtB4_6SenderE8try_send0B1E_",
	}
	for _, s := range closures {
		if !isRustClosureSymbol(s) {
			t.Errorf("expected closure: %s", s)
		}
	}

	nonClosures := []string{
		// legacy real fn
		"_ZN5hyper6client8dispatch19Sender$LT$T$C$U$GT$8try_send17h5dd32ffbeae5b6beE",
		// v0 real method (M element, not NC)
		"_RNvMNtNtCsiYXsGep02p_5hyper6client8dispatchINtB2_6SenderINtNtCs6kuRhDqI2rp_4http7request7RequestNtNtNtCsbey0SzD3JOC_7reqwest10async_impl4body4BodyEINtNtBX_8response8ResponseNtNtNtB6_4body8incoming8IncomingEE8try_sendB1C_",
		// v0 free fn in a value namespace (set_current_task_id shape)
		"_RNvNtNtCs9WjIm1D4ZsH_5tokio7runtime7context19set_current_task_id",
		// identifier containing the letters "NC" mid-symbol must not false-positive
		"_ZN5tokio4sync4mpsc4chan15Tx$LT$T$C$S$GT$4send17hd609113dde8fd8cfE",
		// non-Rust symbol
		"main",
	}
	for _, s := range nonClosures {
		if isRustClosureSymbol(s) {
			t.Errorf("did not expect closure: %s", s)
		}
	}
}
