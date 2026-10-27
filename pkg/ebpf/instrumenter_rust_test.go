// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"debug/elf"
	"log/slog"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// rustTestCode returns a function body that ends in a return instruction and one that
// never returns (NOPs only), for the architecture the test runs on.
func rustTestCode(t *testing.T) (withRet, withoutRet []byte) {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return []byte{0x90, 0x90, 0xc3}, []byte{0x90, 0x90, 0x90, 0x90}
	case "arm64":
		nop := []byte{0x1f, 0x20, 0x03, 0xd5}
		ret := []byte{0xc0, 0x03, 0x5f, 0xd6}
		return append(append([]byte{}, nop...), ret...), append(append([]byte{}, nop...), nop...)
	default:
		t.Skipf("no return-offset decoder for %s", runtime.GOARCH)
		return nil, nil
	}
}

// rustCopy fakes one monomorphized symbol copy whose code lives at off in an in-memory
// program segment.
func rustCopy(off uint64, code []byte) procs.Sym {
	return procs.Sym{
		Name: "copy",
		Off:  off,
		Len:  uint64(len(code)),
		Prog: &elf.Prog{ProgHeader: elf.ProgHeader{Off: off}, ReaderAt: bytes.NewReader(code)},
	}
}

func TestExpandRustPathCopiesWarnsOnCopyWithoutReturnOffsets(t *testing.T) {
	withRet, withoutRet := rustTestCode(t)
	logs := captureLogs(t)
	templates := []*ebpfcommon.ProbeDesc{{Start: &ebpf.Program{}, End: &ebpf.Program{}}}
	matched := []procs.Sym{rustCopy(0x1000, withRet), rustCopy(0x2000, withoutRet)}

	expanded, required, inlined := expandRustPathCopies("tokio::poll", templates, matched, "/proc/1/exe", slog.Default())

	require.Len(t, expanded, 2)
	assert.False(t, required)
	assert.False(t, inlined)
	assert.NotNil(t, expanded[0].End)
	assert.NotEmpty(t, expanded[0].ReturnOffsets)
	assert.Nil(t, expanded[1].End, "a copy without return offsets attaches the entry probe only")
	assert.Empty(t, expanded[1].ReturnOffsets)
	assert.Contains(t, logs.String(), "without return offsets")
	assert.Contains(t, logs.String(), "without_returns=1")
	assert.Contains(t, logs.String(), "copies=2")
}

func TestExpandRustPathCopiesStaysSilentWhenAllCopiesReturn(t *testing.T) {
	withRet, _ := rustTestCode(t)
	logs := captureLogs(t)
	templates := []*ebpfcommon.ProbeDesc{{Start: &ebpf.Program{}, End: &ebpf.Program{}}}

	expanded, _, _ := expandRustPathCopies("tokio::poll", templates, []procs.Sym{rustCopy(0x1000, withRet)}, "/proc/1/exe", slog.Default())

	require.Len(t, expanded, 1)
	assert.NotNil(t, expanded[0].End)
	assert.NotContains(t, logs.String(), "without return offsets")
}

func TestExpandRustPathCopiesMayBeInlinedStaysSilent(t *testing.T) {
	_, withoutRet := rustTestCode(t)
	logs := captureLogs(t)
	templates := []*ebpfcommon.ProbeDesc{{End: &ebpf.Program{}, MayBeInlined: true}}

	expanded, _, inlined := expandRustPathCopies("tokio::Id::next", templates, []procs.Sym{rustCopy(0x1000, withoutRet)}, "/proc/1/exe", slog.Default())

	assert.Empty(t, expanded, "a uretprobe-only copy without return offsets attaches nothing")
	assert.True(t, inlined)
	assert.NotContains(t, logs.String(), "without return offsets")
}

func TestUprobeModulesSkipSelfProbesForNonRust(t *testing.T) {
	i := &instrumenter{}
	tracer := &stubTracer{uprobes: map[string]map[string][]*ebpfcommon.ProbeDesc{
		ebpfcommon.SelfLibKey: {
			"tokio::runtime::task::harness::Harness::poll": {{DemangledPath: true, Start: &ebpf.Program{}}},
		},
	}}

	modules := i.uprobeModules(tracer, 1, svc.InstrumentableGolang, nil, "/proc/1/exe", 0, slog.Default())

	assert.Empty(t, modules, "the self-binary symbol scan runs only for Rust executables")
}
