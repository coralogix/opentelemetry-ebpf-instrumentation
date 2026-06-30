// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gometa // import "go.opentelemetry.io/obi/pkg/internal/gometa"

// Arch selects a Go regabi register layout (1.17+).
type Arch uint8

const (
	ArchInvalid Arch = iota
	ArchAMD64
	ArchARM64
)

func (a Arch) String() string {
	switch a {
	case ArchAMD64:
		return "amd64"
	case ArchARM64:
		return "arm64"
	default:
		return "invalid"
	}
}

// amd64IntRegs maps Go regabi int-arg slots to pt_regs byte offsets in
// declaration order: AX, BX, CX, DI, SI, R8, R9, R10, R11. pt_regs layout
// per arch/x86/include/uapi/asm/ptrace.h (AX=80, BX=40, CX=88, …).
var amd64IntRegs = []int{80, 40, 88, 112, 104, 72, 64, 56, 48}

// arm64IntRegs maps Go regabi int-arg slots to pt_regs byte offsets in
// declaration order: X0..X15. user_pt_regs starts with regs[31] at offset 0.
var arm64IntRegs = []int{0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120}

// regList returns the int-register pt_regs offsets for arch, in Go regabi
// argument order. Nil for unsupported archs.
func regList(a Arch) []int {
	switch a {
	case ArchAMD64:
		return amd64IntRegs
	case ArchARM64:
		return arm64IntRegs
	default:
		return nil
	}
}

// regAllocator hands out consecutive Go regabi int-register slots. Once the
// pool is exhausted further args would spill to the stack; we don't extract
// those.
type regAllocator struct {
	regs []int
	idx  int
}

func newRegAllocator(arch Arch) *regAllocator {
	return &regAllocator{regs: regList(arch)}
}

// take consumes n consecutive slots, returning their pt_regs offsets.
// ok=false when n would exceed the remaining pool.
func (a *regAllocator) take(n int) ([]int, bool) {
	if a.idx+n > len(a.regs) {
		return nil, false
	}
	out := a.regs[a.idx : a.idx+n]
	a.idx += n
	return out, true
}

// skip advances n slots without returning them — used for non-extractable
// kinds (slices, interfaces, ...) so subsequent args land on the right reg.
func (a *regAllocator) skip(n int) {
	a.idx += n
	if a.idx > len(a.regs) {
		a.idx = len(a.regs)
	}
}
