// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"debug/elf"
	"errors"
	"fmt"

	"go.opentelemetry.io/obi/pkg/config"
)

// ObiUSDTPairTid exposes the pair_kind constant for paired function spans.
func ObiUSDTPairTid() uint8 { return obiUSDTPairTid }

// CustomSpanArgKind mirrors enum custom_span_arg_kind in custom_span.h.
type CustomSpanArgKind uint8

const (
	CustomSpanArgNone CustomSpanArgKind = 0
	CustomSpanArgInt  CustomSpanArgKind = 1
	CustomSpanArgStr  CustomSpanArgKind = 2
)

// CustomSpanEventKind mirrors enum custom_span_event_kind in custom_span.h.
type CustomSpanEventKind uint8

const (
	CustomSpanKindInvalid CustomSpanEventKind = 0
	CustomSpanKindStart   CustomSpanEventKind = 1
	CustomSpanKindEnd     CustomSpanEventKind = 2
	CustomSpanKindSingle  CustomSpanEventKind = 3
)

type CompiledCustomSpanSpec struct {
	Spec     obiUSDTSpec
	Cookie   uint64
	ArgKinds [obiUSDTMaxArgs]CustomSpanArgKind
}

// ErrCustomSpanDrift signals attrs that can't be mapped to the probe's
// ELF-parsed argument layout (out-of-range arg index or bad ELF arg size).
var ErrCustomSpanDrift = errors.New("custom_span: attr layout drifts from probe USDT arg spec")

// CompileCustomSpanSpec rewrites a base ELF-parsed spec so string attrs
// become k_obi_usdt_arg_reg_deref_str entries. Integer attrs with no
// configured Type inherit sign + width from the .note.stapsdt record.
// Soft drift (start/end probes disagreeing on a slot, attr-declared int
// width != ELF int width) is silently kept as the ELF kind; userspace
// skips mismatched extractions.
func CompileCustomSpanSpec(
	base obiUSDTSpec,
	span *config.CustomSpanSpec,
	cookie uint64,
) (CompiledCustomSpanSpec, error) {
	out := CompiledCustomSpanSpec{
		Spec:   base,
		Cookie: cookie,
	}
	out.Spec.Cookie = cookie

	for i := uint16(0); i < base.ArgCount; i++ {
		switch base.Args[i].ArgType {
		case obiUSDTArgConst, obiUSDTArgReg, obiUSDTArgRegDeref:
			out.ArgKinds[i] = CustomSpanArgInt
		default:
			out.ArgKinds[i] = CustomSpanArgNone
		}
	}

	for name, a := range span.Attrs {
		if uint16(a.Arg) >= base.ArgCount {
			return CompiledCustomSpanSpec{}, fmt.Errorf(
				"%w: attr %q references arg %d but probe declares only %d args",
				ErrCustomSpanDrift, name, a.Arg, base.ArgCount,
			)
		}

		if a.Type.IsString() {
			if base.Args[a.Arg].ArgType != obiUSDTArgReg {
				continue // soft drift
			}
			out.Spec.Args[a.Arg] = obiUSDTArgSpec{
				RegOff:  base.Args[a.Arg].RegOff,
				ValOff:  uint64(CustomSpanStringSize),
				ArgType: obiUSDTArgRegDerefStr,
			}
			out.ArgKinds[a.Arg] = CustomSpanArgStr
			continue
		}

		if a.Type.Empty() {
			out.ArgKinds[a.Arg] = CustomSpanArgInt
			continue
		}

		probeSize, ok := elfArgSizeBytes(base.Args[a.Arg])
		if !ok {
			return CompiledCustomSpanSpec{}, fmt.Errorf(
				"%w: attr %q: probe arg %d uses unsupported size", ErrCustomSpanDrift, name, a.Arg,
			)
		}
		if uint8(probeSize) != a.Type.SizeBytes() {
			continue // soft drift on int size
		}
		out.ArgKinds[a.Arg] = CustomSpanArgInt
	}

	return out, nil
}

// CustomSpanStringSize mirrors config.CustomSpanStringSize for BPF cap.
const CustomSpanStringSize = config.CustomSpanStringSize

// MakeCustomSpanSpecRewrite captures span+cookie for use as a
// USDTSpecRewriter on the per-probe target.
func MakeCustomSpanSpecRewrite(span *config.CustomSpanSpec, cookie uint64) func(any) (any, error) {
	return func(in any) (any, error) {
		spec, ok := in.(obiUSDTSpec)
		if !ok {
			return nil, fmt.Errorf("MakeCustomSpanSpecRewrite: expected obiUSDTSpec, got %T", in)
		}
		compiled, err := CompileCustomSpanSpec(spec, span, cookie)
		if err != nil {
			return nil, err
		}
		return compiled.Spec, nil
	}
}

// MakeCustomSpanSpecRewriteWithMatch is the same as MakeCustomSpanSpecRewrite
// but also installs an in-BPF match-value filter on the arg at Match.Arg.
// At fire time, BPF compares arg_str[Match.Arg] to spec.MatchName byte-for-byte
// and discards the event on mismatch.
func MakeCustomSpanSpecRewriteWithMatch(span *config.CustomSpanSpec, cookie uint64) func(any) (any, error) {
	return func(in any) (any, error) {
		spec, ok := in.(obiUSDTSpec)
		if !ok {
			return nil, fmt.Errorf("MakeCustomSpanSpecRewriteWithMatch: expected obiUSDTSpec, got %T", in)
		}
		compiled, err := CompileCustomSpanSpec(spec, span, cookie)
		if err != nil {
			return nil, err
		}
		out := compiled.Spec
		if span.HasMatch() {
			m := span.On.Match
			if uint16(m.Arg) >= spec.ArgCount {
				return nil, fmt.Errorf("%w: match.arg %d exceeds probe arg count %d",
					ErrCustomSpanDrift, m.Arg, spec.ArgCount)
			}
			// Coerce both `reg` (the value IS a user pointer to a NUL-string)
			// and `reg_deref` (the value is `*(reg+off)`, which for string args
			// is usually still a pointer the caller wants us to deref) into a
			// string read. This makes match work on USDT macro forms that emit
			// either encoding.
			argT := out.Args[m.Arg].ArgType
			if argT == obiUSDTArgReg || argT == obiUSDTArgRegDeref {
				out.Args[m.Arg] = obiUSDTArgSpec{
					RegOff:  out.Args[m.Arg].RegOff,
					ValOff:  uint64(obiUSDTMatchNameLen),
					ArgType: obiUSDTArgRegDerefStr,
				}
			}
			// Ensure the BPF fill_args loop processes the match arg even when
			// the user declared no attrs on it. Without this, arg_kind stays
			// `none` and match_name_ok always returns 0.
			if uint16(m.Arg)+1 > out.ArgCount {
				out.ArgCount = uint16(m.Arg) + 1
			}
			out.MatchArgIdx = m.Arg
			out.MatchEnabled = 1
			copyMatchName(&out.MatchName, m.Value)
		}
		return out, nil
	}
}

func copyMatchName(dst *[obiUSDTMatchNameLen]byte, s string) {
	n := len(s)
	if n >= obiUSDTMatchNameLen {
		n = obiUSDTMatchNameLen - 1
	}
	copy(dst[:n], s)
	dst[n] = 0
}

// fnArgRegOffset maps a function-mode argument index to its pt_regs byte
// offset. The selected ABI (Go regabi vs C System V) depends on the target
// binary's detected language.
func fnArgRegOffset(arch string, idx uint8, lang FunctionLang) (int16, bool) {
	switch arch {
	case "arm64":
		// AAPCS64 and Go regabi share x0..x7 for the first eight scalar args.
		if idx <= 7 {
			return int16(idx) * 8, true
		}
	case "amd64":
		if lang == FunctionLangGo {
			// Go regabi: AX,BX,CX,DI,SI,R8,R9,R10,R11.
			off := []int16{80, 40, 88, 112, 104, 72, 64, 56, 48}
			if int(idx) < len(off) {
				return off[idx], true
			}
		} else {
			// System V AMD64 (C): RDI,RSI,RDX,RCX,R8,R9.
			off := []int16{112, 104, 96, 88, 72, 64}
			if int(idx) < len(off) {
				return off[idx], true
			}
		}
	}
	return 0, false
}

// FunctionLang selects the string-argument layout for function-mode probes.
type FunctionLang uint8

const (
	FunctionLangGo FunctionLang = iota
	FunctionLangC
)

// DetectFunctionLang reads ELF sections to decide whether a binary uses Go
// regabi string passing or C-style NUL-terminated strings. Looks for the
// canonical Go ELF markers `.note.go.buildid` and `.go.buildinfo`.
func DetectFunctionLang(elfFile *elf.File) FunctionLang {
	for _, sec := range elfFile.Sections {
		switch sec.Name {
		case ".note.go.buildid", ".go.buildinfo", ".gopclntab":
			return FunctionLangGo
		}
	}
	return FunctionLangC
}

// BuildGoABISpec synthesizes a USDT spec mirror for a function uprobe.
// `attrs[N].arg` is the register-index. For Go strings use the {ptr,len}
// 2-register layout; for C strings read NUL-terminated from a single
// pointer arg. The arch selects the pt_regs offset table (arm64 / amd64).
func BuildGoABISpec(span *config.CustomSpanSpec, cookie uint64, arch string, lang FunctionLang) (CompiledCustomSpanSpec, error) {
	out := CompiledCustomSpanSpec{Cookie: cookie}
	out.Spec.Cookie = cookie

	maxArg := uint16(0)
	for name, a := range span.Attrs {
		if uint16(a.Arg) >= obiUSDTMaxArgs {
			return CompiledCustomSpanSpec{}, fmt.Errorf(
				"%w: attr %q arg %d exceeds max %d", ErrCustomSpanDrift, name, a.Arg, obiUSDTMaxArgs-1)
		}
		regOff, ok := fnArgRegOffset(arch, a.Arg, lang)
		if !ok {
			return CompiledCustomSpanSpec{}, fmt.Errorf(
				"%w: attr %q arg %d has no Go regabi mapping on %s", ErrCustomSpanDrift, name, a.Arg, arch)
		}
		if uint16(a.Arg)+1 > maxArg {
			maxArg = uint16(a.Arg) + 1
		}
		spec := obiUSDTArgSpec{RegOff: regOff}
		switch {
		case a.Type.IsString():
			if lang == FunctionLangC {
				spec.ArgType = obiUSDTArgRegDerefStr
			} else {
				spec.ArgType = obiUSDTArgGoString
			}
			spec.ValOff = uint64(config.CustomSpanStringSize)
			out.ArgKinds[a.Arg] = CustomSpanArgStr
		default:
			spec.ArgType = obiUSDTArgReg
			spec.ArgBitshift = sizeToBitshift(a.Type.SizeBytes())
			spec.ArgSigned = boolToU8(a.Type.Signed())
			out.ArgKinds[a.Arg] = CustomSpanArgInt
		}
		out.Spec.Args[a.Arg] = spec
	}
	out.Spec.ArgCount = maxArg
	return out, nil
}

func sizeToBitshift(size uint8) uint8 {
	switch size {
	case 1:
		return 56
	case 2:
		return 48
	case 4:
		return 32
	}
	return 0
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// elfArgSizeBytes decodes the (64 - bits) value stored in ArgBitshift.
func elfArgSizeBytes(arg obiUSDTArgSpec) (int, bool) {
	switch arg.ArgBitshift {
	case 0:
		return 8, true
	case 32:
		return 4, true
	case 48:
		return 2, true
	case 56:
		return 1, true
	default:
		return 0, false
	}
}
