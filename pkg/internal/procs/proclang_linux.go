// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"debug/elf"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/fastelf"
)

// rustDemangle converts a Rust legacy-mangled _ZN…E symbol to a simplified
// demangled path (e.g. "tokio::runtime::task::raw::poll").
//
// Rust legacy mangling only ever has length-prefixed identifiers or the closing
// 'E' at a path position — it never emits a bare Itanium template list (I…E) or
// nested-name (N…E) there, so those are not handled; a stray non-digit simply
// terminates the scan and returns the prefix collected so far.
//
// Rust also encodes generic type parameters directly inside length-prefixed
// identifiers using $LT$...$GT$ escapes (e.g. "LocalOwnedTasks$LT$S$GT$").
// These are stripped so that "LocalOwnedTasks$LT$S$GT$" becomes "LocalOwnedTasks".
//
// The Rust build-hash component (17h<16 lowercase hex chars>) is also dropped.
//
// Returns "" for symbols that do not start with "_ZN" (e.g. v0-scheme _R
// symbols, C symbols) — callers fall back to exact-name matching for those.
func rustDemangle(name string) string {
	if !strings.HasPrefix(name, "_ZN") {
		return ""
	}
	rest := name[3:] // inside the outer nested-name scope opened by _ZN
	var parts []string
	for len(rest) > 0 {
		if rest[0] == 'E' {
			// End of the outer nested name — we are done.
			goto done
		}
		// Read a length-prefixed identifier.
		n := 0
		for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
			n = n*10 + int(rest[0]-'0')
			rest = rest[1:]
		}
		if n == 0 || n > len(rest) {
			break
		}
		part := rest[:n]
		rest = rest[n:]
		// Rust build-hash: 17 chars, starts with 'h', followed by 16 lowercase hex digits.
		if len(part) == 17 && part[0] == 'h' {
			isHash := true
			for _, c := range part[1:] {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					isHash = false
					break
				}
			}
			if isHash {
				break
			}
		}
		// Strip $LT$...$GT$ generic type parameters embedded in the identifier.
		part = stripDollarBrackets(part)
		parts = append(parts, part)
	}
done:
	return strings.Join(parts, "::")
}

// stripDollarBrackets removes $LT$...$GT$ encoded angle brackets from a Rust
// legacy-mangled identifier segment.  Rust encodes generic type parameters
// directly inside length-prefixed identifiers using dollar-escaped brackets
// (e.g. "LocalOwnedTasks$LT$S$GT$" -> "LocalOwnedTasks").  Nesting is handled
// by tracking depth so that "Foo$LT$Bar$LT$X$GT$$GT$" -> "Foo".
func stripDollarBrackets(s string) string {
	for {
		start := strings.Index(s, "$LT$")
		if start == -1 {
			return s
		}
		depth := 1
		i := start + 4
		for i < len(s) && depth > 0 {
			switch {
			case strings.HasPrefix(s[i:], "$LT$"):
				depth++
				i += 4
			case strings.HasPrefix(s[i:], "$GT$"):
				depth--
				i += 4
			default:
				i++
			}
		}
		if depth != 0 {
			return s // malformed encoding — leave unchanged
		}
		s = s[:start] + s[i:]
	}
}

// rustDemangleV0 converts a Rust v0-mangled _R… symbol to a simplified
// demangled path sufficient for prefix matching.
//
// Generic arguments are dropped; back-references are resolved by caching
// parsed results at their byte positions in the input.  Impl paths produce
// "<Type>" which is subsequently stripped of angle brackets by the caller.
//
// Returns "" on any parse failure or unrecognised construct so that callers
// can fall back silently.
func rustDemangleV0(name string) string {
	s := name
	if strings.HasPrefix(s, "__R") { // macOS adds an extra leading underscore
		s = s[1:]
	}
	if !strings.HasPrefix(s, "_R") {
		return ""
	}
	s = s[2:] // strip "_R"; positions in v0Parser are relative to this string

	p := &v0Parser{sym: s, cache: make(map[int]string)}
	result := p.path(0)
	if result == "" {
		return ""
	}
	// Normalise impl syntax: "<Type>::method" -> "Type::method"
	result = strings.ReplaceAll(result, "<", "")
	result = strings.ReplaceAll(result, ">", "")
	// Collapse any double-colon artefact left by ">::" -> "::"
	for strings.Contains(result, "::::") {
		result = strings.ReplaceAll(result, "::::", "::")
	}
	result = strings.Trim(result, ":")
	return result
}

// v0Parser is a stateful parser for the Rust v0 symbol mangling grammar.
// See RFC 2603 (https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html).
type v0Parser struct {
	sym   string
	pos   int
	cache map[int]string // byte-offset of element start -> demangled string
}

// path parses one path element at the current position.
// depth prevents infinite recursion on malformed input.
func (p *v0Parser) path(depth int) string {
	if depth > 64 || p.pos >= len(p.sym) {
		return ""
	}
	startPos := p.pos
	var result string

	switch p.sym[p.pos] {
	case 'C': // crate root: C <disambiguator> <identifier>
		p.pos++
		p.skipDisambiguator()
		result = p.ident()

	case 'N': // nested: N <namespace> <path> <identifier>
		p.pos++
		if p.pos >= len(p.sym) {
			return ""
		}
		// Skip the single namespace-kind byte (v=value, t=type, i=impl, C=closure…);
		// we don't need it for prefix matching.
		p.pos++
		parent := p.path(depth + 1)
		p.skipDisambiguator()
		name := p.ident()
		switch {
		case parent != "" && name != "":
			result = parent + "::" + name
		case parent != "":
			result = parent
		default:
			result = name
		}

	case 'M': // inherent impl: M <disambiguator> <impl-module-path> <self-type>
		p.pos++
		p.skipDisambiguator()
		p.path(depth + 1) // impl-module path — consumed to populate cache for back-refs
		selfType := p.path(depth + 1)
		result = "<" + selfType + ">"

	// Note: X/Y are not hit by the current probe prefixes: those are all N/M/C forms,
	// These arms are retained for demangler completeness and future trait-impl
	// targets, e.g. <T as Future>::poll.
	case 'X': // trait impl: X <disambiguator> <self-type> <trait>
		p.pos++
		p.skipDisambiguator()
		selfType := p.path(depth + 1)
		traitPath := p.path(depth + 1)
		result = "<" + selfType + " as " + traitPath + ">"

	case 'Y': // type-as-trait: Y <type> <trait>
		p.pos++
		selfType := p.path(depth + 1)
		traitPath := p.path(depth + 1)
		result = "<" + selfType + " as " + traitPath + ">"

	case 'I': // generic args: I <path> {<generic-arg>} E — drop args for matching
		p.pos++
		result = p.path(depth + 1)
		p.skipUntilE()

	case 'B': // back-reference: B <base62-position> _
		p.pos++
		ref := p.base62()
		if cached, ok := p.cache[ref]; ok {
			result = cached
		} else {
			savedPos := p.pos
			p.pos = ref
			result = p.path(depth + 1)
			p.pos = savedPos
			p.cache[ref] = result
		}
		p.cache[startPos] = result
		return result
	}

	p.cache[startPos] = result
	return result
}

// skipDisambiguator consumes an optional "s<base62>_" disambiguator.
func (p *v0Parser) skipDisambiguator() {
	if p.pos < len(p.sym) && p.sym[p.pos] == 's' {
		p.pos++
		p.base62()
	}
}

// ident parses a length-prefixed identifier.
// ASCII form: <decimal-len> <bytes>.  Unicode form: "u" <base62-len> <bytes>.
func (p *v0Parser) ident() string {
	if p.pos >= len(p.sym) {
		return ""
	}
	if p.sym[p.pos] == 'u' { // unicode (punycode) identifier — consume, return raw bytes
		p.pos++
		n := p.base62()
		if n == 0 || p.pos+n > len(p.sym) {
			return ""
		}
		s := p.sym[p.pos : p.pos+n]
		p.pos += n
		return s
	}
	n := 0
	for p.pos < len(p.sym) && p.sym[p.pos] >= '0' && p.sym[p.pos] <= '9' {
		n = n*10 + int(p.sym[p.pos]-'0')
		p.pos++
	}
	// Optional '_' between length and bytes (only when bytes start with a digit).
	if p.pos < len(p.sym) && p.sym[p.pos] == '_' {
		p.pos++
	}
	if n == 0 || p.pos+n > len(p.sym) {
		return ""
	}
	s := p.sym[p.pos : p.pos+n]
	p.pos += n
	return s
}

// base62 reads a base-62 encoded integer followed by '_' and returns its value.
// The encoding is: "_" = 0, "0_" = 1, "1_" = 2, …, "z_" = 36, "A_" = 37, … "Z_" = 62.
func (p *v0Parser) base62() int {
	n := 0
	hasDigit := false
	overflow := false
scan:
	for p.pos < len(p.sym) {
		c := p.sym[p.pos]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'z':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'Z':
			d = int(c-'A') + 36
		default:
			// '_' terminator or any non-base62 char: stop WITHOUT consuming it.
			// (A labeled break is required — a plain `break` here would only leave
			// the switch and then wrongly consume the char as a 0 digit.)
			break scan
		}
		hasDigit = true
		p.pos++
		// Keep consuming digits so pos lands on the '_' terminator even for large
		// values: disambiguator hashes (whose value is skipped) encode base62 numbers
		// far larger than len(p.sym). Bailing out mid-number here would strand pos
		// inside the hash and derail every subsequent token. Once the value exceeds
		// any usable string length / byte position it can only be out-of-range —
		// which every caller already rejects via its ">= len(p.sym)" bounds check —
		// so stop accumulating (avoiding signed-int overflow to a negative index) but
		// keep scanning to the terminator.
		if !overflow {
			n = n*62 + d
			if n > len(p.sym) {
				overflow = true
			}
		}
	}
	if p.pos < len(p.sym) && p.sym[p.pos] == '_' {
		p.pos++
	}
	if hasDigit {
		if overflow {
			return len(p.sym) + 1 // sentinel > any valid index; callers reject it
		}
		return n + 1
	}
	return 0
}

// skipUntilE consumes generic-arg content up to and including the matching 'E'.
//
// It only balances the I…E generic-list nesting. Other v0 constructs that also
// close with 'E' — notably a `D…E` dyn-trait bound — are not tracked, so a dyn
// bound inside the generic args decrements depth early and can leave pos short of
// the true matching 'E'. Harmless for prefix matching (the crate/module prefix is
// resolved before the generic args), but it can misalign the trailing identifier
// in the enclosing N element; acceptable given we only need the path prefix.
func (p *v0Parser) skipUntilE() {
	depth := 1
	for p.pos < len(p.sym) && depth > 0 {
		switch p.sym[p.pos] {
		case 'I':
			depth++
		case 'E':
			depth--
		}
		p.pos++
	}
}

func FindProcLanguage(pid app.PID) svc.InstrumentableType {
	maps, err := FindLibMaps(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	// We first check for the languages as cheaply as possible when
	// know they link certain libraries that can tell us the language.
	for _, m := range maps {
		t := instrumentableFromModuleMapSharedLib(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	// We must find the language type from the binary first
	// before resorting to discovery by path or environment variables.
	// For example, a Go application can be called 'node' and we must
	// not identify this application as Node.js.
	filePath, err := resolveProcBinary(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	t := findLanguageFromElf(filePath)

	if t != svc.InstrumentableGeneric {
		return t
	}

	for _, m := range maps {
		t := instrumentableFromModuleMap(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	t = instrumentableFromPath(filePath)
	if t != svc.InstrumentableGeneric {
		return t
	}

	// Last resort to tell Generic from C++ (and maybe others in the future)
	for _, m := range maps {
		t := instrumentableLastResort(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	return svc.InstrumentableGeneric
}

func resolveProcBinary(pid app.PID) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	realPath, err := os.Readlink(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to read process binary: %w", err)
	}

	return fmt.Sprintf("/proc/%d/root%s", pid, realPath), nil
}

func findLanguageFromElf(filePath string) (result svc.InstrumentableType) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("panic while parsing ELF file", "file", filePath, "panic", r)
			result = svc.InstrumentableGeneric
		}
	}()

	ctx, err := fastelf.NewElfContextFromFile(filePath)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	defer ctx.Close()

	if ctx.HasSection(".gopclntab") {
		return svc.InstrumentableGolang
	}

	return matchExeSymbols(ctx)
}

func contains(slice []string, value string) bool {
	return slices.Contains(slice, value)
}

type symbolCollector struct {
	addresses   map[string]Sym
	symbolNames []string
	matches     func(string, []string) (string, bool)
}

func collectSymbols(f *elf.File, syms []elf.Symbol, collectors []symbolCollector, types ...elf.SymType) {
	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}
	for _, s := range syms {
		if !slices.Contains(types, elf.ST_TYPE(s.Info)) {
			continue
		}

		var sym *Sym
		for _, collector := range collectors {
			key, ok := collector.matches(s.Name, collector.symbolNames)
			if !ok {
				continue
			}

			if sym == nil {
				resolvedSym := resolveSymbol(f, s)
				sym = &resolvedSym
			}
			collector.addresses[key] = *sym
		}
	}
}

func FindExeSymbols(f *elf.File, symbolNames []string, types ...elf.SymType) (map[string]Sym, error) {
	exactSyms, _, err := FindExeSymbolsByNameAndSubstring(f, symbolNames, nil, types...)
	return exactSyms, err
}

func FindExeSymbolsBySubstring(f *elf.File, symbolSubstrings []string, types ...elf.SymType) (map[string]Sym, error) {
	_, substringSyms, err := FindExeSymbolsByNameAndSubstring(f, nil, symbolSubstrings, types...)
	return substringSyms, err
}

func FindExeSymbolsByNameAndSubstring(f *elf.File, symbolNames, symbolSubstrings []string, types ...elf.SymType) (map[string]Sym, map[string]Sym, error) {
	exactAddresses := map[string]Sym{}
	substringAddresses := map[string]Sym{}
	collectors := []symbolCollector{
		{
			addresses:   exactAddresses,
			symbolNames: symbolNames,
			matches:     exactSymbolMatch,
		},
		{
			addresses:   substringAddresses,
			symbolNames: symbolSubstrings,
			matches:     substringSymbolMatch,
		},
	}

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, nil, err
	}

	collectSymbols(f, syms, collectors, types...)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, nil, err
	}

	collectSymbols(f, dynsyms, collectors, types...)

	return exactAddresses, substringAddresses, nil
}

func resolveSymbol(f *elf.File, s elf.Symbol) Sym {
	address := s.Value
	var p *elf.Prog

	// Loop over ELF segments.
	for _, prog := range f.Progs {
		// Skip uninteresting segments.
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
			address = s.Value - prog.Vaddr + prog.Off
			p = prog
			break
		}
	}

	return Sym{Name: s.Name, Off: address, Len: s.Size, Prog: p}
}

func exactSymbolMatch(symbolName string, names []string) (string, bool) {
	if contains(names, symbolName) {
		return symbolName, true
	}
	return "", false
}

func substringSymbolMatch(symbolName string, substrings []string) (string, bool) {
	for _, substring := range substrings {
		if strings.Contains(symbolName, substring) {
			return substring, true
		}
	}
	return "", false
}

// FindExeSymbolsByPrefix resolves demangled Rust symbol prefixes to all matching
// ELF symbols in the binary.  Each prefix key in the result maps to one Sym per
// monomorphized copy of that function (e.g. all ~23 copies of raw::poll).
func FindExeSymbolsByPrefix(f *elf.File, prefixes []string) (map[string][]Sym, error) {
	out := map[string][]Sym{}
	// Shared across both symbol tables: a function can appear in .symtab and .dynsym,
	// and attaching a uprobe twice at one file offset would double-fire.
	seen := map[uint64]struct{}{}

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	collectSymbolsByPrefix(f, syms, out, prefixes, seen)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	collectSymbolsByPrefix(f, dynsyms, out, prefixes, seen)

	return out, nil
}

// collectSymbolsByPrefix fills `out` (prefix -> []Sym) for every ELF symbol whose
// demangled Rust name starts with one of the requested prefixes.  Symbols that
// do not demangle are silently skipped (they would be caught by collectSymbols).
func collectSymbolsByPrefix(f *elf.File, syms []elf.Symbol, out map[string][]Sym, prefixes []string, seen map[uint64]struct{}) {
	for _, s := range syms {
		// Only STT_FUNC. Rust monomorphized generics (the Tokio copies) are always
		// STT_FUNC; STT_NOTYPE function symbols only arise from ICF/LTO folding or
		// hand-written asm (not Rust defaults), so matching them is not worth the risk
		// of attaching a uprobe to a non-entry symbol that merely demangles to the prefix.
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		demangled := rustDemangle(s.Name)
		if demangled == "" {
			demangled = rustDemangleV0(s.Name)
		}
		if demangled == "" {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(demangled, prefix) {
				sym := resolveSymbol(f, s)
				// Skip a file offset already recorded (e.g. the same function present
				// in both .symtab and .dynsym) so it is not probed twice.
				if _, dup := seen[sym.Off]; dup {
					break
				}
				seen[sym.Off] = struct{}{}
				slog.Debug("rust symbol matched",
					"mangled", s.Name,
					"demangled", demangled,
					"prefix", prefix,
					"offset", fmt.Sprintf("0x%x", sym.Off))
				out[prefix] = append(out[prefix], sym)
				break
			}
		}
	}
}

func matchExeSymbols(ctx *fastelf.ElfContext) svc.InstrumentableType {
	for _, sec := range ctx.Sections {
		if sec == nil {
			continue
		}

		if sec.Type != fastelf.SHT_SYMTAB && sec.Type != fastelf.SHT_DYNSYM {
			continue
		}

		if int(sec.Link) >= len(ctx.Sections) {
			continue
		}

		strtab := ctx.Sections[sec.Link]

		strs, ok := ctx.SectionData(strtab)
		if !ok {
			continue
		}

		symOffset, symEntrySize, symCount, ok := ctx.SymbolTableBounds(sec)
		if !ok {
			continue
		}

		for i := range symCount {
			sym := fastelf.ReadStruct[fastelf.Elf64_Sym](ctx.Data, symOffset+i*symEntrySize)

			if sym == nil ||
				fastelf.SymType(sym.Info) != fastelf.STT_FUNC ||
				sym.Size == 0 ||
				sym.Value == 0 {
				continue
			}

			name := fastelf.GetCStringUnsafe(strs, sym.Name)

			t := instrumentableFromSymbolName(name)

			if t != svc.InstrumentableGeneric {
				return t
			}
		}
	}

	return svc.InstrumentableGeneric
}
