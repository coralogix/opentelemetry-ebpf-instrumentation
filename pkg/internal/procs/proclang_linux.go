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

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/fastelf"
)

// rustDemangle converts a legacy-mangled _ZN…E symbol to its path with the $LT$…$GT$
// generic arguments and the 17h<hash> build hash dropped, e.g.
// "tokio::runtime::task::harness::Harness::poll". Legacy mangling only puts
// length-prefixed identifiers or the closing 'E' at a path position; a stray byte ends
// the scan with the prefix collected so far. Returns "" for any other scheme.
func rustDemangle(name string) string {
	if !strings.HasPrefix(name, "_ZN") {
		return ""
	}
	rest := name[3:] // inside the outer nested-name scope opened by _ZN
	var parts []string
	for len(rest) > 0 && rest[0] != 'E' {
		// Read a length-prefixed identifier. Digits past the symbol's own length cannot
		// form a valid one and would overflow n.
		n := 0
		for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' && n <= len(rest) {
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
				if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
					isHash = false
					break
				}
			}
			if isHash {
				break
			}
		}
		part = stripDollarBrackets(part)
		parts = append(parts, part)
	}
	return strings.Join(parts, "::")
}

// stripDollarBrackets drops $LT$…$GT$ generic arguments from a legacy identifier, nested ones included.
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

// rustDemangleV0 converts a v0-mangled _R… symbol to its path with generic arguments
// dropped and back-references resolved from a per-position cache. Returns "" on any
// parse failure.
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
	if result == "" || p.overflow {
		return ""
	}
	// Normalise impl syntax: "<Type>::method" -> "Type::method"
	result = strings.ReplaceAll(result, "<", "")
	result = strings.ReplaceAll(result, ">", "")
	// Collapse any double-colon artifact left by ">::" -> "::"
	for strings.Contains(result, "::::") {
		result = strings.ReplaceAll(result, "::::", "::")
	}
	result = strings.Trim(result, ":")
	return result
}

// maxRustV0PathLen bounds one demangled path element. A back-reference pastes the
// element it points at, so a symbol whose elements each reference the next one twice
// doubles the text per element: a few hundred bytes of symbol would demangle to
// gigabytes. No real element comes near this once generic arguments are dropped.
const maxRustV0PathLen = 4096

// v0Parser is a stateful parser for the Rust v0 symbol mangling grammar.
// See RFC 2603 (https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html).
type v0Parser struct {
	sym      string
	pos      int
	cache    map[int]string // byte-offset of element start -> demangled string
	overflow bool           // an element exceeded maxRustV0PathLen; the symbol is rejected
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
		// we do not need it for path matching.
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

	// X and Y never start a probe path but occur inside generic arguments (a closure defined
	// in a trait-impl method), which skipType hands to path().
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
		p.skipGenericArgs(depth + 1)

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
	}

	if len(result) > maxRustV0PathLen {
		p.overflow = true
		result = ""
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
	// Digits past the symbol's own length cannot form a valid one and would overflow n.
	n := 0
	for p.pos < len(p.sym) && p.sym[p.pos] >= '0' && p.sym[p.pos] <= '9' && n <= len(p.sym) {
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
			// Stop without consuming the terminator (a plain break would only leave the switch).
			break scan
		}
		hasDigit = true
		p.pos++
		// Keep scanning to the terminator: disambiguator hashes are base62 numbers far
		// larger than len(p.sym), and stopping inside one would derail every later token.
		// Past len(p.sym) the value can only be out of range, so stop accumulating before
		// it overflows.
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

// skipGenericArgs consumes an I…E generic-argument list by the grammar: pos starts at
// the first arg and ends just past the matching 'E'. A byte scan for 'E' is not enough:
// nested E-terminated constructs and 'E' bytes inside identifiers (Executor) or
// back-reference base62 would stop it short and misalign the trailing method identifier.
func (p *v0Parser) skipGenericArgs(depth int) {
	for depth <= 256 && p.pos < len(p.sym) && p.sym[p.pos] != 'E' {
		before := p.pos
		p.skipArg(depth + 1)
		// path() returns without advancing once its recursion cap is hit: advance one byte
		// rather than spin; a mis-skipped deep symbol fails to match.
		if p.pos <= before {
			p.pos++
		}
	}
	if p.pos < len(p.sym) {
		p.pos++ // consume 'E'
	}
}

// skipArg consumes one generic argument: a lifetime, a const, or a type.
func (p *v0Parser) skipArg(depth int) {
	if depth > 256 || p.pos >= len(p.sym) {
		p.pos = len(p.sym)
		return
	}
	switch p.sym[p.pos] {
	case 'L': // lifetime: L <base62>
		p.pos++
		p.base62()
	case 'K': // const: K <const>
		p.pos++
		p.skipConst(depth + 1)
	default:
		p.skipType(depth + 1)
	}
}

// skipType consumes exactly one <type> per the v0 grammar (RFC 2603).
func (p *v0Parser) skipType(depth int) {
	if depth > 256 || p.pos >= len(p.sym) {
		p.pos = len(p.sym)
		return
	}
	switch p.sym[p.pos] {
	case 'A': // [T; N]
		p.pos++
		p.skipType(depth + 1)
		p.skipConst(depth + 1)
	case 'S': // [T]
		p.pos++
		p.skipType(depth + 1)
	case 'T': // tuple: T {type} E
		p.pos++
		for p.pos < len(p.sym) && p.sym[p.pos] != 'E' {
			before := p.pos
			p.skipType(depth + 1)
			if p.pos <= before {
				p.pos++
			}
		}
		if p.pos < len(p.sym) {
			p.pos++
		}
	case 'R', 'Q': // &T / &mut T : [L<base62>] type
		p.pos++
		if p.pos < len(p.sym) && p.sym[p.pos] == 'L' {
			p.pos++
			p.base62()
		}
		p.skipType(depth + 1)
	case 'P', 'O': // *const T / *mut T
		p.pos++
		p.skipType(depth + 1)
	case 'F': // fn pointer
		p.pos++
		p.skipFnSig(depth + 1)
	case 'D': // dyn bounds <lifetime>
		p.pos++
		p.skipDynBounds(depth + 1)
		if p.pos < len(p.sym) && p.sym[p.pos] == 'L' {
			p.pos++
			p.base62()
		}
	case 'C', 'N', 'M', 'X', 'Y', 'I', 'B':
		// named/path type — path() consumes it fully (its own I…E, and resolves
		// back-references), so identifier bytes are never scanned as structure.
		p.path(depth + 1)
	default:
		// basic type: a single byte (i8/bool/char/…/placeholder)
		p.pos++
	}
}

// skipConst consumes one <const>.
func (p *v0Parser) skipConst(depth int) {
	if depth > 256 || p.pos >= len(p.sym) {
		p.pos = len(p.sym)
		return
	}
	switch p.sym[p.pos] {
	case 'p': // placeholder
		p.pos++
	case 'B': // backref
		p.pos++
		p.base62()
	default:
		p.skipType(depth + 1) // the const's type
		// const value: hex digits terminated by '_'
		for p.pos < len(p.sym) && p.sym[p.pos] != '_' {
			p.pos++
		}
		if p.pos < len(p.sym) {
			p.pos++
		}
	}
}

// skipDynBounds consumes [<binder>] {<dyn-trait>} E (the body of a D… dyn type).
func (p *v0Parser) skipDynBounds(depth int) {
	if p.pos < len(p.sym) && p.sym[p.pos] == 'G' { // binder: G <base62>
		p.pos++
		p.base62()
	}
	for depth <= 256 && p.pos < len(p.sym) && p.sym[p.pos] != 'E' {
		before := p.pos
		p.path(depth + 1) // the trait path
		// associated-type bindings: "p" <ident> <type>
		for p.pos < len(p.sym) && p.sym[p.pos] == 'p' {
			p.pos++
			p.ident()
			p.skipType(depth + 1)
		}
		if p.pos <= before {
			p.pos++
		}
	}
	if p.pos < len(p.sym) {
		p.pos++ // consume 'E'
	}
}

// skipFnSig consumes [<binder>] ["U"] ["K" <abi>] {<type>} E <type>.
func (p *v0Parser) skipFnSig(depth int) {
	if p.pos < len(p.sym) && p.sym[p.pos] == 'G' {
		p.pos++
		p.base62()
	}
	if p.pos < len(p.sym) && p.sym[p.pos] == 'U' {
		p.pos++
	}
	if p.pos < len(p.sym) && p.sym[p.pos] == 'K' { // abi
		p.pos++
		if p.pos < len(p.sym) && p.sym[p.pos] == 'C' {
			p.pos++
		} else {
			p.ident()
		}
	}
	for p.pos < len(p.sym) && p.sym[p.pos] != 'E' {
		before := p.pos
		p.skipType(depth + 1)
		if p.pos <= before {
			p.pos++
		}
	}
	if p.pos < len(p.sym) {
		p.pos++ // consume 'E'
	}
	p.skipType(depth + 1) // return type
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

func FindExeSymbols(f *elf.File, symbolNames []string, types ...elf.SymType) (map[string]Sym, error) {
	wanted := make(map[string]string, len(symbolNames))
	for _, name := range symbolNames {
		if name != "" {
			wanted[name] = name
		}
	}

	return findExeSymbols(f, wanted, nil, types...)
}

// FindExeSymbolsMatching returns the symbols whose name satisfies match, keyed by name.
func FindExeSymbolsMatching(f *elf.File, match func(name string) bool, types ...elf.SymType) (map[string]Sym, error) {
	return findExeSymbols(f, nil, match, types...)
}

func findExeSymbols(f *elf.File, wanted map[string]string, match func(string) bool, types ...elf.SymType) (map[string]Sym, error) {
	addresses := map[string]Sym{}
	if f.SectionByType(elf.SHT_SYMTAB) == nil && f.SectionByType(elf.SHT_DYNSYM) == nil {
		return addresses, nil
	}

	ctx, err := fastelf.NewElfContextFromELF(f)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}

	err = eachSymbolTableEntry(ctx, func(strtab []byte, symbol *fastelf.Elf64_Sym) {
		if !slices.Contains(types, elf.ST_TYPE(symbol.Info)) {
			return
		}

		name := fastelf.GetCStringUnsafe(strtab, symbol.Name)
		var requested string
		var ok bool
		if match == nil {
			requested, ok = wanted[name]
		} else if match(name) {
			requested, ok = strings.Clone(name), true
		}
		if !ok {
			return
		}

		addresses[requested] = resolveSymbol(f, elf.Symbol{
			Name: requested, Value: symbol.Value, Size: symbol.Size,
		})
	})
	if err != nil {
		return nil, err
	}
	return addresses, nil
}

// eachSymbolTableEntry calls visit for every entry of the first .symtab and of the first
// .dynsym of ctx, with the string table the entry's name lives in. A name read from it is
// backed by the mapped file and must be copied to outlive ctx.
func eachSymbolTableEntry(ctx *fastelf.ElfContext, visit func(strtab []byte, symbol *fastelf.Elf64_Sym)) error {
	for _, sectionType := range []uint32{fastelf.SHT_SYMTAB, fastelf.SHT_DYNSYM} {
		for _, section := range ctx.Sections {
			if section == nil || section.Type != sectionType {
				continue
			}

			if section.Size == 0 {
				break
			}

			if section.Link == 0 || uint64(section.Link) >= uint64(len(ctx.Sections)) {
				return errors.New("section has invalid string table link")
			}

			strtab, ok := ctx.SectionData(ctx.Sections[section.Link])
			if !ok {
				return errors.New("invalid string table bounds")
			}

			offset, entrySize, count, ok := ctx.SymbolTableBounds(section)
			if !ok || section.Entsize != elf.Sym64Size || section.Size%section.Entsize != 0 {
				return errors.New("invalid symbol table bounds or entry size")
			}

			populateRange(ctx.Data, ctx.Sections[section.Link].Offset, ctx.Sections[section.Link].Size)
			populateRange(ctx.Data, uint64(offset), uint64(count*entrySize))

			// Symbol tables begin with a reserved null entry.
			for i := 1; i < count; i++ {
				visit(strtab, fastelf.ReadStruct[fastelf.Elf64_Sym](ctx.Data, offset+i*entrySize))
			}
			break
		}
	}
	return nil
}

// populateRange asks the kernel to read the given range of a mapped file in a
// single batch instead of faulting it in page by page during the scan, which
// is several times faster when the symbol tables are not in the page cache.
// It is best effort: MADV_POPULATE_READ needs Linux 5.14, and failing to
// populate only means the pages are faulted in lazily as before.
func populateRange(data []byte, offset, size uint64) {
	end := offset + size
	if size == 0 || end < offset || end > uint64(len(data)) {
		return
	}

	pageMask := uint64(os.Getpagesize()) - 1

	_ = unix.Madvise(data[offset&^pageMask:end], unix.MADV_POPULATE_READ)
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

	return Sym{Name: s.Name, Off: address, Value: s.Value, Len: s.Size, Prog: p}
}

// isRustClosureSymbol detects a closure body on the mangled form: legacy spells it
// $u7b$$u7b$closure$u7d$$u7d$, v0 as a root NC element that the demangler renders as
// the parent function.
func isRustClosureSymbol(name string) bool {
	if strings.Contains(name, "$u7b$$u7b$closure$u7d$$u7d$") { // legacy {{closure}}
		return true
	}
	// Only the root NC form (_RNC / __RNC) is filtered: "NC" mid-symbol can be identifier
	// bytes, and the root form is what collides with the probe paths.
	rest := name
	switch {
	case strings.HasPrefix(rest, "__R"):
		rest = rest[3:]
	case strings.HasPrefix(rest, "_R"):
		rest = rest[2:]
	default:
		return false
	}
	return strings.HasPrefix(rest, "NC")
}

// FindRustSymbols resolves demangled Rust function paths to every ELF symbol whose whole
// demangled path equals one of them, one Sym per monomorphized copy (both demanglers drop
// generic arguments). Nested items such as Cell::new::new_header are different paths and
// never match. Only the symbols naming the crate of a requested path are demangled, so a
// Rust binary without that crate costs one walk of its symbol table.
func FindRustSymbols(f *elf.File, paths []string) (out map[string][]Sym, err error) {
	// The demanglers run on the crate's symbols of every Rust executable on the host; a
	// panic in them must fail this scan, not the process, as in findLanguageFromElf.
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("panic while scanning Rust symbols", "panic", r)
			out, err = nil, fmt.Errorf("rust symbol scan panicked: %v", r)
		}
	}()

	out = map[string][]Sym{}
	if f.SectionByType(elf.SHT_SYMTAB) == nil && f.SectionByType(elf.SHT_DYNSYM) == nil {
		return out, nil
	}

	ctx, err := fastelf.NewElfContextFromELF(f)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	crates := mangledCrateNames(paths)
	// Shared across both symbol tables: a function can appear in .symtab and .dynsym,
	// and attaching a uprobe twice at one file offset would double-fire.
	seen := map[uint64]struct{}{}

	err = eachSymbolTableEntry(ctx, func(strtab []byte, symbol *fastelf.Elf64_Sym) {
		// STT_FUNC only: Rust monomorphized copies always are; an STT_NOTYPE symbol that
		// demangles to the path (ICF/LTO folding, asm) may not be a function entry.
		if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC {
			return
		}
		name := fastelf.GetCStringUnsafe(strtab, symbol.Name)
		if !namesMangledCrate(name, crates) {
			return
		}
		// Closures are filtered on the mangled form (isRustClosureSymbol): a v0 closure demangles
		// to its parent's path, and probing it fires the handler with the closure's ABI.
		if isRustClosureSymbol(name) {
			return
		}
		demangled := rustDemangle(name)
		if demangled == "" {
			demangled = rustDemangleV0(name)
		}
		if demangled == "" || !slices.Contains(paths, demangled) {
			return
		}
		// name is backed by the mapped file, which is unmapped when this scan returns.
		sym := resolveSymbol(f, elf.Symbol{Name: strings.Clone(name), Value: symbol.Value, Size: symbol.Size})
		// Skip a file offset already recorded (e.g. the same function present
		// in both .symtab and .dynsym) so it is not probed twice.
		if _, dup := seen[sym.Off]; dup {
			return
		}
		seen[sym.Off] = struct{}{}
		slog.Debug("rust symbol matched",
			"mangled", sym.Name,
			"path", demangled,
			"offset", fmt.Sprintf("0x%x", sym.Off))
		out[demangled] = append(out[demangled], sym)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// mangledCrateNames returns the crate of every path as both mangling schemes spell an
// identifier, its decimal length followed by its bytes ("5tokio"): a mangled symbol
// without that substring cannot demangle to a path in the crate.
func mangledCrateNames(paths []string) []string {
	var crates []string
	for _, path := range paths {
		crate, _, _ := strings.Cut(path, "::")
		mangled := fmt.Sprintf("%d%s", len(crate), crate)
		if !slices.Contains(crates, mangled) {
			crates = append(crates, mangled)
		}
	}
	return crates
}

func namesMangledCrate(symbol string, crates []string) bool {
	for _, crate := range crates {
		if strings.Contains(symbol, crate) {
			return true
		}
	}
	return false
}

func matchExeSymbols(ctx *fastelf.ElfContext) svc.InstrumentableType {
	isRust := false

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

			if sym == nil || fastelf.SymType(sym.Info) != fastelf.STT_FUNC ||
				sym.Size == 0 ||
				sym.Value == 0 {
				continue
			}

			name := fastelf.GetCStringUnsafe(strs, sym.Name)

			t := instrumentableFromSymbolName(name)

			if t != svc.InstrumentableGeneric {
				if t == svc.InstrumentableRust {
					isRust = true
				} else {
					return t
				}
			}
		}
	}

	if isRust {
		return svc.InstrumentableRust
	}

	return svc.InstrumentableGeneric
}
