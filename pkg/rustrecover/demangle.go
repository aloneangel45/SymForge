// Package rustrecover implements pure-Go Rust symbol demangling (RFC 2603 v0 and
// legacy Itanium-like), cargo-auditable SBOM decompression, toolchain/registry
// carving, core::panic::Location binary struct recovery, and trait vtable scanning.
package rustrecover

import (
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxDemangleDepth  = 128
	maxDemangleOutput = 16 * 1024 // 16 KiB output cap against decompression/backref bombs
	maxDemangleSteps  = 4096      // total AST node budget per symbol
)

// Demangle demangles a Rust v0 (_R...) or legacy (_ZN...E) symbol.
// Returns (demangled, scheme /* "v0" | "legacy" */, true) on success,
// or (sym, "", false) if sym is not a valid Rust mangled symbol.
func Demangle(sym string) (string, string, bool) {
	if sym == "" || len(sym) > maxDemangleOutput {
		return sym, "", false
	}

	if out, ok := demangleV0(sym); ok {
		return out, "v0", true
	}
	if out, ok := demangleLegacy(sym); ok {
		return out, "legacy", true
	}
	return sym, "", false
}

// isStrongLegacyRust reports whether sym is unambiguously a Rust legacy symbol
// (contains trailing 17h<16-hex>E hash, Rust $..$ escapes, or Rust stdlib root).
// Used during binary language detection so C++ Itanium symbols never false-positive as Rust.
func isStrongLegacyRust(rawSym, demangled string) bool {
	trimmed := stripVendorSuffix(rawSym)
	if hasLegacyRustHashSuffix(trimmed) {
		return true
	}
	if strings.Contains(trimmed, "$LT$") || strings.Contains(trimmed, "$GT$") ||
		strings.Contains(trimmed, "$RF$") || strings.Contains(trimmed, "$u20$") ||
		strings.Contains(trimmed, "$C$") || strings.Contains(trimmed, "..") {
		return true
	}
	for _, pfx := range []string{"core::", "std::", "alloc::", "rustc_", "panic_unwind::", "panic_abort::"} {
		if strings.HasPrefix(demangled, pfx) {
			return true
		}
	}
	return false
}

func hasLegacyRustHashSuffix(s string) bool {
	// "...17h" + 16 hex chars + "E" => last 20 bytes
	if len(s) < 23 || s[len(s)-1] != 'E' {
		return false
	}
	tail := s[len(s)-20 : len(s)-1] // "17h" + 16 hex
	if !strings.HasPrefix(tail, "17h") {
		return false
	}
	for i := 3; i < 19; i++ {
		c := tail[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func stripVendorSuffix(sym string) string {
	// Strip @PLT / @GOTPCREL suffixes first
	if at := strings.IndexByte(sym, '@'); at > 0 {
		sym = sym[:at]
	}
	// For legacy _ZN...E.llvm.12345 / _ZN...E.cold.1, do not split on ".." inside segments!
	if strings.HasPrefix(sym, "_ZN") || strings.HasPrefix(sym, "__ZN") {
		if idx := strings.LastIndex(sym, "E."); idx > 3 {
			return sym[:idx+1]
		}
		return sym
	}
	for i := 0; i < len(sym); i++ {
		if sym[i] == '.' || sym[i] == '$' {
			return sym[:i]
		}
	}
	return sym
}

// ---------------------------------------------------------------------------
// Legacy Rust Demangler (_ZN...E / __ZN...E)
// ---------------------------------------------------------------------------

func demangleLegacy(sym string) (string, bool) {
	s := stripVendorSuffix(sym)
	switch {
	case strings.HasPrefix(s, "_ZN"):
		s = s[3:]
	case strings.HasPrefix(s, "__ZN"):
		s = s[4:]
	default:
		return "", false
	}

	if len(s) < 3 || s[len(s)-1] != 'E' {
		return "", false
	}
	body := s[:len(s)-1]

	var rawSegs []string
	pos := 0
	for pos < len(body) {
		if len(rawSegs) >= maxDemangleDepth {
			return "", false
		}
		first := body[pos]
		if first < '1' || first > '9' {
			return "", false
		}
		segLen := 0
		for pos < len(body) && body[pos] >= '0' && body[pos] <= '9' {
			segLen = segLen*10 + int(body[pos]-'0')
			if segLen > len(body) {
				return "", false
			}
			pos++
		}
		if segLen <= 0 || pos+segLen > len(body) {
			return "", false
		}
		seg := body[pos : pos+segLen]
		pos += segLen
		for i := 0; i < len(seg); i++ {
			if seg[i] < 0x20 || seg[i] >= 0x7f {
				return "", false
			}
		}
		rawSegs = append(rawSegs, seg)
	}

	if pos != len(body) || len(rawSegs) == 0 {
		return "", false
	}

	// Strip trailing Rust hash segment 17h[0-9a-f]{16}
	if len(rawSegs) > 1 && isRustHashSegment(rawSegs[len(rawSegs)-1]) {
		rawSegs = rawSegs[:len(rawSegs)-1]
	}

	var b strings.Builder
	for idx, seg := range rawSegs {
		if idx > 0 {
			if b.Len()+2 > maxDemangleOutput {
				return "", false
			}
			b.WriteString("::")
		}
		unesc, ok := unescapeLegacySegment(seg, maxDemangleOutput-b.Len())
		if !ok {
			return "", false
		}
		b.WriteString(unesc)
	}
	return b.String(), true
}

func isRustHashSegment(seg string) bool {
	if len(seg) != 17 || seg[0] != 'h' {
		return false
	}
	for i := 1; i < 17; i++ {
		c := seg[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

var legacyNamedEscapes = map[string]string{
	"LT": "<",
	"GT": ">",
	"LP": "(",
	"RP": ")",
	"C":  ",",
	"SP": "@",
	"BP": "*",
	"RF": "&",
}

func unescapeLegacySegment(seg string, budget int) (string, bool) {
	// Leading "_$" in a segment escapes a leading "$" so the symbol token is valid
	if strings.HasPrefix(seg, "_$") {
		seg = seg[1:]
	}

	var b strings.Builder
	for i := 0; i < len(seg); {
		if b.Len() >= budget {
			return "", false
		}
		if seg[i] == '.' && i+1 < len(seg) && seg[i+1] == '.' {
			if b.Len()+2 > budget {
				return "", false
			}
			b.WriteString("::")
			i += 2
			continue
		}
		if seg[i] == '$' {
			end := strings.IndexByte(seg[i+1:], '$')
			if end > 0 {
				code := seg[i+1 : i+1+end]
				if rep, ok := legacyNamedEscapes[code]; ok {
					if b.Len()+len(rep) > budget {
						return "", false
					}
					b.WriteString(rep)
					i += end + 2
					continue
				}
				if strings.HasPrefix(code, "u") && len(code) >= 2 && len(code) <= 7 {
					val, err := strconv.ParseUint(code[1:], 16, 32)
					if err == nil && utf8.ValidRune(rune(val)) {
						r := rune(val)
						if r == ' ' || unicode.IsPrint(r) {
							var rbuf [4]byte
							n := utf8.EncodeRune(rbuf[:], r)
							if b.Len()+n > budget {
								return "", false
							}
							b.Write(rbuf[:n])
							i += end + 2
							continue
						}
					}
				}
			}
		}
		b.WriteByte(seg[i])
		i++
	}
	return b.String(), true
}

// ---------------------------------------------------------------------------
// Rust v0 Demangler (RFC 2603)
// ---------------------------------------------------------------------------

type v0Parser struct {
	s        string // slice immediately after "_R" / "__R" / "R"
	pos      int
	depth    int
	steps    int
	suppress int
	out      strings.Builder
	failed   bool
}

func demangleV0(sym string) (string, bool) {
	var body string
	switch {
	case strings.HasPrefix(sym, "_R"):
		body = sym[2:]
	case strings.HasPrefix(sym, "__R"):
		body = sym[3:]
	case strings.HasPrefix(sym, "R") && len(sym) >= 3 && isV0PathStarter(sym[1]):
		body = sym[1:]
	default:
		return "", false
	}

	if len(body) == 0 {
		return "", false
	}
	// RFC 2603: optional decimal encoding version after _R; currently rustc emits none.
	if body[0] >= '0' && body[0] <= '9' {
		return "", false
	}
	if !isV0PathStarter(body[0]) {
		return "", false
	}

	p := &v0Parser{s: body}
	p.parsePath(false)
	if p.failed {
		return "", false
	}

	// Optional <instantiating-crate> (<path>)
	if p.pos < len(p.s) && !isVendorSuffixStart(p.s[p.pos]) {
		p.suppress++
		p.parsePath(false)
		p.suppress--
		if p.failed {
			return "", false
		}
	}

	// Optional <vendor-specific-suffix> ('.' | '$' | '@')
	if p.pos < len(p.s) {
		if !isVendorSuffixStart(p.s[p.pos]) {
			return "", false
		}
	}

	res := p.out.String()
	if res == "" {
		return "", false
	}
	return res, true
}

func isV0PathStarter(c byte) bool {
	switch c {
	case 'C', 'M', 'X', 'Y', 'N', 'I', 'B':
		return true
	}
	return false
}

func isVendorSuffixStart(c byte) bool {
	return c == '.' || c == '$' || c == '@'
}

func (p *v0Parser) enter() bool {
	p.depth++
	p.steps++
	if p.depth > maxDemangleDepth || p.steps > maxDemangleSteps {
		p.failed = true
		return false
	}
	return !p.failed
}

func (p *v0Parser) leave() {
	p.depth--
}

func (p *v0Parser) write(str string) {
	if p.failed || p.suppress > 0 || str == "" {
		return
	}
	if p.out.Len()+len(str) > maxDemangleOutput {
		p.failed = true
		return
	}
	p.out.WriteString(str)
}

func (p *v0Parser) writeByte(c byte) {
	if p.failed || p.suppress > 0 {
		return
	}
	if p.out.Len()+1 > maxDemangleOutput {
		p.failed = true
		return
	}
	p.out.WriteByte(c)
}

func (p *v0Parser) peek() (byte, bool) {
	if p.failed || p.pos >= len(p.s) {
		return 0, false
	}
	return p.s[p.pos], true
}

func (p *v0Parser) next() (byte, bool) {
	if p.failed || p.pos >= len(p.s) {
		p.failed = true
		return 0, false
	}
	c := p.s[p.pos]
	p.pos++
	return c, true
}

func (p *v0Parser) consume(want byte) bool {
	if p.pos < len(p.s) && p.s[p.pos] == want {
		p.pos++
		return true
	}
	return false
}

func (p *v0Parser) parseDecimal() (int, bool) {
	c, ok := p.peek()
	if !ok || c < '0' || c > '9' {
		p.failed = true
		return 0, false
	}
	p.pos++
	if c == '0' {
		return 0, true
	}
	val := int(c - '0')
	for p.pos < len(p.s) {
		d := p.s[p.pos]
		if d < '0' || d > '9' {
			break
		}
		if val > (1<<28)/10 {
			p.failed = true
			return 0, false
		}
		val = val*10 + int(d-'0')
		p.pos++
	}
	return val, true
}

func (p *v0Parser) parseBase62() (uint64, bool) {
	if p.failed || p.pos >= len(p.s) {
		p.failed = true
		return 0, false
	}
	if p.s[p.pos] == '_' {
		p.pos++
		return 0, true
	}
	var val uint64
	hasDigits := false
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		p.pos++
		if c == '_' {
			if !hasDigits {
				p.failed = true
				return 0, false
			}
			if val == math.MaxUint64 {
				return math.MaxUint64, true
			}
			return val + 1, true
		}
		var digit uint64
		switch {
		case c >= '0' && c <= '9':
			digit = uint64(c - '0')
		case c >= 'a' && c <= 'z':
			digit = uint64(c-'a') + 10
		case c >= 'A' && c <= 'Z':
			digit = uint64(c-'A') + 36
		default:
			p.failed = true
			return 0, false
		}
		hi, lo := bits.Mul64(val, 62)
		if hi != 0 || lo > math.MaxUint64-digit {
			p.failed = true
			return 0, false
		}
		val = lo + digit
		hasDigits = true
	}
	p.failed = true
	return 0, false
}

func (p *v0Parser) parseOptDisambiguator() (uint64, bool) {
	if p.pos < len(p.s) && p.s[p.pos] == 's' {
		p.pos++
		v, ok := p.parseBase62()
		return v, ok
	}
	return 0, false
}

func (p *v0Parser) parseUndisambiguatedIdent() (string, bool) {
	isPuny := p.consume('u')
	byteLen, ok := p.parseDecimal()
	if !ok {
		return "", false
	}
	if byteLen > 0 {
		p.consume('_')
	}
	if byteLen < 0 || p.pos+byteLen > len(p.s) {
		p.failed = true
		return "", false
	}
	raw := p.s[p.pos : p.pos+byteLen]
	p.pos += byteLen
	if !isPuny {
		for i := 0; i < len(raw); i++ {
			if raw[i] < 0x20 || raw[i] == 0x7f {
				p.failed = true
				return "", false
			}
		}
		return raw, true
	}
	decoded, decOK := decodeRustPunycode(raw)
	if !decOK {
		p.failed = true
		return "", false
	}
	return decoded, true
}

func (p *v0Parser) parseIdent() (name string, disambig uint64, hasDisambig bool, ok bool) {
	disambig, hasDisambig = p.parseOptDisambiguator()
	if p.failed {
		return "", 0, false, false
	}
	name, ok = p.parseUndisambiguatedIdent()
	return name, disambig, hasDisambig, ok
}

func (p *v0Parser) parsePath(inType bool) {
	if !p.enter() {
		return
	}
	defer p.leave()

	tag, ok := p.next()
	if !ok {
		return
	}

	switch tag {
	case 'C':
		name, _, _, ok := p.parseIdent()
		if !ok {
			return
		}
		p.write(name)

	case 'M':
		// Inherent impl: "M" <impl-path> <type>
		p.parseOptDisambiguator()
		p.suppress++
		p.parsePath(false)
		p.suppress--
		if p.failed {
			return
		}
		p.writeByte('<')
		p.parseType()
		p.writeByte('>')

	case 'X':
		// Trait impl: "X" <impl-path> <type> <path>
		p.parseOptDisambiguator()
		p.suppress++
		p.parsePath(false)
		p.suppress--
		if p.failed {
			return
		}
		p.writeByte('<')
		p.parseType()
		p.write(" as ")
		p.parsePath(true)
		p.writeByte('>')

	case 'Y':
		// Trait definition / qualified path: "Y" <type> <path>
		p.writeByte('<')
		p.parseType()
		p.write(" as ")
		p.parsePath(true)
		p.writeByte('>')

	case 'N':
		// Nested path: "N" <namespace> <path> <identifier>
		ns, ok := p.next()
		if !ok || !((ns >= 'a' && ns <= 'z') || (ns >= 'A' && ns <= 'Z')) {
			p.failed = true
			return
		}
		beforeLen := p.out.Len()
		childInType := inType
		if ns == 't' {
			childInType = true
		} else if ns == 'v' || ns == 'C' {
			childInType = false
		}
		p.parsePath(childInType)
		if p.failed {
			return
		}
		wroteParent := p.out.Len() > beforeLen || p.suppress > 0
		name, disambig, hasDisambig, ok := p.parseIdent()
		if !ok {
			return
		}

		if ns >= 'a' && ns <= 'z' {
			if name != "" {
				if wroteParent {
					p.write("::")
				}
				p.write(name)
			}
		} else {
			// Compiler-internal special namespace ('C' closure, 'S' shim/vtable, etc.)
			if wroteParent {
				p.write("::")
			}
			label := specialNamespaceLabel(ns)
			switch {
			case name != "" && hasDisambig:
				p.write(fmt.Sprintf("{%s:%s#%d}", label, name, disambig))
			case name != "":
				p.write(fmt.Sprintf("{%s:%s#0}", label, name))
			case hasDisambig:
				p.write(fmt.Sprintf("{%s#%d}", label, disambig))
			default:
				p.write(fmt.Sprintf("{%s#0}", label))
			}
		}

	case 'I':
		// Generic args: "I" <path> {<generic-arg>} "E"
		p.parsePath(inType)
		if p.failed {
			return
		}
		if !inType {
			p.write("::")
		}
		p.writeByte('<')
		first := true
		for {
			c, ok := p.peek()
			if !ok {
				p.failed = true
				return
			}
			if c == 'E' {
				p.pos++
				break
			}
			// Elide anonymous '_ lifetimes in generic arg display if desired or emit cleanly
			if !first {
				p.write(", ")
			}
			first = false
			p.parseGenericArg()
			if p.failed {
				return
			}
		}
		p.writeByte('>')

	case 'B':
		refStart := p.pos - 1
		target, ok := p.parseBase62()
		if !ok || target >= uint64(refStart) {
			p.failed = true
			return
		}
		saved := p.pos
		p.pos = int(target)
		p.parsePath(inType)
		p.pos = saved

	default:
		p.failed = true
	}
}

func specialNamespaceLabel(ns byte) string {
	switch ns {
	case 'C':
		return "closure"
	case 'S':
		return "shim"
	default:
		return string(ns)
	}
}

func (p *v0Parser) parseGenericArg() {
	if !p.enter() {
		return
	}
	defer p.leave()

	c, ok := p.peek()
	if !ok {
		p.failed = true
		return
	}
	switch c {
	case 'L':
		p.pos++
		lt, ok := p.parseBase62()
		if !ok {
			return
		}
		p.write(formatLifetime(lt))
	case 'K':
		p.pos++
		p.parseConst()
	default:
		p.parseType()
	}
}

func formatLifetime(lt uint64) string {
	if lt == 0 {
		return "'_"
	}
	if lt <= 26 {
		return "'" + string(rune('a'+lt-1))
	}
	return fmt.Sprintf("'_%d", lt)
}

func (p *v0Parser) parseOptLifetime() (uint64, bool) {
	if p.pos < len(p.s) && p.s[p.pos] == 'L' {
		p.pos++
		v, ok := p.parseBase62()
		return v, ok
	}
	return 0, true
}

func (p *v0Parser) parseType() {
	if !p.enter() {
		return
	}
	defer p.leave()

	c, ok := p.peek()
	if !ok {
		p.failed = true
		return
	}

	if basic, isBasic := v0BasicType(c); isBasic {
		p.pos++
		p.write(basic)
		return
	}

	switch c {
	case 'A':
		p.pos++
		p.writeByte('[')
		p.parseType()
		p.write("; ")
		p.parseConst()
		p.writeByte(']')

	case 'S':
		p.pos++
		p.writeByte('[')
		p.parseType()
		p.writeByte(']')

	case 'T':
		p.pos++
		p.writeByte('(')
		count := 0
		for {
			ch, ok := p.peek()
			if !ok {
				p.failed = true
				return
			}
			if ch == 'E' {
				p.pos++
				break
			}
			if count > 0 {
				p.write(", ")
			}
			p.parseType()
			if p.failed {
				return
			}
			count++
		}
		if count == 1 {
			p.writeByte(',')
		}
		p.writeByte(')')

	case 'R', 'Q':
		p.pos++
		lt, ok := p.parseOptLifetime()
		if !ok || p.failed {
			return
		}
		p.writeByte('&')
		if lt > 0 {
			p.write(formatLifetime(lt))
			p.writeByte(' ')
		}
		if c == 'Q' {
			p.write("mut ")
		}
		p.parseType()

	case 'P':
		p.pos++
		p.write("*const ")
		p.parseType()

	case 'O':
		p.pos++
		p.write("*mut ")
		p.parseType()

	case 'F':
		p.pos++
		p.parseFnSig()

	case 'D':
		p.pos++
		p.parseDynTrait()

	case 'B':
		p.pos++
		refStart := p.pos - 1
		target, ok := p.parseBase62()
		if !ok || target >= uint64(refStart) {
			p.failed = true
			return
		}
		saved := p.pos
		p.pos = int(target)
		p.parseType()
		p.pos = saved

	default:
		if isV0PathStarter(c) {
			p.parsePath(true)
			return
		}
		p.failed = true
	}
}

func v0BasicType(c byte) (string, bool) {
	switch c {
	case 'a':
		return "i8", true
	case 'b':
		return "bool", true
	case 'c':
		return "char", true
	case 'd':
		return "f64", true
	case 'e':
		return "str", true
	case 'f':
		return "f32", true
	case 'h':
		return "u8", true
	case 'i':
		return "isize", true
	case 'j':
		return "usize", true
	case 'l':
		return "i32", true
	case 'm':
		return "u32", true
	case 'n':
		return "i128", true
	case 'o':
		return "u128", true
	case 'p':
		return "_", true
	case 's':
		return "i16", true
	case 't':
		return "u16", true
	case 'u':
		return "()", true
	case 'v':
		return "...", true
	case 'z':
		return "!", true
	}
	return "", false
}

func (p *v0Parser) parseOptBinder() {
	if p.pos < len(p.s) && p.s[p.pos] == 'G' {
		p.pos++
		_, _ = p.parseBase62()
	}
}

func (p *v0Parser) parseFnSig() {
	// [<binder>] ["U"] ["K" <abi>] {<type>} "E" <type>
	p.parseOptBinder()
	if p.failed {
		return
	}
	if p.consume('U') {
		p.write("unsafe ")
	}
	if p.consume('K') {
		if p.consume('C') {
			p.write(`extern "C" `)
		} else {
			abi, ok := p.parseUndisambiguatedIdent()
			if !ok {
				return
			}
			p.write(`extern "` + strings.ReplaceAll(abi, "-", "-") + `" `)
		}
	}
	p.write("fn(")
	idx := 0
	for {
		ch, ok := p.peek()
		if !ok {
			p.failed = true
			return
		}
		if ch == 'E' {
			p.pos++
			break
		}
		if idx > 0 {
			p.write(", ")
		}
		p.parseType()
		if p.failed {
			return
		}
		idx++
	}
	p.writeByte(')')

	// Return type: omit " -> ()" if 'u'
	ch, ok := p.peek()
	if !ok {
		p.failed = true
		return
	}
	if ch == 'u' {
		p.pos++
		return
	}
	p.write(" -> ")
	p.parseType()
}

func (p *v0Parser) parseDynTrait() {
	// "D" [<binder>] {<dyn-trait>} "E" <lifetime>
	p.parseOptBinder()
	if p.failed {
		return
	}
	p.write("dyn ")
	traitIdx := 0
	for {
		ch, ok := p.peek()
		if !ok {
			p.failed = true
			return
		}
		if ch == 'E' {
			p.pos++
			break
		}
		if traitIdx > 0 {
			p.write(" + ")
		}
		// <dyn-trait> = <path> {<dyn-trait-assoc-binding>}
		// Check if assoc bindings follow before closing '>': parse path, then 'p' bindings
		p.parsePath(true)
		if p.failed {
			return
		}
		var assocCount int
		for p.pos < len(p.s) && p.s[p.pos] == 'p' {
			p.pos++
			assocName, ok := p.parseUndisambiguatedIdent()
			if !ok {
				return
			}
			if assocCount == 0 {
				p.writeByte('<')
			} else {
				p.write(", ")
			}
			p.write(assocName)
			p.write(" = ")
			p.parseType()
			if p.failed {
				return
			}
			assocCount++
		}
		if assocCount > 0 {
			p.writeByte('>')
		}
		traitIdx++
	}

	// Trailing <lifetime>
	if !p.consume('L') {
		p.failed = true
		return
	}
	lt, ok := p.parseBase62()
	if !ok {
		return
	}
	if lt > 0 {
		if traitIdx > 0 {
			p.write(" + ")
		}
		p.write(formatLifetime(lt))
	}
}

func (p *v0Parser) parseConst() {
	if !p.enter() {
		return
	}
	defer p.leave()

	c, ok := p.peek()
	if !ok {
		p.failed = true
		return
	}
	if c == 'p' {
		p.pos++
		p.writeByte('_')
		return
	}
	if c == 'B' {
		p.pos++
		refStart := p.pos - 1
		target, ok := p.parseBase62()
		if !ok || target >= uint64(refStart) {
			p.failed = true
			return
		}
		saved := p.pos
		p.pos = int(target)
		p.parseConst()
		p.pos = saved
		return
	}

	// Parse const type silently to format bool/char/int cleanly
	typeTag := c
	p.suppress++
	p.parseType()
	p.suppress--
	if p.failed {
		return
	}

	neg := p.consume('n')
	startHex := p.pos
	for p.pos < len(p.s) {
		hc := p.s[p.pos]
		if hc == '_' {
			break
		}
		if !((hc >= '0' && hc <= '9') || (hc >= 'a' && hc <= 'f')) {
			p.failed = true
			return
		}
		p.pos++
	}
	if p.pos >= len(p.s) || p.s[p.pos] != '_' {
		p.failed = true
		return
	}
	hexStr := p.s[startHex:p.pos]
	p.pos++ // consume '_'

	if hexStr == "" {
		hexStr = "0"
	}
	if typeTag == 'b' && !neg {
		switch hexStr {
		case "0":
			p.write("false")
			return
		case "1":
			p.write("true")
			return
		}
	}
	if neg {
		p.writeByte('-')
	}
	if v, err := strconv.ParseUint(hexStr, 16, 64); err == nil {
		p.write(strconv.FormatUint(v, 10))
	} else {
		p.write("0x" + hexStr)
	}
}

// decodeRustPunycode decodes RFC 3492 bootstring with Rust's '_' separator convention.
func decodeRustPunycode(input string) (string, bool) {
	const (
		base        = 36
		tmin        = 1
		tmax        = 26
		skew        = 38
		damp        = 700
		initialBias = 72
		initialN    = 0x80
		maxRunes    = 1024
	)

	var out []rune
	tail := input
	if sep := strings.LastIndexByte(input, '_'); sep >= 0 {
		for _, r := range input[:sep] {
			if r >= 0x80 {
				return "", false
			}
			out = append(out, r)
		}
		tail = input[sep+1:]
	}

	n := initialN
	i := 0
	bias := initialBias

	for pos := 0; pos < len(tail); {
		oldi := i
		w := 1
		for k := base; ; k += base {
			if pos >= len(tail) {
				return "", false
			}
			c := tail[pos]
			pos++
			var digit int
			switch {
			case c >= 'a' && c <= 'z':
				digit = int(c - 'a')
			case c >= '0' && c <= '9':
				digit = int(c-'0') + 26
			default:
				return "", false
			}
			if digit > (1<<28-i)/w {
				return "", false
			}
			i += digit * w
			var t int
			switch {
			case k <= bias:
				t = tmin
			case k >= bias+tmax:
				t = tmax
			default:
				t = k - bias
			}
			if digit < t {
				break
			}
			if w > (1<<28)/(base-t) {
				return "", false
			}
			w *= (base - t)
		}

		outLen := len(out) + 1
		if outLen > maxRunes {
			return "", false
		}
		delta := i - oldi
		if oldi == 0 {
			delta /= damp
		} else {
			delta /= 2
		}
		delta += delta / outLen
		k := 0
		for delta > ((base-tmin)*tmax)/2 {
			delta /= (base - tmin)
			k += base
		}
		bias = k + (((base - tmin + 1) * delta) / (delta + skew))

		if i/outLen > 0x10ffff-n {
			return "", false
		}
		n += i / outLen
		i %= outLen
		r := rune(n)
		if !utf8.ValidRune(r) {
			return "", false
		}
		out = append(out, 0)
		copy(out[i+1:], out[i:])
		out[i] = r
		i++
	}
	return string(out), true
}

// ---------------------------------------------------------------------------
// Crate & Receiver Extraction from Demangled Rust Names
// ---------------------------------------------------------------------------

// splitDemangledCrate extracts (crateName, modulePkg, receiver) from a demangled Rust symbol.
func splitDemangledCrate(demangled string) (crateName, pkgPath, receiver string) {
	parts := splitTopLevelColons(demangled)
	if len(parts) == 0 {
		return "", "", ""
	}

	first := parts[0]
	if strings.HasPrefix(first, "<") && strings.HasSuffix(first, ">") {
		inner := first[1 : len(first)-1]
		selfType, traitPath := splitTopLevelAs(inner)
		receiver = cleanTypeForReceiver(selfType)
		crateName, pkgPath = crateFromTypeExpr(selfType)
		if crateName == "" && traitPath != "" {
			crateName, pkgPath = crateFromTypeExpr(traitPath)
		}
		return crateName, pkgPath, receiver
	}

	crateName = stripGenerics(first)
	if len(parts) >= 2 {
		modParts := []string{crateName}
		for i := 1; i < len(parts)-1 && i < 3; i++ {
			seg := stripGenerics(parts[i])
			if seg == "" || strings.HasPrefix(seg, "{") {
				break
			}
			modParts = append(modParts, seg)
		}
		pkgPath = strings.Join(modParts, "::")
	} else {
		pkgPath = crateName
	}
	return crateName, pkgPath, ""
}

func crateFromTypeExpr(expr string) (string, string) {
	t := cleanTypeForReceiver(expr)
	parts := splitTopLevelColons(t)
	if len(parts) < 2 {
		return "", ""
	}
	crate := stripGenerics(parts[0])
	if crate == "" || strings.ContainsAny(crate, " ()[]*&") {
		return "", ""
	}
	if len(parts) >= 3 {
		second := stripGenerics(parts[1])
		if second != "" && !strings.HasPrefix(second, "{") {
			return crate, crate + "::" + second
		}
	}
	return crate, crate
}

func cleanTypeForReceiver(t string) string {
	t = strings.TrimSpace(t)
	for {
		switch {
		case strings.HasPrefix(t, "&mut "):
			t = strings.TrimSpace(t[5:])
		case strings.HasPrefix(t, "&"):
			t = strings.TrimSpace(t[1:])
			if strings.HasPrefix(t, "'") {
				if sp := strings.IndexByte(t, ' '); sp > 0 {
					t = strings.TrimSpace(t[sp+1:])
				}
			}
		case strings.HasPrefix(t, "*const "):
			t = strings.TrimSpace(t[7:])
		case strings.HasPrefix(t, "*mut "):
			t = strings.TrimSpace(t[5:])
		default:
			return t
		}
	}
}

func stripGenerics(seg string) string {
	if idx := strings.IndexByte(seg, '<'); idx >= 0 {
		return seg[:idx]
	}
	return seg
}

func splitTopLevelColons(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<', '(', '[', '{':
			depth++
		case '>', ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 && i+1 < len(s) && s[i+1] == ':' {
				parts = append(parts, s[start:i])
				i++
				start = i + 1
			}
		}
	}
	if start <= len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}

func splitTopLevelAs(s string) (string, string) {
	depth := 0
	for i := 0; i+4 <= len(s); i++ {
		switch s[i] {
		case '<', '(', '[', '{':
			depth++
		case '>', ')', ']', '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && s[i:i+4] == " as " {
				return s[:i], s[i+4:]
			}
		}
	}
	return s, ""
}
