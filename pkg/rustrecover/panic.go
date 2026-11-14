package rustrecover

import (
	"bytes"
	"sort"
	"strings"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

const (
	maxPanicLocations = 4096
	maxRustPathLen    = 512
	maxPanicLine      = 500000
	maxPanicCol       = 10000
)

type rsSliceSpan struct {
	va   uint64
	size uint64
	path string
}

// buildELFRelativeMap parses .rela.dyn / .rela.data.rel.ro (if present on 64-bit ELF PIE binaries)
// so pointers stored as 0 in .data.rel.ro with RELA r_addend still resolve to exact virtual addresses.
func buildELFRelativeMap(lb *loader.LoadedBinary) map[uint64]uint64 {
	if lb.Info.Format != model.FormatELF || lb.Info.PointerSize != 8 {
		return nil
	}
	const (
		rX86_64Relative  = 8
		rAArch64Relative = 1027
	)
	var out map[uint64]uint64
	for i := range lb.Sections {
		s := &lb.Sections[i]
		if !strings.HasPrefix(s.Name, ".rela") || strings.HasPrefix(s.Name, ".rela.plt") {
			continue
		}
		data, ok := lb.SectionBytes(s)
		if !ok || len(data) < 24 {
			continue
		}
		for off := 0; off+24 <= len(data); off += 24 {
			rOffset := lb.Order.Uint64(data[off : off+8])
			rInfo := lb.Order.Uint64(data[off+8 : off+16])
			rAddend := lb.Order.Uint64(data[off+16 : off+24])
			rType := uint32(rInfo & 0xffffffff)
			if (rType == rX86_64Relative || rType == rAArch64Relative) && rOffset != 0 && rAddend != 0 {
				if out == nil {
					out = make(map[uint64]uint64, len(data)/24)
				}
				out[rOffset] = rAddend
			}
		}
	}
	return out
}

func readRelocPtr(lb *loader.LoadedBinary, secData []byte, off int, slotVA uint64, relMap map[uint64]uint64) uint64 {
	var v uint64
	if lb.Info.PointerSize == 8 {
		v = lb.Order.Uint64(secData[off : off+8])
	} else {
		v = uint64(lb.Order.Uint32(secData[off : off+4]))
	}
	if v == 0 && relMap != nil {
		if target, ok := relMap[slotVA]; ok {
			return target
		}
	}
	if v != 0 && lb.SectionContainingVA(v) == nil &&
		(lb.Info.Format == model.FormatMachO || lb.Info.Format == model.FormatMachOFat) &&
		lb.Info.PointerSize == 8 {
		if (v >> 63) == 0 {
			low36 := v & 0xfffffffff
			if lb.SectionContainingVA(low36) != nil {
				return low36
			}
			candOffset := lb.Info.ImageBase + low36
			if lb.SectionContainingVA(candOffset) != nil {
				return candOffset
			}
			high8 := (v >> 36) & 0xff
			candTarget := (high8 << 56) | low36
			if lb.SectionContainingVA(candTarget) != nil {
				return candTarget
			}
		} else if (v >> 62) == 2 {
			// arm64e authenticated rebase pointer (auth=1, bind=0): low 32 bits = offset from ImageBase
			candPAC := lb.Info.ImageBase + (v & 0xffffffff)
			if lb.SectionContainingVA(candPAC) != nil {
				return candPAC
			}
		}
	}
	return v
}

// carvePanicLocations locates .rs source path slices and carves binary core::panic::Location structs.
func carvePanicLocations(lb *loader.LoadedBinary, relMap map[uint64]uint64) (panics []model.PanicLocation, hasPanicMarkers bool) {
	ptrSize := lb.Info.PointerSize
	if ptrSize != 4 && ptrSize != 8 {
		return nil, false
	}

	// Step 1: Index .rs source path slices in read-only / non-exec sections and check panic runtime markers
	rsByEndVA := make(map[uint64]rsSliceSpan)
	raw := lb.Raw()
	hasPanicMarkers = hasRustPanicRuntimeMarkers(raw)

	for i := range lb.Sections {
		s := &lb.Sections[i]
		if s.Executable || !s.Readable || s.FileSize == 0 || isIgnoredMetadataSection(s.Name) {
			continue
		}
		secData, ok := lb.SectionBytes(s)
		if !ok {
			continue
		}
		for _, sp := range scanSectionRustPaths(s.VirtualAddr, secData) {
			rsByEndVA[sp.va+sp.size] = sp
		}
	}

	// Step 2: Scan non-executable data sections on 4-byte alignment for core::panic::Location structs
	seenStruct := make(map[uint64]struct{})
	seenTuple := make(map[ panicDedupKey ]struct{})

	emit := func(loc model.PanicLocation) {
		if len(panics) >= maxPanicLocations {
			return
		}
		if _, dup := seenStruct[loc.StructAddr]; dup {
			return
		}
		key := panicDedupKey{file: loc.File, line: loc.Line, col: loc.Column, addr: loc.StructAddr}
		if _, dup := seenTuple[key]; dup {
			return
		}
		seenStruct[loc.StructAddr] = struct{}{}
		seenTuple[key] = struct{}{}
		loc.Crate = inferCrateFromRustPath(loc.File)
		panics = append(panics, loc)
	}

	layoutASize := 2*ptrSize + 8 // (ptr, len, line, col): 24 on 64-bit, 16 on 32-bit
	layoutCStrSize := ptrSize + 8 // (ptr, line, col): 16 on 64-bit, 12 on 32-bit

	for i := range lb.Sections {
		s := &lb.Sections[i]
		if s.Executable || !s.Readable || s.FileSize < 12 || isIgnoredMetadataSection(s.Name) {
			continue
		}
		secData, ok := lb.SectionBytes(s)
		if !ok {
			continue
		}

		for off := 0; off+12 <= len(secData); off += 4 {
			if len(panics) >= maxPanicLocations {
				break
			}
			slotVA := s.VirtualAddr + uint64(off)

			// --- Layout A: [ptr: uintptr, len: uintptr, line: uint32, col: uint32] ---
			if off+layoutASize <= len(secData) {
				ptr := readRelocPtr(lb, secData, off, slotVA, relMap)
				strLen := readPlainUintPtr(lb, secData, off+ptrSize)
				line := lb.Order.Uint32(secData[off+2*ptrSize : off+2*ptrSize+4])
				col := lb.Order.Uint32(secData[off+2*ptrSize+4 : off+2*ptrSize+8])

				if fileStr, ok := matchRustPathSlice(lb, ptr, strLen, line, col, rsByEndVA); ok {
					emit(model.PanicLocation{
						File:        fileStr,
						Line:        line,
						Column:      col,
						StructAddr:  slotVA,
						FileStrAddr: ptr,
					})
					off += layoutASize - 4
					continue
				}

				// --- Layout B1 (reordered repr(Rust)): [line: uint32, col: uint32, ptr: uintptr, len: uintptr] ---
				// Guard against Mach-O 64-bit pointers (0x00000001_0000xxxx) immediately preceding a Layout A struct
				// at off+8, whose low32/high32 words otherwise look like (line, col=1).
				hasLayoutAAtPlus8 := false
				if off+8+layoutASize <= len(secData) {
					ptrNext := readRelocPtr(lb, secData, off+8, slotVA+8, relMap)
					lenNext := readPlainUintPtr(lb, secData, off+8+ptrSize)
					lineNext := lb.Order.Uint32(secData[off+8+2*ptrSize : off+8+2*ptrSize+4])
					colNext := lb.Order.Uint32(secData[off+8+2*ptrSize+4 : off+8+2*ptrSize+8])
					if _, okNext := matchRustPathSlice(lb, ptrNext, lenNext, lineNext, colNext, rsByEndVA); okNext {
						hasLayoutAAtPlus8 = true
					}
				}
				if !hasLayoutAAtPlus8 && lb.SectionContainingVA(readRelocPtr(lb, secData, off, slotVA, relMap)) == nil {
					lineB := lb.Order.Uint32(secData[off : off+4])
					colB := lb.Order.Uint32(secData[off+4 : off+8])
					ptrB := readRelocPtr(lb, secData, off+8, slotVA+8, relMap)
					lenB := readPlainUintPtr(lb, secData, off+8+ptrSize)
					if fileStr, ok := matchRustPathSlice(lb, ptrB, lenB, lineB, colB, rsByEndVA); ok {
						emit(model.PanicLocation{
							File:        fileStr,
							Line:        lineB,
							Column:      colB,
							StructAddr:  slotVA,
							FileStrAddr: ptrB,
						})
						off += layoutASize - 4
						continue
					}
				}
			}

			// --- Layout B2 (&CStr Location): [ptr: uintptr, line: uint32, col: uint32] ---
			if off+layoutCStrSize <= len(secData) {
				ptr := readRelocPtr(lb, secData, off, slotVA, relMap)
				line := lb.Order.Uint32(secData[off+ptrSize : off+ptrSize+4])
				col := lb.Order.Uint32(secData[off+ptrSize+4 : off+ptrSize+8])
				if validLineCol(line, col) && ptr != 0 && !lb.IsCodeVA(ptr) {
					if cstr, ok := lb.ReadCStringAtVA(ptr, maxRustPathLen); ok && isValidRustSourcePath(cstr) {
						emit(model.PanicLocation{
							File:        cstr,
							Line:        line,
							Column:      col,
							StructAddr:  slotVA,
							FileStrAddr: ptr,
						})
						off += layoutCStrSize - 4
						continue
					}
				}
			}

			// --- Layout B3 (Relative 32-bit pointer): [rel32: int32, line: uint32, col: uint32] ---
			rel32 := int32(lb.Order.Uint32(secData[off : off+4]))
			lineR := lb.Order.Uint32(secData[off+4 : off+8])
			colR := lb.Order.Uint32(secData[off+8 : off+12])
			if rel32 != 0 && validLineCol(lineR, colR) {
				targetVA := uint64(int64(slotVA) + int64(rel32))
				if !lb.IsCodeVA(targetVA) {
					if cstr, ok := lb.ReadCStringAtVA(targetVA, maxRustPathLen); ok && isValidRustSourcePath(cstr) {
						emit(model.PanicLocation{
							File:        cstr,
							Line:        lineR,
							Column:      colR,
							StructAddr:  slotVA,
							FileStrAddr: targetVA,
						})
						off += 8 // +4 from loop => +12
						continue
					}
				}
			}
		}
	}

	sort.Slice(panics, func(i, j int) bool {
		return panics[i].StructAddr < panics[j].StructAddr
	})
	return panics, hasPanicMarkers
}

type panicDedupKey struct {
	file string
	line uint32
	col  uint32
	addr uint64
}

func readPlainUintPtr(lb *loader.LoadedBinary, secData []byte, off int) uint64 {
	if lb.Info.PointerSize == 8 {
		return lb.Order.Uint64(secData[off : off+8])
	}
	return uint64(lb.Order.Uint32(secData[off : off+4]))
}

func validLineCol(line, col uint32) bool {
	return line >= 1 && line <= maxPanicLine && col >= 1 && col <= maxPanicCol
}

func matchRustPathSlice(
	lb *loader.LoadedBinary,
	ptr uint64,
	strLen uint64,
	line uint32,
	col uint32,
	rsByEndVA map[uint64]rsSliceSpan,
) (string, bool) {
	if ptr == 0 || strLen < 4 || strLen > maxRustPathLen || !validLineCol(line, col) {
		return "", false
	}
	if lb.IsCodeVA(ptr) {
		return "", false
	}
	// Fast check against pre-indexed .rs spans when exact start+end matches
	if sp, ok := rsByEndVA[ptr+strLen]; ok && sp.va == ptr {
		return sp.path, true
	}
	// Direct VA slice lookup (handles back-to-back non-null-terminated .rodata strings!)
	buf, ok := lb.ReadAtVA(ptr, int(strLen))
	if !ok {
		return "", false
	}
	s := string(buf)
	if !isValidRustSourcePath(s) {
		return "", false
	}
	return s, true
}

// scanSectionRustPaths locates candidate ".rs" source paths inside a read-only section.
func scanSectionRustPaths(baseVA uint64, data []byte) []rsSliceSpan {
	var spans []rsSliceSpan
	suffix := []byte(".rs")
	off := 0
	for off < len(data) {
		idx := bytes.Index(data[off:], suffix)
		if idx < 0 {
			break
		}
		endPos := off + idx + 3 // inclusive end of ".rs"
		off = endPos

		// Reject if ".rs" is immediately followed by an identifier character (e.g. ".rsrc" or ".rs_foo")
		if endPos < len(data) && isIdentContByte(data[endPos]) {
			continue
		}

		// Walk backwards up to maxRustPathLen while bytes are valid path characters
		startPos := endPos - 3
		minStart := 0
		if endPos > maxRustPathLen {
			minStart = endPos - maxRustPathLen
		}
		for startPos > minStart && isRustPathByte(data[startPos-1]) {
			startPos--
		}
		cand := string(data[startPos:endPos])
		if isValidRustSourcePath(cand) {
			spans = append(spans, rsSliceSpan{
				va:   baseVA + uint64(startPos),
				size: uint64(endPos - startPos),
				path: cand,
			})
		}
	}
	return spans
}

func isValidRustSourcePath(s string) bool {
	if len(s) < 4 || len(s) > maxRustPathLen || !strings.HasSuffix(s, ".rs") {
		return false
	}
	stem := s[:len(s)-3]
	if stem == "" {
		return false
	}
	// Last character before ".rs" must be a valid Rust filename char
	last := stem[len(stem)-1]
	if !((last >= 'a' && last <= 'z') || (last >= 'A' && last <= 'Z') || (last >= '0' && last <= '9') || last == '_' || last == '-') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isRustPathByte(s[i]) {
			return false
		}
	}
	return true
}

func isRustPathByte(c byte) bool {
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
		return true
	}
	switch c {
	case '_', '-', '.', '/', '\\', ':', '+', '@', '~', ' ':
		return true
	}
	return false
}

func isIdentContByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func isIgnoredMetadataSection(name string) bool {
	n := strings.ToLower(name)
	if strings.Contains(n, "rel.ro") {
		return false
	}
	for _, pfx := range []string{
		".debug", "__dwarf", ".pdata", ".xdata", ".eh_frame",
		".idata", ".reloc", ".symtab", ".strtab", ".rela", ".rel.", ".relr",
		".gopclntab", "__gopclntab",
	} {
		if strings.HasPrefix(n, pfx) {
			return true
		}
	}
	return false
}

func hasRustPanicRuntimeMarkers(raw []byte) bool {
	markers := [][]byte{
		[]byte("core::panicking"),
		[]byte("panicking.rs"),
		[]byte("rust_begin_unwind"),
		[]byte("RUST_BACKTRACE"),
		[]byte("panicked at "),
	}
	for _, m := range markers {
		if bytes.Contains(raw, m) {
			return true
		}
	}
	return false
}

func inferCrateFromRustPath(p string) string {
	norm := strings.ReplaceAll(p, `\`, "/")

	// 1. Cargo registry: /.cargo/registry/src/<index>/<crate>-<ver>/...
	if idx := strings.Index(norm, ".cargo/registry/src/"); idx >= 0 {
		rest := norm[idx+len(".cargo/registry/src/"):]
		if slash1 := strings.IndexByte(rest, '/'); slash1 > 0 {
			afterHost := rest[slash1+1:]
			if slash2 := strings.IndexByte(afterHost, '/'); slash2 > 0 {
				crateDir := afterHost[:slash2]
				if name, _, ok := splitCrateAndSemver(crateDir); ok {
					return name
				}
			}
		}
	}

	// 2. Rust sysroot stdlib: /rustc/<hash>/library/<crate>/src/... or library/<crate>/src/...
	if idx := strings.Index(norm, "library/"); idx >= 0 {
		rest := norm[idx+len("library/"):]
		if slash := strings.IndexByte(rest, '/'); slash > 0 {
			cand := rest[:slash]
			if isValidCrateIdent(cand) {
				return cand
			}
		}
	}

	return ""
}
