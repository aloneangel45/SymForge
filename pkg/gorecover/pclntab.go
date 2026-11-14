package gorecover

import (
	"bytes"
	"debug/gosym"
	"encoding/binary"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

const (
	MagicGo12  uint32 = 0xfffffffb // Go 1.2  - 1.15
	MagicGo116 uint32 = 0xfffffffa // Go 1.16 - 1.17
	MagicGo118 uint32 = 0xfffffff0 // Go 1.18 - 1.19
	MagicGo120 uint32 = 0xfffffff1 // Go 1.20 - 1.27+

	maxPCLnTabFuncs = 2_000_000
	maxPCLnTabFiles = 2_000_000
)

type parsedPCLnTab struct {
	magic          uint32
	versionName    string
	order          binary.ByteOrder
	minLC          uint8
	ptrSize        uint8
	va             uint64
	fileOffset     uint64
	data           []byte
	nfunc          uint64
	nfiles         uint64
	hdrTextStart   uint64
	funcnameOffset uint64
	cuOffset       uint64
	filetabOffset  uint64
	pctabOffset    uint64
	pclnOffset     uint64
}

type magicPattern struct {
	prefix      [6]byte
	magic       uint32
	versionName string
	order       binary.ByteOrder
}

var pclnMagicPatterns = []magicPattern{
	// Little-endian (most common: x86_64, arm64, x86, arm)
	{prefix: [6]byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00}, magic: MagicGo120, versionName: "go1.20+", order: binary.LittleEndian},
	{prefix: [6]byte{0xf0, 0xff, 0xff, 0xff, 0x00, 0x00}, magic: MagicGo118, versionName: "go1.18", order: binary.LittleEndian},
	{prefix: [6]byte{0xfa, 0xff, 0xff, 0xff, 0x00, 0x00}, magic: MagicGo116, versionName: "go1.16", order: binary.LittleEndian},
	{prefix: [6]byte{0xfb, 0xff, 0xff, 0xff, 0x00, 0x00}, magic: MagicGo12, versionName: "go1.2", order: binary.LittleEndian},
	// Big-endian
	{prefix: [6]byte{0xff, 0xff, 0xff, 0xf1, 0x00, 0x00}, magic: MagicGo120, versionName: "go1.20+", order: binary.BigEndian},
	{prefix: [6]byte{0xff, 0xff, 0xff, 0xf0, 0x00, 0x00}, magic: MagicGo118, versionName: "go1.18", order: binary.BigEndian},
	{prefix: [6]byte{0xff, 0xff, 0xff, 0xfa, 0x00, 0x00}, magic: MagicGo116, versionName: "go1.16", order: binary.BigEndian},
	{prefix: [6]byte{0xff, 0xff, 0xff, 0xfb, 0x00, 0x00}, magic: MagicGo12, versionName: "go1.2", order: binary.BigEndian},
}

var candidatePCLnSections = []string{
	".gopclntab",
	"__TEXT.__gopclntab",
	"__DATA.__gopclntab",
	"__DATA_CONST.__gopclntab",
	".data.rel.ro.gopclntab",
	"__gopclntab",
	".rdata",
	".data.rel.ro",
	".rodata",
	"__TEXT.__rodata",
	".data",
	"__DATA.__data",
}

// locatePCLnTab searches named sections first and falls back to scanning raw binary bytes.
func locatePCLnTab(lb *loader.LoadedBinary) (*parsedPCLnTab, bool) {
	raw := lb.Raw()
	if len(raw) < 16 {
		return nil, false
	}

	// 1. Search named sections in priority order.
	visitedSec := make(map[int]bool, len(lb.Sections))
	for _, wantName := range candidatePCLnSections {
		for idx := range lb.Sections {
			if visitedSec[idx] {
				continue
			}
			sec := &lb.Sections[idx]
			if !strings.EqualFold(sec.Name, wantName) {
				continue
			}
			visitedSec[idx] = true
			secBytes, ok := lb.SectionBytes(sec)
			if !ok || len(secBytes) < 16 {
				continue
			}

			// Fast check at exact start of dedicated section.
			if p, ok := tryParsePCLnAt(raw, sec.FileOffset, sec.FileOffset+sec.FileSize, sec.VirtualAddr); ok {
				return p, true
			}
			// Scan inside merged read-only/data section (e.g., Windows PE .rdata).
			if p, ok := scanBufferForPCLn(lb, raw, secBytes, sec.FileOffset, sec.VirtualAddr, true); ok {
				return p, true
			}
		}
	}

	// 2. Fallback: scan entire raw file image (handles sstrip'd ELF PT_LOAD or custom packers).
	if p, ok := scanBufferForPCLn(lb, raw, raw, 0, 0, false); ok {
		return p, true
	}

	return nil, false
}

func scanBufferForPCLn(
	lb *loader.LoadedBinary,
	fullRaw []byte,
	window []byte,
	windowFileOff uint64,
	windowBaseVA uint64,
	hasBaseVA bool,
) (*parsedPCLnTab, bool) {
	// Find earliest valid candidate across all 8 magic patterns.
	var best *parsedPCLnTab
	for _, pat := range pclnMagicPatterns {
		searchFrom := 0
		for searchFrom+16 <= len(window) {
			rel := bytes.Index(window[searchFrom:], pat.prefix[:])
			if rel < 0 {
				break
			}
			pos := searchFrom + rel
			searchFrom = pos + 2

			fileOff := windowFileOff + uint64(pos)
			var va uint64
			if hasBaseVA {
				va = windowBaseVA + uint64(pos)
			} else if mappedVA, ok := lb.OffsetToVA(fileOff); ok {
				va = mappedVA
			}

			// Bound available slice to end of containing section if known, otherwise full file.
			limitOff := uint64(len(fullRaw))
			if hasBaseVA {
				secEnd := windowFileOff + uint64(len(window))
				if secEnd <= limitOff {
					limitOff = secEnd
				}
			}

			cand, ok := validatePCLnCandidate(fullRaw, fileOff, limitOff, va, pat)
			if !ok && limitOff < uint64(len(fullRaw)) {
				// Retry extending to end of file in case linker split tables across adjacent sections.
				cand, ok = validatePCLnCandidate(fullRaw, fileOff, uint64(len(fullRaw)), va, pat)
			}
			if ok {
				if best == nil || cand.fileOffset < best.fileOffset {
					best = cand
				}
				break
			}
		}
	}
	if best != nil {
		return best, true
	}
	return nil, false
}

func tryParsePCLnAt(fullRaw []byte, fileOff, limitOff, va uint64) (*parsedPCLnTab, bool) {
	if fileOff+16 > uint64(len(fullRaw)) {
		return nil, false
	}
	for _, pat := range pclnMagicPatterns {
		if bytes.Equal(fullRaw[fileOff:fileOff+6], pat.prefix[:]) {
			if p, ok := validatePCLnCandidate(fullRaw, fileOff, limitOff, va, pat); ok {
				return p, true
			}
			if limitOff < uint64(len(fullRaw)) {
				if p, ok := validatePCLnCandidate(fullRaw, fileOff, uint64(len(fullRaw)), va, pat); ok {
					return p, true
				}
			}
		}
	}
	return nil, false
}

func validatePCLnCandidate(fullRaw []byte, fileOff, limitOff, va uint64, pat magicPattern) (*parsedPCLnTab, bool) {
	if limitOff > uint64(len(fullRaw)) {
		limitOff = uint64(len(fullRaw))
	}
	if fileOff >= limitOff || limitOff-fileOff < 16 {
		return nil, false
	}
	data := fullRaw[fileOff:limitOff]

	// Header bytes [0..7]: magic[4], pad1(0), pad2(0), minLC, ptrSize
	if data[4] != 0 || data[5] != 0 {
		return nil, false
	}
	minLC := data[6]
	if minLC != 1 && minLC != 2 && minLC != 4 {
		return nil, false
	}
	ptrSize := data[7]
	if ptrSize != 4 && ptrSize != 8 {
		return nil, false
	}
	ps := uint64(ptrSize)
	bo := pat.order

	wordAt := func(idx uint64) (uint64, bool) {
		off := 8 + idx*ps
		if off+ps > uint64(len(data)) {
			return 0, false
		}
		if ps == 4 {
			return uint64(bo.Uint32(data[off : off+4])), true
		}
		return bo.Uint64(data[off : off+8]), true
	}

	p := &parsedPCLnTab{
		magic:       pat.magic,
		versionName: pat.versionName,
		order:       bo,
		minLC:       minLC,
		ptrSize:     ptrSize,
		va:          va,
		fileOffset:  fileOff,
		data:        data,
	}

	switch pat.magic {
	case MagicGo118, MagicGo120:
		hdrLen := 8 + 8*ps
		if uint64(len(data)) < hdrLen {
			return nil, false
		}
		nfunc, _ := wordAt(0)
		nfiles, _ := wordAt(1)
		textStart, _ := wordAt(2)
		funcnameOff, _ := wordAt(3)
		cuOff, _ := wordAt(4)
		filetabOff, _ := wordAt(5)
		pctabOff, _ := wordAt(6)
		pclnOff, _ := wordAt(7)

		if nfunc == 0 || nfunc > maxPCLnTabFuncs || nfiles > maxPCLnTabFiles {
			return nil, false
		}
		uLen := uint64(len(data))
		if funcnameOff < hdrLen || funcnameOff >= uLen ||
			cuOff < hdrLen || cuOff > uLen ||
			filetabOff < hdrLen || filetabOff > uLen ||
			pctabOff < hdrLen || pctabOff > uLen ||
			pclnOff < hdrLen || pclnOff >= uLen {
			return nil, false
		}

		// ftab at pclnOff holds (nfunc * 8 + 4) minimum bytes: nfunc {entryoff, funcoff} + trailing end entryoff.
		minFTabBytes := nfunc*8 + 4
		if pclnOff+minFTabBytes > uLen {
			return nil, false
		}
		if nfiles > 0 && cuOff+4 > uLen {
			return nil, false
		}

		// Validate monotonicity of initial ftab entries and at least one printable function name.
		checkN := nfunc
		if checkN > 16 {
			checkN = 16
		}
		validNames := 0
		for i := uint64(0); i < checkN; i++ {
			off := pclnOff + i*8
			e0 := bo.Uint32(data[off : off+4])
			fOff := bo.Uint32(data[off+4 : off+8])
			e1 := bo.Uint32(data[off+8 : off+12])
			if e0 > e1 {
				return nil, false
			}
			fPos := pclnOff + uint64(fOff)
			if fPos+36 > uLen {
				return nil, false
			}
			fnEntry := bo.Uint32(data[fPos : fPos+4])
			if fnEntry != e0 {
				return nil, false
			}
			nameOff := int32(bo.Uint32(data[fPos+4 : fPos+8]))
			if nameOff >= 0 && funcnameOff+uint64(nameOff) < uLen {
				if name, ok := readCStringSlice(data[funcnameOff:], uint64(nameOff), 1024); ok && looksLikeGoSymbol(name) {
					validNames++
				}
			}
		}
		if validNames == 0 {
			return nil, false
		}

		p.nfunc = nfunc
		p.nfiles = nfiles
		p.hdrTextStart = textStart
		p.funcnameOffset = funcnameOff
		p.cuOffset = cuOff
		p.filetabOffset = filetabOff
		p.pctabOffset = pctabOff
		p.pclnOffset = pclnOff
		return p, true

	case MagicGo116:
		hdrLen := 8 + 7*ps
		if uint64(len(data)) < hdrLen {
			return nil, false
		}
		nfunc, _ := wordAt(0)
		nfiles, _ := wordAt(1)
		funcnameOff, _ := wordAt(2)
		cuOff, _ := wordAt(3)
		filetabOff, _ := wordAt(4)
		pctabOff, _ := wordAt(5)
		pclnOff, _ := wordAt(6)

		if nfunc == 0 || nfunc > maxPCLnTabFuncs || nfiles > maxPCLnTabFiles {
			return nil, false
		}
		uLen := uint64(len(data))
		ftabBytes := (nfunc*2 + 1) * ps
		if funcnameOff < hdrLen || funcnameOff >= uLen ||
			cuOff < hdrLen || cuOff > uLen ||
			filetabOff < hdrLen || filetabOff > uLen ||
			pctabOff < hdrLen || pctabOff > uLen ||
			pclnOff < hdrLen || pclnOff+ftabBytes > uLen {
			return nil, false
		}
		if !validateLegacyFTab(data[pclnOff:], nfunc, ps, bo, data[pclnOff:], data[funcnameOff:], false) {
			return nil, false
		}

		p.nfunc = nfunc
		p.nfiles = nfiles
		p.funcnameOffset = funcnameOff
		p.cuOffset = cuOff
		p.filetabOffset = filetabOff
		p.pctabOffset = pctabOff
		p.pclnOffset = pclnOff
		return p, true

	case MagicGo12:
		hdrLen := 8 + ps
		if uint64(len(data)) < hdrLen {
			return nil, false
		}
		nfunc, _ := wordAt(0)
		if nfunc == 0 || nfunc > maxPCLnTabFuncs {
			return nil, false
		}
		uLen := uint64(len(data))
		ftabBytes := (nfunc*2 + 1) * ps
		if hdrLen+ftabBytes+4 > uLen {
			return nil, false
		}
		fileOff := uint64(bo.Uint32(data[hdrLen+ftabBytes : hdrLen+ftabBytes+4]))
		if fileOff < hdrLen || fileOff+4 > uLen {
			return nil, false
		}
		nfiles := uint64(bo.Uint32(data[fileOff : fileOff+4]))
		if nfiles > maxPCLnTabFiles || fileOff+nfiles*4 > uLen {
			return nil, false
		}
		if !validateLegacyFTab(data[hdrLen:], nfunc, ps, bo, data, data, true) {
			return nil, false
		}

		p.nfunc = nfunc
		p.nfiles = nfiles
		p.filetabOffset = fileOff
		p.pclnOffset = hdrLen
		return p, true
	}

	return nil, false
}

func validateLegacyFTab(ftab []byte, nfunc, ps uint64, bo binary.ByteOrder, funcBase, nameBase []byte, isGo12 bool) bool {
	checkN := nfunc
	if checkN > 16 {
		checkN = 16
	}
	stride := 2 * ps
	validNames := 0
	for i := uint64(0); i < checkN; i++ {
		off := i * stride
		if off+stride+ps > uint64(len(ftab)) {
			return false
		}
		e0 := readUintPtr(ftab[off:], int(ps), bo)
		fOff := readUintPtr(ftab[off+ps:], int(ps), bo)
		e1 := readUintPtr(ftab[off+stride:], int(ps), bo)
		if e0 > e1 {
			return false
		}
		if fOff+ps+4 > uint64(len(funcBase)) {
			return false
		}
		fnEntry := readUintPtr(funcBase[fOff:], int(ps), bo)
		if fnEntry != e0 {
			return false
		}
		nameOff := int32(bo.Uint32(funcBase[fOff+ps : fOff+ps+4]))
		if nameOff > 0 && uint64(nameOff) < uint64(len(nameBase)) {
			if name, ok := readCStringSlice(nameBase, uint64(nameOff), 1024); ok && looksLikeGoSymbol(name) {
				validNames++
			}
		} else if isGo12 && nameOff == 0 {
			continue
		}
	}
	return validNames > 0
}

// resolveTextStartFallback determines the code base address when moduledata is absent or unrelocated.
func resolveTextStartFallback(lb *loader.LoadedBinary, pcln *parsedPCLnTab) uint64 {
	if pcln != nil && pcln.hdrTextStart != 0 && lb.IsCodeVA(pcln.hdrTextStart) {
		return pcln.hdrTextStart
	}
	if sec, _, ok := lb.SectionByName(".text", "__TEXT.__text", "__text"); ok && sec.VirtualAddr != 0 {
		return sec.VirtualAddr
	}
	for i := range lb.Sections {
		if lb.Sections[i].Executable && lb.Sections[i].VirtualAddr != 0 {
			return lb.Sections[i].VirtualAddr
		}
	}
	if pcln != nil && pcln.hdrTextStart != 0 {
		return pcln.hdrTextStart
	}
	return lb.Info.EntryPoint
}

// recoverFunctions decodes all function entries, sizes, source files, lines, and categories from pclntab.
func recoverFunctions(
	lb *loader.LoadedBinary,
	pcln *parsedPCLnTab,
	md *parsedModuleData,
	meta *model.GoMetadata,
) []model.Function {
	if pcln == nil {
		return nil
	}
	switch pcln.magic {
	case MagicGo118, MagicGo120:
		return recoverFunctionsGo118Plus(pcln, md, meta)
	case MagicGo12, MagicGo116:
		return recoverFunctionsLegacyGosym(lb, pcln, meta)
	default:
		return nil
	}
}

func recoverFunctionsGo118Plus(
	pcln *parsedPCLnTab,
	md *parsedModuleData,
	meta *model.GoMetadata,
) []model.Function {
	data := pcln.data
	bo := pcln.order
	uLen := uint64(len(data))

	funcnametab := data[pcln.funcnameOffset:]
	var cutab, filetab, pctab []byte
	if pcln.cuOffset < uLen {
		cutab = data[pcln.cuOffset:]
	}
	if pcln.filetabOffset < uLen {
		filetab = data[pcln.filetabOffset:]
	}
	if pcln.pctabOffset < uLen {
		pctab = data[pcln.pctabOffset:]
	}
	pclntab := data[pcln.pclnOffset:]

	textStart := meta.TextStart
	funcs := make([]model.Function, 0, pcln.nfunc)

	for i := uint64(0); i < pcln.nfunc; i++ {
		ftOff := i * 8
		if ftOff+12 > uint64(len(pclntab)) {
			break
		}
		entryOff := bo.Uint32(pclntab[ftOff : ftOff+4])
		funcOff := bo.Uint32(pclntab[ftOff+4 : ftOff+8])
		nextEntryOff := bo.Uint32(pclntab[ftOff+8 : ftOff+12])

		if uint64(funcOff)+36 > uint64(len(pclntab)) {
			continue
		}
		fRec := pclntab[funcOff:]

		// _func layout (Go 1.18 - 1.27+):
		// [0:4]   entryOff uint32
		// [4:8]   nameOff  int32
		// [8:12]  args     int32
		// [12:16] deferreturn uint32
		// [16:20] pcsp     uint32
		// [20:24] pcfile   uint32
		// [24:28] pcln     uint32
		// [28:32] npcdata  uint32
		// [32:36] cuOffset uint32
		// [36:40] startLine int32 (Go 1.20+)
		nameOff := int32(bo.Uint32(fRec[4:8]))
		pcfile := bo.Uint32(fRec[20:24])
		pclnOff := bo.Uint32(fRec[24:28])
		cuOffset := bo.Uint32(fRec[32:36])

		var startLine int32
		if pcln.magic == MagicGo120 && uint64(funcOff)+40 <= uint64(len(pclntab)) {
			startLine = int32(bo.Uint32(fRec[36:40]))
		}

		if nameOff < 0 || uint64(nameOff) >= uint64(len(funcnametab)) {
			continue
		}
		name, ok := readCStringSlice(funcnametab, uint64(nameOff), 4096)
		if !ok || name == "" {
			continue
		}

		entryVA := resolveTextOffVA(textStart, entryOff, md)
		endVA := resolveTextOffVA(textStart, nextEntryOff, md)
		var size uint64
		if endVA >= entryVA {
			size = endVA - entryVA
		}

		var srcFile string
		if fileIdx, ok := decodePCValueAtEntry(pctab, pcfile, pcln.minLC); ok && fileIdx >= 0 {
			cuByteOff := (uint64(cuOffset) + uint64(fileIdx)) * 4
			if cuByteOff+4 <= uint64(len(cutab)) {
				fileByteOff := bo.Uint32(cutab[cuByteOff : cuByteOff+4])
				if fileByteOff != ^uint32(0) && uint64(fileByteOff) < uint64(len(filetab)) {
					if fStr, ok := readCStringSlice(filetab, uint64(fileByteOff), 4096); ok {
						srcFile = fStr
					}
				}
			}
		}

		var lineNum int
		if ln, ok := decodePCValueAtEntry(pctab, pclnOff, pcln.minLC); ok && ln > 0 {
			lineNum = int(ln)
		} else if startLine > 0 {
			lineNum = int(startLine)
		}

		pkg, recv, _ := parseGoSymbol(name)
		cat := classifyGoPackage(pkg, name, meta.MainModule)

		funcs = append(funcs, model.Function{
			Name:          name,
			Package:       pkg,
			Receiver:      recv,
			SourceFile:    srcFile,
			Line:          lineNum,
			Entry:         entryVA,
			End:           endVA,
			Size:          size,
			Category:      cat,
			RecoveredFrom: "gopclntab",
		})
	}

	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].Entry < funcs[j].Entry
	})
	return funcs
}

func recoverFunctionsLegacyGosym(
	_ *loader.LoadedBinary,
	pcln *parsedPCLnTab,
	meta *model.GoMetadata,
) (funcs []model.Function) {
	defer func() {
		if r := recover(); r != nil {
			funcs = nil
		}
	}()

	lt := gosym.NewLineTable(pcln.data, meta.TextStart)
	tbl, err := gosym.NewTable(nil, lt)
	if err != nil || tbl == nil || len(tbl.Funcs) == 0 {
		return nil
	}

	funcs = make([]model.Function, 0, len(tbl.Funcs))
	for i := range tbl.Funcs {
		gf := &tbl.Funcs[i]
		if gf.Name == "" {
			continue
		}
		var size uint64
		if gf.End >= gf.Entry {
			size = gf.End - gf.Entry
		}
		file, line, _ := tbl.PCToLine(gf.Entry)
		if file == "?" {
			file = ""
		}
		if line < 0 {
			line = 0
		}

		pkg, recv, _ := parseGoSymbol(gf.Name)
		cat := classifyGoPackage(pkg, gf.Name, meta.MainModule)

		funcs = append(funcs, model.Function{
			Name:          gf.Name,
			Package:       pkg,
			Receiver:      recv,
			SourceFile:    file,
			Line:          line,
			Entry:         gf.Entry,
			End:           gf.End,
			Size:          size,
			Category:      cat,
			RecoveredFrom: "gopclntab",
		})
	}

	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].Entry < funcs[j].Entry
	})
	return funcs
}

// decodePCValueAtEntry decodes a Go pctab zig-zag varint stream at PC delta 0 (function entry).
func decodePCValueAtEntry(pctab []byte, off uint32, minLC uint8) (int32, bool) {
	if off == 0 || uint64(off) >= uint64(len(pctab)) {
		return -1, false
	}
	p := pctab[off:]
	val := int32(-1)
	var relPC uint64
	first := true

	for steps := 0; steps < 64 && len(p) > 0; steps++ {
		uvdelta, n1, ok := readPCVarint(p)
		if !ok {
			return -1, false
		}
		if uvdelta == 0 && !first {
			return -1, false
		}
		p = p[n1:]
		sdelta := int32(-(uvdelta & 1) ^ (uvdelta >> 1))
		val += sdelta

		pcdelta, n2, ok := readPCVarint(p)
		if !ok {
			return -1, false
		}
		p = p[n2:]
		relPC += uint64(pcdelta) * uint64(minLC)
		if relPC > 0 {
			return val, true
		}
		first = false
	}
	return -1, false
}

func readPCVarint(p []byte) (val uint32, read int, ok bool) {
	var v uint32
	var shift uint
	for i := 0; i < 5 && i < len(p); i++ {
		b := p[i]
		v |= uint32(b&0x7f) << shift
		if (b & 0x80) == 0 {
			return v, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

func resolveTextOffVA(textStart uint64, entryOff uint32, md *parsedModuleData) uint64 {
	off := uint64(entryOff)
	if md != nil && len(md.textsects) > 1 {
		for idx, ts := range md.textsects {
			if (off >= ts.vaddr && off < ts.end) || (idx == len(md.textsects)-1 && off == ts.end) {
				return ts.baseaddr + (off - ts.vaddr)
			}
		}
	}
	return textStart + off
}

// parseGoSymbol splits a Go linker symbol name into (Package, Receiver, ShortName).
func parseGoSymbol(sym string) (pkg, receiver, shortName string) {
	if sym == "" {
		return "", "", ""
	}
	if strings.HasPrefix(sym, "type:") || strings.HasPrefix(sym, "go:") {
		return "runtime", "", sym
	}

	// Stop scanning for package path slashes before any '(' or '[' (e.g. generic type parameters).
	scanStop := len(sym)
	for i := 0; i < len(sym); i++ {
		if sym[i] == '(' || sym[i] == '[' {
			scanStop = i
			break
		}
	}

	lastSlash := strings.LastIndexByte(sym[:scanStop], '/')
	searchStart := 0
	if lastSlash >= 0 {
		searchStart = lastSlash + 1
	}

	relDot := strings.IndexByte(sym[searchStart:scanStop], '.')
	if relDot < 0 {
		// Bare assembly or runtime symbol without package dot (e.g. _rt0_amd64_linux).
		return "runtime", "", sym
	}

	pkgEnd := searchStart + relDot
	// Handle versioned package suffixes like gopkg.in/yaml.v3.Unmarshal.
	afterDot := sym[pkgEnd+1 : scanStop]
	if nextDot := strings.IndexByte(afterDot, '.'); nextDot > 1 && afterDot[0] == 'v' && isAllDigits(afterDot[1:nextDot]) {
		pkgEnd += 1 + nextDot
	}

	pkg = sym[:pkgEnd]
	rest := sym[pkgEnd+1:]
	if rest == "" {
		return pkg, "", sym
	}

	// Pointer or parenthesized receiver: (*Server).Serve or (*Cache[int]).Get
	if rest[0] == '(' {
		depth := 0
		closeIdx := -1
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					closeIdx = i
				}
			}
			if closeIdx >= 0 {
				break
			}
		}
		if closeIdx > 1 && closeIdx+1 < len(rest) && rest[closeIdx+1] == '.' {
			return pkg, rest[1:closeIdx], rest[closeIdx+2:]
		}
	}

	// Check for value-receiver method (e.g. Worker.Run or Box[int].Get) vs compiler closure suffix.
	dotIdx := indexDotOutsideBrackets(rest)
	if dotIdx > 0 {
		head := rest[:dotIdx]
		tail := rest[dotIdx+1:]
		if head != "init" && head != "glob" && tail != "" && !startsWithCompilerSuffix(tail) {
			return pkg, head, tail
		}
	}

	return pkg, "", rest
}

func indexDotOutsideBrackets(s string) int {
	brack := 0
	paren := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			brack++
		case ']':
			if brack > 0 {
				brack--
			}
		case '(':
			paren++
		case ')':
			if paren > 0 {
				paren--
			}
		case '.':
			if brack == 0 && paren == 0 {
				return i
			}
		}
	}
	return -1
}

func startsWithCompilerSuffix(tail string) bool {
	seg := tail
	if d := strings.IndexByte(tail, '.'); d >= 0 {
		seg = tail[:d]
	}
	if seg == "" || isAllDigits(seg) {
		return true
	}
	switch seg {
	case "abi0", "abiinternal", "stkobj", "arginfo0", "arginfo1", "argliveinfo", "wrapnilchk":
		return true
	}
	for _, pfx := range []string{"func", "deferwrap", "gowrap", "init"} {
		if strings.HasPrefix(seg, pfx) && isAllDigits(seg[len(pfx):]) {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// classifyGoPackage classifies a Go package/symbol into runtime, user, dependency, or stdlib.
func classifyGoPackage(pkg, fullSym, mainModule string) model.PackageCategory {
	if strings.HasPrefix(fullSym, "type:") || strings.HasPrefix(fullSym, "go:") {
		return model.CategoryRuntime
	}
	if pkg == "" ||
		pkg == "runtime" ||
		strings.HasPrefix(pkg, "runtime/") ||
		pkg == "internal/abi" ||
		pkg == "internal/cpu" ||
		pkg == "internal/bytealg" ||
		pkg == "internal/runtime" ||
		strings.HasPrefix(pkg, "internal/runtime/") {
		return model.CategoryRuntime
	}

	if pkg == "main" || pkg == "command-line-arguments" {
		return model.CategoryUser
	}
	if mainModule != "" && (pkg == mainModule || strings.HasPrefix(pkg, mainModule+"/")) {
		return model.CategoryUser
	}

	firstSeg := pkg
	if slash := strings.IndexByte(pkg, '/'); slash >= 0 {
		firstSeg = pkg[:slash]
	}
	if strings.ContainsRune(firstSeg, '.') {
		return model.CategoryDependency
	}

	return model.CategoryStdlib
}

func readCStringSlice(buf []byte, off uint64, maxLen int) (string, bool) {
	if off >= uint64(len(buf)) || maxLen <= 0 {
		return "", false
	}
	end := off + uint64(maxLen)
	if end > uint64(len(buf)) {
		end = uint64(len(buf))
	}
	sub := buf[off:end]
	nul := bytes.IndexByte(sub, 0)
	if nul < 0 {
		return "", false
	}
	s := string(sub[:nul])
	if !utf8.ValidString(s) {
		return "", false
	}
	return s, true
}

func looksLikeGoSymbol(s string) bool {
	if len(s) == 0 || len(s) > 2048 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}
