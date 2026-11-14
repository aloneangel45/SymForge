package gorecover

import (
	"encoding/binary"
	"strings"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

type textSectEntry struct {
	vaddr    uint64
	end      uint64
	baseaddr uint64
}

type parsedModuleData struct {
	va             uint64
	minpc          uint64
	maxpc          uint64
	text           uint64
	etext          uint64
	types          uint64
	etypes         uint64
	typedesclen    uint64
	itaboffset     uint64
	itabsize       uint64
	typelinksVA    uint64
	typelinksCount uint64
	itablinksVA    uint64
	itablinksCount uint64
	rodata         uint64
	gofunc         uint64
	textsects      []textSectEntry
}

var candidateModuleDataSections = []string{
	".noptrdata",
	"__DATA.__noptrdata",
	".data",
	"__DATA.__data",
	".data.rel.ro",
	"__DATA_CONST.__const",
	".rdata",
}

// locateModuleData scans data sections for Go's firstmoduledata structure anchored at pcln.va.
func locateModuleData(lb *loader.LoadedBinary, pcln *parsedPCLnTab) *parsedModuleData {
	if lb == nil || pcln == nil || pcln.va == 0 {
		return nil
	}
	ps := int(pcln.ptrSize)
	if ps != 4 && ps != 8 {
		return nil
	}

	visited := make(map[int]bool, len(lb.Sections))
	for _, want := range candidateModuleDataSections {
		for idx := range lb.Sections {
			if visited[idx] {
				continue
			}
			sec := &lb.Sections[idx]
			if !strings.EqualFold(sec.Name, want) {
				continue
			}
			visited[idx] = true
			if md := scanSectionForModuleData(lb, sec, pcln, ps); md != nil {
				return md
			}
		}
	}

	// Fallback: scan remaining non-executable readable sections (e.g. PT_LOAD segments in sstrip binaries).
	for idx := range lb.Sections {
		if visited[idx] {
			continue
		}
		sec := &lb.Sections[idx]
		if sec.FileSize == 0 {
			continue
		}
		if md := scanSectionForModuleData(lb, sec, pcln, ps); md != nil {
			return md
		}
	}
	return nil
}

func scanSectionForModuleData(
	lb *loader.LoadedBinary,
	sec *model.SectionInfo,
	pcln *parsedPCLnTab,
	ps int,
) *parsedModuleData {
	secBytes, ok := lb.SectionBytes(sec)
	if !ok || len(secBytes) < 26*ps {
		return nil
	}
	bo := pcln.order

	// Align scan step to pointer size (with 4-byte step fallback if section start was unaligned).
	step := ps
	if step > 4 {
		step = 4
	}

	for off := 0; off+26*ps <= len(secBytes); off += step {
		w0 := normalizePointer(lb, readUintPtr(secBytes[off:], ps, bo))
		if w0 != pcln.va {
			continue
		}
		candVA := sec.VirtualAddr + uint64(off)
		switch pcln.magic {
		case MagicGo118, MagicGo120, MagicGo116:
			if md := tryParseModernModuleData(lb, secBytes[off:], candVA, pcln, ps, bo); md != nil {
				return md
			}
		case MagicGo12:
			if md := tryParseGo12ModuleData(lb, secBytes[off:], candVA, pcln, ps, bo); md != nil {
				return md
			}
		}
	}
	return nil
}

func tryParseModernModuleData(
	lb *loader.LoadedBinary,
	buf []byte,
	mdVA uint64,
	pcln *parsedPCLnTab,
	ps int,
	bo binary.ByteOrder,
) *parsedModuleData {
	if len(buf) < 40*ps {
		return nil
	}

	rawWord := func(idx int) uint64 {
		pos := idx * ps
		if pos+ps > len(buf) {
			return 0
		}
		return readUintPtr(buf[pos:], ps, bo)
	}
	ptrWord := func(idx int) uint64 {
		return normalizePointer(lb, rawWord(idx))
	}

	// Verify slice headers matching pcHeader offsets:
	// w1..3:  funcnametab (ptr == pcln.va + funcnameOffset)
	// w7..9:  filetab     (ptr == pcln.va + filetabOffset)
	// w13..15: pclntable  (ptr == pcln.va + pclnOffset)
	// w16..18: ftab       (ptr == pcln.va + pclnOffset, len == nfunc + 1)
	if ptrWord(1) != pcln.va+pcln.funcnameOffset {
		return nil
	}
	if rawWord(2) == 0 || rawWord(2) > rawWord(3) {
		return nil
	}
	if pcln.filetabOffset > 0 && ptrWord(7) != pcln.va+pcln.filetabOffset {
		return nil
	}
	if ptrWord(13) != pcln.va+pcln.pclnOffset {
		return nil
	}
	if ptrWord(16) != pcln.va+pcln.pclnOffset {
		return nil
	}
	ftabLen := rawWord(17)
	if ftabLen != pcln.nfunc+1 && ftabLen != pcln.nfunc {
		return nil
	}

	minpc := ptrWord(20)
	maxpc := ptrWord(21)
	text := ptrWord(22)
	etext := ptrWord(23)
	if text == 0 || etext < text || (!lb.IsCodeVA(text) && !lb.IsCodeVA(minpc)) {
		return nil
	}

	md := &parsedModuleData{
		va:    mdVA,
		minpc: minpc,
		maxpc: maxpc,
		text:  text,
		etext: etext,
	}

	// Identify Go version-specific layout of types/etypes/typelinks:
	// Layout A (Go 1.27+):
	//   w37 = types, w38 = typedesclen (size <= etypes-types), w39 = etypes,
	//   w40 = itaboffset, w41 = itabsize, w42 = rodata, w43 = gofunc, w45..47 = textsectmap
	tA := ptrWord(37)
	descLenA := rawWord(38)
	etA := ptrWord(39)
	if validTypesRange(lb, tA, etA) && descLenA <= (etA-tA) {
		md.types = tA
		md.typedesclen = descLenA
		md.etypes = etA
		md.itaboffset = rawWord(40)
		md.itabsize = rawWord(41)
		md.rodata = ptrWord(42)
		md.gofunc = ptrWord(43)
		md.textsects = parseTextSectSlice(lb, ptrWord(45), rawWord(46), ps, bo)
		return md
	}

	// Layout B (Go 1.20 - 1.26):
	//   w37 = types, w38 = etypes, w39 = rodata, w40 = gofunc,
	//   w41..43 = textsectmap, w44..46 = typelinks, w47..49 = itablinks
	tB := ptrWord(37)
	etB := ptrWord(38)
	if validTypesRange(lb, tB, etB) {
		md.types = tB
		md.etypes = etB
		md.rodata = ptrWord(39)
		md.gofunc = ptrWord(40)
		md.textsects = parseTextSectSlice(lb, ptrWord(41), rawWord(42), ps, bo)
		populateLegacyTypeAndItabLinks(lb, md, ptrWord(44), rawWord(45), rawWord(46), ptrWord(47), rawWord(48), rawWord(49), ps)
		return md
	}

	// Layout C (Go 1.16 - 1.19, before covctrs/ecovctrs):
	//   w35 = types, w36 = etypes
	tC := ptrWord(35)
	etC := ptrWord(36)
	if validTypesRange(lb, tC, etC) {
		md.types = tC
		md.etypes = etC
		if pcln.magic == MagicGo118 {
			// Go 1.18 - 1.19 has rodata (w37), gofunc (w38), textsectmap (w39..41), typelinks (w42..44), itablinks (w45..47)
			md.rodata = ptrWord(37)
			md.gofunc = ptrWord(38)
			md.textsects = parseTextSectSlice(lb, ptrWord(39), rawWord(40), ps, bo)
			populateLegacyTypeAndItabLinks(lb, md, ptrWord(42), rawWord(43), rawWord(44), ptrWord(45), rawWord(46), rawWord(47), ps)
		} else {
			// Go 1.16 - 1.17: textsectmap (w37..39), typelinks (w40..42), itablinks (w43..45)
			md.textsects = parseTextSectSlice(lb, ptrWord(37), rawWord(38), ps, bo)
			populateLegacyTypeAndItabLinks(lb, md, ptrWord(40), rawWord(41), rawWord(42), ptrWord(43), rawWord(44), rawWord(45), ps)
		}
		return md
	}

	return md
}

func tryParseGo12ModuleData(
	lb *loader.LoadedBinary,
	buf []byte,
	mdVA uint64,
	pcln *parsedPCLnTab,
	ps int,
	bo binary.ByteOrder,
) *parsedModuleData {
	if len(buf) < 28*ps {
		return nil
	}
	rawWord := func(idx int) uint64 {
		pos := idx * ps
		if pos+ps > len(buf) {
			return 0
		}
		return readUintPtr(buf[pos:], ps, bo)
	}
	ptrWord := func(idx int) uint64 {
		return normalizePointer(lb, rawWord(idx))
	}

	// Go 1.2 - 1.15 moduledata:
	// w0..2: pclntable, w3..5: ftab (ptr == pcln.va + pclnOffset, len == nfunc+1),
	// w6..8: filetab, w9: findfunctab, w10: minpc, w11: maxpc, w12: text, w13: etext
	if ptrWord(3) != pcln.va+pcln.pclnOffset {
		return nil
	}
	if rawWord(4) != pcln.nfunc+1 && rawWord(4) != pcln.nfunc {
		return nil
	}
	minpc := ptrWord(10)
	maxpc := ptrWord(11)
	text := ptrWord(12)
	etext := ptrWord(13)
	if text == 0 || etext < text || (!lb.IsCodeVA(text) && !lb.IsCodeVA(minpc)) {
		return nil
	}
	return &parsedModuleData{
		va:    mdVA,
		minpc: minpc,
		maxpc: maxpc,
		text:  text,
		etext: etext,
	}
}

func validTypesRange(lb *loader.LoadedBinary, typesVA, etypesVA uint64) bool {
	if typesVA == 0 || etypesVA <= typesVA {
		return false
	}
	span := etypesVA - typesVA
	if span < 32 || span > uint64(len(lb.Raw())) {
		return false
	}
	return lb.IsReadableVA(typesVA) && lb.IsReadableVA(etypesVA-1)
}

func populateLegacyTypeAndItabLinks(
	lb *loader.LoadedBinary,
	md *parsedModuleData,
	tlPtr, tlLen, tlCap uint64,
	itPtr, itLen, itCap uint64,
	ps int,
) {
	if tlPtr != 0 && tlLen > 0 && tlLen <= tlCap && tlLen <= 500_000 {
		if _, ok := lb.ReadAtVA(tlPtr, int(minUint64(tlLen*4, 64))); ok {
			md.typelinksVA = tlPtr
			md.typelinksCount = tlLen
		}
	}
	if itPtr != 0 && itLen > 0 && itLen <= itCap && itLen <= 500_000 {
		if _, ok := lb.ReadAtVA(itPtr, int(minUint64(itLen*uint64(ps), 64))); ok {
			md.itablinksVA = itPtr
			md.itablinksCount = itLen
		}
	}
}

func parseTextSectSlice(
	lb *loader.LoadedBinary,
	slicePtr, sliceLen uint64,
	ps int,
	bo binary.ByteOrder,
) []textSectEntry {
	if slicePtr == 0 || sliceLen == 0 || sliceLen > 256 {
		return nil
	}
	entrySize := 3 * ps
	raw, ok := lb.ReadAtVA(slicePtr, int(sliceLen)*entrySize)
	if !ok {
		return nil
	}
	out := make([]textSectEntry, 0, sliceLen)
	for i := 0; i < int(sliceLen); i++ {
		base := i * entrySize
		vaddr := readUintPtr(raw[base:], ps, bo)
		end := readUintPtr(raw[base+ps:], ps, bo)
		baseaddr := normalizePointer(lb, readUintPtr(raw[base+2*ps:], ps, bo))
		if end < vaddr || baseaddr == 0 {
			return nil
		}
		out = append(out, textSectEntry{
			vaddr:    vaddr,
			end:      end,
			baseaddr: baseaddr,
		})
	}
	return out
}

// normalizePointer resolves pointers that may carry Apple Mach-O LC_DYLD_CHAINED_FIXUPS metadata.
func normalizePointer(lb *loader.LoadedBinary, ptr uint64) uint64 {
	if ptr == 0 || lb == nil {
		return 0
	}
	if lb.SectionContainingVA(ptr) != nil {
		return ptr
	}
	if (lb.Info.Format == model.FormatMachO || lb.Info.Format == model.FormatMachOFat) && lb.Info.PointerSize == 8 {
		// Chained rebase pointers have bit 63 == 0 (bind == 0) and 36-bit target or image-base offset.
		if (ptr >> 63) == 0 {
			low36 := ptr & 0xfffffffff
			candOffset := lb.Info.ImageBase + low36
			if lb.SectionContainingVA(candOffset) != nil {
				return candOffset
			}
			high8 := (ptr >> 36) & 0xff
			candTarget := (high8 << 56) | low36
			if lb.SectionContainingVA(candTarget) != nil {
				return candTarget
			}
		}
	}
	return ptr
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
