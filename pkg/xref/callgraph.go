package xref

import (
	"sort"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

const (
	maxFuncScanBytes     = 256 * 1024
	defaultUnknownFnSpan = 4096
)

type rawCallEdge struct {
	callerIdx int
	targetVA  uint64
}

type rawDataRef struct {
	callerIdx int
	insnVA    uint64
	targetVA  uint64
}

type strRange struct {
	start         uint64
	end           uint64
	strIdx        int
	allowInterior bool
}

// stringIndex supports O(1) exact VA lookups and O(log N) interior containment lookups.
type stringIndex struct {
	byAddr map[uint64]int
	ranges []strRange
}

func buildStringIndex(strs []model.ExtractedString, entries []extractedEntry) *stringIndex {
	idx := &stringIndex{
		byAddr: make(map[uint64]int, len(strs)),
		ranges: make([]strRange, 0, len(strs)),
	}
	for i := range strs {
		addr := strs[i].Addr
		idx.byAddr[addr] = i
		span := entries[i].rawByteSpan
		if span == 0 {
			span = uint64(strs[i].Length)
		}
		if span > 0 {
			idx.ranges = append(idx.ranges, strRange{
				start:         addr,
				end:           addr + span,
				strIdx:        i,
				allowInterior: entries[i].allowInterior,
			})
		}
	}
	return idx
}

// lookup resolves targetVA to a string index via exact Addr match first, then interior containment
// within null-terminated or wide strings.
func (idx *stringIndex) lookup(targetVA uint64) (int, bool) {
	if idx == nil {
		return -1, false
	}
	if i, ok := idx.byAddr[targetVA]; ok {
		return i, true
	}
	// Binary search last range whose start <= targetVA.
	pos := sort.Search(len(idx.ranges), func(i int) bool {
		return idx.ranges[i].start > targetVA
	}) - 1
	if pos >= 0 {
		r := idx.ranges[pos]
		if r.allowInterior && targetVA >= r.start && targetVA < r.end {
			return r.strIdx, true
		}
	}
	return -1, false
}

// analyzer coordinates function scanning, dynamic Go string slicing, and XREF linking.
type analyzer struct {
	lb          *loader.LoadedBinary
	funcs       []model.Function
	funcSizes   []uint64
	entryMap    map[uint64]int
	strExt      *stringExtractor
	crypto      []cryptoEntry
	callEdges   []rawCallEdge
	dataRefs    []rawDataRef
	refAddrHint map[uint64]struct{}
	x86Scratch  []x86Step
	armScratch  []arm64Step
}

func newAnalyzer(lb *loader.LoadedBinary, inFuncs []model.Function, opts Options) *analyzer {
	funcs := make([]model.Function, len(inFuncs))
	entryMap := make(map[uint64]int, len(inFuncs))
	for i := range inFuncs {
		fn := inFuncs[i]
		fn.Calls = cloneUint64Slice(fn.Calls)
		fn.CalledBy = cloneUint64Slice(fn.CalledBy)
		if len(fn.StringRefs) > 0 {
			cp := make([]model.StringRef, len(fn.StringRefs))
			copy(cp, fn.StringRefs)
			fn.StringRefs = cp
		} else {
			fn.StringRefs = nil
		}
		if len(fn.CryptoRefs) > 0 {
			cp := make([]string, len(fn.CryptoRefs))
			copy(cp, fn.CryptoRefs)
			fn.CryptoRefs = cp
		} else {
			fn.CryptoRefs = nil
		}
		funcs[i] = fn
		if fn.Entry != 0 {
			if _, exists := entryMap[fn.Entry]; !exists {
				entryMap[fn.Entry] = i
			}
		}
	}

	funcSizes := computeEffectiveFuncSizes(lb, funcs)
	strExt := newStringExtractor(lb, opts.MinStringLen)
	crypto := detectCryptoConstants(lb)

	return &analyzer{
		lb:          lb,
		funcs:       funcs,
		funcSizes:   funcSizes,
		entryMap:    entryMap,
		strExt:      strExt,
		crypto:      crypto,
		refAddrHint: make(map[uint64]struct{}, 512),
	}
}

// computeEffectiveFuncSizes resolves bounded disassembly spans for every function,
// inferring gaps from the next sorted function entry when Size and End are zero.
func computeEffectiveFuncSizes(lb *loader.LoadedBinary, funcs []model.Function) []uint64 {
	sizes := make([]uint64, len(funcs))
	if len(funcs) == 0 {
		return sizes
	}

	type idxEntry struct {
		idx   int
		entry uint64
	}
	order := make([]idxEntry, len(funcs))
	for i := range funcs {
		order[i] = idxEntry{idx: i, entry: funcs[i].Entry}
	}
	sort.Slice(order, func(i, j int) bool {
		return order[i].entry < order[j].entry
	})

	for k, item := range order {
		fn := &funcs[item.idx]
		sz := fn.Size
		if sz == 0 && fn.End > fn.Entry {
			sz = fn.End - fn.Entry
		}
		if sz == 0 {
			// Infer from next function in the same executable section if available.
			if k+1 < len(order) && order[k+1].entry > fn.Entry {
				secA := lb.SectionContainingVA(fn.Entry)
				secB := lb.SectionContainingVA(order[k+1].entry)
				if secA != nil && secA == secB {
					sz = order[k+1].entry - fn.Entry
				}
			}
			if sz == 0 {
				sz = defaultUnknownFnSpan
			}
			if sz > 16*1024 {
				sz = 16 * 1024
			}
		}
		if sz > maxFuncScanBytes {
			sz = maxFuncScanBytes
		}
		sizes[item.idx] = sz
	}
	return sizes
}

func (a *analyzer) functionCodeSlice(fnEntry uint64, maxSpan uint64) []byte {
	if fnEntry == 0 || maxSpan == 0 {
		return nil
	}
	if maxSpan > maxFuncScanBytes {
		maxSpan = maxFuncScanBytes
	}
	sec := a.lb.SectionContainingVA(fnEntry)
	if sec != nil && sec.FileSize > 0 && fnEntry >= sec.VirtualAddr {
		secEnd := sec.VirtualAddr + sec.FileSize
		if fnEntry >= secEnd {
			return nil
		}
		avail := secEnd - fnEntry
		if maxSpan > avail {
			maxSpan = avail
		}
	}
	code, ok := a.lb.ReadAtVA(fnEntry, int(maxSpan))
	if !ok {
		return nil
	}
	return code
}

func (a *analyzer) recordCall(callerIdx int, targetVA uint64) {
	if _, ok := a.entryMap[targetVA]; ok {
		a.callEdges = append(a.callEdges, rawCallEdge{
			callerIdx: callerIdx,
			targetVA:  targetVA,
		})
	}
}

func (a *analyzer) recordDataRef(callerIdx int, insnVA uint64, targetVA uint64) {
	if targetVA == 0 {
		return
	}
	a.dataRefs = append(a.dataRefs, rawDataRef{
		callerIdx: callerIdx,
		insnVA:    insnVA,
		targetVA:  targetVA,
	})
	a.refAddrHint[targetVA] = struct{}{}

	// Also resolve indirect static Go string headers or GOT pointers stored in read-only data
	// when targetVA itself is not already a sliced string or crypto constant.
	if _, hasDirect := a.strExt.exactSlices[targetVA]; !hasDirect {
		ptrSize := a.lb.Info.PointerSize
		if (ptrSize == 8 || ptrSize == 4) && a.lb.Order != nil {
			if raw, sec, ok := a.strExt.sliceAtVA(targetVA, ptrSize*2); ok && sec.readOnly && len(raw) >= ptrSize*2 {
				var indPtr, indLen uint64
				if ptrSize == 8 {
					indPtr = a.lb.Order.Uint64(raw[:8])
					indLen = a.lb.Order.Uint64(raw[8:16])
				} else {
					indPtr = uint64(a.lb.Order.Uint32(raw[:4]))
					indLen = uint64(a.lb.Order.Uint32(raw[4:8]))
				}
				if indLen >= 4 && indLen <= maxGoHeaderStrLen {
					if _, known := a.strExt.exactSlices[indPtr]; known {
						a.dataRefs = append(a.dataRefs, rawDataRef{
							callerIdx: callerIdx,
							insnVA:    insnVA,
							targetVA:  indPtr,
						})
						a.refAddrHint[indPtr] = struct{}{}
					}
				}
			}
		}
	}
}

func (a *analyzer) run(opts Options) *Result {
	// 1. Static Go/Rust (ptr, len) string header splitting across read-only sections.
	a.strExt.scanStaticGoStringHeaders()

	// 2. Single-pass function disassembly across architecture to collect call edges,
	// data XREFs, and instruction-level Go (LEA/ADRP+ADD, MOV imm) string slices.
	arch := a.lb.Info.Arch
	for i := range a.funcs {
		fn := &a.funcs[i]
		code := a.functionCodeSlice(fn.Entry, a.funcSizes[i])
		if len(code) == 0 {
			continue
		}
		switch arch {
		case model.ArchX86_64:
			a.scanX86Function(i, fn.Entry, code, 64)
		case model.ArchX86:
			a.scanX86Function(i, fn.Entry, code, 32)
		case model.ArchARM64:
			a.scanARM64Function(i, fn.Entry, code)
		}
	}

	// 3. Finalize extracted & classified strings with all static + instruction-discovered split points.
	stringsOut, strIdx := a.strExt.finalize(opts.MaxStrings, a.refAddrHint)

	// 4. Link Calls & CalledBy (deduplicated per function).
	callSeen := make(map[[2]uint64]struct{}, len(a.callEdges))
	for _, edge := range a.callEdges {
		calleeIdx, ok := a.entryMap[edge.targetVA]
		if !ok {
			continue
		}
		callerEntry := a.funcs[edge.callerIdx].Entry
		pair := [2]uint64{callerEntry, edge.targetVA}
		if _, dup := callSeen[pair]; dup {
			continue
		}
		callSeen[pair] = struct{}{}
		a.funcs[edge.callerIdx].Calls = appendUniqueUint64(a.funcs[edge.callerIdx].Calls, edge.targetVA)
		a.funcs[calleeIdx].CalledBy = appendUniqueUint64(a.funcs[calleeIdx].CalledBy, callerEntry)
	}

	// 5. Link StringRefs & CryptoRefs (deduplicated per function and per target).
	type fnStrKey struct {
		fnIdx  int
		strIdx int
	}
	seenFnStr := make(map[fnStrKey]struct{}, len(a.dataRefs))

	for _, ref := range a.dataRefs {
		callerEntry := a.funcs[ref.callerIdx].Entry

		// Link StringRef
		if sIdx, ok := strIdx.lookup(ref.targetVA); ok {
			key := fnStrKey{fnIdx: ref.callerIdx, strIdx: sIdx}
			if _, dup := seenFnStr[key]; !dup {
				seenFnStr[key] = struct{}{}
				s := &stringsOut[sIdx]
				a.funcs[ref.callerIdx].StringRefs = append(a.funcs[ref.callerIdx].StringRefs, model.StringRef{
					Addr:     s.Addr,
					InsnAddr: ref.insnVA,
					Value:    s.Value,
					Kind:     s.Kind,
				})
				s.ReferencedBy = appendUniqueUint64(s.ReferencedBy, callerEntry)
			}
		}

		// Link CryptoRefs: match within [c.Addr, c.Addr + span) (or [c.Addr, c.Addr+256) when no unrelated string sits at targetVA).
		for cIdx := range a.crypto {
			ce := &a.crypto[cIdx]
			limit := ce.span
			if limit < 256 {
				// Allow up to 256-byte window only when targetVA does not collide with an unrelated string literal.
				if sIdx, isStr := strIdx.lookup(ref.targetVA); !isStr || stringsOut[sIdx].Addr == ce.det.Addr {
					limit = 256
				}
			}
			if ref.targetVA >= ce.det.Addr && ref.targetVA < ce.det.Addr+limit {
				a.funcs[ref.callerIdx].CryptoRefs = appendUniqueString(a.funcs[ref.callerIdx].CryptoRefs, ce.det.Name)
				ce.det.ReferencedBy = appendUniqueUint64(ce.det.ReferencedBy, callerEntry)
			}
		}
	}

	cryptoOut := make([]model.CryptoDetection, len(a.crypto))
	for i := range a.crypto {
		cryptoOut[i] = a.crypto[i].det
	}

	return &Result{
		Functions: a.funcs,
		Strings:   stringsOut,
		Crypto:    cryptoOut,
	}
}

func cloneUint64Slice(in []uint64) []uint64 {
	if len(in) == 0 {
		return nil
	}
	cp := make([]uint64, len(in))
	copy(cp, in)
	return cp
}

func appendUniqueUint64(slice []uint64, val uint64) []uint64 {
	for _, existing := range slice {
		if existing == val {
			return slice
		}
	}
	return append(slice, val)
}

func appendUniqueString(slice []string, val string) []string {
	for _, existing := range slice {
		if existing == val {
			return slice
		}
	}
	return append(slice, val)
}
