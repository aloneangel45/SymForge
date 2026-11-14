package gorecover

import (
	"encoding/binary"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

const (
	abiKindInvalid       uint8 = 0
	abiKindBool          uint8 = 1
	abiKindComplex128    uint8 = 16
	abiKindArray         uint8 = 17
	abiKindChan          uint8 = 18
	abiKindFunc          uint8 = 19
	abiKindInterface     uint8 = 20
	abiKindMap           uint8 = 21
	abiKindPointer       uint8 = 22
	abiKindSlice         uint8 = 23
	abiKindString        uint8 = 24
	abiKindStruct        uint8 = 25
	abiKindUnsafePointer uint8 = 26
	abiKindMask          uint8 = 0x1f

	tflagUncommon  uint8 = 1 << 0
	tflagExtraStar uint8 = 1 << 1
	tflagNamed     uint8 = 1 << 2

	maxStructFields     = 4096
	maxInterfaceMethods = 4096
	maxVisitedTypes     = 100_000
)

type rawABIType struct {
	va         uint64
	size       uint64
	ptrBytes   uint64
	hash       uint32
	tflag      uint8
	align      uint8
	fieldAlign uint8
	kind       uint8
	strOff     int32
	ptrToThis  int32
}

// recoverTypes walks Go runtime type descriptors (supporting both Go 1.27+ contiguous
// typedesc/itab regions and Go <=1.26 typelinks/itablinks) to recover named struct and interface types.
func recoverTypes(
	lb *loader.LoadedBinary,
	pcln *parsedPCLnTab,
	md *parsedModuleData,
	meta *model.GoMetadata,
) []model.RecoveredType {
	if lb == nil || pcln == nil || md == nil || md.types == 0 || md.etypes <= md.types {
		return nil
	}
	ps := int(pcln.ptrSize)
	if ps != 4 && ps != 8 {
		return nil
	}
	bo := pcln.order

	var queue []uint64
	enqueued := make(map[uint64]struct{}, 1024)
	enqueue := func(va uint64) {
		if va < md.types || va >= md.etypes || len(enqueued) >= maxVisitedTypes {
			return
		}
		if _, seen := enqueued[va]; seen {
			return
		}
		enqueued[va] = struct{}{}
		queue = append(queue, va)
	}

	// 1. Seed from legacy typelinks []int32 when present (Go <= 1.26).
	if md.typelinksVA != 0 && md.typelinksCount > 0 {
		cnt := int(minUint64(md.typelinksCount, maxVisitedTypes))
		if rawLinks, ok := lb.ReadAtVA(md.typelinksVA, cnt*4); ok {
			for i := 0; i < cnt; i++ {
				off := int32(bo.Uint32(rawLinks[i*4 : i*4+4]))
				if off > 0 {
					enqueue(md.types + uint64(off))
				}
			}
		}
	}

	// 2. Seed from Go 1.27+ contiguous type descriptor table [md.types + ps .. md.types + md.typedesclen).
	if md.typedesclen > 0 && md.types+md.typedesclen <= md.etypes {
		walkContiguousTypeDescs(lb, md, ps, bo, enqueue)
	}

	// 3. Seed from pre-compiled ITab tables (recovers interfaces only referenced via interface dispatch).
	seedFromITabs(lb, md, ps, bo, enqueue)

	// 4. Traverse reachable type graph (unwrapping *T, []T, struct fields, etc.) and collect named structs & interfaces.
	byName := make(map[string]model.RecoveredType)
	for head := 0; head < len(queue); head++ {
		tva := queue[head]
		hdr, ok := readABITypeHeader(lb, md, tva, ps, bo)
		if !ok {
			continue
		}

		// Follow child element types so *MyStruct / []MyStruct / FuncType args discover MyStruct & MyInterface.
		enqueueChildTypes(lb, md, hdr, ps, bo, enqueue)

		if hdr.kind != abiKindStruct && hdr.kind != abiKindInterface {
			continue
		}
		if (hdr.tflag & tflagNamed) == 0 {
			continue
		}

		rt, ok := decodeNamedStructOrInterface(lb, pcln, md, hdr, ps, bo, enqueue)
		if !ok {
			continue
		}

		// Filter out Go runtime/compiler synthetic types so recovered types stay clean and relevant.
		cat := classifyGoPackage(rt.Package, rt.Name, meta.MainModule)
		if cat == model.CategoryRuntime || isSyntheticRuntimeType(rt.Name) {
			continue
		}

		dedupKey := rt.Kind + ":" + rt.Package + ":" + rt.Name
		if existing, exists := byName[dedupKey]; !exists || len(rt.Fields)+len(rt.Methods) > len(existing.Fields)+len(existing.Methods) {
			byName[dedupKey] = rt
		}
	}

	if len(byName) == 0 {
		return nil
	}

	out := make([]model.RecoveredType, 0, len(byName))
	for _, rt := range byName {
		out = append(out, rt)
	}

	sort.Slice(out, func(i, j int) bool {
		ci := classifyGoPackage(out[i].Package, out[i].Name, meta.MainModule)
		cj := classifyGoPackage(out[j].Package, out[j].Name, meta.MainModule)
		pi, pj := categoryPriority(ci), categoryPriority(cj)
		if pi != pj {
			return pi < pj
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})

	return out
}

func walkContiguousTypeDescs(
	lb *loader.LoadedBinary,
	md *parsedModuleData,
	ps int,
	bo binary.ByteOrder,
	enqueue func(uint64),
) {
	uPS := uint64(ps)
	td := md.types + uPS
	end := md.types + md.typedesclen
	if end > md.etypes {
		end = md.etypes
	}

	for td < end {
		td = (td + uPS - 1) &^ (uPS - 1)
		if td >= end {
			break
		}
		hdr, ok := readABITypeHeader(lb, md, td, ps, bo)
		if !ok {
			td += uPS
			continue
		}
		enqueue(td)
		step, ok := computeDescriptorSize(lb, hdr, ps, bo)
		if !ok || step < uint64(4*ps+16) {
			td += uPS
			continue
		}
		td += step
	}
}

func computeDescriptorSize(
	lb *loader.LoadedBinary,
	hdr rawABIType,
	ps int,
	bo binary.ByteOrder,
) (uint64, bool) {
	baseTypeSz := uint64(4*ps + 16)
	var baseSz, addSz uint64

	switch hdr.kind {
	case abiKindBool, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, abiKindComplex128,
		abiKindString, abiKindUnsafePointer:
		baseSz = baseTypeSz
	case abiKindPointer, abiKindSlice:
		baseSz = baseTypeSz + uint64(ps)
	case abiKindChan:
		baseSz = baseTypeSz + uint64(2*ps)
	case abiKindArray:
		baseSz = baseTypeSz + uint64(3*ps)
	case abiKindFunc:
		baseSz = baseTypeSz + uint64(ps)
		ext, ok := lb.ReadAtVA(hdr.va+baseTypeSz, 4)
		if !ok {
			return 0, false
		}
		inCnt := uint64(bo.Uint16(ext[0:2]))
		outCnt := uint64(bo.Uint16(ext[2:4]) & 0x7fff)
		if inCnt+outCnt > 1024 {
			return 0, false
		}
		addSz = (inCnt + outCnt) * uint64(ps)
	case abiKindInterface:
		baseSz = baseTypeSz + uint64(4*ps)
		ext, ok := lb.ReadAtVA(hdr.va+baseTypeSz+uint64(ps), 3*ps)
		if !ok {
			return 0, false
		}
		mLen := readUintPtr(ext[ps:], ps, bo)
		if mLen > maxInterfaceMethods {
			return 0, false
		}
		addSz = mLen * 8
	case abiKindStruct:
		baseSz = baseTypeSz + uint64(4*ps)
		ext, ok := lb.ReadAtVA(hdr.va+baseTypeSz+uint64(ps), 3*ps)
		if !ok {
			return 0, false
		}
		fLen := readUintPtr(ext[ps:], ps, bo)
		if fLen > maxStructFields {
			return 0, false
		}
		addSz = fLen * uint64(3*ps)
	case abiKindMap:
		// Go 1.24 - 1.27 swissmap abi.MapType has 11 pointer-sized words after abi.Type.
		baseSz = baseTypeSz + uint64(11*ps)
	default:
		return 0, false
	}

	total := baseSz
	if (hdr.tflag & tflagUncommon) != 0 {
		uc, ok := lb.ReadAtVA(hdr.va+baseSz, 16)
		if !ok {
			return 0, false
		}
		mcount := uint64(bo.Uint16(uc[4:6]))
		if mcount > maxInterfaceMethods {
			return 0, false
		}
		total += 16 + mcount*16
	}
	total += addSz
	return total, true
}

func seedFromITabs(
	lb *loader.LoadedBinary,
	md *parsedModuleData,
	ps int,
	bo binary.ByteOrder,
	enqueue func(uint64),
) {
	// Go <= 1.26: itablinks []*itab slice
	if md.itablinksVA != 0 && md.itablinksCount > 0 {
		cnt := int(minUint64(md.itablinksCount, 65536))
		if ptrs, ok := lb.ReadAtVA(md.itablinksVA, cnt*ps); ok {
			for i := 0; i < cnt; i++ {
				itabVA := normalizePointer(lb, readUintPtr(ptrs[i*ps:], ps, bo))
				if itabHdr, ok := lb.ReadAtVA(itabVA, 2*ps); ok {
					enqueue(normalizePointer(lb, readUintPtr(itabHdr[0:], ps, bo)))
					enqueue(normalizePointer(lb, readUintPtr(itabHdr[ps:], ps, bo)))
				}
			}
		}
	}

	// Go 1.27+: contiguous itab region [md.types + md.itaboffset .. + md.itabsize)
	if md.itabsize >= uint64(4*ps) && md.types+md.itaboffset+md.itabsize <= md.etypes {
		start := md.types + md.itaboffset
		end := start + md.itabsize
		uPS := uint64(ps)
		for p := start; p+uint64(4*ps) <= end; p += uPS {
			buf, ok := lb.ReadAtVA(p, 3*ps)
			if !ok {
				break
			}
			interVA := normalizePointer(lb, readUintPtr(buf[0:], ps, bo))
			concVA := normalizePointer(lb, readUintPtr(buf[ps:], ps, bo))
			itabHash := bo.Uint32(buf[2*ps : 2*ps+4])
			if interVA < md.types || interVA >= md.etypes || concVA < md.types || concVA >= md.etypes {
				continue
			}
			interHdr, ok1 := readABITypeHeader(lb, md, interVA, ps, bo)
			concHdr, ok2 := readABITypeHeader(lb, md, concVA, ps, bo)
			if ok1 && ok2 && interHdr.kind == abiKindInterface && concHdr.hash == itabHash {
				enqueue(interVA)
				enqueue(concVA)
			}
		}
	}
}

func enqueueChildTypes(
	lb *loader.LoadedBinary,
	md *parsedModuleData,
	hdr rawABIType,
	ps int,
	bo binary.ByteOrder,
	enqueue func(uint64),
) {
	baseSz := uint64(4*ps + 16)
	if hdr.ptrToThis > 0 {
		enqueue(md.types + uint64(hdr.ptrToThis))
	}
	switch hdr.kind {
	case abiKindPointer, abiKindSlice, abiKindArray, abiKindChan:
		if ext, ok := lb.ReadAtVA(hdr.va+baseSz, ps); ok {
			enqueue(normalizePointer(lb, readUintPtr(ext, ps, bo)))
		}
	case abiKindMap:
		if ext, ok := lb.ReadAtVA(hdr.va+baseSz, 2*ps); ok {
			enqueue(normalizePointer(lb, readUintPtr(ext[0:], ps, bo)))
			enqueue(normalizePointer(lb, readUintPtr(ext[ps:], ps, bo)))
		}
	case abiKindFunc:
		if ext, ok := lb.ReadAtVA(hdr.va+baseSz, 4); ok {
			inCnt := int(bo.Uint16(ext[0:2]))
			outCnt := int(bo.Uint16(ext[2:4]) & 0x7fff)
			total := inCnt + outCnt
			if total > 0 && total <= 64 {
				argOff := hdr.va + baseSz + uint64(ps)
				if (hdr.tflag & tflagUncommon) != 0 {
					argOff += 16
				}
				if argsRaw, ok := lb.ReadAtVA(argOff, total*ps); ok {
					for i := 0; i < total; i++ {
						enqueue(normalizePointer(lb, readUintPtr(argsRaw[i*ps:], ps, bo)))
					}
				}
			}
		}
	}
}

func readABITypeHeader(
	lb *loader.LoadedBinary,
	md *parsedModuleData,
	va uint64,
	ps int,
	bo binary.ByteOrder,
) (rawABIType, bool) {
	if va < md.types || va >= md.etypes {
		return rawABIType{}, false
	}
	baseSz := 4*ps + 16
	if va+uint64(baseSz) > md.etypes {
		return rawABIType{}, false
	}
	buf, ok := lb.ReadAtVA(va, baseSz)
	if !ok {
		return rawABIType{}, false
	}

	sz := readUintPtr(buf[0:], ps, bo)
	ptrBytes := readUintPtr(buf[ps:], ps, bo)
	hash := bo.Uint32(buf[2*ps : 2*ps+4])
	tflag := buf[2*ps+4]
	align := buf[2*ps+5]
	fieldAlign := buf[2*ps+6]
	kind := buf[2*ps+7] & abiKindMask
	strOff := int32(bo.Uint32(buf[4*ps+8 : 4*ps+12]))
	ptrToThis := int32(bo.Uint32(buf[4*ps+12 : 4*ps+16]))

	if kind == abiKindInvalid || kind > abiKindUnsafePointer {
		return rawABIType{}, false
	}
	if ptrBytes > sz {
		return rawABIType{}, false
	}
	if !isPowerOfTwoOrZero(align) || !isPowerOfTwoOrZero(fieldAlign) {
		return rawABIType{}, false
	}
	if strOff <= 0 || md.types+uint64(strOff) >= md.etypes {
		return rawABIType{}, false
	}

	return rawABIType{
		va:         va,
		size:       sz,
		ptrBytes:   ptrBytes,
		hash:       hash,
		tflag:      tflag,
		align:      align,
		fieldAlign: fieldAlign,
		kind:       kind,
		strOff:     strOff,
		ptrToThis:  ptrToThis,
	}, true
}

func decodeNamedStructOrInterface(
	lb *loader.LoadedBinary,
	pcln *parsedPCLnTab,
	md *parsedModuleData,
	hdr rawABIType,
	ps int,
	bo binary.ByteOrder,
	enqueue func(uint64),
) (model.RecoveredType, bool) {
	typeStr, ok := resolveTypeString(lb, md, hdr)
	if !ok || typeStr == "" {
		return model.RecoveredType{}, false
	}

	baseSz := uint64(4*ps + 16)
	extSz := uint64(4 * ps) // PkgPath (1 ptr) + SliceHeader (3 ptrs)
	extBuf, ok := lb.ReadAtVA(hdr.va+baseSz, int(extSz))
	if !ok {
		return model.RecoveredType{}, false
	}

	pkgNameVA := normalizePointer(lb, readUintPtr(extBuf[0:], ps, bo))
	slicePtr := normalizePointer(lb, readUintPtr(extBuf[ps:], ps, bo))
	sliceLen := readUintPtr(extBuf[2*ps:], ps, bo)
	sliceCap := readUintPtr(extBuf[3*ps:], ps, bo)
	if sliceLen > sliceCap {
		return model.RecoveredType{}, false
	}

	var pkgPath string
	if pkgNameVA != 0 {
		pkgPath, _, _, _ = decodeABINameAtVA(lb, pkgNameVA)
	}
	if pkgPath == "" && (hdr.tflag&tflagUncommon) != 0 {
		ucOff := hdr.va + baseSz + extSz
		if ucBuf, ok := lb.ReadAtVA(ucOff, 16); ok {
			pkgOff := int32(bo.Uint32(ucBuf[0:4]))
			if pkgOff > 0 && md.types+uint64(pkgOff) < md.etypes {
				pkgPath, _, _, _ = decodeABINameAtVA(lb, md.types+uint64(pkgOff))
			}
		}
	}
	if pkgPath == "" {
		if dot := strings.IndexByte(typeStr, '.'); dot > 0 {
			pkgPath = typeStr[:dot]
		}
	}

	rt := model.RecoveredType{
		Name:    typeStr,
		Package: pkgPath,
		Size:    hdr.size,
		Align:   hdr.align,
		Addr:    hdr.va,
	}

	if hdr.kind == abiKindStruct {
		rt.Kind = "struct"
		if sliceLen > maxStructFields {
			return model.RecoveredType{}, false
		}
		if sliceLen > 0 {
			if slicePtr == 0 {
				return model.RecoveredType{}, false
			}
			fieldStride := 3 * ps
			fieldsRaw, ok := lb.ReadAtVA(slicePtr, int(sliceLen)*fieldStride)
			if !ok {
				return model.RecoveredType{}, false
			}
			fields := make([]model.StructField, 0, sliceLen)
			legacyOffsetEmbed := pcln.magic != MagicGo120 // Go <= 1.19 could pack embed bit in low bit on <=1.18
			for i := 0; i < int(sliceLen); i++ {
				fBase := i * fieldStride
				fNameVA := normalizePointer(lb, readUintPtr(fieldsRaw[fBase:], ps, bo))
				fTypVA := normalizePointer(lb, readUintPtr(fieldsRaw[fBase+ps:], ps, bo))
				fOff := readUintPtr(fieldsRaw[fBase+2*ps:], ps, bo)

				fName, fTag, fEmbed, ok := decodeABINameAtVA(lb, fNameVA)
				if !ok || fName == "" {
					continue
				}
				if legacyOffsetEmbed && pcln.magic != MagicGo118 && (fOff&1) != 0 && fOff > hdr.size {
					fEmbed = true
					fOff >>= 1
				}

				var fTypeName string
				if fTypVA != 0 {
					enqueue(fTypVA)
					if fHdr, ok := readABITypeHeader(lb, md, fTypVA, ps, bo); ok {
						fTypeName, _ = resolveTypeString(lb, md, fHdr)
					}
				}

				fields = append(fields, model.StructField{
					Name:     fName,
					TypeName: fTypeName,
					Offset:   fOff,
					Embedded: fEmbed,
					Tag:      fTag,
				})
			}
			rt.Fields = fields
		}
		return rt, true
	}

	// Kind == Interface
	rt.Kind = "interface"
	if sliceLen > maxInterfaceMethods {
		return model.RecoveredType{}, false
	}
	if sliceLen > 0 {
		if slicePtr == 0 {
			return model.RecoveredType{}, false
		}
		methodsRaw, ok := lb.ReadAtVA(slicePtr, int(sliceLen)*8)
		if !ok {
			return model.RecoveredType{}, false
		}
		methods := make([]string, 0, sliceLen)
		for i := 0; i < int(sliceLen); i++ {
			mBase := i * 8
			mNameOff := int32(bo.Uint32(methodsRaw[mBase : mBase+4]))
			mTypOff := int32(bo.Uint32(methodsRaw[mBase+4 : mBase+8]))
			if mTypOff > 0 {
				enqueue(md.types + uint64(mTypOff))
			}
			if mNameOff <= 0 || md.types+uint64(mNameOff) >= md.etypes {
				continue
			}
			mName, _, _, ok := decodeABINameAtVA(lb, md.types+uint64(mNameOff))
			if ok && mName != "" {
				methods = append(methods, mName)
			}
		}
		rt.Methods = methods
	}
	return rt, true
}

func resolveTypeString(lb *loader.LoadedBinary, md *parsedModuleData, hdr rawABIType) (string, bool) {
	if hdr.strOff <= 0 {
		return "", false
	}
	nameVA := md.types + uint64(hdr.strOff)
	if nameVA >= md.etypes {
		return "", false
	}
	s, _, _, ok := decodeABINameAtVA(lb, nameVA)
	if !ok || s == "" {
		return "", false
	}
	if (hdr.tflag&tflagExtraStar) != 0 && strings.HasPrefix(s, "*") {
		s = s[1:]
	}
	return s, s != ""
}

// decodeABINameAtVA decodes an internal/abi.Name encoded at virtual address va.
func decodeABINameAtVA(lb *loader.LoadedBinary, va uint64) (name, tag string, embedded, ok bool) {
	if va == 0 {
		return "", "", false, false
	}
	// Read initial header + varint window.
	head, ok := lb.ReadAtVA(va, 16)
	if !ok || len(head) < 2 {
		return "", "", false, false
	}
	bits := head[0]
	// Valid abi.Name bitmask uses bits 0..3 only.
	if (bits & 0xf0) != 0 {
		return "", "", false, false
	}
	hasTag := (bits & (1 << 1)) != 0
	embedded = (bits & (1 << 3)) != 0

	nameLen, nBytes, ok := readABINameVarint(head[1:])
	if !ok || nameLen < 0 || nameLen > 4096 {
		return "", "", false, false
	}

	nameStartVA := va + 1 + uint64(nBytes)
	if nameLen > 0 {
		nb, ok := lb.ReadAtVA(nameStartVA, nameLen)
		if !ok {
			return "", "", false, false
		}
		name = string(nb)
		if !utf8.ValidString(name) {
			return "", "", false, false
		}
	}

	if hasTag {
		tagHdrVA := nameStartVA + uint64(nameLen)
		tagHead, ok := lb.ReadAtVA(tagHdrVA, 12)
		if ok && len(tagHead) > 0 {
			tagLen, tBytes, ok := readABINameVarint(tagHead)
			if ok && tagLen > 0 && tagLen <= 4096 {
				if tb, ok := lb.ReadAtVA(tagHdrVA+uint64(tBytes), tagLen); ok && utf8.Valid(tb) {
					tag = string(tb)
				}
			}
		}
	}

	return name, tag, embedded, true
}

func readABINameVarint(buf []byte) (val, read int, ok bool) {
	var v int
	for i := 0; i < 4 && i < len(buf); i++ {
		b := buf[i]
		v |= int(b&0x7f) << (7 * i)
		if (b & 0x80) == 0 {
			return v, i + 1, true
		}
	}
	return 0, 0, false
}

func isPowerOfTwoOrZero(v uint8) bool {
	return v == 0 || (v&(v-1)) == 0
}

func isSyntheticRuntimeType(name string) bool {
	return strings.Contains(name, "[go.shape.") ||
		strings.HasPrefix(name, "bucket<") ||
		strings.HasPrefix(name, "group<") ||
		strings.HasPrefix(name, "noalg.") ||
		strings.HasPrefix(name, "methodValue")
}
