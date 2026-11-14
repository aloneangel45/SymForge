package rustrecover

import (
	"fmt"
	"strings"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

const (
	maxVTables          = 512
	maxVTableObjectSize = 1 << 24 // 16 MiB concrete type size upper bound
	maxVTableMethods    = 64
)

// scanRustVTables scans non-executable read-only data sections on pointer alignment
// for Rust trait object vtables: [drop_in_place, size, align, method_0, ...].
func scanRustVTables(
	lb *loader.LoadedBinary,
	relMap map[uint64]uint64,
	funcNames map[uint64]string,
	dataSymNames map[uint64]string,
) []model.RecoveredType {
	ptrSize := lb.Info.PointerSize
	if ptrSize != 4 && ptrSize != 8 {
		return nil
	}

	var vtables []model.RecoveredType
	minHeaderBytes := 4 * ptrSize

	for i := range lb.Sections {
		if len(vtables) >= maxVTables {
			break
		}
		s := &lb.Sections[i]
		if !isCandidateVTableSection(s) || s.FileSize < uint64(minHeaderBytes) {
			continue
		}
		secData, ok := lb.SectionBytes(s)
		if !ok {
			continue
		}

		off := 0
		allowNullDrop := isExplicitRelocConstSection(s, lb)
		for off+minHeaderBytes <= len(secData) && len(vtables) < maxVTables {
			vtableVA := s.VirtualAddr + uint64(off)
			dropPtr, size, align, m0, valid := checkVTableHeaderAt(lb, secData, off, vtableVA, ptrSize, relMap, allowNullDrop)
			if !valid {
				off += ptrSize
				continue
			}
			_ = dropPtr

			methods := []string{resolveMethodLabel(m0, funcNames)}
			curOff := off + 4*ptrSize
			for len(methods) < maxVTableMethods && curOff+ptrSize <= len(secData) {
				slotVA := s.VirtualAddr + uint64(curOff)
				// If curOff itself begins a distinct valid vtable header, stop before swallowing next vtable's drop_in_place
				if curOff+minHeaderBytes <= len(secData) {
					if _, _, _, _, nextValid := checkVTableHeaderAt(lb, secData, curOff, slotVA, ptrSize, relMap, allowNullDrop); nextValid {
						break
					}
				}
				mPtr := readRelocPtr(lb, secData, curOff, slotVA, relMap)
				if !isPlausibleCodeEntry(lb, mPtr) {
					break
				}
				methods = append(methods, resolveMethodLabel(mPtr, funcNames))
				curOff += ptrSize
			}

			vtName, vtPkg := inferVTableIdentity(vtableVA, m0, funcNames, dataSymNames)
			vtables = append(vtables, model.RecoveredType{
				Name:    vtName,
				Package: vtPkg,
				Kind:    "vtable",
				Size:    size,
				Align:   uint8(align),
				Addr:    vtableVA,
				Methods: methods,
			})

			off = curOff
		}
	}

	return vtables
}

func checkVTableHeaderAt(
	lb *loader.LoadedBinary,
	secData []byte,
	off int,
	slotVA uint64,
	ptrSize int,
	relMap map[uint64]uint64,
	allowNullDrop bool,
) (dropPtr, size, align, method0 uint64, ok bool) {
	dropPtr = readRelocPtr(lb, secData, off, slotVA, relMap)
	if dropPtr == 0 {
		// Rust 1.77+ encodes Option<unsafe fn(*mut ())>::None as 0 when concrete type has no Drop glue.
		if !allowNullDrop {
			return 0, 0, 0, 0, false
		}
	} else if !isPlausibleCodeEntry(lb, dropPtr) {
		return 0, 0, 0, 0, false
	}

	size = readPlainUintPtr(lb, secData, off+ptrSize)
	align = readPlainUintPtr(lb, secData, off+2*ptrSize)
	maxSz := uint64(maxVTableObjectSize)
	if dropPtr == 0 {
		maxSz = 65536
	}
	if size > maxSz || lb.IsCodeVA(size) || !isValidVTableAlign(align) || lb.IsCodeVA(align) {
		return 0, 0, 0, 0, false
	}
	if size%align != 0 {
		return 0, 0, 0, 0, false
	}

	method0 = readRelocPtr(lb, secData, off+3*ptrSize, slotVA+uint64(3*ptrSize), relMap)
	if !isPlausibleCodeEntry(lb, method0) {
		return 0, 0, 0, 0, false
	}
	return dropPtr, size, align, method0, true
}

func isPlausibleCodeEntry(lb *loader.LoadedBinary, va uint64) bool {
	if va == 0 || !lb.IsCodeVA(va) {
		return false
	}
	if lb.Info.Arch == model.ArchARM64 && (va&3) != 0 {
		return false
	}
	// Reject pointers into INT3 (0xCC) or zero-fill padding between functions on x86/x86_64.
	if code, ok := lb.ReadAtVA(va, 2); ok && len(code) == 2 {
		if (code[0] == 0x00 && code[1] == 0x00) || code[0] == 0xcc {
			return false
		}
	}
	return true
}

func isExplicitRelocConstSection(s *model.SectionInfo, lb *loader.LoadedBinary) bool {
	lower := strings.ToLower(s.Name)
	if strings.Contains(lower, "rel.ro") || lower == "__data_const.__const" || lower == "__data.__const" || lower == ".rdata" {
		return true
	}
	if !lb.Info.PIE && (lower == ".rodata" || strings.HasPrefix(lower, ".rodata.") || lower == "__text.__const") {
		return true
	}
	return false
}

func isValidVTableAlign(a uint64) bool {
	return a > 0 && a <= 64 && (a&(a-1)) == 0
}

func isCandidateVTableSection(s *model.SectionInfo) bool {
	if s.Executable || !s.Readable || s.FileSize == 0 || isIgnoredMetadataSection(s.Name) {
		return false
	}
	lower := strings.ToLower(s.Name)
	// Explicit allow for RELRO / Mach-O const sections even when container header marks segment writable pre-relocation
	if strings.Contains(lower, "rel.ro") || strings.Contains(lower, "__const") ||
		lower == ".rodata" || strings.HasPrefix(lower, ".rodata.") || lower == ".rdata" {
		return true
	}
	return !s.Writable
}

func resolveMethodLabel(va uint64, funcNames map[uint64]string) string {
	if name, ok := funcNames[va]; ok && name != "" {
		return name
	}
	return fmt.Sprintf("sub_%x", va)
}

func inferVTableIdentity(
	vtableVA uint64,
	method0VA uint64,
	funcNames map[uint64]string,
	dataSymNames map[uint64]string,
) (name, pkg string) {
	if dSym, ok := dataSymNames[vtableVA]; ok && dSym != "" {
		crate, _, _ := splitDemangledCrate(dSym)
		return dSym, crate
	}
	if m0Name, ok := funcNames[method0VA]; ok && strings.HasPrefix(m0Name, "<") {
		parts := splitTopLevelColons(m0Name)
		if len(parts) > 0 && strings.HasPrefix(parts[0], "<") && strings.HasSuffix(parts[0], ">") {
			crate, _, _ := splitDemangledCrate(m0Name)
			return "vtable" + parts[0], crate
		}
	}
	return fmt.Sprintf("vtable_%x", vtableVA), ""
}
