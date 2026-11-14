package loader

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"

	"github.com/aloneangel45/symforge/pkg/model"
)

func isMachOMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	mLE := binary.LittleEndian.Uint32(data[:4])
	mBE := binary.BigEndian.Uint32(data[:4])
	switch mLE {
	case macho.Magic32, macho.Magic64, macho.MagicFat:
		return true
	}
	switch mBE {
	case macho.Magic32, macho.Magic64, macho.MagicFat:
		return true
	}
	return false
}

func loadMachO(path string, data []byte) (*LoadedBinary, error) {
	isFat := false
	sliceData := data

	// Check for Universal Fat Mach-O (0xCAFEBABE big-endian)
	if binary.BigEndian.Uint32(data[:4]) == macho.MagicFat {
		ff, err := macho.NewFatFile(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("parse Mach-O Fat binary %s: %w", path, err)
		}
		defer ff.Close()
		if len(ff.Arches) == 0 {
			return nil, fmt.Errorf("Mach-O Fat binary %s contains zero architecture slices", path)
		}
		// Prefer arm64 or x86_64 slice deterministically
		chosen := ff.Arches[0]
		for _, a := range ff.Arches {
			if a.Cpu == macho.CpuArm64 {
				chosen = a
				break
			}
			if a.Cpu == macho.CpuAmd64 {
				chosen = a
			}
		}
		end := uint64(chosen.Offset) + uint64(chosen.Size)
		if end > uint64(len(data)) {
			return nil, fmt.Errorf("Mach-O Fat slice exceeds file bounds in %s", path)
		}
		sliceData = data[chosen.Offset:end]
		isFat = true
	}

	mf, err := macho.NewFile(bytes.NewReader(sliceData))
	if err != nil {
		return nil, fmt.Errorf("parse Mach-O %s: %w", path, err)
	}
	defer mf.Close()

	var arch model.Architecture
	ptrSize := 8
	switch mf.Cpu {
	case macho.CpuAmd64:
		arch = model.ArchX86_64
	case macho.CpuArm64:
		arch = model.ArchARM64
	case macho.Cpu386:
		arch = model.ArchX86
		ptrSize = 4
	case macho.CpuArm:
		arch = model.ArchARM
		ptrSize = 4
	default:
		arch = model.ArchUnknown
	}

	endian := "little"
	var order binary.ByteOrder = binary.LittleEndian
	if mf.ByteOrder == binary.BigEndian {
		endian = "big"
		order = binary.BigEndian
	}

	// Build segment protection lookup
	segProt := make(map[string]uint32)
	var imageBase uint64
	hasBase := false
	for _, ld := range mf.Loads {
		if seg, ok := ld.(*macho.Segment); ok {
			segProt[seg.Name] = seg.Prot
			if seg.Name == "__TEXT" || (!hasBase && seg.Filesz > 0 && seg.Name != "__PAGEZERO") {
				imageBase = seg.Addr
				hasBase = true
			}
		}
	}

	var sections []model.SectionInfo
	var textEntryFallback uint64
	for _, s := range mf.Sections {
		fOff := uint64(s.Offset)
		fSize := s.Size
		var secBytes []byte
		// Zerofill sections (S_ZEROFILL = 0x1) have Offset == 0 and no backing bytes
		if (s.Flags&0xff) != 0x1 && fSize > 0 && fOff < uint64(len(sliceData)) {
			end := fOff + fSize
			if end > uint64(len(sliceData)) {
				end = uint64(len(sliceData))
			}
			if end > fOff {
				secBytes = sliceData[fOff:end]
				fSize = end - fOff
			} else {
				fSize = 0
			}
		} else {
			fSize = 0
		}

		prot := segProt[s.Seg]
		exec := (prot&0x4) != 0 || (s.Flags&0x80000000) != 0 // VM_PROT_EXECUTE or S_ATTR_PURE_INSTRUCTIONS
		read := (prot&0x1) != 0 || fSize > 0
		write := (prot & 0x2) != 0

		fullName := s.Seg + "." + s.Name
		if s.Name == "__text" && textEntryFallback == 0 {
			textEntryFallback = s.Addr
		}
		sections = append(sections, model.SectionInfo{
			Name:        fullName,
			VirtualAddr: s.Addr,
			VirtualSize: s.Size,
			FileOffset:  fOff,
			FileSize:    fSize,
			Entropy:     ShannonEntropy(secBytes),
			Executable:  exec,
			Readable:    read,
			Writable:    write,
		})
	}

	entryVA := parseMachOEntryPoint(mf, imageBase, textEntryFallback, order)

	var syms []model.SymbolEntry
	if mf.Symtab != nil {
		for _, sym := range mf.Symtab.Syms {
			if sym.Name == "" || sym.Value == 0 {
				continue
			}
			// Ignore debug STAB entries (N_STAB = 0xe0)
			if (sym.Type & 0xe0) != 0 {
				continue
			}
			secName := ""
			if sym.Sect > 0 && int(sym.Sect) <= len(mf.Sections) {
				sec := mf.Sections[sym.Sect-1]
				secName = sec.Seg + "." + sec.Name
			}
			syms = append(syms, model.SymbolEntry{
				Name:    sym.Name,
				Addr:    sym.Value,
				Section: secName,
			})
		}
	}

	format := model.FormatMachO
	if isFat {
		format = model.FormatMachOFat
	}

	return &LoadedBinary{
		Info: model.BinaryInfo{
			Format:      format,
			Arch:        arch,
			Endianness:  endian,
			PointerSize: ptrSize,
			EntryPoint:  entryVA,
			ImageBase:   imageBase,
			PIE:         (mf.Flags & 0x200000) != 0, // MH_PIE
			Stripped:    len(syms) <= 4,            // Stripped Mach-O retains only _mh_execute_header or ~1-2 dyld stubs
			Language:    model.LangNative,
		},
		Sections: sections,
		Symbols:  syms,
		Order:    order,
		raw:      sliceData,
	}, nil
}

func parseMachOEntryPoint(mf *macho.File, imageBase, fallback uint64, order binary.ByteOrder) uint64 {
	// LC_MAIN = 0x80000028 (cmd: uint32, cmdsize: uint32, entryoff: uint64, stacksize: uint64)
	const lcMain = 0x80000028
	for _, ld := range mf.Loads {
		raw := ld.Raw()
		if len(raw) >= 16 && order.Uint32(raw[:4]) == lcMain {
			entryOff := order.Uint64(raw[8:16])
			return imageBase + entryOff
		}
	}
	return fallback
}
