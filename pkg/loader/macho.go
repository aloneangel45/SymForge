package loader

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"

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

func machoCPUToArch(cpu macho.Cpu) model.Architecture {
	switch cpu {
	case macho.CpuAmd64:
		return model.ArchX86_64
	case macho.CpuArm64:
		return model.ArchARM64
	case macho.Cpu386:
		return model.ArchX86
	case macho.CpuArm:
		return model.ArchARM
	default:
		return model.ArchUnknown
	}
}

func loadMachO(path string, data []byte, opts LoadOptions) (*LoadedBinary, error) {
	isFat := false
	sliceData := data
	var availableArches []string

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

		seenArch := make(map[string]struct{}, len(ff.Arches))
		for _, a := range ff.Arches {
			name := string(machoCPUToArch(a.Cpu))
			if name == "" || name == string(model.ArchUnknown) {
				name = strings.ToLower(a.Cpu.String())
			}
			if _, dup := seenArch[name]; !dup {
				seenArch[name] = struct{}{}
				availableArches = append(availableArches, name)
			}
		}

		var chosen macho.FatArch
		matched := false
		if strings.TrimSpace(opts.Arch) != "" {
			wantArch, ok := NormalizeArch(opts.Arch)
			if !ok {
				return nil, fmt.Errorf("unsupported architecture %q for universal Mach-O %s (available: %s)",
					opts.Arch, path, strings.Join(availableArches, ", "))
			}
			for _, a := range ff.Arches {
				if machoCPUToArch(a.Cpu) == wantArch {
					chosen = a
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("architecture %q not found in universal Mach-O %s (available: %s)",
					opts.Arch, path, strings.Join(availableArches, ", "))
			}
		} else {
			// Default: host architecture if present, else first slice.
			hostArch, _ := NormalizeArch(runtime.GOARCH)
			chosen = ff.Arches[0]
			for _, a := range ff.Arches {
				if machoCPUToArch(a.Cpu) == hostArch {
					chosen = a
					break
				}
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

	arch := machoCPUToArch(mf.Cpu)
	ptrSize := 8
	if arch == model.ArchX86 || arch == model.ArchARM {
		ptrSize = 4
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
		// In Mach-O, __TEXT has VM_PROT_EXECUTE at the segment level even for read-only
		// data sections like __TEXT.__cstring and __TEXT.__const. Only mark sections with
		// instruction attributes (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) or __text as Executable.
		exec := (s.Flags&(0x80000000|0x00000400)) != 0 || s.Name == "__text"
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

	imports := extractMachOImports(mf, order)

	format := model.FormatMachO
	if isFat {
		format = model.FormatMachOFat
	}

	return &LoadedBinary{
		Info: model.BinaryInfo{
			Format:          format,
			Arch:            arch,
			AvailableArches: availableArches,
			Endianness:      endian,
			PointerSize:     ptrSize,
			EntryPoint:      entryVA,
			ImageBase:       imageBase,
			PIE:             (mf.Flags & 0x200000) != 0, // MH_PIE
			Stripped:        len(syms) <= 4,            // Stripped Mach-O retains only _mh_execute_header or ~1-2 dyld stubs
			Language:        model.LangNative,
		},
		Sections: sections,
		Symbols:  syms,
		Imports:  imports,
		Order:    order,
		raw:      sliceData,
	}, nil
}

func extractMachOImports(mf *macho.File, order binary.ByteOrder) []model.ImportSymbol {
	const (
		lcLoadDylib       = 0x0000000c
		lcLoadWeakDylib   = 0x80000018
		lcReexportDylib   = 0x8000001f
		lcLazyLoadDylib   = 0x00000020
		lcLoadUpwardDylib = 0x80000023
		mhTwoLevel        = 0x00000080
	)

	// Preserve exact load-command dylib ordering so two-level namespace ordinals (1..N) map accurately.
	var dylibs []string
	for _, ld := range mf.Loads {
		if dl, ok := ld.(*macho.Dylib); ok && dl.Name != "" {
			dylibs = append(dylibs, dl.Name)
			continue
		}
		raw := ld.Raw()
		if len(raw) < 24 {
			continue
		}
		cmd := order.Uint32(raw[:4])
		if cmd == lcLoadDylib || cmd == lcLoadWeakDylib || cmd == lcReexportDylib || cmd == lcLazyLoadDylib || cmd == lcLoadUpwardDylib {
			nameOff := order.Uint32(raw[8:12])
			if int(nameOff) >= 24 && int(nameOff) < len(raw) {
				s := raw[nameOff:]
				if idx := bytes.IndexByte(s, 0); idx >= 0 {
					s = s[:idx]
				}
				if len(s) > 0 {
					dylibs = append(dylibs, string(s))
				}
			}
		}
	}
	if stdLibs, err := mf.ImportedLibraries(); err == nil {
		seen := make(map[string]struct{}, len(dylibs))
		for _, d := range dylibs {
			seen[d] = struct{}{}
		}
		for _, d := range stdLibs {
			if d != "" {
				if _, ok := seen[d]; !ok {
					dylibs = append(dylibs, d)
					seen[d] = struct{}{}
				}
			}
		}
	}

	var imports []model.ImportSymbol
	seenSym := make(map[string]struct{})
	seenLibWithSym := make(map[string]struct{})
	twoLevel := (mf.Flags & mhTwoLevel) != 0

	if mf.Symtab != nil {
		for _, sym := range mf.Symtab.Syms {
			if sym.Name == "" {
				continue
			}
			// Undefined external symbol: N_STAB == 0, N_TYPE == N_UNDF (0), N_EXT == 1
			if (sym.Type&0xe0) != 0 || (sym.Type&0x0e) != 0 || (sym.Type&0x01) == 0 || sym.Sect != 0 {
				continue
			}
			lib := ""
			if twoLevel {
				ord := int((sym.Desc >> 8) & 0xff)
				if ord >= 1 && ord <= len(dylibs) {
					lib = dylibs[ord-1]
				}
			}
			seenSym[sym.Name] = struct{}{}
			if lib != "" {
				seenLibWithSym[lib] = struct{}{}
			}
			imports = append(imports, model.ImportSymbol{
				Library: lib,
				Name:    sym.Name,
			})
		}
	}

	if stdSyms, err := mf.ImportedSymbols(); err == nil {
		for _, name := range stdSyms {
			if name == "" {
				continue
			}
			if _, ok := seenSym[name]; ok {
				continue
			}
			seenSym[name] = struct{}{}
			imports = append(imports, model.ImportSymbol{
				Name: name,
			})
		}
	}

	for _, lib := range dylibs {
		if _, covered := seenLibWithSym[lib]; !covered {
			imports = append(imports, model.ImportSymbol{Library: lib})
		}
	}

	return imports
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
