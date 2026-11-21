package loader

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/aloneangel45/symforge/pkg/model"
)

func loadELF(path string, data []byte) (*LoadedBinary, error) {
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse ELF %s: %w", path, err)
	}
	defer ef.Close()

	var arch model.Architecture
	switch ef.Machine {
	case elf.EM_X86_64:
		arch = model.ArchX86_64
	case elf.EM_AARCH64:
		arch = model.ArchARM64
	case elf.EM_386:
		arch = model.ArchX86
	case elf.EM_ARM:
		arch = model.ArchARM
	default:
		arch = model.ArchUnknown
	}

	ptrSize := 8
	if ef.Class == elf.ELFCLASS32 {
		ptrSize = 4
	}

	endian := "little"
	var order binary.ByteOrder = binary.LittleEndian
	if ef.ByteOrder == binary.BigEndian {
		endian = "big"
		order = binary.BigEndian
	}

	var imageBase uint64
	hasBase := false
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD && p.Filesz > 0 {
			if !hasBase || p.Vaddr < imageBase {
				imageBase = p.Vaddr
				hasBase = true
			}
		}
	}

	var sections []model.SectionInfo
	for _, s := range ef.Sections {
		if s.Type == elf.SHT_NULL {
			continue
		}
		var secBytes []byte
		var fileSize uint64
		if s.Type != elf.SHT_NOBITS && s.Size > 0 && s.Offset < uint64(len(data)) {
			end := s.Offset + s.Size
			if end > uint64(len(data)) {
				end = uint64(len(data))
			}
			if end > s.Offset {
				secBytes = data[s.Offset:end]
				fileSize = end - s.Offset
			}
		}
		sections = append(sections, model.SectionInfo{
			Name:        s.Name,
			VirtualAddr: s.Addr,
			VirtualSize: s.Size,
			FileOffset:  s.Offset,
			FileSize:    fileSize,
			Entropy:     ShannonEntropy(secBytes),
			Executable:  (s.Flags & elf.SHF_EXECINSTR) != 0,
			Readable:    (s.Flags&elf.SHF_ALLOC) != 0 || fileSize > 0,
			Writable:    (s.Flags & elf.SHF_WRITE) != 0,
		})
	}

	// Fallback if section headers were completely stripped (`sstrip`): synthesize from PT_LOAD segments
	if len(sections) == 0 {
		for idx, p := range ef.Progs {
			if p.Type != elf.PT_LOAD || p.Filesz == 0 || p.Off >= uint64(len(data)) {
				continue
			}
			end := p.Off + p.Filesz
			if end > uint64(len(data)) {
				end = uint64(len(data))
			}
			segBytes := data[p.Off:end]
			sections = append(sections, model.SectionInfo{
				Name:        fmt.Sprintf("PT_LOAD_%d", idx),
				VirtualAddr: p.Vaddr,
				VirtualSize: p.Memsz,
				FileOffset:  p.Off,
				FileSize:    end - p.Off,
				Entropy:     ShannonEntropy(segBytes),
				Executable:  (p.Flags & elf.PF_X) != 0,
				Readable:    (p.Flags & elf.PF_R) != 0,
				Writable:    (p.Flags & elf.PF_W) != 0,
			})
		}
	}

	var syms []model.SymbolEntry
	staticSyms, symErr := ef.Symbols()
	stripped := symErr != nil || len(staticSyms) == 0
	for _, sym := range staticSyms {
		if sym.Name == "" || sym.Value == 0 {
			continue
		}
		secName := ""
		if int(sym.Section) >= 0 && int(sym.Section) < len(ef.Sections) {
			secName = ef.Sections[sym.Section].Name
		}
		syms = append(syms, model.SymbolEntry{
			Name:    sym.Name,
			Addr:    sym.Value,
			Size:    sym.Size,
			Section: secName,
			Dynamic: false,
		})
	}

	if dynSyms, dErr := ef.DynamicSymbols(); dErr == nil {
		for _, sym := range dynSyms {
			if sym.Name == "" || sym.Value == 0 {
				continue
			}
			syms = append(syms, model.SymbolEntry{
				Name:    sym.Name,
				Addr:    sym.Value,
				Size:    sym.Size,
				Dynamic: true,
			})
		}
	}

	imports := extractELFImports(ef)

	return &LoadedBinary{
		Info: model.BinaryInfo{
			Format:      model.FormatELF,
			Arch:        arch,
			Endianness:  endian,
			PointerSize: ptrSize,
			EntryPoint:  ef.Entry,
			ImageBase:   imageBase,
			PIE:         ef.Type == elf.ET_DYN,
			Stripped:    stripped,
			Language:    model.LangNative,
		},
		Sections: sections,
		Symbols:  syms,
		Imports:  imports,
		Order:    order,
		raw:      data,
	}, nil
}

func extractELFImports(ef *elf.File) []model.ImportSymbol {
	var imports []model.ImportSymbol
	seenSym := make(map[string]struct{})
	seenLibWithSym := make(map[string]struct{})

	if impSyms, err := ef.ImportedSymbols(); err == nil {
		for _, imp := range impSyms {
			if imp.Name == "" {
				continue
			}
			seenSym[imp.Name] = struct{}{}
			if imp.Library != "" {
				seenLibWithSym[imp.Library] = struct{}{}
			}
			imports = append(imports, model.ImportSymbol{
				Library: imp.Library,
				Name:    imp.Name,
			})
		}
	}

	// Fallback for undefined dynamic symbols if ImportedSymbols returned partial or errored
	if dynSyms, err := ef.DynamicSymbols(); err == nil {
		for _, sym := range dynSyms {
			if sym.Name == "" || sym.Section != elf.SHN_UNDEF {
				continue
			}
			if _, ok := seenSym[sym.Name]; ok {
				continue
			}
			seenSym[sym.Name] = struct{}{}
			imports = append(imports, model.ImportSymbol{
				Name:    sym.Name,
				Address: sym.Value,
			})
		}
	}

	// Recover DT_NEEDED shared library dependencies
	if libs, err := ef.ImportedLibraries(); err == nil {
		for _, lib := range libs {
			if lib == "" {
				continue
			}
			if _, covered := seenLibWithSym[lib]; !covered {
				imports = append(imports, model.ImportSymbol{
					Library: lib,
				})
			}
		}
	}

	return imports
}
