package loader

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/aloneangel45/symforge/pkg/model"
)

const (
	peScnMemExecute = 0x20000000
	peScnMemRead    = 0x40000000
	peScnMemWrite   = 0x80000000
)

func loadPE(path string, data []byte) (*LoadedBinary, error) {
	pf, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse PE %s: %w", path, err)
	}
	defer pf.Close()

	var arch model.Architecture
	switch pf.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = model.ArchX86_64
	case pe.IMAGE_FILE_MACHINE_ARM64:
		arch = model.ArchARM64
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = model.ArchX86
	case pe.IMAGE_FILE_MACHINE_ARM, pe.IMAGE_FILE_MACHINE_ARMNT:
		arch = model.ArchARM
	default:
		arch = model.ArchUnknown
	}

	var imageBase uint64 = 0x400000
	var entryRVA uint32
	ptrSize := 8
	pie := false

	switch opt := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		imageBase = opt.ImageBase
		entryRVA = opt.AddressOfEntryPoint
		ptrSize = 8
		pie = (opt.DllCharacteristics & 0x0040) != 0 // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
	case *pe.OptionalHeader32:
		imageBase = uint64(opt.ImageBase)
		entryRVA = opt.AddressOfEntryPoint
		ptrSize = 4
		pie = (opt.DllCharacteristics & 0x0040) != 0
	}

	var sections []model.SectionInfo
	for _, s := range pf.Sections {
		va := imageBase + uint64(s.VirtualAddress)
		vsize := uint64(s.VirtualSize)
		fOff := uint64(s.Offset)
		fSize := uint64(s.Size)
		var secBytes []byte
		if fSize > 0 && fOff < uint64(len(data)) {
			end := fOff + fSize
			if end > uint64(len(data)) {
				end = uint64(len(data))
			}
			if end > fOff {
				secBytes = data[fOff:end]
				fSize = end - fOff
			} else {
				fSize = 0
			}
		} else {
			fSize = 0
		}
		if vsize == 0 {
			vsize = fSize
		}
		sections = append(sections, model.SectionInfo{
			Name:        s.Name,
			VirtualAddr: va,
			VirtualSize: vsize,
			FileOffset:  fOff,
			FileSize:    fSize,
			Entropy:     ShannonEntropy(secBytes),
			Executable:  (s.Characteristics & peScnMemExecute) != 0,
			Readable:    (s.Characteristics&peScnMemRead) != 0 || fSize > 0,
			Writable:    (s.Characteristics & peScnMemWrite) != 0,
		})
	}

	var syms []model.SymbolEntry
	for _, sym := range pf.Symbols {
		if sym.Name == "" || sym.SectionNumber <= 0 || int(sym.SectionNumber) > len(pf.Sections) {
			continue
		}
		sec := pf.Sections[sym.SectionNumber-1]
		addr := imageBase + uint64(sec.VirtualAddress) + uint64(sym.Value)
		syms = append(syms, model.SymbolEntry{
			Name:    sym.Name,
			Addr:    addr,
			Section: sec.Name,
		})
	}

	lb := &LoadedBinary{
		Info: model.BinaryInfo{
			Format:      model.FormatPE,
			Arch:        arch,
			Endianness:  "little",
			PointerSize: ptrSize,
			EntryPoint:  imageBase + uint64(entryRVA),
			ImageBase:   imageBase,
			PIE:         pie,
			Stripped:    len(syms) == 0,
			Language:    model.LangNative,
		},
		Sections: sections,
		Symbols:  syms,
		Order:    binary.LittleEndian,
		raw:      data,
	}

	// Extract x64 PE .pdata RUNTIME_FUNCTION unwind entries (12 bytes each: BeginRVA, EndRVA, UnwindInfoRVA)
	// This recovers exact function boundaries on stripped Windows Rust & C++ binaries!
	if arch == model.ArchX86_64 {
		lb.RuntimeFuncs = extractPEPDataX64(pf, lb, imageBase)
	}

	lb.Imports = extractPEImports(pf, lb, imageBase, ptrSize)

	return lb, nil
}

func extractPEImports(pf *pe.File, lb *LoadedBinary, imageBase uint64, ptrSize int) []model.ImportSymbol {
	var importDir pe.DataDirectory
	switch opt := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(opt.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			importDir = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
	case *pe.OptionalHeader32:
		if len(opt.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			importDir = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
	}

	var imports []model.ImportSymbol
	if importDir.VirtualAddress != 0 && (ptrSize == 4 || ptrSize == 8) {
		dirVA := imageBase + uint64(importDir.VirtualAddress)
		const maxDescriptors = 2048
		const maxThunksPerDLL = 16384

		for i := 0; i < maxDescriptors; i++ {
			desc, ok := lb.ReadAtVA(dirVA+uint64(i)*20, 20)
			if !ok {
				break
			}
			origFirstThunk := binary.LittleEndian.Uint32(desc[0:4])
			nameRVA := binary.LittleEndian.Uint32(desc[12:16])
			firstThunk := binary.LittleEndian.Uint32(desc[16:20])
			if origFirstThunk == 0 && nameRVA == 0 && firstThunk == 0 {
				break
			}

			dllName := ""
			if nameRVA != 0 {
				if s, ok := lb.ReadCStringAtVA(imageBase+uint64(nameRVA), 260); ok {
					dllName = s
				}
			}

			lookupRVA := origFirstThunk
			if lookupRVA == 0 {
				lookupRVA = firstThunk
			}
			addedForDLL := 0
			if lookupRVA != 0 {
				lookupVA := imageBase + uint64(lookupRVA)
				for idx := 0; idx < maxThunksPerDLL; idx++ {
					thunkBytes, ok := lb.ReadAtVA(lookupVA+uint64(idx)*uint64(ptrSize), ptrSize)
					if !ok {
						break
					}
					var thunk uint64
					var isOrdinal bool
					var hintNameRVA uint64
					if ptrSize == 8 {
						thunk = binary.LittleEndian.Uint64(thunkBytes)
						if thunk == 0 {
							break
						}
						isOrdinal = (thunk & (uint64(1) << 63)) != 0
						hintNameRVA = thunk & 0x7fffffff
					} else {
						t32 := binary.LittleEndian.Uint32(thunkBytes)
						if t32 == 0 {
							break
						}
						thunk = uint64(t32)
						isOrdinal = (t32 & 0x80000000) != 0
						hintNameRVA = uint64(t32 & 0x7fffffff)
					}

					var symName string
					if isOrdinal {
						symName = fmt.Sprintf("Ordinal#%d", thunk&0xffff)
					} else if hintNameRVA != 0 {
						// IMAGE_IMPORT_BY_NAME: 2-byte Hint followed by null-terminated ASCII name
						if name, ok := lb.ReadCStringAtVA(imageBase+hintNameRVA+2, 512); ok {
							symName = name
						}
					}
					if symName == "" && dllName == "" {
						continue
					}
					var iatAddr uint64
					if firstThunk != 0 {
						iatAddr = imageBase + uint64(firstThunk) + uint64(idx)*uint64(ptrSize)
					}
					imports = append(imports, model.ImportSymbol{
						Library: dllName,
						Name:    symName,
						Address: iatAddr,
					})
					addedForDLL++
				}
			}
			if addedForDLL == 0 && dllName != "" {
				imports = append(imports, model.ImportSymbol{Library: dllName})
			}
		}
	}

	// Graceful fallback to Go stdlib debug/pe if direct IAT/INT directory parsing yielded nothing
	if len(imports) == 0 {
		seenLib := make(map[string]struct{})
		if symStrings, err := pf.ImportedSymbols(); err == nil {
			for _, entry := range symStrings {
				if entry == "" {
					continue
				}
				symName := entry
				dllName := ""
				if idx := strings.LastIndexByte(entry, ':'); idx > 0 {
					symName = entry[:idx]
					dllName = entry[idx+1:]
				}
				if dllName != "" {
					seenLib[strings.ToLower(dllName)] = struct{}{}
				}
				imports = append(imports, model.ImportSymbol{
					Library: dllName,
					Name:    symName,
				})
			}
		}
		if libs, err := pf.ImportedLibraries(); err == nil {
			for _, lib := range libs {
				if lib == "" {
					continue
				}
				if _, ok := seenLib[strings.ToLower(lib)]; !ok {
					imports = append(imports, model.ImportSymbol{Library: lib})
				}
			}
		}
	}

	return imports
}

func extractPEPDataX64(pf *pe.File, lb *LoadedBinary, imageBase uint64) []model.RuntimeBounds {
	var pdataBytes []byte
	if opt, ok := pf.OptionalHeader.(*pe.OptionalHeader64); ok {
		// IMAGE_DIRECTORY_ENTRY_EXCEPTION = index 3
		if len(opt.DataDirectory) > 3 {
			dir := opt.DataDirectory[3]
			if dir.VirtualAddress > 0 && dir.Size >= 12 {
				if raw, ok := lb.ReadAtVA(imageBase+uint64(dir.VirtualAddress), int(dir.Size)); ok {
					pdataBytes = raw
				}
			}
		}
	}
	if len(pdataBytes) == 0 {
		if _, secData, ok := lb.SectionByName(".pdata"); ok {
			pdataBytes = secData
		}
	}
	if len(pdataBytes) < 12 {
		return nil
	}

	var bounds []model.RuntimeBounds
	seen := make(map[uint64]struct{})
	for off := 0; off+12 <= len(pdataBytes); off += 12 {
		beginRVA := binary.LittleEndian.Uint32(pdataBytes[off : off+4])
		endRVA := binary.LittleEndian.Uint32(pdataBytes[off+4 : off+8])
		if beginRVA == 0 || endRVA <= beginRVA {
			continue
		}
		startVA := imageBase + uint64(beginRVA)
		endVA := imageBase + uint64(endRVA)
		if !lb.IsCodeVA(startVA) {
			continue
		}
		if _, dup := seen[startVA]; dup {
			continue
		}
		seen[startVA] = struct{}{}
		bounds = append(bounds, model.RuntimeBounds{Start: startVA, End: endVA})
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i].Start < bounds[j].Start })
	return bounds
}
