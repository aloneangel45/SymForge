package loader

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloneangel45/symforge/pkg/model"
)

func TestLoadFile_CrossCompiledELF_PE_MachO_Stripped(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "sample.go")
	code := `package main
import "fmt"
func main() { fmt.Println("symforge-loader-check") }
`
	if err := os.WriteFile(src, []byte(code), 0644); err != nil {
		t.Fatal(err)
	}

	targets := []struct {
		goos   string
		goarch string
		format model.BinaryFormat
		arch   model.Architecture
	}{
		{"linux", "amd64", model.FormatELF, model.ArchX86_64},
		{"linux", "arm64", model.FormatELF, model.ArchARM64},
		{"windows", "amd64", model.FormatPE, model.ArchX86_64},
		{"darwin", "arm64", model.FormatMachO, model.ArchARM64},
	}

	for _, tc := range targets {
		outBin := filepath.Join(tmp, tc.goos+"_"+tc.goarch)
		if tc.goos == "windows" {
			outBin += ".exe"
		}
		cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outBin, src)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+tc.goos, "GOARCH="+tc.goarch)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s/%s failed: %v\n%s", tc.goos, tc.goarch, err, string(out))
		}

		lb, err := LoadFile(outBin)
		if err != nil {
			t.Fatalf("LoadFile(%s/%s) failed: %v", tc.goos, tc.goarch, err)
		}
		if lb.Info.Format != tc.format {
			t.Errorf("%s/%s format = %q, want %q", tc.goos, tc.goarch, lb.Info.Format, tc.format)
		}
		if lb.Info.Arch != tc.arch {
			t.Errorf("%s/%s arch = %q, want %q", tc.goos, tc.goarch, lb.Info.Arch, tc.arch)
		}
		if !lb.Info.Stripped {
			t.Errorf("%s/%s expected Stripped=true on -ldflags='-s -w' binary", tc.goos, tc.goarch)
		}
		if lb.Info.PointerSize != 8 {
			t.Errorf("%s/%s PointerSize = %d, want 8", tc.goos, tc.goarch, lb.Info.PointerSize)
		}
		if len(lb.Sections) == 0 {
			t.Fatalf("%s/%s had 0 sections", tc.goos, tc.goarch)
		}
		if tc.goos == "windows" && tc.goarch == "amd64" && len(lb.RuntimeFuncs) == 0 {
			t.Errorf("expected PE x86_64 .pdata RuntimeFuncs > 0, got 0")
		}
		// Verify EntryPoint maps into a valid executable code section
		if lb.Info.EntryPoint != 0 && !lb.IsCodeVA(lb.Info.EntryPoint) {
			t.Errorf("%s/%s EntryPoint 0x%x did not resolve to executable section", tc.goos, tc.goarch, lb.Info.EntryPoint)
		}
	}
}

func TestLoadBytes_RejectsMalformedAndTinyInputs(t *testing.T) {
	if _, err := LoadBytes("tiny.bin", []byte("short")); err == nil {
		t.Fatal("expected error for tiny input")
	}
	if _, err := LoadBytes("unknown.bin", []byte("0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatal("expected error for unknown magic")
	}
	// Truncated ELF header with valid magic
	badELF := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 24)...)
	if _, err := LoadBytes("trunc.elf", badELF); err == nil {
		t.Fatal("expected error for truncated ELF")
	}
}

func TestNormalizePointerSectionStemAndOverflowSafety(t *testing.T) {
	lb := &LoadedBinary{
		Info: model.BinaryInfo{
			Format:      model.FormatMachO,
			Arch:        model.ArchARM64,
			PointerSize: 8,
			ImageBase:   0x100000000,
		},
		Sections: []model.SectionInfo{
			{
				Name:        "__TEXT.__gopclntab",
				VirtualAddr: 0x100080000,
				VirtualSize: 0x4000,
				FileOffset:  0x100,
				FileSize:    0x4000,
			},
			{
				Name:        "__DATA,.dep-v0",
				VirtualAddr: 0x100090000,
				VirtualSize: 0x1000,
				FileOffset:  0x4100,
				FileSize:    0x1000,
			},
			{
				Name:        "__WRAP",
				VirtualAddr: ^uint64(0) - 15,
				VirtualSize: 64, // VirtualAddr + VirtualSize would wrap uint64 without subtraction check
				FileOffset:  0,
				FileSize:    16,
			},
		},
		raw: make([]byte, 0x6000),
	}

	// 1. Mach-O chained rebase (ImageBase + low36)
	chainedOffset := uint64(0x0010000000080120) // high bits metadata, low36 = 0x80120 -> 0x100080120
	if got := lb.NormalizePointer(chainedOffset); got != 0x100080120 {
		t.Fatalf("NormalizePointer(chainedOffset) = 0x%x, want 0x100080120", got)
	}

	// 2. Mach-O arm64e PAC authenticated rebase ((ptr>>62)==2, low32 = offset from ImageBase)
	pacPtr := (uint64(2) << 62) | 0x00090040
	if got := lb.NormalizePointer(pacPtr); got != 0x100090040 {
		t.Fatalf("NormalizePointer(pacPtr) = 0x%x, want 0x100090040", got)
	}

	// 3. Normalized section stem matching across Mach-O dot/comma prefixes
	if sec, _, ok := lb.SectionByName(".gopclntab"); !ok || sec == nil || sec.VirtualAddr != 0x100080000 {
		t.Fatalf("SectionByName(.gopclntab) failed on __TEXT.__gopclntab: %+v", sec)
	}
	if sec, _, ok := lb.SectionByName(".dep-v0"); !ok || sec == nil || sec.VirtualAddr != 0x100090000 {
		t.Fatalf("SectionByName(.dep-v0) failed on __DATA,.dep-v0: %+v", sec)
	}

	// 4. uint64 wraparound safety: low address 0x5 must NOT match __WRAP (^uint64(0)-15 + 64 wraps past 0x5)
	if _, ok := lb.VAToOffset(0x5); ok {
		t.Fatalf("VAToOffset(0x5) falsely matched overflowed section range")
	}
}

func TestNativeImportsAndUniversalFatMachOSelection(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "sample.go")
	code := `package main
import "fmt"
func main() { fmt.Println("symforge-imports-fat-check") }
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	build := func(goos, goarch string) string {
		outBin := filepath.Join(tmp, goos+"_"+goarch)
		if goos == "windows" {
			outBin += ".exe"
		}
		cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outBin, src)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s/%s failed: %v\n%s", goos, goarch, err, string(out))
		}
		return outBin
	}

	// 1. PE import table recovery
	peBin := build("windows", "amd64")
	lbPE, err := LoadFile(peBin)
	if err != nil {
		t.Fatalf("LoadFile PE failed: %v", err)
	}
	if len(lbPE.Imports) == 0 {
		t.Fatalf("expected PE imports > 0, got 0")
	}
	foundKernel32 := false
	for _, imp := range lbPE.Imports {
		if strings.EqualFold(imp.Library, "kernel32.dll") && imp.Name != "" && imp.Address != 0 {
			foundKernel32 = true
			break
		}
	}
	if !foundKernel32 {
		t.Errorf("expected PE kernel32.dll import with resolved symbol name & IAT VA, got %+v", lbPE.Imports[:minInt(len(lbPE.Imports), 10)])
	}

	// 2. Mach-O imports + synthetic Universal Fat Mach-O (arm64 + amd64 slices)
	armBin := build("darwin", "arm64")
	amdBin := build("darwin", "amd64")
	armBytes, err := os.ReadFile(armBin)
	if err != nil {
		t.Fatal(err)
	}
	amdBytes, err := os.ReadFile(amdBin)
	if err != nil {
		t.Fatal(err)
	}

	lbThinMachO, err := LoadBytes("thin_arm64", armBytes)
	if err != nil {
		t.Fatalf("LoadBytes thin Mach-O failed: %v", err)
	}
	foundLibSystem := false
	for _, imp := range lbThinMachO.Imports {
		if strings.Contains(imp.Library, "libSystem") {
			foundLibSystem = true
			break
		}
	}
	if !foundLibSystem {
		t.Errorf("expected Mach-O libSystem dylib import, got %+v", lbThinMachO.Imports)
	}

	// Pack arm64 and amd64 slices into a valid 0xCAFEBABE Universal Fat Mach-O binary
	fatBytes := buildUniversalFatMachO(t, []fatSlice{
		{cpu: macho.CpuArm64, subCPU: 0, align: 14, data: armBytes},
		{cpu: macho.CpuAmd64, subCPU: 3, align: 12, data: amdBytes},
	})
	fatPath := filepath.Join(tmp, "universal_app")
	if err := os.WriteFile(fatPath, fatBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	lbArm, err := LoadFileWithOptions(fatPath, LoadOptions{Arch: "arm64"})
	if err != nil {
		t.Fatalf("LoadFileWithOptions(arm64) failed: %v", err)
	}
	if lbArm.Info.Format != model.FormatMachOFat || lbArm.Info.Arch != model.ArchARM64 {
		t.Fatalf("expected macho-fat/arm64, got %s/%s", lbArm.Info.Format, lbArm.Info.Arch)
	}
	if len(lbArm.Info.AvailableArches) != 2 {
		t.Fatalf("expected 2 AvailableArches, got %v", lbArm.Info.AvailableArches)
	}

	lbAmd, err := LoadFileWithOptions(fatPath, LoadOptions{Arch: "amd64"})
	if err != nil {
		t.Fatalf("LoadFileWithOptions(amd64) failed: %v", err)
	}
	if lbAmd.Info.Arch != model.ArchX86_64 {
		t.Fatalf("expected x86_64 slice, got %s", lbAmd.Info.Arch)
	}

	if _, err := LoadFileWithOptions(fatPath, LoadOptions{Arch: "arm"}); err == nil {
		t.Fatalf("expected error requesting missing arch 'arm' from arm64+x86_64 Fat Mach-O")
	}
}

type fatSlice struct {
	cpu    macho.Cpu
	subCPU uint32
	align  uint32
	data   []byte
}

func buildUniversalFatMachO(t *testing.T, slices []fatSlice) []byte {
	t.Helper()
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(macho.MagicFat))
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(slices)))

	// Header = 8 + 20*N; align slices to 16384 (2^14)
	offset := uint32(16384)
	type hdrEntry struct {
		slice  fatSlice
		offset uint32
	}
	entries := make([]hdrEntry, len(slices))
	for i, s := range slices {
		alignBytes := uint32(1 << s.align)
		if rem := offset % alignBytes; rem != 0 {
			offset += alignBytes - rem
		}
		entries[i] = hdrEntry{slice: s, offset: offset}
		offset += uint32(len(s.data))
	}

	for _, e := range entries {
		_ = binary.Write(&buf, binary.BigEndian, uint32(e.slice.cpu))
		_ = binary.Write(&buf, binary.BigEndian, e.slice.subCPU)
		_ = binary.Write(&buf, binary.BigEndian, e.offset)
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(e.slice.data)))
		_ = binary.Write(&buf, binary.BigEndian, e.slice.align)
	}

	for _, e := range entries {
		if uint32(buf.Len()) < e.offset {
			buf.Write(make([]byte, int(e.offset)-buf.Len()))
		}
		buf.Write(e.slice.data)
	}
	return buf.Bytes()
}

// buildSyntheticPE constructs a minimal valid PE32 or PE32+ executable with a single .rdata
// section at RVA 0x1000 (file offset 0x200) containing rdata and pointing IMAGE_DIRECTORY_ENTRY_IMPORT
// at importRVA with importSize.
func buildSyntheticPE(is64 bool, imageBase uint64, entryRVA, importRVA, importSize uint32, rdata []byte) []byte {
	const (
		peOff      = 0x80
		secFileOff = 0x200
		secRVA     = 0x1000
	)
	secSize := len(rdata)
	if secSize < 0x200 {
		secSize = 0x200
	}
	buf := make([]byte, secFileOff+secSize)
	// DOS header
	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3c:0x40], peOff)
	// PE signature
	copy(buf[peOff:peOff+4], "PE\x00\x00")
	// COFF FileHeader (20 bytes)
	coffOff := peOff + 4
	optSize := uint16(224)
	machine := uint16(0x014c) // IMAGE_FILE_MACHINE_I386
	if is64 {
		optSize = 240
		machine = 0x8664 // IMAGE_FILE_MACHINE_AMD64
	}
	binary.LittleEndian.PutUint16(buf[coffOff+0:coffOff+2], machine)
	binary.LittleEndian.PutUint16(buf[coffOff+2:coffOff+4], 1) // NumberOfSections
	binary.LittleEndian.PutUint16(buf[coffOff+16:coffOff+18], optSize)
	binary.LittleEndian.PutUint16(buf[coffOff+18:coffOff+20], 0x0002) // IMAGE_FILE_EXECUTABLE_IMAGE

	// OptionalHeader
	optOff := coffOff + 20
	if is64 {
		binary.LittleEndian.PutUint16(buf[optOff+0:optOff+2], 0x20b) // PE32+
		binary.LittleEndian.PutUint32(buf[optOff+16:optOff+20], entryRVA)
		binary.LittleEndian.PutUint64(buf[optOff+24:optOff+32], imageBase)
		binary.LittleEndian.PutUint32(buf[optOff+32:optOff+36], 0x1000) // SectionAlignment
		binary.LittleEndian.PutUint32(buf[optOff+36:optOff+40], 0x200)  // FileAlignment
		binary.LittleEndian.PutUint32(buf[optOff+56:optOff+60], 0x4000) // SizeOfImage
		binary.LittleEndian.PutUint32(buf[optOff+60:optOff+64], 0x200)  // SizeOfHeaders
		binary.LittleEndian.PutUint32(buf[optOff+108:optOff+112], 16)   // NumberOfRvaAndSizes
		ddOff := optOff + 112 + 8                                       // DataDirectory[1] = IMPORT
		binary.LittleEndian.PutUint32(buf[ddOff:ddOff+4], importRVA)
		binary.LittleEndian.PutUint32(buf[ddOff+4:ddOff+8], importSize)
	} else {
		binary.LittleEndian.PutUint16(buf[optOff+0:optOff+2], 0x10b) // PE32
		binary.LittleEndian.PutUint32(buf[optOff+16:optOff+20], entryRVA)
		binary.LittleEndian.PutUint32(buf[optOff+28:optOff+32], uint32(imageBase))
		binary.LittleEndian.PutUint32(buf[optOff+32:optOff+36], 0x1000)
		binary.LittleEndian.PutUint32(buf[optOff+36:optOff+40], 0x200)
		binary.LittleEndian.PutUint32(buf[optOff+56:optOff+60], 0x4000)
		binary.LittleEndian.PutUint32(buf[optOff+60:optOff+64], 0x200)
		binary.LittleEndian.PutUint32(buf[optOff+92:optOff+96], 16)
		ddOff := optOff + 96 + 8 // DataDirectory[1] = IMPORT
		binary.LittleEndian.PutUint32(buf[ddOff:ddOff+4], importRVA)
		binary.LittleEndian.PutUint32(buf[ddOff+4:ddOff+8], importSize)
	}

	// Section header (.rdata)
	secHdrOff := optOff + int(optSize)
	copy(buf[secHdrOff:secHdrOff+8], ".rdata\x00\x00")
	binary.LittleEndian.PutUint32(buf[secHdrOff+8:secHdrOff+12], uint32(secSize))
	binary.LittleEndian.PutUint32(buf[secHdrOff+12:secHdrOff+16], secRVA)
	binary.LittleEndian.PutUint32(buf[secHdrOff+16:secHdrOff+20], uint32(secSize))
	binary.LittleEndian.PutUint32(buf[secHdrOff+20:secHdrOff+24], secFileOff)
	binary.LittleEndian.PutUint32(buf[secHdrOff+36:secHdrOff+40], peScnMemRead)

	copy(buf[secFileOff:], rdata)
	return buf
}

func TestCraftedPEImportTableHardening(t *testing.T) {
	// 1. Valid PE32 (4-byte thunks): named import + ordinal import + zero entryRVA (DLL)
	rdata32 := make([]byte, 0x200)
	// Descriptor at RVA 0x1000 (off 0): INT=0x1040, Name=0x1080, IAT=0x1060
	binary.LittleEndian.PutUint32(rdata32[0:4], 0x1040)
	binary.LittleEndian.PutUint32(rdata32[12:16], 0x1080)
	binary.LittleEndian.PutUint32(rdata32[16:20], 0x1060)
	// Thunks at off 0x40: named @ 0x10a0, ordinal #42 (0x8000002a), terminator 0
	binary.LittleEndian.PutUint32(rdata32[0x40:0x44], 0x10a0)
	binary.LittleEndian.PutUint32(rdata32[0x44:0x48], 0x8000002a)
	copy(rdata32[0x80:], "WS2_32.dll\x00")
	copy(rdata32[0xa2:], "WSAStartup\x00")

	pe32 := buildSyntheticPE(false, 0x400000, 0, 0x1000, 40, rdata32)
	lb32, err := LoadBytes("crafted32.dll", pe32)
	if err != nil {
		t.Fatalf("LoadBytes PE32 failed: %v", err)
	}
	if lb32.Info.EntryPoint != 0 {
		t.Errorf("expected EntryPoint=0 when entryRVA=0, got 0x%x", lb32.Info.EntryPoint)
	}
	if len(lb32.Imports) != 2 {
		t.Fatalf("expected 2 PE32 imports, got %+v", lb32.Imports)
	}
	if lb32.Imports[0].Name != "Ordinal#42" || lb32.Imports[1].Name != "WSAStartup" || lb32.Imports[1].Address != 0x401060 {
		t.Fatalf("unexpected PE32 imports: %+v", lb32.Imports)
	}

	// 2. PE32+ (8-byte thunks): valid named, valid ordinal, bound/corrupted upper-bits thunk (must skip),
	//    stripped INT falling back to IAT, and truncated non-null-terminated string at EOF.
	rdata64 := make([]byte, 0x200)
	// Descriptor 0: INT=0x999900 (unmapped -> must fall back to IAT=0x1060), Name=0x10c0, IAT=0x1060
	binary.LittleEndian.PutUint32(rdata64[0:4], 0x999900)
	binary.LittleEndian.PutUint32(rdata64[12:16], 0x10c0)
	binary.LittleEndian.PutUint32(rdata64[16:20], 0x1060)
	// Thunks at 0x60:
	//   [0] valid Hint/Name RVA 0x10e0 ("VirtualAlloc")
	//   [1] bound/corrupted 64-bit pointer 0x00007ff8_000010e0 (bits 31..62 non-zero -> MUST be ignored)
	//   [2] valid 64-bit ordinal (1<<63)|7 -> "Ordinal#7"
	//   [3] truncated string RVA pointing near EOF (0x11fa, no null byte) -> MUST be skipped cleanly
	//   [4] terminator 0
	binary.LittleEndian.PutUint64(rdata64[0x60:0x68], 0x10e0)
	binary.LittleEndian.PutUint64(rdata64[0x68:0x70], 0x00007ff8000010e0)
	binary.LittleEndian.PutUint64(rdata64[0x70:0x78], (uint64(1)<<63)|7)
	binary.LittleEndian.PutUint64(rdata64[0x78:0x80], 0x11fa)
	copy(rdata64[0xc0:], "KERNEL32.dll\x00")
	copy(rdata64[0xe2:], "VirtualAlloc\x00")
	copy(rdata64[0x1fc:], "NOZ!") // 4 bytes at very end of section without NUL

	pe64 := buildSyntheticPE(true, 0x140000000, 0x1000, 0x1000, 40, rdata64)
	lb64, err := LoadBytes("crafted64.exe", pe64)
	if err != nil {
		t.Fatalf("LoadBytes PE32+ failed: %v", err)
	}
	if len(lb64.Imports) != 2 {
		t.Fatalf("expected exactly 2 valid PE32+ imports (skipping bound/truncated thunks), got %+v", lb64.Imports)
	}
	if lb64.Imports[0].Name != "Ordinal#7" || lb64.Imports[1].Name != "VirtualAlloc" {
		t.Fatalf("unexpected PE32+ imports: %+v", lb64.Imports)
	}

	// 3. Circular / repeated descriptor DoS: 500 identical descriptors pointing to same thunk table
	rdataDoS := make([]byte, 512*20+0x200)
	thunkOff := 512 * 20
	nameOff := thunkOff + 0x40
	hintOff := thunkOff + 0x80
	for i := 0; i < 500; i++ {
		off := i * 20
		binary.LittleEndian.PutUint32(rdataDoS[off+0:off+4], uint32(0x1000+thunkOff))
		binary.LittleEndian.PutUint32(rdataDoS[off+12:off+16], uint32(0x1000+nameOff))
		binary.LittleEndian.PutUint32(rdataDoS[off+16:off+20], uint32(0x1000+thunkOff))
	}
	binary.LittleEndian.PutUint64(rdataDoS[thunkOff:thunkOff+8], uint64(0x1000+hintOff))
	copy(rdataDoS[nameOff:], "NTDLL.dll\x00")
	copy(rdataDoS[hintOff+2:], "NtClose\x00")

	peDoS := buildSyntheticPE(true, 0x140000000, 0x1000, 0x1000, uint32(500*20), rdataDoS)
	lbDoS, err := LoadBytes("crafted_dos.exe", peDoS)
	if err != nil {
		t.Fatalf("LoadBytes PE DoS failed: %v", err)
	}
	if len(lbDoS.Imports) > 2 {
		t.Fatalf("expected deduplicated/guarded imports from circular descriptors, got %d entries", len(lbDoS.Imports))
	}

	// 4. Huge ImageBase uint64 wraparound safety (must not panic)
	peWrap := buildSyntheticPE(true, ^uint64(0)-0x100, 0x1000, 0x1000, 40, rdata64)
	if _, err := LoadBytes("crafted_wrap.exe", peWrap); err != nil {
		t.Fatalf("LoadBytes PE wraparound failed unexpectedly: %v", err)
	}
}

func TestCraftedELFOverflowAndMissingDynsym(t *testing.T) {
	// 1. Minimal 64-bit ELF with 0 sections (sstrip) and PT_LOAD Filesz that overflows uint64(Off + Filesz)
	elfBuf := make([]byte, 0x200)
	copy(elfBuf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	elfBuf[4] = 2 // ELFCLASS64
	elfBuf[5] = 1 // ELFDATA2LSB
	elfBuf[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(elfBuf[16:18], 2)    // ET_EXEC
	binary.LittleEndian.PutUint16(elfBuf[18:20], 62)   // EM_X86_64
	binary.LittleEndian.PutUint32(elfBuf[20:24], 1)    // EV_CURRENT
	binary.LittleEndian.PutUint64(elfBuf[24:32], 0x400100)
	binary.LittleEndian.PutUint64(elfBuf[32:40], 64)   // e_phoff
	binary.LittleEndian.PutUint16(elfBuf[52:54], 64)   // e_ehsize
	binary.LittleEndian.PutUint16(elfBuf[54:56], 56)   // e_phentsize
	binary.LittleEndian.PutUint16(elfBuf[56:58], 1)    // e_phnum

	// PT_LOAD at offset 64 with p_offset=0x100 and p_filesz=0x7fffffffffffffff (exceeds file size & tests overflow-safe clamping)
	ph := elfBuf[64 : 64+56]
	binary.LittleEndian.PutUint32(ph[0:4], 1) // PT_LOAD
	binary.LittleEndian.PutUint32(ph[4:8], 5) // PF_R | PF_X
	binary.LittleEndian.PutUint64(ph[8:16], 0x100)
	binary.LittleEndian.PutUint64(ph[16:24], 0x400100)
	binary.LittleEndian.PutUint64(ph[24:32], 0x400100)
	binary.LittleEndian.PutUint64(ph[32:40], 0x7fffffffffffffff)
	binary.LittleEndian.PutUint64(ph[40:48], 0x7fffffffffffffff)
	binary.LittleEndian.PutUint64(ph[48:56], 0x1000)

	lb, err := LoadBytes("crafted_overflow.elf", elfBuf)
	if err != nil {
		t.Fatalf("LoadBytes stripped large-Filesz ELF failed: %v", err)
	}
	if len(lb.Sections) != 1 || lb.Sections[0].FileSize != 0x100 {
		t.Fatalf("expected clamped PT_LOAD section size 0x100, got %+v", lb.Sections)
	}
	if !lb.Info.Stripped {
		t.Errorf("expected Stripped=true on 0-section ELF")
	}

	// Also ensure extreme ^uint64(0)-0x50 Filesz fails cleanly without panicking
	binary.LittleEndian.PutUint64(ph[32:40], ^uint64(0)-0x50)
	if _, err := LoadBytes("crafted_wrap_elf.elf", elfBuf); err == nil {
		t.Fatalf("expected error for extreme >MaxInt64 ELF PT_LOAD Filesz")
	}

	// 2. ELF with truncated/out-of-bounds .dynsym section header (must load gracefully without failing)
	elfTrunc := make([]byte, 0x300)
	copy(elfTrunc[0:4], []byte{0x7f, 'E', 'L', 'F'})
	elfTrunc[4] = 2 // ELFCLASS64
	elfTrunc[5] = 1 // ELFDATA2LSB
	elfTrunc[6] = 1
	binary.LittleEndian.PutUint16(elfTrunc[16:18], 2)
	binary.LittleEndian.PutUint16(elfTrunc[18:20], 62)
	binary.LittleEndian.PutUint32(elfTrunc[20:24], 1)
	binary.LittleEndian.PutUint64(elfTrunc[40:48], 0x80) // e_shoff
	binary.LittleEndian.PutUint16(elfTrunc[52:54], 64)
	binary.LittleEndian.PutUint16(elfTrunc[58:60], 64) // e_shentsize
	binary.LittleEndian.PutUint16(elfTrunc[60:62], 3)  // e_shnum: NULL, .shstrtab, .dynsym
	binary.LittleEndian.PutUint16(elfTrunc[62:64], 1)  // e_shstrndx = 1

	shstr := []byte("\x00.shstrtab\x00.dynsym\x00")
	copy(elfTrunc[0x200:], shstr)
	// Section 1: .shstrtab
	sh1 := elfTrunc[0x80+64 : 0x80+128]
	binary.LittleEndian.PutUint32(sh1[0:4], 1)
	binary.LittleEndian.PutUint32(sh1[4:8], 3) // SHT_STRTAB
	binary.LittleEndian.PutUint64(sh1[24:32], 0x200)
	binary.LittleEndian.PutUint64(sh1[32:40], uint64(len(shstr)))
	// Section 2: .dynsym pointing past EOF (truncated binary)
	sh2 := elfTrunc[0x80+128 : 0x80+192]
	binary.LittleEndian.PutUint32(sh2[0:4], 11)
	binary.LittleEndian.PutUint32(sh2[4:8], 11) // SHT_DYNSYM
	binary.LittleEndian.PutUint64(sh2[24:32], 0x9000)
	binary.LittleEndian.PutUint64(sh2[32:40], 0x200)
	binary.LittleEndian.PutUint32(sh2[40:44], 1)  // sh_link
	binary.LittleEndian.PutUint64(sh2[56:64], 24) // sh_entsize

	lbTrunc, err := LoadBytes("truncated_dynsym.elf", elfTrunc)
	if err != nil {
		t.Fatalf("LoadBytes ELF with truncated .dynsym should succeed gracefully, got: %v", err)
	}
	if lbTrunc.Info.Format != model.FormatELF || !lbTrunc.Info.Stripped {
		t.Fatalf("unexpected truncated ELF info: %+v", lbTrunc.Info)
	}
}

func TestUniversalFatMachOAliasesAndAvailableArchesErrors(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "sample.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	build := func(goarch string) []byte {
		outBin := filepath.Join(tmp, "darwin_"+goarch)
		cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outBin, src)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=darwin", "GOARCH="+goarch)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build darwin/%s failed: %v\n%s", goarch, err, string(out))
		}
		b, err := os.ReadFile(outBin)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	armBytes := build("arm64")
	amdBytes := build("amd64")
	fatBytes := buildUniversalFatMachO(t, []fatSlice{
		{cpu: macho.CpuArm64, subCPU: 0, align: 14, data: armBytes},
		{cpu: macho.CpuAmd64, subCPU: 3, align: 12, data: amdBytes},
	})

	for _, tc := range []struct {
		alias string
		want  model.Architecture
	}{
		{"x86_64", model.ArchX86_64},
		{"amd64", model.ArchX86_64},
		{"x64", model.ArchX86_64},
		{"aarch64", model.ArchARM64},
		{"arm64", model.ArchARM64},
		{"arm64e", model.ArchARM64},
	} {
		lb, err := LoadBytesWithOptions("fat_alias", fatBytes, LoadOptions{Arch: tc.alias})
		if err != nil {
			t.Fatalf("alias %q failed: %v", tc.alias, err)
		}
		if lb.Info.Arch != tc.want {
			t.Errorf("alias %q -> arch %q, want %q", tc.alias, lb.Info.Arch, tc.want)
		}
	}

	// Both valid-but-missing arch AND unrecognized arch must list AvailableArches in error message
	for _, badArch := range []string{"x86", "mips64"} {
		_, err := LoadBytesWithOptions("fat_missing", fatBytes, LoadOptions{Arch: badArch})
		if err == nil {
			t.Fatalf("expected error for %q on arm64+x86_64 Fat Mach-O", badArch)
		}
		if !strings.Contains(err.Error(), "arm64") || !strings.Contains(err.Error(), "x86_64") {
			t.Errorf("error for %q did not list AvailableArches: %v", badArch, err)
		}
	}
}
