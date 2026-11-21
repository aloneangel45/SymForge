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
