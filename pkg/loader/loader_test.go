package loader

import (
	"os"
	"os/exec"
	"path/filepath"
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
