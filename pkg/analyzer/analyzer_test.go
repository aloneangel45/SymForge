package analyzer

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

func buildStrippedGoSample(t *testing.T, goos, goarch string) string {
	t.Helper()
	dir := t.TempDir()
	mod := "module example.com/vaultprobe\n\ngo 1.24.0\n"
	src := `package main

import (
	"crypto/sha256"
	"fmt"
)

type VaultConfig struct {
	Endpoint string ` + "`json:\"endpoint\"`" + `
	Retries  int    ` + "`json:\"retries\"`" + `
}

//go:noinline
func VerifyEndpoint(cfg VaultConfig) [32]byte {
	msg := cfg.Endpoint + "/v1/health"
	return sha256.Sum256([]byte(msg))
}

func main() {
	cfg := VaultConfig{Endpoint: "https://vault.symforge.internal", Retries: 3}
	sum := VerifyEndpoint(cfg)
	fmt.Printf("%x\n", sum[0])
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	outBin := filepath.Join(dir, "vaultprobe")
	if goos == "windows" {
		outBin += ".exe"
	}
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", outBin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build (%s/%s) failed: %v\n%s", goos, goarch, err, string(out))
	}
	return outBin
}

func TestEngineAnalyzeAndInspectStrippedGo(t *testing.T) {
	binPath := buildStrippedGoSample(t, "linux", "amd64")
	eng := NewEngine(4)

	res, err := eng.AnalyzeFile(binPath, Options{})
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}
	if res.Binary.Language != model.LangGo {
		t.Fatalf("expected LangGo, got %s", res.Binary.Language)
	}
	if !res.Binary.Stripped {
		t.Fatalf("expected stripped=true")
	}
	if res.Go == nil || !res.Go.Detected {
		t.Fatalf("expected Go metadata detected")
	}

	// Second call must hit cache cleanly and return identical pointer/data
	resCached, err := eng.AnalyzeFile(binPath, Options{})
	if err != nil {
		t.Fatalf("cached AnalyzeFile failed: %v", err)
	}
	if resCached.Binary.SHA256 != res.Binary.SHA256 {
		t.Fatalf("cache mismatch")
	}

	insp, err := eng.InspectFunction(binPath, "VerifyEndpoint", true, 80)
	if err != nil {
		t.Fatalf("InspectFunction(VerifyEndpoint) failed: %v", err)
	}
	if !strings.Contains(insp.Function.Name, "VerifyEndpoint") {
		t.Fatalf("unexpected function %q", insp.Function.Name)
	}
	if len(insp.Instructions) == 0 {
		t.Fatalf("expected decoded x86_64 instructions for VerifyEndpoint")
	}
}

func TestConcurrentColdCacheDeduplicationAndInMemoryDisasm(t *testing.T) {
	origPath := buildStrippedGoSample(t, "linux", "amd64")
	// Copy to a disposable path so we can test in-memory disassembly even if we don't touch disk again
	tmpCopy := filepath.Join(t.TempDir(), "vaultprobe_copy")
	raw, err := os.ReadFile(origPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpCopy, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(4)
	const workers = 8
	results := make([]*model.AnalysisResult, workers)
	errs := make([]error, workers)

	done := make(chan int, workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			results[idx], errs[idx] = eng.AnalyzeFile(tmpCopy, Options{})
			done <- idx
		}(i)
	}
	for i := 0; i < workers; i++ {
		<-done
	}
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d failed: %v", i, errs[i])
		}
		if results[i] != results[0] {
			t.Fatalf("expected concurrent cold-cache callers to share deduplicated *AnalysisResult pointer")
		}
	}

	insp, err := eng.InspectFunction(tmpCopy, "VerifyEndpoint", true, 64)
	if err != nil || len(insp.Instructions) == 0 {
		t.Fatalf("InspectFunction from cached LoadedBinary failed: err=%v insns=%d", err, len(insp.Instructions))
	}
}

func TestCacheKeyArchOptionsAndRapidSameSizeOverwrite(t *testing.T) {
	// 1. Fat Mach-O cache isolation across --arch slices + AvailableArches error propagation
	armPath := buildStrippedGoSample(t, "darwin", "arm64")
	amdPath := buildStrippedGoSample(t, "darwin", "amd64")
	armRaw, err := os.ReadFile(armPath)
	if err != nil {
		t.Fatal(err)
	}
	amdRaw, err := os.ReadFile(amdPath)
	if err != nil {
		t.Fatal(err)
	}

	var fatBuf bytes.Buffer
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(macho.MagicFat))
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(2))
	off1 := uint32(16384)
	off2 := off1 + uint32(len(armRaw))
	if rem := off2 % 4096; rem != 0 {
		off2 += 4096 - rem
	}
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(macho.CpuArm64))
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(0))
	_ = binary.Write(&fatBuf, binary.BigEndian, off1)
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(len(armRaw)))
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(14))
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(macho.CpuAmd64))
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(3))
	_ = binary.Write(&fatBuf, binary.BigEndian, off2)
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(len(amdRaw)))
	_ = binary.Write(&fatBuf, binary.BigEndian, uint32(12))
	fatBuf.Write(make([]byte, int(off1)-fatBuf.Len()))
	fatBuf.Write(armRaw)
	fatBuf.Write(make([]byte, int(off2)-fatBuf.Len()))
	fatBuf.Write(amdRaw)

	fatPath := filepath.Join(t.TempDir(), "universal_probe")
	if err := os.WriteFile(fatPath, fatBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(8)
	resArm, err := eng.AnalyzeFile(fatPath, Options{Arch: "arm64"})
	if err != nil {
		t.Fatalf("AnalyzeFile(arm64) failed: %v", err)
	}
	resAmd, err := eng.AnalyzeFile(fatPath, Options{Arch: "x86_64"})
	if err != nil {
		t.Fatalf("AnalyzeFile(x86_64) failed: %v", err)
	}
	if resArm.Binary.Arch != model.ArchARM64 || resAmd.Binary.Arch != model.ArchX86_64 {
		t.Fatalf("cache collided across Fat Mach-O slices: arm=%s amd=%s", resArm.Binary.Arch, resAmd.Binary.Arch)
	}
	if _, err := eng.AnalyzeFile(fatPath, Options{Arch: "riscv64"}); err == nil || !strings.Contains(err.Error(), "arm64") {
		t.Fatalf("expected invalid arch error on Fat Mach-O to list available arches, got: %v", err)
	}

	// 2. Rapid in-place same-size overwrite with IDENTICAL mtime must NOT return stale cache!
	mutPath := filepath.Join(t.TempDir(), "mutable_bin")
	raw1, err := os.ReadFile(buildStrippedGoSample(t, "linux", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mutPath, raw1, 0o644); err != nil {
		t.Fatal(err)
	}
	st1, err := os.Stat(mutPath)
	if err != nil {
		t.Fatal(err)
	}

	r1, err := eng.AnalyzeFile(mutPath, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Flip bytes inside the URL string while keeping EXACT same length and restoring identical mtime
	raw2 := append([]byte(nil), raw1...)
	idx := bytes.Index(raw2, []byte("https://vault.symforge.internal"))
	if idx < 0 {
		t.Fatal("expected test marker string in binary")
	}
	copy(raw2[idx:], "https://patch.symforge.internal")
	if err := os.WriteFile(mutPath, raw2, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(mutPath, st1.ModTime(), st1.ModTime()); err != nil {
		t.Fatal(err)
	}

	r2, err := eng.AnalyzeFile(mutPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Binary.SHA256 == r2.Binary.SHA256 {
		t.Fatalf("cache returned stale SHA256 after same-size same-mtime overwrite!")
	}

	// 3. Different MaxStrings options must not collide in cache
	rFew, err := eng.AnalyzeFile(mutPath, Options{MaxStrings: 5})
	if err != nil {
		t.Fatal(err)
	}
	rMany, err := eng.AnalyzeFile(mutPath, Options{MaxStrings: 500})
	if err != nil {
		t.Fatal(err)
	}
	if len(rFew.Strings) > 5 || len(rMany.Strings) <= len(rFew.Strings) {
		t.Fatalf("cache collided across MaxStrings options: few=%d many=%d", len(rFew.Strings), len(rMany.Strings))
	}
}
