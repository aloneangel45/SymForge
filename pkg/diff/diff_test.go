package diff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloneangel45/symforge/pkg/analyzer"
	"github.com/aloneangel45/symforge/pkg/model"
)

func TestCompareSyntheticModels(t *testing.T) {
	base := &model.AnalysisResult{
		Binary: model.BinaryInfo{
			Path:       "app_v1.exe",
			SHA256:     "aaaa",
			SizeBytes:  100000,
			Format:     model.FormatPE,
			Arch:       model.ArchX86_64,
			MaxEntropy: 6.1,
		},
		Go: &model.GoMetadata{Detected: true, Version: "go1.26.0"},
		Packages: []model.PackageSummary{
			{Name: "main", Category: model.CategoryUser, FunctionCount: 2, TotalBytes: 300},
			{Name: "old/pkg", Category: model.CategoryUser, FunctionCount: 1, TotalBytes: 100},
			{Name: "runtime", Category: model.CategoryRuntime, FunctionCount: 1, TotalBytes: 50},
		},
		Functions: []model.Function{
			{Name: "main.main", Package: "main", Category: model.CategoryUser, Entry: 0x1000, Size: 200},
			{Name: "main.legacyHandler", Package: "main", Category: model.CategoryUser, Entry: 0x1200, Size: 100},
			{Name: "runtime.gopark", Package: "runtime", Category: model.CategoryRuntime, Entry: 0x2000, Size: 50},
		},
		Dependencies: []model.Dependency{
			{Ecosystem: "gomod", Name: "golang.org/x/crypto", Version: "v0.30.0"},
			{Ecosystem: "gomod", Name: "github.com/old/dep", Version: "v1.0.0"},
		},
		Imports: []model.ImportSymbol{
			{Library: "KERNEL32.dll", Name: "GetCurrentProcessId", Address: 0x4000},
		},
		Strings: []model.ExtractedString{
			{Value: "https://old.example.com/v1", Kind: model.StringURL, Addr: 0x5000},
			{Value: "noise general string", Kind: model.StringGeneral, Addr: 0x5100},
		},
		Crypto: []model.CryptoDetection{
			{Name: "SHA-256 K Constants", Algorithm: "SHA-256", Addr: 0x6000},
		},
	}

	target := &model.AnalysisResult{
		Binary: model.BinaryInfo{
			Path:       "app_v2.exe",
			SHA256:     "bbbb",
			SizeBytes:  120000,
			Format:     model.FormatPE,
			Arch:       model.ArchX86_64,
			MaxEntropy: 7.3,
		},
		Go: &model.GoMetadata{Detected: true, Version: "go1.27.3"},
		Packages: []model.PackageSummary{
			{Name: "main", Category: model.CategoryUser, FunctionCount: 2, TotalBytes: 420},
			{Name: "new/netc2", Category: model.CategoryUser, FunctionCount: 1, TotalBytes: 220},
			{Name: "runtime", Category: model.CategoryRuntime, FunctionCount: 1, TotalBytes: 80},
		},
		Functions: []model.Function{
			{Name: "main.main", Package: "main", Category: model.CategoryUser, Entry: 0x1000, Size: 260},
			{Name: "main.newBeacon", Package: "main", Category: model.CategoryUser, Entry: 0x1400, Size: 160},
			{Name: "runtime.gopark", Package: "runtime", Category: model.CategoryRuntime, Entry: 0x2000, Size: 80},
		},
		Dependencies: []model.Dependency{
			{Ecosystem: "gomod", Name: "golang.org/x/crypto", Version: "v0.35.0"},
			{Ecosystem: "gomod", Name: "github.com/new/dep", Version: "v2.0.0"},
		},
		Imports: []model.ImportSymbol{
			{Library: "KERNEL32.dll", Name: "GetCurrentProcessId", Address: 0x4000},
			{Library: "KERNEL32.dll", Name: "WriteProcessMemory", Address: 0x4008},
		},
		Strings: []model.ExtractedString{
			{Value: "https://new.example.com/v2", Kind: model.StringURL, Addr: 0x5200},
			{Value: "AKIAIOSFODNN7EXAMPLE", Kind: model.StringSecretCandidate, Addr: 0x5300},
		},
		Crypto: []model.CryptoDetection{
			{Name: "SHA-256 K Constants", Algorithm: "SHA-256", Addr: 0x6000},
			{Name: "AES Forward S-Box", Algorithm: "AES", Addr: 0x6200},
		},
	}

	res, err := Compare(base, target, Options{UserOnly: true, Limit: 50})
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if res.Identical {
		t.Fatalf("expected non-identical diff")
	}
	if res.Summary.AddedFunctions != 1 || res.AddedFunctions[0].Name != "main.newBeacon" {
		t.Fatalf("unexpected added functions: %+v", res.AddedFunctions)
	}
	if res.Summary.RemovedFunctions != 1 || res.RemovedFunctions[0].Name != "main.legacyHandler" {
		t.Fatalf("unexpected removed functions: %+v", res.RemovedFunctions)
	}
	if res.Summary.ModifiedFunctions != 1 || res.ModifiedFunctions[0].SizeDelta != 60 {
		t.Fatalf("unexpected modified functions: %+v", res.ModifiedFunctions)
	}
	if res.Summary.ChangedDeps != 1 || res.Dependencies.Changed[0].NewVersion != "v0.35.0" {
		t.Fatalf("unexpected dependency diff: %+v", res.Dependencies)
	}
	if res.Summary.AddedImports != 1 || res.Imports.Added[0].Name != "WriteProcessMemory" {
		t.Fatalf("unexpected import diff: %+v", res.Imports)
	}
	if res.Summary.AddedCrypto != 1 || res.Crypto.Added[0].Algorithm != "AES" {
		t.Fatalf("unexpected crypto diff: %+v", res.Crypto)
	}
	if res.Summary.AddedStrings != 2 || res.Summary.RemovedStrings != 1 {
		t.Fatalf("unexpected string diff summary: +%d -%d", res.Summary.AddedStrings, res.Summary.RemovedStrings)
	}

	// Verify critical highlight for WriteProcessMemory
	foundCrit := false
	for _, h := range res.RiskHighlights {
		if h.Severity == "critical" && strings.Contains(h.Detail, "WriteProcessMemory") {
			foundCrit = true
		}
	}
	if !foundCrit {
		t.Fatalf("expected critical risk highlight for WriteProcessMemory, got %+v", res.RiskHighlights)
	}

	// Identical comparison
	same, err := Compare(base, base, Options{})
	if err != nil {
		t.Fatalf("identical Compare failed: %v", err)
	}
	if !same.Identical {
		t.Fatalf("expected Identical=true when comparing binary with itself")
	}
}

func TestCompareRealStrippedGoBinaries(t *testing.T) {
	dir := t.TempDir()
	buildVersion := func(name, src string) string {
		sub := filepath.Join(dir, name)
		_ = os.MkdirAll(sub, 0o755)
		_ = os.WriteFile(filepath.Join(sub, "go.mod"), []byte("module example.com/difftest\n\ngo 1.24.0\n"), 0o644)
		_ = os.WriteFile(filepath.Join(sub, "main.go"), []byte(src), 0o644)
		outBin := filepath.Join(sub, name)
		cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outBin, ".")
		cmd.Dir = sub
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s failed: %v\n%s", name, err, string(out))
		}
		return outBin
	}

	v1 := buildVersion("v1", `package main
import "fmt"
//go:noinline
func OldWorker(x int) int { return x + 1 }
func main() { fmt.Println(OldWorker(1), "https://v1.symforge.test/api") }
`)
	v2 := buildVersion("v2", `package main
import "fmt"
//go:noinline
func NewWorker(x int) int { return x*3 + 7 }
func main() { fmt.Println(NewWorker(2), "https://v2.symforge.test/api") }
`)

	eng := analyzer.NewEngine(4)
	r1, err := eng.AnalyzeFile(v1, analyzer.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := eng.AnalyzeFile(v2, analyzer.Options{})
	if err != nil {
		t.Fatal(err)
	}

	dr, err := Compare(r1, r2, Options{UserOnly: true, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	foundAdded := false
	for _, fn := range dr.AddedFunctions {
		if fn.Name == "main.NewWorker" {
			foundAdded = true
		}
	}
	foundRemoved := false
	for _, fn := range dr.RemovedFunctions {
		if fn.Name == "main.OldWorker" {
			foundRemoved = true
		}
	}
	if !foundAdded || !foundRemoved {
		t.Fatalf("expected main.NewWorker added (%v) and main.OldWorker removed (%v); added=%+v removed=%+v",
			foundAdded, foundRemoved, dr.AddedFunctions, dr.RemovedFunctions)
	}
}

func TestCompareDuplicateFunctionNamesAndEdgeCases(t *testing.T) {
	// 1. Duplicate function names (Go init / Rust closures / stripped symbols) must NOT overwrite each other
	binA := &model.AnalysisResult{
		Binary: model.BinaryInfo{Path: "a", SHA256: "1111", Arch: model.ArchX86_64},
		Functions: []model.Function{
			{Name: "main.init", Package: "main", Category: model.CategoryUser, Entry: 0x1000, Size: 100, SourceFile: "a.go", Line: 10},
			{Name: "main.init", Package: "main", Category: model.CategoryUser, Entry: 0x1100, Size: 200, SourceFile: "b.go", Line: 20},
			{Name: "_RNvCs_worker_c1", Demangled: "crate::worker::{{closure}}", Package: "crate", Category: model.CategoryUser, Entry: 0x2000, Size: 80},
			{Name: "_RNvCs_worker_c2", Demangled: "crate::worker::{{closure}}", Package: "crate", Category: model.CategoryUser, Entry: 0x2100, Size: 120, CryptoRefs: []string{"aes", "SHA-256"}},
		},
	}
	binB := &model.AnalysisResult{
		Binary: model.BinaryInfo{Path: "b", SHA256: "2222", Arch: model.ArchX86_64},
		Functions: []model.Function{
			{Name: "main.init", Package: "main", Category: model.CategoryUser, Entry: 0x1000, Size: 100, SourceFile: "a.go", Line: 10},
			{Name: "main.init", Package: "main", Category: model.CategoryUser, Entry: 0x1100, Size: 200, SourceFile: "b.go", Line: 20},
			{Name: "main.init", Package: "main", Category: model.CategoryUser, Entry: 0x1300, Size: 150, SourceFile: "c.go", Line: 30},
			{Name: "_RNvCs_worker_c1", Demangled: "crate::worker::{{closure}}", Package: "crate", Category: model.CategoryUser, Entry: 0x2000, Size: 80},
			{Name: "_RNvCs_worker_c2", Demangled: "crate::worker::{{closure}}", Package: "crate", Category: model.CategoryUser, Entry: 0x2200, Size: 180, CryptoRefs: []string{"AES", "sha-256"}},
		},
		Imports: []model.ImportSymbol{
			// Benign Windows API containing "system" must NOT trigger sensitiveAPIs highlight
			{Library: "KERNEL32.dll", Name: "GetSystemInfo", Address: 0x9000},
		},
	}

	dr, err := Compare(binA, binB, Options{UserOnly: true})
	if err != nil {
		t.Fatalf("Compare duplicate functions failed: %v", err)
	}
	if dr.Summary.FunctionsA != 4 || dr.Summary.FunctionsB != 5 {
		t.Fatalf("expected FunctionsA=4 FunctionsB=5 (preserving duplicates), got A=%d B=%d", dr.Summary.FunctionsA, dr.Summary.FunctionsB)
	}
	if dr.Summary.AddedFunctions != 1 || dr.AddedFunctions[0].Entry != 0x1300 {
		t.Fatalf("expected 1 added main.init @ 0x1300, got %+v", dr.AddedFunctions)
	}
	if dr.Summary.ModifiedFunctions != 1 || dr.ModifiedFunctions[0].SizeDelta != 60 {
		t.Fatalf("expected 1 modified closure with delta +60, got %+v", dr.ModifiedFunctions)
	}
	// Case-insensitive CryptoRefs ["aes","SHA-256"] vs ["AES","sha-256"] must NOT report crypto_refs_changed
	for _, reason := range dr.ModifiedFunctions[0].Reasons {
		if reason == "crypto_refs_changed" {
			t.Fatalf("false positive crypto_refs_changed on case-only difference: %+v", dr.ModifiedFunctions[0].Reasons)
		}
	}
	if dr.Summary.UnchangedFunctions != 3 {
		t.Fatalf("expected 3 unchanged duplicate functions, got %d", dr.Summary.UnchangedFunctions)
	}
	// Verify GetSystemInfo did not trigger sensitive native import highlight
	for _, h := range dr.RiskHighlights {
		if strings.Contains(h.Detail, "GetSystemInfo") {
			t.Fatalf("false positive sensitive API highlight on GetSystemInfo: %+v", h)
		}
	}

	// 2. Empty binaries diff cleanly
	emptyA := &model.AnalysisResult{Binary: model.BinaryInfo{Path: "e1", Arch: model.ArchX86_64}}
	emptyB := &model.AnalysisResult{Binary: model.BinaryInfo{Path: "e2", Arch: model.ArchX86_64}}
	emptyDiff, err := Compare(emptyA, emptyB, Options{})
	if err != nil || !emptyDiff.Identical || emptyDiff.Summary.FunctionsA != 0 {
		t.Fatalf("unexpected empty diff: err=%v res=%+v", err, emptyDiff)
	}

	// 3. Same Fat Mach-O SHA256 but different Arch slices with different functions must NOT be Identical
	fatArm := &model.AnalysisResult{
		Binary:    model.BinaryInfo{Path: "fat", SHA256: "samehash", Arch: model.ArchARM64},
		Functions: []model.Function{{Name: "arm_only", Entry: 0x1000, Size: 32, Category: model.CategoryUser}},
	}
	fatAmd := &model.AnalysisResult{
		Binary:    model.BinaryInfo{Path: "fat", SHA256: "samehash", Arch: model.ArchX86_64},
		Functions: []model.Function{{Name: "amd_only", Entry: 0x2000, Size: 64, Category: model.CategoryUser}},
	}
	fatDiff, err := Compare(fatArm, fatAmd, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if fatDiff.Identical {
		t.Fatalf("expected Identical=false when comparing different Arch slices of same Fat Mach-O")
	}
}
