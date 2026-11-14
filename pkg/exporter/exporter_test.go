package exporter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aloneangel45/symforge/pkg/model"
)

func sampleResult() *model.AnalysisResult {
	return &model.AnalysisResult{
		Binary: model.BinaryInfo{
			Path:        `C:\samples\vaultd.exe`,
			SHA256:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			SizeBytes:   4194304,
			Format:      model.FormatPE,
			Arch:        model.ArchX86_64,
			Endianness:  "little",
			PointerSize: 8,
			EntryPoint:  0x140001000,
			ImageBase:   0x140000000,
			Stripped:    true,
			Language:    model.LangGo,
		},
		Go: &model.GoMetadata{
			Detected:       true,
			Version:        "go1.27.3",
			PCLnTabVersion: "go1.20+",
			PCLnTabMagic:   0xfffffff1,
			MainModule:     "github.com/acme/vaultd",
			ModuleVersion:  "v1.4.0",
		},
		Packages: []model.PackageSummary{
			{Name: "github.com/acme/vaultd/internal/auth", Category: model.CategoryUser, FunctionCount: 1, TotalBytes: 240},
			{Name: "runtime", Category: model.CategoryRuntime, FunctionCount: 1, TotalBytes: 128},
		},
		Functions: []model.Function{
			{
				Name:       "github.com/acme/vaultd/internal/auth.(*Verifier).VerifyToken",
				Package:    "github.com/acme/vaultd/internal/auth",
				SourceFile: "/workspace/internal/auth/verify.go",
				Line:       42,
				Entry:      0x140088120,
				Size:       240,
				Category:   model.CategoryUser,
				CryptoRefs: []string{"SHA-256 K Constants"},
				StringRefs: []model.StringRef{
					{Addr: 0x140120000, InsnAddr: 0x140088148, Value: "https://vault.acme.internal/v1/verify", Kind: model.StringURL},
				},
			},
			{
				Name:     "runtime.gopark",
				Package:  "runtime",
				Entry:    0x140031000,
				Size:     128,
				Category: model.CategoryRuntime,
			},
		},
		Types: []model.RecoveredType{
			{
				Name:    "auth.TokenClaims",
				Package: "github.com/acme/vaultd/internal/auth",
				Kind:    "struct",
				Size:    48,
				Addr:    0x140150000,
			},
		},
		Dependencies: []model.Dependency{
			{Name: "golang.org/x/crypto", Version: "v0.31.0", Ecosystem: "golang", Source: "go.buildinfo"},
			{Name: "serde", Version: "1.0.215", Ecosystem: "cargo", Source: "rust.dep-v0"},
		},
		Strings: []model.ExtractedString{
			{Value: "https://vault.acme.internal/v1/verify", Addr: 0x140120000, Kind: model.StringURL, ReferencedBy: []uint64{0x140088120}},
		},
		Crypto: []model.CryptoDetection{
			{Name: "SHA-256 K Constants", Algorithm: "SHA-256", Addr: 0x140160000, Confidence: "high", ReferencedBy: []uint64{0x140088120}},
		},
	}
}

func TestExportAllFormats(t *testing.T) {
	res := sampleResult()

	ghidraOut, err := Export(res, FormatGhidra, Options{UserOnly: true})
	if err != nil {
		t.Fatalf("ghidra export failed: %v", err)
	}
	gs := string(ghidraOut)
	if !strings.Contains(gs, "ORIG_IMAGE_BASE = 0x140000000") || !strings.Contains(gs, "VerifyToken") {
		t.Fatalf("unexpected ghidra output:\n%s", gs)
	}
	if strings.Contains(gs, "runtime.gopark") {
		t.Fatalf("UserOnly=true leaked runtime.gopark into ghidra script")
	}

	idaOut, err := Export(res, FormatIDA, Options{UserOnly: false})
	if err != nil {
		t.Fatalf("ida export failed: %v", err)
	}
	if !strings.Contains(string(idaOut), "runtime.gopark") || !strings.Contains(string(idaOut), "ida_nalt.get_imagebase()") {
		t.Fatalf("unexpected ida output:\n%s", string(idaOut))
	}

	binjaOut, err := Export(res, FormatBinja, Options{UserOnly: true})
	if err != nil {
		t.Fatalf("binja export failed: %v", err)
	}
	if !strings.Contains(string(binjaOut), "SymbolType.FunctionSymbol") {
		t.Fatalf("unexpected binja output:\n%s", string(binjaOut))
	}

	mdOut, err := Export(res, FormatMarkdown, Options{UserOnly: true})
	if err != nil {
		t.Fatalf("markdown export failed: %v", err)
	}
	if !strings.Contains(string(mdOut), "go1.27.3") || !strings.Contains(string(mdOut), "https://vault.acme.internal/v1/verify") {
		t.Fatalf("unexpected markdown output:\n%s", string(mdOut))
	}

	sbomOut, err := Export(res, FormatSBOM, Options{})
	if err != nil {
		t.Fatalf("sbom export failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(sbomOut, &parsed); err != nil {
		t.Fatalf("invalid CycloneDX JSON: %v", err)
	}
	if parsed["bomFormat"] != "CycloneDX" || parsed["specVersion"] != "1.5" {
		t.Fatalf("unexpected CycloneDX header: %+v", parsed)
	}
	meta := parsed["metadata"].(map[string]any)
	comp := meta["component"].(map[string]any)
	if comp["name"] != "vaultd.exe" {
		t.Fatalf("expected normalized Windows basename vaultd.exe, got %v", comp["name"])
	}
	if !strings.Contains(string(sbomOut), "pkg:golang/golang.org/x/crypto@v0.31.0") || !strings.Contains(string(sbomOut), "pkg:cargo/serde@1.0.215") {
		t.Fatalf("missing expected purls in SBOM:\n%s", string(sbomOut))
	}
}
