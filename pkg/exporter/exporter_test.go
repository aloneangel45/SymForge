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
			{Name: "golang.org/x/crypto", Version: "v0.31.0", Ecosystem: "gomod", Source: "buildinfo"},
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
	if !strings.Contains(gs, "println = print") {
		t.Fatalf("expected PyGhidra Python 3 println fallback in ghidra script")
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
	if comp["name"] != "vaultd.exe" || comp["version"] != "v1.4.0" {
		t.Fatalf("expected normalized Windows basename vaultd.exe and version v1.4.0, got name=%v version=%v", comp["name"], comp["version"])
	}
	if !strings.Contains(string(sbomOut), "pkg:golang/golang.org/x/crypto@v0.31.0") || !strings.Contains(string(sbomOut), "pkg:cargo/serde@1.0.215") {
		t.Fatalf("missing expected purls in SBOM:\n%s", string(sbomOut))
	}

	// Graphviz DOT & Mermaid call graph exports
	res.Functions[0].Calls = []uint64{0x140031000}
	dotOut, err := Export(res, FormatDOT, Options{UserOnly: false, Limit: 20})
	if err != nil {
		t.Fatalf("dot export failed: %v", err)
	}
	ds := string(dotOut)
	if !strings.Contains(ds, "digraph SymForgeCallGraph") || !strings.Contains(ds, "fn_140088120 -> fn_140031000;") {
		t.Fatalf("unexpected DOT output:\n%s", ds)
	}

	mmdOut, err := Export(res, FormatMermaid, Options{UserOnly: false, Limit: 20})
	if err != nil {
		t.Fatalf("mermaid export failed: %v", err)
	}
	ms := string(mmdOut)
	if !strings.Contains(ms, "flowchart LR") || !strings.Contains(ms, "fn_140088120 --> fn_140031000") {
		t.Fatalf("unexpected Mermaid output:\n%s", ms)
	}

	// UserOnly graph export omits runtime edge cleanly
	mmdUser, err := Export(res, FormatMermaid, Options{UserOnly: true, Limit: 20})
	if err != nil {
		t.Fatalf("mermaid user-only export failed: %v", err)
	}
	if strings.Contains(string(mmdUser), "runtime.gopark") {
		t.Fatalf("UserOnly=true leaked runtime.gopark into Mermaid graph")
	}
}

func TestGraphExportDOTAndMermaidEscapingHardening(t *testing.T) {
	// Nil safety
	if got := ExportDOT(nil, Options{}); got != nil {
		t.Fatalf("expected nil from ExportDOT(nil), got %q", string(got))
	}
	if got := ExportMermaid(nil, Options{}); got != nil {
		t.Fatalf("expected nil from ExportMermaid(nil), got %q", string(got))
	}

	res := &model.AnalysisResult{
		Binary: model.BinaryInfo{
			Path:   "/tmp/evil\"path\n%%inject\\bin",
			Format: model.FormatELF,
			Arch:   model.ArchX86_64,
		},
		Functions: []model.Function{
			{
				Name:     "github.com/org/repo/pkg.(*Client[string]).Do\"Quote\"\nInject",
				Category: model.CategoryUser,
				Entry:    0x401000,
				Calls:    []uint64{0x402000, 0x403000},
			},
			// Duplicate Entry should be deduplicated cleanly
			{
				Name:     "duplicate_entry_ignored",
				Category: model.CategoryUser,
				Entry:    0x401000,
			},
			{
				Name:      "_RNvCs_vec",
				Demangled: "alloc::vec::Vec<&mut [u8]>::{{closure}}",
				Category:  model.CategoryDependency,
				Entry:     0x402000,
				Calls:     []uint64{0x403000},
			},
			{
				Name:     "main.func1.1 | pipe; semi #1 `tick` [arr] (arg)",
				Category: model.CategoryUser,
				Entry:    0x403000,
			},
		},
	}

	// 1. Graphviz DOT verification
	dotBytes := ExportDOT(res, Options{Limit: 20})
	dotStr := string(dotBytes)
	if strings.Count(dotStr, "fn_401000 [label=") != 1 {
		t.Fatalf("expected deduplicated single DOT node for fn_401000:\n%s", dotStr)
	}
	// Every node line must have balanced unescaped quotes and no raw control chars/newlines inside label
	for _, line := range strings.Split(dotStr, "\n") {
		if strings.Contains(line, "[label=\"") {
			unescapedQuotes := 0
			for i := 0; i < len(line); i++ {
				if line[i] == '"' {
					bs := 0
					for j := i - 1; j >= 0 && line[j] == '\\'; j-- {
						bs++
					}
					if bs%2 == 0 {
						unescapedQuotes++
					}
				}
			}
			if unescapedQuotes%2 != 0 {
				t.Fatalf("unbalanced DOT quotes on line: %s", line)
			}
		}
	}
	if !strings.Contains(dotStr, `\"Quote\"`) {
		t.Fatalf("expected escaped quotes in DOT output:\n%s", dotStr)
	}

	// 2. Mermaid verification
	mmdBytes := ExportMermaid(res, Options{Limit: 20})
	mmdStr := string(mmdBytes)
	if strings.Count(mmdStr, "fn_401000[") != 1 {
		t.Fatalf("expected deduplicated single Mermaid node for fn_401000:\n%s", mmdStr)
	}
	// Verify header comment didn't inject a second line
	lines := strings.Split(mmdStr, "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "  %% SymForge Call Graph:") || strings.Contains(lines[2], "inject") {
		t.Fatalf("Mermaid comment newline injection detected:\n%s", mmdStr)
	}
	// Inspect every Mermaid node label inside fn_<hex>["..."]:::cls
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(trim, "fn_") || !strings.Contains(trim, "[\"") {
			continue
		}
		start := strings.Index(trim, "[\"") + 2
		end := strings.LastIndex(trim, "\"]:::")
		if end <= start {
			t.Fatalf("malformed Mermaid node line: %s", line)
		}
		label := trim[start:end]
		for _, forbidden := range []string{`"`, "`", "[", "]", "{", "}", "<", ">", "|"} {
			if strings.Contains(label, forbidden) {
				t.Errorf("unescaped hazardous Mermaid char %q in label %q", forbidden, label)
			}
		}
	}
	for _, wantEntity := range []string{"&amp;", "&lt;", "&gt;", "&quot;", "&#123;&#123;closure&#125;&#125;", "&#124;", "&#59;", "&#91;", "&#93;", "&#96;", "&#35;"} {
		if !strings.Contains(mmdStr, wantEntity) {
			t.Errorf("expected Mermaid entity %q in output:\n%s", wantEntity, mmdStr)
		}
	}
}
