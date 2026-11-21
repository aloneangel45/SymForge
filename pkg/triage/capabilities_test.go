package triage

import (
	"testing"

	"github.com/aloneangel45/symforge/pkg/model"
)

func TestScanCapabilitiesAndIoCs(t *testing.T) {
	res := &model.AnalysisResult{
		Binary: model.BinaryInfo{
			Path:       "implant.exe",
			Format:     model.FormatPE,
			Arch:       model.ArchX86_64,
			Language:   model.LangGo,
			MaxEntropy: 7.62,
		},
		Sections: []model.SectionInfo{
			{Name: "UPX0", VirtualAddr: 0x140001000, FileSize: 65536, Entropy: 7.62, Executable: true},
		},
		Imports: []model.ImportSymbol{
			{Library: "KERNEL32.dll", Name: "VirtualAllocEx"},
			{Library: "KERNEL32.dll", Name: "WriteProcessMemory"},
			{Library: "KERNEL32.dll", Name: "CreateRemoteThread"},
			{Library: "KERNEL32.dll", Name: "CreateProcessW"},
			{Library: "KERNEL32.dll", Name: "IsDebuggerPresent"},
			{Library: "WINHTTP.dll", Name: "WinHttpOpen"},
			{Library: "ADVAPI32.dll", Name: "RegSetValueExW"},
			{Library: "ADVAPI32.dll", Name: "AdjustTokenPrivileges"},
		},
		Functions: []model.Function{
			{Name: "os/exec.(*Cmd).Start", Package: "os/exec", Category: model.CategoryStdlib},
			{Name: "net/http.(*Client).Do", Package: "net/http", Category: model.CategoryStdlib},
			{Name: "crypto/aes.NewCipher", Package: "crypto/aes", Category: model.CategoryStdlib},
		},
		Strings: []model.ExtractedString{
			{Value: "https://c2.example.org/beacon", Kind: model.StringURL, Addr: 0x1000},
			{Value: "connect to 198.51.100.42:443 fallback 10.0.0.5 and 2001:db8::1", Kind: model.StringGeneral, Addr: 0x1100},
			{Value: `Software\Microsoft\Windows\CurrentVersion\Run`, Kind: model.StringGeneral, Addr: 0x1200},
			{Value: "AKIAIOSFODNN7EXAMPLE", Kind: model.StringSecretCandidate, Addr: 0x1300},
			{Value: "/proc/self/status", Kind: model.StringFilePath, Addr: 0x1400},
			{Value: "cmd.exe /c whoami", Kind: model.StringCommand, Addr: 0x1500},
			{Value: "version v1.2.3.4 and OID 1.2.840.113549.1.1.1 and x509 2.5.4.10 and rust ring::aead sha2::", Kind: model.StringGeneral, Addr: 0x1600},
		},
		Crypto: []model.CryptoDetection{
			{Name: "AES Forward S-Box", Algorithm: "AES", Addr: 0x2000},
		},
	}

	rep, err := Scan(res)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if rep.RiskLevel != SeverityCritical {
		t.Fatalf("expected critical risk level, got %s", rep.RiskLevel)
	}
	if !rep.Obfuscation.UPXDetected || !rep.Obfuscation.PackedLikely {
		t.Fatalf("expected UPX and PackedLikely=true, got %+v", rep.Obfuscation)
	}

	// Verify IoC extraction accuracy (public vs private IPv4, IPv6, URL, no false-positive v1.2.3.4 or OID)
	if len(rep.NetworkIoCs.URLs) != 1 || rep.NetworkIoCs.URLs[0] != "https://c2.example.org/beacon" {
		t.Errorf("unexpected URLs: %+v", rep.NetworkIoCs.URLs)
	}
	if len(rep.NetworkIoCs.PublicIPv4) != 1 || rep.NetworkIoCs.PublicIPv4[0] != "198.51.100.42" {
		t.Errorf("unexpected PublicIPv4 (should exclude v1.2.3.4 and OID): %+v", rep.NetworkIoCs.PublicIPv4)
	}
	if len(rep.NetworkIoCs.PrivateIPv4) != 1 || rep.NetworkIoCs.PrivateIPv4[0] != "10.0.0.5" {
		t.Errorf("unexpected PrivateIPv4: %+v", rep.NetworkIoCs.PrivateIPv4)
	}
	if len(rep.NetworkIoCs.IPv6) != 1 || rep.NetworkIoCs.IPv6[0] != "2001:db8::1" {
		t.Errorf("unexpected IPv6: %+v", rep.NetworkIoCs.IPv6)
	}

	// Verify all expected finding categories were emitted
	cats := make(map[string]bool)
	for _, f := range rep.Findings {
		cats[f.Category] = true
	}
	for _, want := range []string{"execution", "network", "memory_injection", "anti_debug", "persistence", "privilege", "crypto", "secrets", "packer"} {
		if !cats[want] {
			t.Errorf("missing expected finding category %q; got %+v", want, cats)
		}
	}
}

func TestGarbleObfuscationDetectionVsCleanGoBinary(t *testing.T) {
	// 1. Garble-obfuscated Go binary: stripped BuildInfo + random base64-like pkg/fn names + missing source files
	garbled := &model.AnalysisResult{
		Binary: model.BinaryInfo{
			Path:     "garbled_agent",
			Format:   model.FormatELF,
			Arch:     model.ArchX86_64,
			Language: model.LangGo,
		},
		Go: &model.GoMetadata{
			Detected: true,
			Version:  "", // stripped
		},
		Packages: []model.PackageSummary{
			{Name: "z8K2mN9q", Category: model.CategoryUser, FunctionCount: 3},
			{Name: "X4vB1pL0", Category: model.CategoryUser, FunctionCount: 3},
			{Name: "k9_mP2xZ", Category: model.CategoryDependency, FunctionCount: 2},
		},
		Functions: []model.Function{
			{Name: "z8K2mN9q.Q7wE3rT9", Package: "z8K2mN9q", Category: model.CategoryUser},
			{Name: "z8K2mN9q.M2nB8vC4", Package: "z8K2mN9q", Category: model.CategoryUser},
			{Name: "X4vB1pL0.H5jK9lP1", Package: "X4vB1pL0", Category: model.CategoryUser},
			{Name: "X4vB1pL0.R8tY2uI6", Package: "X4vB1pL0", Category: model.CategoryUser},
			{Name: "k9_mP2xZ.W3eR7tY1", Package: "k9_mP2xZ", Category: model.CategoryDependency},
			{Name: "runtime.gopark", Package: "runtime", Category: model.CategoryRuntime},
			{Name: "runtime.mallocgc", Package: "runtime", Category: model.CategoryRuntime},
			{Name: "runtime.schedule", Package: "runtime", Category: model.CategoryRuntime},
			{Name: "runtime.mstart", Package: "runtime", Category: model.CategoryRuntime},
			{Name: "runtime.newproc", Package: "runtime", Category: model.CategoryRuntime},
		},
	}

	gRep, err := Scan(garbled)
	if err != nil {
		t.Fatal(err)
	}
	if !gRep.Obfuscation.GarbleLikely || gRep.Obfuscation.GarbleScore < 75 {
		t.Fatalf("expected GarbleLikely=true with high score, got %+v", gRep.Obfuscation)
	}

	// 2. Normal stripped Go binary (keeps BuildInfo, readable names, source paths): must NOT trigger GarbleLikely
	clean := &model.AnalysisResult{
		Binary: model.BinaryInfo{
			Path:     "clean_server",
			Format:   model.FormatELF,
			Arch:     model.ArchX86_64,
			Language: model.LangGo,
			Stripped: true,
		},
		Go: &model.GoMetadata{
			Detected:      true,
			Version:       "go1.27.3",
			MainModule:    "github.com/acme/server",
			BuildSettings: map[string]string{"GOOS": "linux", "GOARCH": "amd64"},
		},
		Packages: []model.PackageSummary{
			{Name: "main", Category: model.CategoryUser, FunctionCount: 3},
			{Name: "github.com/acme/server/internal/api", Category: model.CategoryUser, FunctionCount: 2},
		},
		Functions: []model.Function{
			{Name: "main.main", Package: "main", Category: model.CategoryUser, SourceFile: "cmd/server/main.go"},
			{Name: "main.HandleHTTP", Package: "main", Category: model.CategoryUser, SourceFile: "cmd/server/http.go"},
			{Name: "github.com/acme/server/internal/api.VerifyJWT", Package: "github.com/acme/server/internal/api", Category: model.CategoryUser, SourceFile: "internal/api/jwt.go"},
			{Name: "github.com/acme/server/internal/api.DecodeBase64", Package: "github.com/acme/server/internal/api", Category: model.CategoryUser, SourceFile: "internal/api/decode.go"},
		},
	}

	cRep, err := Scan(clean)
	if err != nil {
		t.Fatal(err)
	}
	if cRep.Obfuscation.GarbleLikely {
		t.Fatalf("normal stripped Go binary falsely flagged as garble: %+v", cRep.Obfuscation)
	}
}
