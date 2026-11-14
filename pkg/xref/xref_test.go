package xref_test

import (
	"debug/gosym"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
	"github.com/aloneangel45/symforge/pkg/xref"
)

const sampleProgramSrc = `package main

import "os"

// FIPS-197 Rijndael Forward S-Box (256 bytes) stored in read-only/data memory.
var testRijndaelSBox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// Neighboring same-length strings to verify Go non-null-terminated string blob slicing!
var neighborStrs = []string{
	"neighbor_padding_string_exactly_42_bytes_A",
	"neighbor_padding_string_exactly_42_bytes_B",
}

//go:noinline
func beta(endpoint string, idx int) byte {
	sigma := "expand 32-byte k"
	return testRijndaelSBox[idx&0xff] ^ sigma[len(endpoint)%len(sigma)]
}

//go:noinline
func alpha(seed int) byte {
	endpoint := "https://api.symforge.internal/v2/telemetry"
	return beta(endpoint, seed)
}

func main() {
	v := alpha(len(os.Args))
	if v == 0xff && len(neighborStrs) == 99 {
		os.Exit(1)
	}
}
`

func buildStrippedFixture(t *testing.T, goos, goarch string) string {
	t.Helper()
	dir := t.TempDir()

	modFile := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(modFile, []byte("module symforge_xref_fixture\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("write fixture go.mod: %v", err)
	}
	mainFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(mainFile, []byte(sampleProgramSrc), 0o600); err != nil {
		t.Fatalf("write fixture main.go: %v", err)
	}

	outBin := filepath.Join(dir, "fixture_"+goos+"_"+goarch)
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outBin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+goos,
		"GOARCH="+goarch,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build (%s/%s) failed: %v\n%s", goos, goarch, err, string(out))
	}
	return outBin
}

func recoverFunctionsViaGoSym(t *testing.T, lb *loader.LoadedBinary) []model.Function {
	t.Helper()
	textSec, _, ok := lb.SectionByName(".text", "__TEXT.__text")
	if !ok {
		t.Fatalf("missing .text section in fixture")
	}
	_, pclnBytes, ok := lb.SectionByName(".gopclntab", ".data.rel.ro.gopclntab", "__TEXT.__gopclntab")
	if !ok {
		t.Fatalf("missing .gopclntab section in fixture")
	}

	lt := gosym.NewLineTable(pclnBytes, textSec.VirtualAddr)
	tab, err := gosym.NewTable(nil, lt)
	if err != nil {
		t.Fatalf("gosym.NewTable: %v", err)
	}

	funcs := make([]model.Function, 0, len(tab.Funcs))
	for _, gf := range tab.Funcs {
		if gf.Entry == 0 || gf.End <= gf.Entry {
			continue
		}
		funcs = append(funcs, model.Function{
			Name:          gf.Name,
			Package:       gf.PackageName(),
			Entry:         gf.Entry,
			End:           gf.End,
			Size:          gf.End - gf.Entry,
			RecoveredFrom: "gopclntab_test",
		})
	}
	return funcs
}

func TestAnalyzeAndDisassemble_StrippedCrossArch(t *testing.T) {
	targets := []struct {
		name     string
		goos     string
		goarch   string
		wantArch model.Architecture
	}{
		{
			name:     "linux_amd64_x86_64",
			goos:     "linux",
			goarch:   "amd64",
			wantArch: model.ArchX86_64,
		},
		{
			name:     "linux_arm64",
			goos:     "linux",
			goarch:   "arm64",
			wantArch: model.ArchARM64,
		},
	}

	const wantURL = "https://api.symforge.internal/v2/telemetry"

	for _, tc := range targets {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			binPath := buildStrippedFixture(t, tc.goos, tc.goarch)
			lb, err := loader.LoadFile(binPath)
			if err != nil {
				t.Fatalf("loader.LoadFile: %v", err)
			}
			if lb.Info.Arch != tc.wantArch {
				t.Fatalf("got arch %q, want %q", lb.Info.Arch, tc.wantArch)
			}
			if !lb.Info.Stripped {
				t.Fatalf("expected stripped ELF binary (-ldflags=\"-s -w\")")
			}

			funcs := recoverFunctionsViaGoSym(t, lb)
			if len(funcs) < 100 {
				t.Fatalf("expected >= 100 functions in Go binary, got %d", len(funcs))
			}

			start := time.Now()
			res, err := xref.Analyze(lb, funcs, xref.Options{})
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("xref.Analyze: %v", err)
			}
			t.Logf("[%s] analyzed %d functions, %d strings, %d crypto constants in %v",
				tc.name, len(res.Functions), len(res.Strings), len(res.Crypto), elapsed)

			var alphaFn, betaFn *model.Function
			for i := range res.Functions {
				fn := &res.Functions[i]
				switch fn.Name {
				case "main.alpha":
					alphaFn = fn
				case "main.beta":
					betaFn = fn
				}
			}
			if alphaFn == nil || betaFn == nil {
				t.Fatalf("failed to locate main.alpha (%v) or main.beta (%v)", alphaFn, betaFn)
			}

			// 1. Verify bidirectional call graph: alpha -> beta and beta <- alpha.
			if !containsUint64(alphaFn.Calls, betaFn.Entry) {
				t.Errorf("[%s] alpha.Calls = %#x, missing beta.Entry %#x", tc.name, alphaFn.Calls, betaFn.Entry)
			}
			if !containsUint64(betaFn.CalledBy, alphaFn.Entry) {
				t.Errorf("[%s] beta.CalledBy = %#x, missing alpha.Entry %#x", tc.name, betaFn.CalledBy, alphaFn.Entry)
			}

			// 2. Verify alpha StringRefs contains exact sliced URL classified as StringURL.
			foundURLRef := false
			var urlAddr uint64
			for _, sr := range alphaFn.StringRefs {
				if sr.Value == wantURL {
					foundURLRef = true
					urlAddr = sr.Addr
					if sr.Kind != model.StringURL {
						t.Errorf("[%s] URL StringRef kind = %q, want %q", tc.name, sr.Kind, model.StringURL)
					}
					if sr.InsnAddr < alphaFn.Entry || sr.InsnAddr >= alphaFn.End {
						t.Errorf("[%s] URL StringRef InsnAddr %#x outside alpha [%#x, %#x)",
							tc.name, sr.InsnAddr, alphaFn.Entry, alphaFn.End)
					}
				}
			}
			if !foundURLRef {
				t.Fatalf("[%s] alpha.StringRefs %+v missing exact URL %q", tc.name, alphaFn.StringRefs, wantURL)
			}

			// Verify reverse ReferencedBy on the extracted URL string and Neighbor string splitting.
			foundExtractedURL := false
			foundNeighborA := false
			for _, es := range res.Strings {
				if es.Value == wantURL {
					foundExtractedURL = true
					if es.Kind != model.StringURL {
						t.Errorf("[%s] ExtractedString kind = %q, want %q", tc.name, es.Kind, model.StringURL)
					}
					if !containsUint64(es.ReferencedBy, alphaFn.Entry) {
						t.Errorf("[%s] URL ExtractedString.ReferencedBy %#x missing alpha.Entry %#x",
							tc.name, es.ReferencedBy, alphaFn.Entry)
					}
				}
				if es.Value == "neighbor_padding_string_exactly_42_bytes_A" {
					foundNeighborA = true
				}
			}
			if !foundExtractedURL {
				t.Errorf("[%s] res.Strings missing exact URL %q", tc.name, wantURL)
			}
			if !foundNeighborA {
				t.Errorf("[%s] static Go (ptr,len) string table splitter did not slice neighborStrs cleanly", tc.name)
			}

			// 3. Verify Crypto Constant Detector found both AES Forward S-Box and ChaCha20 sigma!
			var foundAES, foundChaCha bool
			for _, c := range res.Crypto {
				if c.Name == "AES Forward S-Box" && c.Algorithm == "AES" {
					foundAES = true
				}
				if c.Name == "ChaCha20 / Salsa20 Constant" && c.Algorithm == "ChaCha20" {
					foundChaCha = true
				}
			}
			if !foundAES {
				t.Errorf("[%s] crypto detector missed AES Forward S-Box; got %+v", tc.name, res.Crypto)
			}
			if !foundChaCha {
				t.Errorf("[%s] crypto detector missed ChaCha20 / Salsa20 Constant; got %+v", tc.name, res.Crypto)
			}
			if !containsString(betaFn.CryptoRefs, "AES Forward S-Box") {
				t.Errorf("[%s] expected beta.CryptoRefs %v to contain AES Forward S-Box", tc.name, betaFn.CryptoRefs)
			}
			if !containsString(betaFn.CryptoRefs, "ChaCha20 / Salsa20 Constant") {
				t.Errorf("[%s] expected beta.CryptoRefs %v to contain ChaCha20 / Salsa20 Constant", tc.name, betaFn.CryptoRefs)
			}

			// 4. Verify DisassembleFunction resolves both symMap (main.beta) and strMap (wantURL).
			symMap := map[uint64]string{
				alphaFn.Entry: "main.alpha",
				betaFn.Entry:  "main.beta",
			}
			strMap := map[uint64]string{
				urlAddr: wantURL,
			}
			insns, err := xref.DisassembleFunction(lb, *alphaFn, symMap, strMap, 128)
			if err != nil {
				t.Fatalf("[%s] DisassembleFunction(alpha): %v", tc.name, err)
			}
			if len(insns) == 0 {
				t.Fatalf("[%s] DisassembleFunction returned 0 instructions", tc.name)
			}

			sawBetaTarget := false
			sawURLString := false
			for _, insn := range insns {
				if insn.BytesHex == "" || insn.Text == "" {
					t.Errorf("[%s] empty BytesHex or Text in instruction %+v", tc.name, insn)
				}
				if insn.TargetAddr == betaFn.Entry && insn.TargetSymbol == "main.beta" {
					sawBetaTarget = true
				}
				if insn.StringRef == wantURL {
					sawURLString = true
				}
			}
			if !sawBetaTarget {
				t.Errorf("[%s] DisassembleFunction did not annotate call to main.beta (%#x); insns=%+v",
					tc.name, betaFn.Entry, insns)
			}
			if !sawURLString {
				t.Errorf("[%s] DisassembleFunction did not annotate StringRef %q at %#x; insns=%+v",
					tc.name, wantURL, urlAddr, insns)
			}
		})
	}
}

func TestClassifyString_AllCategories(t *testing.T) {
	cases := []struct {
		input string
		want  model.StringKind
	}{
		{"https://api.symforge.internal/v2/telemetry", model.StringURL},
		{"wss://stream.internal:8443/events", model.StringURL},
		{"postgres://db.internal:5432/prod", model.StringURL},
		{"redis://cache.internal:6379/0", model.StringURL},
		{"mongodb://mongo.internal:27017/admin", model.StringURL},
		{"grpc://mesh.internal:9090", model.StringURL},

		// Defensive secret-leak auditing patterns
		{"AKIAIOSFODNN7EXAMPLE", model.StringSecretCandidate},
		{"AIzaSyDaGmWKa4JsXZ-HjGw7xN_example12345", model.StringSecretCandidate},
		{"ghp_1234567890abcdefghijklmnopqrstuvwxyz", model.StringSecretCandidate},
		{"github_pat_11ABCDEFG0123456789_secretTokenValue", model.StringSecretCandidate},
		{"sk-ant-api03-testkey0123456789", model.StringSecretCandidate},
		{"sk-proj-testOpenAIProjectKey123456", model.StringSecretCandidate},
		{"xoxb-1234567890-abcdef123456", model.StringSecretCandidate},
		{"-----BEGIN EC PRIVATE KEY-----", model.StringSecretCandidate},
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig", model.StringSecretCandidate},

		// API routes
		{"/api/v1/users/profile", model.StringAPIRoute},
		{"/v2/metrics/ingest", model.StringAPIRoute},
		{"/graphql/query", model.StringAPIRoute},
		{"/oauth/token", model.StringAPIRoute},
		{"/webhook/stripe", model.StringAPIRoute},

		// SQL statements
		{"SELECT id, email FROM accounts WHERE active = 1", model.StringSQL},
		{"INSERT INTO audit_logs (actor, event) VALUES ($1, $2)", model.StringSQL},
		{"CREATE TABLE sessions (id TEXT PRIMARY KEY)", model.StringSQL},
		{"UPDATE devices SET last_seen = NOW() WHERE id = ?", model.StringSQL},

		// File paths
		{"/etc/ssl/certs/ca-certificates.crt", model.StringFilePath},
		{"/proc/self/maps", model.StringFilePath},
		{"/usr/local/bin/symforge", model.StringFilePath},
		{"internal/engine/scanner.go:142", model.StringFilePath},
		{"crates/core/src/lib.rs", model.StringFilePath},
		{"certs/server.pem", model.StringFilePath},
		{"C:\\ProgramData\\SymForge\\config.yaml", model.StringFilePath},

		// Commands
		{"/bin/sh -c uname -a", model.StringCommand},
		{"cmd.exe /c ver", model.StringCommand},
		{"powershell -NoProfile -Command Get-Process", model.StringCommand},
		{"systemctl restart symforge.service", model.StringCommand},
		{"ipconfig /all", model.StringCommand},

		// Error messages
		{"error: connection reset by peer", model.StringErrorMsg},
		{"failed to parse configuration file config.json", model.StringErrorMsg},
		{"panic: runtime error: index out of range", model.StringErrorMsg},
		{"invalid signature header", model.StringErrorMsg},
		{"request rejected: unauthorized client", model.StringErrorMsg},

		// General strings
		{"SymForge Binary Analyzer v1.0", model.StringGeneral},
	}

	for _, tc := range cases {
		got := xref.ClassifyString(tc.input)
		if got != tc.want {
			t.Errorf("ClassifyString(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestUTF16LEAndSHA256Detection(t *testing.T) {
	// Build a minimal Go fixture containing a UTF-16LE wide string array and SHA-256 initial hash values.
	src := `package main

import "os"

var sha256IV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

var aesTe0Sample = [16]uint32{
	0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d,
	0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554,
	0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d,
	0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a,
}

// UTF-16LE encoded "https://wide.symforge.test/v1\x00"
var wideEndpoint = [...]uint16{
	'h', 't', 't', 'p', 's', ':', '/', '/',
	'w', 'i', 'd', 'e', '.', 's', 'y', 'm', 'f', 'o', 'r', 'g', 'e', '.', 't', 'e', 's', 't',
	'/', 'v', '1', 0,
}

func main() {
	if sha256IV[len(os.Args)&7]^aesTe0Sample[len(os.Args)&15] == uint32(wideEndpoint[len(os.Args)&15]) {
		os.Exit(2)
	}
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module utf16_sha_fixture\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	outBin := filepath.Join(dir, "fixture_amd64")
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outBin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(out))
	}

	lb, err := loader.LoadFile(outBin)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	res, err := xref.Analyze(lb, nil, xref.Options{MinStringLen: 4, MaxStrings: 20000})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	foundWide := false
	for _, s := range res.Strings {
		if s.Encoding == "utf-16le" && strings.Contains(s.Value, "https://wide.symforge.test/v1") {
			foundWide = true
			if s.Kind != model.StringURL {
				t.Errorf("wide URL kind = %q, want %q", s.Kind, model.StringURL)
			}
		}
	}
	if !foundWide {
		t.Errorf("failed to extract UTF-16LE wide URL string")
	}

	foundSHA := false
	foundTe0 := false
	for _, c := range res.Crypto {
		if c.Name == "SHA-256 Initial Hash Values" && c.Algorithm == "SHA-256" {
			foundSHA = true
		}
		if c.Name == "AES Te0 T-Table" && c.Algorithm == "AES" {
			foundTe0 = true
		}
	}
	if !foundSHA {
		t.Errorf("failed to detect SHA-256 Initial Hash Values; got %+v", res.Crypto)
	}
	if !foundTe0 {
		t.Errorf("failed to detect AES Te0 T-Table; got %+v", res.Crypto)
	}

	// Verify error handling on nil LoadedBinary and zero Entry.
	if _, err := xref.Analyze(nil, nil, xref.Options{}); err == nil {
		t.Errorf("expected error on nil LoadedBinary in Analyze")
	}
	if _, err := xref.DisassembleFunction(lb, model.Function{}, nil, nil, 10); err == nil {
		t.Errorf("expected error on zero Entry in DisassembleFunction")
	}
}

func containsUint64(vals []uint64, want uint64) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
