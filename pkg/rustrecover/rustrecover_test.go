package rustrecover

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

func TestDemangleV0AndLegacy(t *testing.T) {
	tests := []struct {
		name       string
		sym        string
		want       string
		wantScheme string
		wantOK     bool
	}{
		{
			name:       "v0 simple user function",
			sym:        "_RNvCs1sRw4cpoMxN_6sample12verify_token",
			want:       "sample::verify_token",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 macOS double underscore prefix",
			sym:        "__RNvCs1sRw4cpoMxN_6sample4main",
			want:       "sample::main",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 trait impl with backrefs",
			sym:        "_RNvXCs1sRw4cpoMxN_6sampleNtB2_8HmacAuthNtB2_13Authenticator5check",
			want:       "<sample::HmacAuth as sample::Authenticator>::check",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 inherent impl with disambiguator and backref",
			sym:        "_RNvMs5_NtCsinMxvmwVKXS_5alloc7raw_vecNtB5_11RawVecInner11finish_growCs1sRw4cpoMxN_6sample",
			want:       "<alloc::raw_vec::RawVecInner>::finish_grow",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 closure and instantiating crate",
			sym:        "_RNCINvNtCs9qcQDiGWtgW_3std2rt10lang_startuE0Cs1sRw4cpoMxN_6sample",
			want:       "std::rt::lang_start::<()>::{closure#0}",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 vtable shim",
			sym:        "_RNSNvYNCINvNtCs9qcQDiGWtgW_3std2rt10lang_startuE0INtNtNtCs2Ja4erDm0Jl_4core3ops8function6FnOnceuE9call_once6vtableCs1sRw4cpoMxN_6sample",
			want:       "<std::rt::lang_start::<()>::{closure#0} as core::ops::function::FnOnce<()>>::call_once::{shim:vtable#0}",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 generic drop_glue with nested Vec<String>",
			sym:        "_RINvNtCs2Ja4erDm0Jl_4core3ptr9drop_glueINtNtCsinMxvmwVKXS_5alloc3vec3VecNtNtBG_6string6StringEECs1sRw4cpoMxN_6sample",
			want:       "core::ptr::drop_glue::<alloc::vec::Vec<alloc::string::String>>",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 fn signature and underscore-prefixed ident",
			sym:        "_RINvNtNtCs9qcQDiGWtgW_3std3sys9backtrace28___rust_begin_short_backtraceFEuuECs1sRw4cpoMxN_6sample",
			want:       "std::sys::backtrace::__rust_begin_short_backtrace::<fn(), ()>",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 array const generic and slice reference",
			sym:        "_RINvCs1_4demo7processTAhj20_RSbEE",
			want:       "demo::process::<([u8; 32], &[bool])>",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 dyn trait with lifetime",
			sym:        "_RINvCs1_4demo6acceptRDNtB2_6ReaderEL0_E",
			want:       "demo::accept::<&dyn demo::Reader + 'a>",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "v0 punycode unicode identifier",
			sym:        "_RNvCs1_4demou7_caf_dma",
			want:       "demo::café",
			wantScheme: "v0",
			wantOK:     true,
		},
		{
			name:       "legacy standard with 17h hash",
			sym:        "_ZN4core3fmt5write17h0123456789abcdefE",
			want:       "core::fmt::write",
			wantScheme: "legacy",
			wantOK:     true,
		},
		{
			name:       "legacy trait impl escapes and llvm suffix",
			sym:        "_ZN55_$LT$sample..HmacAuth$u20$as$u20$core..fmt..Display$GT$3fmt17hdeadbeefcafebabeE.llvm.12345",
			want:       "<sample::HmacAuth as core::fmt::Display>::fmt",
			wantScheme: "legacy",
			wantOK:     true,
		},
		{
			name:       "legacy full special escape table",
			sym:        "_ZN4test71_$LP$$BP$const$u20$u8$C$$u20$$RF$$u27$a$u20$$u5b$u8$u3b$$u20$4$u5d$$RP$17h1122334455667788E",
			want:       "test::(*const u8, &'a [u8; 4])",
			wantScheme: "legacy",
			wantOK:     true,
		},
		{
			name:       "plain C symbol rejected",
			sym:        "malloc",
			want:       "malloc",
			wantScheme: "",
			wantOK:     false,
		},
		{
			name:       "C++ non-nested function rejected",
			sym:        "_Z12verify_tokenPKcm",
			want:       "_Z12verify_tokenPKcm",
			wantScheme: "",
			wantOK:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, scheme, ok := Demangle(tc.sym)
			if ok != tc.wantOK || scheme != tc.wantScheme || got != tc.want {
				t.Fatalf("Demangle(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.sym, got, scheme, ok, tc.want, tc.wantScheme, tc.wantOK)
			}
		})
	}
}

func TestDemangleMaliciousInputs(t *testing.T) {
	malicious := []string{
		"_RB_",                                     // self backref at offset 0
		"_RNvB0_3foo",                              // forward backref
		"_RINvCs1_1a1bB99_E",                       // out-of-bounds backref
		"_R" + strings.Repeat("R", 200) + "l",      // excessive recursion depth > 128
		"_R" + strings.Repeat("I", 150) + "l",      // unclosed deep generics
		"_ZN999999999fooE",                         // truncated legacy segment length
		"_ZN0fooE",                                 // zero-length legacy segment
		"_RNvCs1_1au99999_zzzzzzzzzzzzzzzzzzzzzzz", // malformed punycode length
	}

	// Also craft an exponential backref chain (DAG doubling output each step) to test output/step cap
	var bomb strings.Builder
	bomb.WriteString("_RINvCs1_1a1bTuple")
	// First element: 'l' (i32) at known offset, then chain T B<prev> B<prev> E
	startOff := bomb.Len() - 2 // offset after "_R"
	bomb.WriteByte('l')
	prev := startOff
	for i := 0; i < 40; i++ {
		cur := bomb.Len() - 2
		b62 := encodeTestBase62(uint64(prev))
		bomb.WriteString("TB" + b62 + "B" + b62 + "E")
		prev = cur
	}
	bomb.WriteByte('E')
	malicious = append(malicious, bomb.String())

	for i, sym := range malicious {
		got, scheme, ok := Demangle(sym)
		if ok || scheme != "" || got != sym {
			t.Fatalf("malicious[%d] unexpectedly succeeded: (%q, %q, %v)", i, got, scheme, ok)
		}
	}
}

func encodeTestBase62(v uint64) string {
	if v == 0 {
		return "_"
	}
	v--
	const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if v == 0 {
		return "0_"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{chars[v%62]}, digits...)
		v /= 62
	}
	return string(digits) + "_"
}

func TestSyntheticAuditablePanicAndVTableRecovery(t *testing.T) {
	// Compress cargo-auditable JSON payload for .dep-v0
	sbomJSON := `{"packages":[{"name":"hmac","version":"0.12.1","kind":"runtime"},{"name":"sha2","version":"0.10.8","kind":null}]}`
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write([]byte(sbomJSON)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	depV0Bytes := zbuf.Bytes()

	// Build .text (VA 0x401000) with 3 distinct function stubs: drop_in_place, auth_check, auth_realm
	const (
		textVA   = 0x401000
		rodataVA = 0x402000
		depVA    = 0x403000
	)
	textBytes := make([]byte, 0x60)
	textBytes[0x00] = 0xc3 // drop_in_place @ 0x401000
	textBytes[0x20] = 0xc3 // method_0      @ 0x401020
	textBytes[0x40] = 0xc3 // method_1      @ 0x401040

	// Build .rodata (VA 0x402000)
	var rodata bytes.Buffer
	writeAligned8 := func() {
		for rodata.Len()%8 != 0 {
			rodata.WriteByte(0)
		}
	}

	rodata.WriteString("/rustc/4d91de4e48198da2e33413efdcd9cd2cc0c46688/library/core/src/panicking.rs\x00")
	rodata.WriteString("rustc 1.85.0 (4d91de4e4 2025-02-17)\x00")
	rodata.WriteString("/home/builder/.cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-util-0.7.12/src/lib.rs\x00")

	winRegPath := `C:\Users\builder\.cargo\registry\src\index.crates.io-6f17d22bba15001f\serde_json-1.0.128\src\de.rs`
	winRegStrVA := uint64(rodataVA + rodata.Len())
	rodata.WriteString(winRegPath)
	rodata.WriteByte(0)

	userFile := "src/auth/token.rs"
	userFileVA := uint64(rodataVA + rodata.Len())
	rodata.WriteString(userFile) // intentionally NOT null-terminated to test exact (ptr,len) slicing!
	rodata.WriteString("trailing_literal")

	// Carve Location #1 (Layout A: ptr, len, line=77, col=9) -> src/auth/token.rs
	writeAligned8()
	loc1VA := uint64(rodataVA + rodata.Len())
	var locBuf [24]byte
	binary.LittleEndian.PutUint64(locBuf[0:8], userFileVA)
	binary.LittleEndian.PutUint64(locBuf[8:16], uint64(len(userFile)))
	binary.LittleEndian.PutUint32(locBuf[16:20], 77)
	binary.LittleEndian.PutUint32(locBuf[20:24], 9)
	rodata.Write(locBuf[:])

	// Carve Location #2 (Layout A: ptr, len, line=312, col=17) -> serde_json
	loc2VA := uint64(rodataVA + rodata.Len())
	binary.LittleEndian.PutUint64(locBuf[0:8], winRegStrVA)
	binary.LittleEndian.PutUint64(locBuf[8:16], uint64(len(winRegPath)))
	binary.LittleEndian.PutUint32(locBuf[16:20], 312)
	binary.LittleEndian.PutUint32(locBuf[20:24], 17)
	rodata.Write(locBuf[:])

	// Emit two adjacent Rust trait vtables in .rodata to test header validation + boundary splitting:
	// VTable #1: [drop=0x401000, size=32, align=8, m0=0x401020, m1=0x401040]
	writeAligned8()
	vt1VA := uint64(rodataVA + rodata.Len())
	var qword [8]byte
	putU64 := func(v uint64) {
		binary.LittleEndian.PutUint64(qword[:], v)
		rodata.Write(qword[:])
	}
	putU64(textVA + 0x00) // drop_in_place
	putU64(32)            // size
	putU64(8)             // align
	putU64(textVA + 0x20) // method_0
	putU64(textVA + 0x40) // method_1

	// VTable #2 immediately adjacent: [drop=0x401000, size=16, align=8, m0=0x401020]
	vt2VA := uint64(rodataVA + rodata.Len())
	putU64(textVA + 0x00)
	putU64(16)
	putU64(8)
	putU64(textVA + 0x20)

	elfImage := buildSyntheticELF64(textVA, textBytes, rodataVA, rodata.Bytes(), depVA, depV0Bytes)
	lb, err := loader.LoadBytes("synthetic_rust.elf", elfImage)
	if err != nil {
		t.Fatalf("loader.LoadBytes failed: %v", err)
	}

	res, err := Analyze(lb)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if !res.Meta.Detected {
		t.Fatalf("expected Rust Detected=true")
	}
	if !res.Meta.AuditableSBOM {
		t.Fatalf("expected AuditableSBOM=true")
	}
	if res.Meta.CompilerVersion != "1.85.0" {
		t.Errorf("CompilerVersion = %q, want 1.85.0", res.Meta.CompilerVersion)
	}
	if res.Meta.CompilerCommit != "4d91de4e48198da2e33413efdcd9cd2cc0c46688" {
		t.Errorf("CompilerCommit = %q", res.Meta.CompilerCommit)
	}

	// Verify 4 Cargo dependencies (2 cargo-auditable + 2 registry-path)
	wantDeps := map[string]string{
		"hmac@0.12.1":       "cargo-auditable",
		"sha2@0.10.8":       "cargo-auditable",
		"tokio-util@0.7.12": "registry-path",
		"serde_json@1.0.128": "registry-path",
	}
	for _, d := range res.Dependencies {
		key := d.Name + "@" + d.Version
		if src, ok := wantDeps[key]; ok && d.Source == src && d.Ecosystem == "cargo" {
			delete(wantDeps, key)
		}
	}
	if len(wantDeps) > 0 {
		t.Fatalf("missing expected dependencies: %v (got %+v)", wantDeps, res.Dependencies)
	}

	// Verify both PanicLocation records
	var foundLoc1, foundLoc2 bool
	for _, p := range res.Panics {
		if p.StructAddr == loc1VA && p.File == userFile && p.Line == 77 && p.Column == 9 && p.FileStrAddr == userFileVA {
			foundLoc1 = true
		}
		if p.StructAddr == loc2VA && p.File == winRegPath && p.Crate == "serde_json" && p.Line == 312 && p.Column == 17 {
			foundLoc2 = true
		}
	}
	if !foundLoc1 || !foundLoc2 {
		t.Fatalf("expected both PanicLocations carved (foundLoc1=%v, foundLoc2=%v), got: %+v", foundLoc1, foundLoc2, res.Panics)
	}

	// Verify both adjacent VTables were cleanly split and recovered
	if len(res.Types) != 2 {
		t.Fatalf("expected 2 vtables, got %d: %+v", len(res.Types), res.Types)
	}
	if res.Types[0].Addr != vt1VA || res.Types[0].Size != 32 || res.Types[0].Align != 8 || len(res.Types[0].Methods) != 2 {
		t.Fatalf("unexpected vtable[0]: %+v", res.Types[0])
	}
	if res.Types[1].Addr != vt2VA || res.Types[1].Size != 16 || res.Types[1].Align != 8 || len(res.Types[1].Methods) != 1 {
		t.Fatalf("unexpected vtable[1]: %+v", res.Types[1])
	}
}

func TestGoBinaryDoesNotFalsePositiveAsRust(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not in PATH")
	}
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "main.go")
	exePath := filepath.Join(tmpDir, "purego.exe")
	goSrc := `package main
import "fmt"
func main() { fmt.Println("symforge pure go check") }
`
	if err := os.WriteFile(srcPath, []byte(goSrc), 0644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	cmd := exec.Command(goBin, "build", "-o", exePath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(out))
	}

	lb, err := loader.LoadFile(exePath)
	if err != nil {
		t.Fatalf("LoadFile(purego): %v", err)
	}
	res, err := Analyze(lb)
	if err != nil {
		t.Fatalf("Analyze(purego): %v", err)
	}
	if res.Meta == nil || res.Meta.Detected {
		t.Fatalf("pure Go binary false-positived as Rust: %+v", res.Meta)
	}
}

func TestRealRustcIntegrationUnstrippedAndStripped(t *testing.T) {
	rustcBin, err := exec.LookPath("rustc")
	if err != nil {
		t.Skip("rustc not installed in PATH")
	}

	tmpDir := t.TempDir()
	// Keep exact line numbers deterministic: panic!("invalid signature") is on line 14!
	rustSrc := strings.Join([]string{
		`pub trait Authenticator {`,                                   // 1
		`    fn check_sig(&self, token: &[u8]) -> bool;`,              // 2
		`    fn realm(&self) -> &'static str;`,                        // 3
		`}`,                                                           // 4
		`pub struct HmacVerifier {`,                                   // 5
		`    pub secret: [u8; 32],`,                                   // 6
		`}`,                                                           // 7
		`impl Authenticator for HmacVerifier {`,                       // 8
		`    #[inline(never)]`,                                        // 9
		`    fn check_sig(&self, token: &[u8]) -> bool {`,             // 10
		`        token.len() == self.secret.len() && token[0] == self.secret[0]`, // 11
		`    }`,                                                       // 12
		`    #[inline(never)]`,                                        // 13
		`    fn realm(&self) -> &'static str { "symforge-auth" }`,     // 14
		`}`,                                                           // 15
		`#[inline(never)]`,                                            // 16
		`pub fn verify_token(auth: &dyn Authenticator, token: &[u8]) -> bool {`, // 17
		`    if token.is_empty() {`,                                   // 18
		`        panic!("invalid signature");`,                        // 19 <-- EXACT LINE 19!
		`    }`,                                                       // 20
		`    auth.check_sig(token) && !auth.realm().is_empty()`,       // 21
		`}`,                                                           // 22
		`fn main() {`,                                                 // 23
		`    let v = HmacVerifier { secret: [0x5a; 32] };`,            // 24
		`    let dyn_auth: &dyn Authenticator = std::hint::black_box(&v);`, // 25
		`    let args: Vec<String> = std::env::args().collect();`,     // 26
		`    let tok = if args.len() > 1 { args[1].as_bytes() } else { &[0x5a; 32] };`, // 27
		`    if verify_token(dyn_auth, tok) {`,                        // 28
		`        println!("{}", dyn_auth.realm());`,                   // 29
		`    }`,                                                       // 30
		`}`,                                                           // 31
		``,
	}, "\n")

	srcFile := filepath.Join(tmpDir, "main.rs")
	if err := os.WriteFile(srcFile, []byte(rustSrc), 0644); err != nil {
		t.Fatalf("write main.rs: %v", err)
	}

	unstrippedExe := filepath.Join(tmpDir, "auth_unstripped.exe")
	strippedExe := filepath.Join(tmpDir, "auth_stripped.exe")

	compileRustTestBinary(t, rustcBin, tmpDir, "main.rs", unstrippedExe, false)
	compileRustTestBinary(t, rustcBin, tmpDir, "main.rs", strippedExe, true)

	// --- 1. Validate Unstripped Binary ---
	lbUnstripped, err := loader.LoadFile(unstrippedExe)
	if err != nil {
		t.Fatalf("LoadFile(unstripped): %v", err)
	}
	resUn, err := Analyze(lbUnstripped)
	if err != nil {
		t.Fatalf("Analyze(unstripped): %v", err)
	}
	if !resUn.Meta.Detected {
		t.Fatalf("unstripped Rust binary not detected")
	}
	if len(resUn.Meta.CompilerCommit) < 7 {
		t.Errorf("expected non-empty CompilerCommit, got %q", resUn.Meta.CompilerCommit)
	}

	// On COFF/ELF/Mach-O targets with symbol tables, verify v0 demangling of verify_token & Authenticator
	if !lbUnstripped.Info.Stripped {
		if resUn.Meta.ManglingScheme != "v0" {
			t.Errorf("ManglingScheme = %q, want v0", resUn.Meta.ManglingScheme)
		}
		var sawVerifyToken, sawTraitImpl bool
		for _, fn := range resUn.Functions {
			if strings.HasSuffix(fn.Demangled, "::verify_token") && fn.Category == model.CategoryUser {
				sawVerifyToken = true
			}
			if strings.Contains(fn.Demangled, "HmacVerifier") && strings.Contains(fn.Demangled, "Authenticator") {
				sawTraitImpl = true
			}
		}
		if !sawVerifyToken {
			t.Errorf("did not find demangled user function ::verify_token in %d recovered functions", len(resUn.Functions))
		}
		if !sawTraitImpl {
			t.Errorf("did not find demangled <HmacVerifier as Authenticator> method")
		}
	}

	assertHasMainRsPanicLine(t, "unstripped", resUn.Panics, 19)
	if len(resUn.Types) == 0 || resUn.Meta.VTableCount == 0 {
		t.Errorf("expected recovered vtables on unstripped binary, got 0")
	}

	// --- 2. Validate Stripped Binary (-C strip=symbols) ---
	lbStripped, err := loader.LoadFile(strippedExe)
	if err != nil {
		t.Fatalf("LoadFile(stripped): %v", err)
	}
	if !lbStripped.Info.Stripped {
		t.Errorf("expected lbStripped.Info.Stripped=true")
	}
	resSt, err := Analyze(lbStripped)
	if err != nil {
		t.Fatalf("Analyze(stripped): %v", err)
	}
	if !resSt.Meta.Detected {
		t.Fatalf("stripped Rust binary not detected")
	}
	if len(resSt.Meta.CompilerCommit) < 7 {
		t.Errorf("stripped CompilerCommit = %q, expected >=7 hex chars", resSt.Meta.CompilerCommit)
	}
	assertHasMainRsPanicLine(t, "stripped", resSt.Panics, 19)

	if len(resSt.Types) == 0 {
		t.Errorf("expected recovered vtables on stripped binary, got 0")
	}

	// On x86_64 Windows PE, verify .pdata synthesized sub_<hex> and entry functions
	if lbStripped.Info.Format == model.FormatPE && lbStripped.Info.Arch == model.ArchX86_64 {
		var pdataCount int
		var sawEntry bool
		for _, fn := range resSt.Functions {
			if fn.RecoveredFrom == "pdata" {
				pdataCount++
			}
			if fn.Name == "entry" {
				sawEntry = true
			}
		}
		if pdataCount < 10 {
			t.Errorf("expected >=10 .pdata synthesized functions on stripped x64 PE, got %d", pdataCount)
		}
		if !sawEntry {
			t.Errorf("expected 'entry' function synthesized on stripped x64 PE")
		}
	}
}

func assertHasMainRsPanicLine(t *testing.T, label string, panics []model.PanicLocation, wantLine uint32) {
	t.Helper()
	for _, p := range panics {
		norm := strings.ReplaceAll(p.File, `\`, "/")
		if (norm == "main.rs" || strings.HasSuffix(norm, "/main.rs")) && p.Line == wantLine {
			return
		}
	}
	t.Fatalf("[%s] did not find PanicLocation for main.rs:%d (total panics=%d)", label, wantLine, len(panics))
}

func compileRustTestBinary(t *testing.T, rustcBin, workDir, srcRel, outPath string, stripSyms bool) {
	t.Helper()
	baseArgs := []string{"-O", "-C", "symbol-mangling-version=v0"}
	if stripSyms {
		baseArgs = append(baseArgs, "-C", "strip=symbols")
	}

	// Attempt 1: default linker invocation
	args1 := append(append([]string{}, baseArgs...), srcRel, "-o", outPath)
	cmd1 := exec.Command(rustcBin, args1...)
	cmd1.Dir = workDir
	out1, err1 := cmd1.CombinedOutput()
	if err1 == nil {
		return
	}

	// Attempt 2: Windows x86_64-pc-windows-gnu self-contained CRT/unwind libraries when external mingw lacks libgcc_eh
	args2 := append(append([]string{"-C", "link-self-contained=yes"}, baseArgs...), srcRel, "-o", outPath)
	cmd2 := exec.Command(rustcBin, args2...)
	cmd2.Dir = workDir
	out2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		return
	}

	t.Fatalf("rustc compilation failed:\nattempt 1: %v\n%s\nattempt 2: %v\n%s", err1, string(out1), err2, string(out2))
}

// buildSyntheticELF64 constructs a minimal valid 64-bit little-endian x86_64 ELF image
// with .text, .rodata, .dep-v0, and .shstrtab sections for deterministic unit testing.
func buildSyntheticELF64(
	textVA uint64, textData []byte,
	rodataVA uint64, rodataData []byte,
	depVA uint64, depData []byte,
) []byte {
	shstrtab := []byte("\x00.text\x00.rodata\x00.dep-v0\x00.shstrtab\x00")
	const (
		nameNull     = 0
		nameText     = 1
		nameRodata   = 7
		nameDepV0    = 15
		nameShstrtab = 23
	)

	align16 := func(v int) int {
		if v%16 == 0 {
			return v
		}
		return v + (16 - v%16)
	}

	// Layout:
	// 0x000..0x040: ELF64 Ehdr (64 bytes)
	// 0x040..0x0b0: 2 x ELF64 Phdr (2 * 56 = 112 bytes) -> 0xb0
	const (
		ehdrSize = 64
		phdrSize = 56
		shdrSize = 64
		numPhdrs = 2
		numShdrs = 5
	)

	off := align16(ehdrSize + numPhdrs*phdrSize)
	textOff := off
	off = align16(off + len(textData))
	rodataOff := off
	off = align16(off + len(rodataData))
	depOff := off
	off = align16(off + len(depData))
	shstrOff := off
	off = align16(off + len(shstrtab))
	shdrOff := off
	totalSize := shdrOff + numShdrs*shdrSize

	buf := make([]byte, totalSize)
	le := binary.LittleEndian

	// ELF Header
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2 // ELFCLASS64
	buf[5] = 1 // ELFDATA2LSB
	buf[6] = 1 // EV_CURRENT
	le.PutUint16(buf[16:18], 2)  // ET_EXEC
	le.PutUint16(buf[18:20], 62) // EM_X86_64
	le.PutUint32(buf[20:24], 1)  // EV_CURRENT
	le.PutUint64(buf[24:32], textVA)
	le.PutUint64(buf[32:40], ehdrSize)
	le.PutUint64(buf[40:48], uint64(shdrOff))
	le.PutUint16(buf[52:54], ehdrSize)
	le.PutUint16(buf[54:56], phdrSize)
	le.PutUint16(buf[56:58], numPhdrs)
	le.PutUint16(buf[58:60], shdrSize)
	le.PutUint16(buf[60:62], numShdrs)
	le.PutUint16(buf[62:64], 4) // shstrndx

	writePhdr := func(idx int, flags uint32, fOff uint64, vaddr uint64, fsz uint64) {
		p := buf[ehdrSize+idx*phdrSize:]
		le.PutUint32(p[0:4], 1) // PT_LOAD
		le.PutUint32(p[4:8], flags)
		le.PutUint64(p[8:16], fOff)
		le.PutUint64(p[16:24], vaddr)
		le.PutUint64(p[24:32], vaddr)
		le.PutUint64(p[32:40], fsz)
		le.PutUint64(p[40:48], fsz)
		le.PutUint64(p[48:56], 0x1000)
	}
	writePhdr(0, 5, uint64(textOff), textVA, uint64(len(textData)))     // PF_R | PF_X
	writePhdr(1, 4, uint64(rodataOff), rodataVA, uint64(len(rodataData))) // PF_R

	copy(buf[textOff:], textData)
	copy(buf[rodataOff:], rodataData)
	copy(buf[depOff:], depData)
	copy(buf[shstrOff:], shstrtab)

	writeShdr := func(idx int, nameOff uint32, shType uint32, flags uint64, addr uint64, fOff uint64, sz uint64) {
		s := buf[shdrOff+idx*shdrSize:]
		le.PutUint32(s[0:4], nameOff)
		le.PutUint32(s[4:8], shType)
		le.PutUint64(s[8:16], flags)
		le.PutUint64(s[16:24], addr)
		le.PutUint64(s[24:32], fOff)
		le.PutUint64(s[32:40], sz)
		le.PutUint64(s[48:56], 8)
	}
	// SHT_PROGBITS = 1, SHT_STRTAB = 3; SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4
	writeShdr(0, nameNull, 0, 0, 0, 0, 0)
	writeShdr(1, nameText, 1, 0x2|0x4, textVA, uint64(textOff), uint64(len(textData)))
	writeShdr(2, nameRodata, 1, 0x2, rodataVA, uint64(rodataOff), uint64(len(rodataData)))
	writeShdr(3, nameDepV0, 1, 0x2, depVA, uint64(depOff), uint64(len(depData)))
	writeShdr(4, nameShstrtab, 3, 0, 0, uint64(shstrOff), uint64(len(shstrtab)))

	return buf
}
