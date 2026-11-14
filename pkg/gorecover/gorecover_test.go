package gorecover

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

const sampleProgramSource = `package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

var buildTag = "dev"

type AuditMeta struct {
	CreatedBy string ` + "`json:\"created_by\"`" + `
	Revision  uint64 ` + "`json:\"revision\"`" + `
}

type ServerConfig struct {
	AuditMeta
	ListenAddr string   ` + "`json:\"listen_addr\" env:\"LISTEN_ADDR\"`" + `
	MaxWorkers int      ` + "`json:\"max_workers\"`" + `
	Endpoints  []string ` + "`json:\"endpoints\"`" + `
}

type TaskRunner interface {
	Execute(payload string) (int, error)
	RunnerName() string
}

type WorkerEngine struct {
	cfg ServerConfig
	mu  sync.Mutex
	ops int
}

//go:noinline
func (w *WorkerEngine) Execute(payload string) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ops++
	sum := sha256.Sum256([]byte(strings.ToUpper(payload) + w.cfg.ListenAddr))
	return int(sum[0]) + w.ops, nil
}

//go:noinline
func (w *WorkerEngine) RunnerName() string {
	return "symforge-worker:" + w.cfg.ListenAddr
}

//go:noinline
func dispatchBatch(r TaskRunner, inputs []string) int {
	var wg sync.WaitGroup
	results := make(chan int, len(inputs))
	for _, item := range inputs {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := r.Execute(item)
			if err == nil {
				results <- n
			}
		}()
	}
	wg.Wait()
	close(results)
	total := 0
	for v := range results {
		total += v
	}
	return total
}

func main() {
	cfg := ServerConfig{
		AuditMeta:  AuditMeta{CreatedBy: "symforge", Revision: 42},
		ListenAddr: "127.0.0.1:9090",
		MaxWorkers: 4,
		Endpoints:  []string{"/healthz", "/v1/analyze"},
	}
	rawJSON, _ := json.Marshal(cfg)
	var decoded ServerConfig
	_ = json.Unmarshal(rawJSON, &decoded)

	var runner TaskRunner = &WorkerEngine{cfg: decoded}
	if len(os.Args) > 99 {
		runner = nil
	}
	score := dispatchBatch(runner, decoded.Endpoints)
	fmt.Printf("%s [%s] -> %d (%d bytes)\n", runner.RunnerName(), buildTag, score, len(rawJSON))
}
`

func TestCrossCompiledStrippedGoBinaries(t *testing.T) {
	srcDir := t.TempDir()
	goMod := "module example.com/symforgesample\n\ngo 1.21\n"
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sample.go"), []byte(sampleProgramSource), 0o600); err != nil {
		t.Fatalf("write sample.go: %v", err)
	}

	targets := []struct {
		name      string
		goos      string
		goarch    string
		buildmode string
		ext       string
		format    model.BinaryFormat
	}{
		{name: "linux_amd64", goos: "linux", goarch: "amd64", buildmode: "exe", ext: "", format: model.FormatELF},
		{name: "linux_amd64_pie", goos: "linux", goarch: "amd64", buildmode: "pie", ext: "", format: model.FormatELF},
		{name: "linux_arm64", goos: "linux", goarch: "arm64", buildmode: "exe", ext: "", format: model.FormatELF},
		{name: "windows_amd64", goos: "windows", goarch: "amd64", buildmode: "exe", ext: ".exe", format: model.FormatPE},
		{name: "darwin_arm64", goos: "darwin", goarch: "arm64", buildmode: "exe", ext: "", format: model.FormatMachO},
	}

	outDir := t.TempDir()
	for _, tc := range targets {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			binName := "sample_" + tc.name + tc.ext
			binPath := filepath.Join(outDir, binName)

			cmd := exec.Command("go", "build", "-buildmode="+tc.buildmode, "-trimpath", "-ldflags=-s -w -X main.buildTag=v1.0.0", "-o", binPath, ".")
			cmd.Dir = srcDir
			cmd.Env = append(os.Environ(),
				"CGO_ENABLED=0",
				"GOOS="+tc.goos,
				"GOARCH="+tc.goarch,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("go build %s/%s failed: %v\n%s", tc.goos, tc.goarch, err, string(out))
			}

			lb, err := loader.LoadFile(binPath)
			if err != nil {
				t.Fatalf("loader.LoadFile(%s): %v", binPath, err)
			}
			if lb.Info.Format != tc.format {
				t.Fatalf("expected format %s, got %s", tc.format, lb.Info.Format)
			}
			if !lb.Info.Stripped {
				t.Fatalf("expected stripped binary for %s/%s", tc.goos, tc.goarch)
			}

			res, err := Analyze(lb)
			if err != nil {
				t.Fatalf("Analyze(%s/%s): %v", tc.goos, tc.goarch, err)
			}
			if res == nil || res.Meta == nil || !res.Meta.Detected {
				t.Fatalf("expected Go binary to be detected for %s/%s", tc.goos, tc.goarch)
			}

			// 1. Validate buildinfo metadata
			if !strings.HasPrefix(res.Meta.Version, "go1.") {
				t.Errorf("unexpected Go version: %q", res.Meta.Version)
			}
			if res.Meta.MainModule != "example.com/symforgesample" {
				t.Errorf("expected MainModule example.com/symforgesample, got %q", res.Meta.MainModule)
			}
			if res.Meta.BuildSettings["GOOS"] != tc.goos || res.Meta.BuildSettings["GOARCH"] != tc.goarch {
				t.Errorf("unexpected BuildSettings GOOS/GOARCH: %+v", res.Meta.BuildSettings)
			}
			if res.Meta.BuildSettings["CGO_ENABLED"] != "0" || res.Meta.BuildSettings["-compiler"] != "gc" || res.Meta.BuildSettings["-trimpath"] != "true" {
				t.Errorf("expected CGO_ENABLED=0, -compiler=gc, -trimpath=true in BuildSettings, got %+v", res.Meta.BuildSettings)
			}

			// Verify raw "\xff Go buildinf:" fallback scanner directly on the stripped image.
			fallbackBI := scanRawBuildInfo(lb)
			if fallbackBI == nil || fallbackBI.GoVersion != res.Meta.Version || fallbackBI.Main.Path != "example.com/symforgesample" {
				t.Errorf("raw buildinfo fallback scanner mismatch: %+v", fallbackBI)
			}

			// 2. Validate pclntab & moduledata addresses
			if res.Meta.PCLnTabMagic != MagicGo120 {
				t.Errorf("expected PCLnTabMagic 0x%x, got 0x%x", MagicGo120, res.Meta.PCLnTabMagic)
			}
			if res.Meta.PCLnTabAddr == 0 || res.Meta.TextStart == 0 {
				t.Errorf("expected non-zero PCLnTabAddr (0x%x) and TextStart (0x%x)", res.Meta.PCLnTabAddr, res.Meta.TextStart)
			}
			if res.Meta.ModuleDataAddr == 0 || res.Meta.TypesAddr == 0 || res.Meta.ETypesAddr <= res.Meta.TypesAddr {
				t.Errorf("expected populated moduledata/types bounds, got md=0x%x types=0x%x..0x%x",
					res.Meta.ModuleDataAddr, res.Meta.TypesAddr, res.Meta.ETypesAddr)
			}

			// 3. Validate recovered functions, executable Entry VAs, source file & line, and category
			var (
				foundMain    *model.Function
				foundExecute *model.Function
				foundBatch   *model.Function
			)
			for i := range res.Functions {
				fn := &res.Functions[i]
				switch fn.Name {
				case "main.main":
					foundMain = fn
				case "main.(*WorkerEngine).Execute":
					foundExecute = fn
				case "main.dispatchBatch":
					foundBatch = fn
				}
			}

			for label, fn := range map[string]*model.Function{
				"main.main":                   foundMain,
				"main.(*WorkerEngine).Execute": foundExecute,
				"main.dispatchBatch":          foundBatch,
			} {
				if fn == nil {
					t.Fatalf("missing recovered function %s on %s/%s", label, tc.goos, tc.goarch)
				}
				if fn.Entry == 0 || !lb.IsCodeVA(fn.Entry) {
					t.Errorf("%s Entry 0x%x is not inside an executable code section", label, fn.Entry)
				}
				if fn.Size == 0 || fn.End <= fn.Entry {
					t.Errorf("%s invalid bounds Entry=0x%x End=0x%x Size=%d", label, fn.Entry, fn.End, fn.Size)
				}
				if !strings.HasSuffix(filepath.ToSlash(fn.SourceFile), "sample.go") {
					t.Errorf("%s expected SourceFile ending in sample.go, got %q", label, fn.SourceFile)
				}
				if fn.Line <= 0 {
					t.Errorf("%s expected Line > 0, got %d", label, fn.Line)
				}
				if fn.Category != model.CategoryUser {
					t.Errorf("%s expected CategoryUser, got %s", label, fn.Category)
				}
			}
			if foundExecute.Receiver != "*WorkerEngine" {
				t.Errorf("expected Receiver *WorkerEngine, got %q", foundExecute.Receiver)
			}

			// 4. Validate aggregated packages
			foundMainPkg := false
			for _, pkg := range res.Packages {
				if pkg.Name == "main" {
					foundMainPkg = true
					if pkg.Category != model.CategoryUser || pkg.FunctionCount < 3 || pkg.TotalBytes == 0 {
						t.Errorf("unexpected main PackageSummary: %+v", pkg)
					}
				}
			}
			if !foundMainPkg {
				t.Errorf("missing 'main' in recovered Packages")
			}

			// 5. Validate recovered custom struct and interface types
			var (
				cfgStruct  *model.RecoveredType
				runnerIface *model.RecoveredType
			)
			for i := range res.Types {
				rt := &res.Types[i]
				if rt.Kind == "struct" && strings.HasSuffix(rt.Name, "ServerConfig") {
					cfgStruct = rt
				}
				if rt.Kind == "interface" && strings.HasSuffix(rt.Name, "TaskRunner") {
					runnerIface = rt
				}
			}

			if cfgStruct == nil {
				t.Fatalf("failed to recover struct ServerConfig on %s/%s (recovered %d types)", tc.goos, tc.goarch, len(res.Types))
			}
			hasListenField := false
			hasEmbeddedAudit := false
			for _, f := range cfgStruct.Fields {
				if f.Name == "ListenAddr" && f.TypeName == "string" && strings.Contains(f.Tag, `json:"listen_addr"`) {
					hasListenField = true
				}
				if f.Name == "AuditMeta" && f.Embedded {
					hasEmbeddedAudit = true
				}
			}
			if !hasListenField {
				t.Errorf("ServerConfig missing ListenAddr field/tag: %+v", cfgStruct.Fields)
			}
			if !hasEmbeddedAudit {
				t.Errorf("ServerConfig missing embedded AuditMeta field: %+v", cfgStruct.Fields)
			}

			if runnerIface == nil {
				t.Fatalf("failed to recover interface TaskRunner on %s/%s", tc.goos, tc.goarch)
			}
			methodSet := strings.Join(runnerIface.Methods, ",")
			if !strings.Contains(methodSet, "Execute") || !strings.Contains(methodSet, "RunnerName") {
				t.Errorf("TaskRunner methods mismatch: got %v", runnerIface.Methods)
			}
		})
	}
}

func TestNonGoAndAdversarialPCLnTab(t *testing.T) {
	// Synthesize a minimal valid 64-bit little-endian ELF executable with .text and .rodata.
	makeMinimalELF := func(rodataPayload []byte) []byte {
		const (
			ehdrSize = 64
			phdrSize = 56
			shdrSize = 64
			textOff  = 0x200
			textVA   = 0x401000
			roOff    = 0x300
			roVA     = 0x402000
		)
		shstrtab := []byte("\x00.text\x00.gopclntab\x00.shstrtab\x00")
		totalLen := roOff + len(rodataPayload) + 64 + len(shstrtab) + 4*shdrSize
		buf := make([]byte, totalLen)

		// ELF64 header
		copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
		buf[4] = 2 // ELFCLASS64
		buf[5] = 1 // ELFDATA2LSB
		buf[6] = 1 // EV_CURRENT
		binary.LittleEndian.PutUint16(buf[16:18], 2)  // ET_EXEC
		binary.LittleEndian.PutUint16(buf[18:20], 62) // EM_X86_64
		binary.LittleEndian.PutUint32(buf[20:24], 1)  // EV_CURRENT
		binary.LittleEndian.PutUint64(buf[24:32], textVA)
		binary.LittleEndian.PutUint64(buf[32:40], ehdrSize) // e_phoff
		shoff := roOff + len(rodataPayload) + len(shstrtab)
		shoff = (shoff + 7) &^ 7
		binary.LittleEndian.PutUint64(buf[40:48], uint64(shoff)) // e_shoff
		binary.LittleEndian.PutUint16(buf[52:54], ehdrSize)
		binary.LittleEndian.PutUint16(buf[54:56], phdrSize)
		binary.LittleEndian.PutUint16(buf[56:58], 1) // e_phnum
		binary.LittleEndian.PutUint16(buf[58:60], shdrSize)
		binary.LittleEndian.PutUint16(buf[60:62], 4) // e_shnum
		binary.LittleEndian.PutUint16(buf[62:64], 3) // e_shstrndx

		// PT_LOAD covering file
		ph := buf[ehdrSize : ehdrSize+phdrSize]
		binary.LittleEndian.PutUint32(ph[0:4], 1) // PT_LOAD
		binary.LittleEndian.PutUint32(ph[4:8], 5) // PF_R | PF_X
		binary.LittleEndian.PutUint64(ph[8:16], 0)
		binary.LittleEndian.PutUint64(ph[16:24], 0x400000)
		binary.LittleEndian.PutUint64(ph[32:40], uint64(totalLen))
		binary.LittleEndian.PutUint64(ph[40:48], uint64(totalLen))
		binary.LittleEndian.PutUint64(ph[48:56], 0x1000)

		// .text NOP + RET
		buf[textOff] = 0x90
		buf[textOff+1] = 0xc3
		copy(buf[roOff:], rodataPayload)
		strOff := roOff + len(rodataPayload)
		copy(buf[strOff:], shstrtab)

		putShdr := func(idx int, nameIdx, shType uint32, flags, addr, off, size uint64) {
			s := buf[shoff+idx*shdrSize : shoff+(idx+1)*shdrSize]
			binary.LittleEndian.PutUint32(s[0:4], nameIdx)
			binary.LittleEndian.PutUint32(s[4:8], shType)
			binary.LittleEndian.PutUint64(s[8:16], flags)
			binary.LittleEndian.PutUint64(s[16:24], addr)
			binary.LittleEndian.PutUint64(s[24:32], off)
			binary.LittleEndian.PutUint64(s[32:40], size)
		}
		putShdr(1, 1, 1, 0x6, textVA, textOff, 16)                        // .text
		putShdr(2, 7, 1, 0x2, roVA, roOff, uint64(len(rodataPayload)))    // .gopclntab
		putShdr(3, 18, 3, 0x0, 0, uint64(strOff), uint64(len(shstrtab))) // .shstrtab
		return buf
	}

	t.Run("non_go_elf", func(t *testing.T) {
		elfBytes := makeMinimalELF([]byte("plain native C string without go metadata\x00"))
		lb, err := loader.LoadBytes("native.elf", elfBytes)
		if err != nil {
			t.Fatalf("LoadBytes: %v", err)
		}
		res, err := Analyze(lb)
		if err != nil {
			t.Fatalf("Analyze returned error on non-Go binary: %v", err)
		}
		if res == nil || res.Meta == nil || res.Meta.Detected {
			t.Fatalf("expected Detected=false on non-Go binary, got %+v", res.Meta)
		}
	})

	adversarialPayloads := []struct {
		name string
		data []byte
	}{
		{
			name: "truncated_magic_only",
			data: []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08},
		},
		{
			name: "huge_nfunc_overflow",
			data: func() []byte {
				b := make([]byte, 128)
				copy(b, []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08})
				binary.LittleEndian.PutUint64(b[8:16], ^uint64(0))
				return b
			}(),
		},
		{
			name: "out_of_bounds_offsets",
			data: func() []byte {
				b := make([]byte, 96)
				copy(b, []byte{0xf0, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08})
				binary.LittleEndian.PutUint64(b[8:16], 10)          // nfunc
				binary.LittleEndian.PutUint64(b[32:40], 0xdeadbeef) // funcnameOffset OOB
				binary.LittleEndian.PutUint64(b[64:72], 0xfeedface) // pclnOffset OOB
				return b
			}(),
		},
		{
			name: "big_endian_corrupt_go12",
			data: func() []byte {
				b := make([]byte, 80)
				copy(b, []byte{0xff, 0xff, 0xff, 0xfb, 0x00, 0x00, 0x04, 0x08})
				binary.BigEndian.PutUint64(b[8:16], 500000)
				return b
			}(),
		},
	}

	for _, tc := range adversarialPayloads {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			lb, err := loader.LoadBytes(tc.name, makeMinimalELF(tc.data))
			if err != nil {
				t.Fatalf("LoadBytes: %v", err)
			}
			res, err := Analyze(lb)
			if err != nil {
				t.Fatalf("Analyze returned unexpected error: %v", err)
			}
			if res.Meta.Detected {
				t.Fatalf("corrupt pclntab %s must not false-positive as valid Go binary", tc.name)
			}
		})
	}

	// Verify infinite varint stream (0x80 bytes) in pctab never hangs or panics.
	if _, ok := decodePCValueAtEntry(bytesRepeat(0x80, 128), 1, 1); ok {
		t.Fatalf("expected corrupt varint stream to fail cleanly")
	}
}

func TestSymbolParsingAndDependencyReplacements(t *testing.T) {
	cases := []struct {
		sym      string
		wantPkg  string
		wantRecv string
		wantCat  model.PackageCategory
	}{
		{"main.main", "main", "", model.CategoryUser},
		{"example.com/app/internal/auth.(*TokenVerifier).Verify", "example.com/app/internal/auth", "*TokenVerifier", model.CategoryUser},
		{"github.com/spf13/cobra.(*Command).Execute", "github.com/spf13/cobra", "*Command", model.CategoryDependency},
		{"gopkg.in/yaml.v3.Unmarshal", "gopkg.in/yaml.v3", "", model.CategoryDependency},
		{"net/http.(*Server).ListenAndServe", "net/http", "*Server", model.CategoryStdlib},
		{"runtime.gopark", "runtime", "", model.CategoryRuntime},
		{"internal/abi.(*Type).Kind", "internal/abi", "*Type", model.CategoryRuntime},
		{"type:.eq.main.ServerConfig", "runtime", "", model.CategoryRuntime},
	}

	for _, tc := range cases {
		pkg, recv, _ := parseGoSymbol(tc.sym)
		cat := classifyGoPackage(pkg, tc.sym, "example.com/app")
		if pkg != tc.wantPkg || recv != tc.wantRecv || cat != tc.wantCat {
			t.Errorf("parseGoSymbol(%q) = (pkg=%q, recv=%q, cat=%q), want (pkg=%q, recv=%q, cat=%q)",
				tc.sym, pkg, recv, cat, tc.wantPkg, tc.wantRecv, tc.wantCat)
		}
	}

	deps := extractGoDependencies([]*debug.Module{
		{
			Path:    "github.com/old/pkg",
			Version: "v1.0.0",
			Replace: &debug.Module{
				Path:    "github.com/fork/pkg",
				Version: "v1.0.1-patched",
				Sum:     "h1:patchedsum=",
			},
		},
		{
			Path:    "golang.org/x/sys",
			Version: "v0.25.0",
			Sum:     "h1:syssum=",
		},
	})
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}
	if deps[0].Name != "github.com/fork/pkg" || deps[0].Version != "v1.0.1-patched" || deps[0].Ecosystem != "gomod" || deps[0].Source != "buildinfo" {
		t.Errorf("unexpected replaced dependency: %+v", deps[0])
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
