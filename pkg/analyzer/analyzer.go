// Package analyzer orchestrates SymForge's binary loader, Go and Rust recovery
// engines, and multi-architecture XREF/disassembly analyzer behind a thread-safe
// analysis cache shared by the CLI and MCP server.
package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aloneangel45/symforge/pkg/gorecover"
	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
	"github.com/aloneangel45/symforge/pkg/rustrecover"
	"github.com/aloneangel45/symforge/pkg/xref"
)

// Options tunes string extraction, Fat Mach-O architecture selection, and caching during full binary analysis.
type Options struct {
	MinStringLen int
	MaxStrings   int
	Arch         string
	BypassCache  bool
}

// CallEdge pairs a call target or caller virtual address with its resolved symbol name.
type CallEdge struct {
	Addr uint64 `json:"addr"`
	Name string `json:"name,omitempty"`
}

// FunctionInspection holds rich per-function details, resolved call edges, and optional disassembly.
type FunctionInspection struct {
	Function     model.Function            `json:"function"`
	Calls        []CallEdge                `json:"calls,omitempty"`
	CalledBy     []CallEdge                `json:"called_by,omitempty"`
	Instructions []model.DisasmInstruction `json:"instructions,omitempty"`
}

type cacheKey struct {
	absPath      string
	size         int64
	mtimeNano    int64
	arch         string
	minStringLen int
	maxStrings   int
}

type cacheEntry struct {
	key    cacheKey
	lb     *loader.LoadedBinary
	result *model.AnalysisResult
	symMap map[uint64]string
	strMap map[uint64]string
}

type inflightAnalysis struct {
	done  chan struct{}
	entry *cacheEntry
	err   error
}

// Engine manages cached binary analysis across CLI and MCP invocations.
type Engine struct {
	mu         sync.Mutex
	maxEntries int
	entries    []cacheEntry
	inflight   map[cacheKey]*inflightAnalysis
}

// NewEngine creates an Engine with bounded in-memory result caching.
func NewEngine(maxEntries int) *Engine {
	if maxEntries <= 0 {
		maxEntries = 16
	}
	return &Engine{
		maxEntries: maxEntries,
		entries:    make([]cacheEntry, 0, maxEntries),
		inflight:   make(map[cacheKey]*inflightAnalysis),
	}
}

// DefaultEngine is a process-wide shared analyzer engine.
var DefaultEngine = NewEngine(16)

// AnalyzeFile performs (or serves from cache) full binary forensics on path.
func (e *Engine) AnalyzeFile(path string, opts Options) (*model.AnalysisResult, error) {
	entry, err := e.analyzeCached(path, opts)
	if err != nil {
		return nil, err
	}
	return entry.result, nil
}

func (e *Engine) analyzeCached(path string, opts Options) (*cacheEntry, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	st, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("target path %q is a directory, expected binary file", path)
	}

	normArch := ""
	rawArch := strings.ToLower(strings.TrimSpace(opts.Arch))
	if rawArch != "" {
		if rawArch == "arm64e" {
			normArch = "arm64e"
		} else if a, ok := loader.NormalizeArch(rawArch); ok {
			normArch = string(a)
		} else {
			// Delegate unknown arch validation to LoadFileWithOptions so universal Fat Mach-O
			// binaries report their available architecture slices in the error message.
			normArch = rawArch
		}
	}

	ck := cacheKey{
		absPath:      absPath,
		size:         st.Size(),
		mtimeNano:    st.ModTime().UnixNano(),
		arch:         normArch,
		minStringLen: opts.MinStringLen,
		maxStrings:   opts.MaxStrings,
	}

	// On filesystems with coarse mtime ticks (1-15ms), rapid in-place overwrites of the same
	// byte length can share identical (size, mtimeNano). Verify SHA-256 for recently modified files.
	recentlyModified := false
	if age := time.Since(st.ModTime()); age < 2*time.Second {
		recentlyModified = true
	}

	var flight *inflightAnalysis
	if !opts.BypassCache {
		e.mu.Lock()
		for i, item := range e.entries {
			if item.key == ck {
				stale := false
				if recentlyModified && item.result != nil && item.result.Binary.SHA256 != "" {
					e.mu.Unlock()
					if curHash, hErr := fileSHA256(absPath); hErr == nil && curHash != item.result.Binary.SHA256 {
						stale = true
					}
					if !stale {
						e.mu.Lock()
						for j, cur := range e.entries {
							if cur.key == ck {
								if j > 0 {
									copy(e.entries[1:j+1], e.entries[0:j])
									e.entries[0] = cur
								}
								e.mu.Unlock()
								return &cur, nil
							}
						}
						e.mu.Unlock()
						return &item, nil
					}
					e.mu.Lock()
					break
				}
				if i > 0 {
					copy(e.entries[1:i+1], e.entries[0:i])
					e.entries[0] = item
				}
				e.mu.Unlock()
				return &item, nil
			}
		}
		if existingFlight, waiting := e.inflight[ck]; waiting {
			e.mu.Unlock()
			<-existingFlight.done
			return existingFlight.entry, existingFlight.err
		}
		if e.inflight == nil {
			e.inflight = make(map[cacheKey]*inflightAnalysis)
		}
		flight = &inflightAnalysis{done: make(chan struct{})}
		e.inflight[ck] = flight
		e.mu.Unlock()
	}

	finishFlight := func(entry *cacheEntry, ferr error) (*cacheEntry, error) {
		if flight != nil {
			e.mu.Lock()
			flight.entry = entry
			flight.err = ferr
			delete(e.inflight, ck)
			close(flight.done)
			e.mu.Unlock()
		}
		return entry, ferr
	}

	start := time.Now()
	lb, err := loader.LoadFileWithOptions(absPath, loader.LoadOptions{Arch: opts.Arch})
	if err != nil {
		return finishFlight(nil, err)
	}

	res, symMap, strMap, err := AnalyzeLoaded(lb, opts, start)
	if err != nil {
		return finishFlight(nil, err)
	}

	ce := cacheEntry{
		key:    ck,
		lb:     lb,
		result: res,
		symMap: symMap,
		strMap: strMap,
	}

	e.mu.Lock()
	// Prepend MRU entry and evict oldest if needed.
	filtered := make([]cacheEntry, 0, e.maxEntries)
	filtered = append(filtered, ce)
	for _, existing := range e.entries {
		if existing.key == ck {
			continue
		}
		if len(filtered) >= e.maxEntries {
			break
		}
		filtered = append(filtered, existing)
	}
	e.entries = filtered
	e.mu.Unlock()

	return finishFlight(&ce, nil)
}

// AnalyzeBytes runs full SymForge analysis on raw in-memory binary bytes.
func AnalyzeBytes(name string, data []byte, opts Options) (*model.AnalysisResult, error) {
	start := time.Now()
	lb, err := loader.LoadBytesWithOptions(name, data, loader.LoadOptions{Arch: opts.Arch})
	if err != nil {
		return nil, err
	}
	res, _, _, err := AnalyzeLoaded(lb, opts, start)
	return res, err
}

// AnalyzeLoaded runs Go recovery, Rust recovery, Native fallback, and XREF analysis on lb.
func AnalyzeLoaded(lb *loader.LoadedBinary, opts Options, start time.Time) (*model.AnalysisResult, map[uint64]string, map[uint64]string, error) {
	if start.IsZero() {
		start = time.Now()
	}

	goRes, err := gorecover.Analyze(lb)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("go recovery failed: %w", err)
	}
	rustRes, err := rustrecover.Analyze(lb)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rust recovery failed: %w", err)
	}

	info := lb.Info
	goDetected := goRes != nil && goRes.Meta != nil && goRes.Meta.Detected
	rustDetected := rustRes != nil && rustRes.Meta != nil && rustRes.Meta.Detected

	// Guard against rare mixed false-positive: if Go pclntab recovered hundreds of functions
	// and Rust only matched incidental symbols without v0 mangling or auditable SBOM, prefer Go.
	if goDetected && rustDetected {
		if len(goRes.Functions) > 20 && !rustRes.Meta.AuditableSBOM && rustRes.Meta.ManglingScheme != "v0" && rustRes.Meta.CompilerVersion == "" {
			rustDetected = false
		}
	}

	switch {
	case goDetected && rustDetected:
		info.Language = model.LangGoRust
	case goDetected:
		info.Language = model.LangGo
	case rustDetected:
		info.Language = model.LangRust
	default:
		info.Language = model.LangNative
	}

	mergedFuncs := mergeFunctions(lb, goRes, rustRes, goDetected, rustDetected)

	xrefRes, err := xref.Analyze(lb, mergedFuncs, xref.Options{
		MinStringLen: opts.MinStringLen,
		MaxStrings:   opts.MaxStrings,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("xref analysis failed: %w", err)
	}

	pkgs := mergePackages(goRes, rustRes, xrefRes.Functions, goDetected, rustDetected)
	types := mergeTypes(goRes, rustRes, goDetected, rustDetected)
	deps := mergeDependencies(goRes, rustRes, goDetected, rustDetected)
	var panics []model.PanicLocation
	if rustDetected && rustRes != nil {
		panics = rustRes.Panics
	}

	out := &model.AnalysisResult{
		Binary:             info,
		Sections:           lb.Sections,
		Imports:            lb.Imports,
		Packages:           pkgs,
		Functions:          xrefRes.Functions,
		Types:              types,
		Dependencies:       deps,
		Panics:             panics,
		Strings:            xrefRes.Strings,
		Crypto:             xrefRes.Crypto,
		AnalysisDurationMs: float64(time.Since(start).Microseconds()) / 1000.0,
	}
	if goDetected {
		out.Go = goRes.Meta
	}
	if rustDetected {
		out.Rust = rustRes.Meta
	}

	symMap := make(map[uint64]string, len(out.Functions)+len(lb.Symbols))
	for _, s := range lb.Symbols {
		if s.Addr != 0 && s.Name != "" {
			if s.Demangled != "" {
				symMap[s.Addr] = s.Demangled
			} else {
				symMap[s.Addr] = s.Name
			}
		}
	}
	for _, fn := range out.Functions {
		if fn.Entry != 0 {
			if fn.Demangled != "" {
				symMap[fn.Entry] = fn.Demangled
			} else {
				symMap[fn.Entry] = fn.Name
			}
		}
	}

	strMap := make(map[uint64]string, len(out.Strings))
	for _, s := range out.Strings {
		if s.Addr != 0 {
			strMap[s.Addr] = s.Value
		}
	}

	return out, symMap, strMap, nil
}

// InspectFunction locates a function by name, demangled name, hex VA, or unique substring,
// resolves its outgoing/incoming call edges, and optionally decodes machine instructions.
func (e *Engine) InspectFunction(path, target string, disassemble bool, maxInsns int) (*FunctionInspection, error) {
	return e.InspectFunctionWithOptions(path, target, disassemble, maxInsns, Options{})
}

// InspectFunctionWithOptions is like InspectFunction with explicit analysis options (such as Fat Mach-O Arch).
func (e *Engine) InspectFunctionWithOptions(path, target string, disassemble bool, maxInsns int, opts Options) (*FunctionInspection, error) {
	ce, err := e.analyzeCached(path, opts)
	if err != nil {
		return nil, err
	}
	fn, err := FindFunction(ce.result.Functions, target)
	if err != nil {
		return nil, err
	}

	calls := make([]CallEdge, 0, len(fn.Calls))
	for _, addr := range fn.Calls {
		calls = append(calls, CallEdge{
			Addr: addr,
			Name: ce.symMap[addr],
		})
	}
	calledBy := make([]CallEdge, 0, len(fn.CalledBy))
	for _, addr := range fn.CalledBy {
		calledBy = append(calledBy, CallEdge{
			Addr: addr,
			Name: ce.symMap[addr],
		})
	}

	insp := &FunctionInspection{
		Function: *fn,
		Calls:    calls,
		CalledBy: calledBy,
	}

	if disassemble {
		lb := ce.lb
		if lb == nil {
			var err error
			lb, err = loader.LoadFileWithOptions(ce.key.absPath, loader.LoadOptions{Arch: opts.Arch})
			if err != nil {
				return nil, err
			}
		}
		insns, err := xref.DisassembleFunction(lb, *fn, ce.symMap, ce.strMap, maxInsns)
		if err != nil {
			return nil, err
		}
		insp.Instructions = insns
	}

	return insp, nil
}

// FindFunction resolves target (exact name, demangled name, 0x-prefixed hex VA, or substring).
func FindFunction(funcs []model.Function, target string) (*model.Function, error) {
	q := strings.TrimSpace(target)
	if q == "" {
		return nil, fmt.Errorf("empty function target")
	}

	// 1. Hex address lookup (e.g. 0x401000 or raw hex if all hex digits and matches an Entry)
	addrStr := strings.TrimPrefix(strings.ToLower(q), "0x")
	if va, err := strconv.ParseUint(addrStr, 16, 64); err == nil && (strings.HasPrefix(strings.ToLower(q), "0x") || len(addrStr) >= 5) {
		for i := range funcs {
			if funcs[i].Entry == va {
				cp := funcs[i]
				return &cp, nil
			}
		}
		// Check if VA falls inside [Entry, End)
		for i := range funcs {
			if funcs[i].End > funcs[i].Entry && va >= funcs[i].Entry && va < funcs[i].End {
				cp := funcs[i]
				return &cp, nil
			}
		}
	}

	// 2. Exact match on Name or Demangled
	for i := range funcs {
		if funcs[i].Name == q || (funcs[i].Demangled != "" && funcs[i].Demangled == q) {
			cp := funcs[i]
			return &cp, nil
		}
	}

	// 3. Case-insensitive exact match
	ql := strings.ToLower(q)
	for i := range funcs {
		if strings.ToLower(funcs[i].Name) == ql || (funcs[i].Demangled != "" && strings.ToLower(funcs[i].Demangled) == ql) {
			cp := funcs[i]
			return &cp, nil
		}
	}

	// 4. Substring match (prefer CategoryUser, then shortest name)
	var matches []model.Function
	for _, fn := range funcs {
		if strings.Contains(strings.ToLower(fn.Name), ql) || (fn.Demangled != "" && strings.Contains(strings.ToLower(fn.Demangled), ql)) {
			matches = append(matches, fn)
		}
	}
	if len(matches) > 0 {
		sort.Slice(matches, func(i, j int) bool {
			if (matches[i].Category == model.CategoryUser) != (matches[j].Category == model.CategoryUser) {
				return matches[i].Category == model.CategoryUser
			}
			return len(matches[i].Name) < len(matches[j].Name)
		})
		cp := matches[0]
		return &cp, nil
	}

	return nil, fmt.Errorf("function %q not found among %d recovered functions", target, len(funcs))
}

func mergeFunctions(lb *loader.LoadedBinary, goRes *gorecover.Result, rustRes *rustrecover.Result, goDetected, rustDetected bool) []model.Function {
	byEntry := make(map[uint64]model.Function)

	if goDetected && goRes != nil {
		for _, fn := range goRes.Functions {
			if fn.Entry != 0 {
				byEntry[fn.Entry] = fn
			}
		}
	}
	if rustDetected && rustRes != nil {
		for _, fn := range rustRes.Functions {
			if fn.Entry == 0 {
				continue
			}
			if _, exists := byEntry[fn.Entry]; !exists {
				byEntry[fn.Entry] = fn
			}
		}
	}

	// Native fallback when neither Go nor Rust yielded functions
	if len(byEntry) == 0 {
		for _, sym := range lb.Symbols {
			if sym.Addr == 0 || sym.Name == "" || !lb.IsCodeVA(sym.Addr) {
				continue
			}
			dem, _, _ := rustrecover.Demangle(sym.Name)
			fn := model.Function{
				Name:          sym.Name,
				Demangled:     dem,
				Package:       "native",
				Entry:         sym.Addr,
				Size:          sym.Size,
				Category:      model.CategoryNative,
				RecoveredFrom: "symtab",
			}
			if sym.Size > 0 {
				fn.End = sym.Addr + sym.Size
			}
			byEntry[sym.Addr] = fn
		}
		for _, rf := range lb.RuntimeFuncs {
			if rf.Start == 0 || rf.End <= rf.Start {
				continue
			}
			if existing, ok := byEntry[rf.Start]; ok {
				if existing.End == 0 {
					existing.End = rf.End
					existing.Size = rf.End - rf.Start
					byEntry[rf.Start] = existing
				}
				continue
			}
			byEntry[rf.Start] = model.Function{
				Name:          fmt.Sprintf("sub_%x", rf.Start),
				Package:       "native",
				Entry:         rf.Start,
				End:           rf.End,
				Size:          rf.End - rf.Start,
				Category:      model.CategoryNative,
				RecoveredFrom: "pdata",
			}
		}
		if lb.Info.EntryPoint != 0 && lb.IsCodeVA(lb.Info.EntryPoint) {
			if _, ok := byEntry[lb.Info.EntryPoint]; !ok {
				byEntry[lb.Info.EntryPoint] = model.Function{
					Name:          "_entry",
					Package:       "native",
					Entry:         lb.Info.EntryPoint,
					Category:      model.CategoryNative,
					RecoveredFrom: "entrypoint",
				}
			}
		}
	}

	out := make([]model.Function, 0, len(byEntry))
	for _, fn := range byEntry {
		out = append(out, fn)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Entry < out[j].Entry
	})

	// Infer missing sizes between adjacent functions inside the same executable section.
	for i := range out {
		if out[i].Size == 0 && out[i].End > out[i].Entry {
			out[i].Size = out[i].End - out[i].Entry
		}
		if out[i].Size == 0 && i+1 < len(out) {
			s1 := lb.SectionContainingVA(out[i].Entry)
			s2 := lb.SectionContainingVA(out[i+1].Entry)
			if s1 != nil && s2 != nil && s1.VirtualAddr == s2.VirtualAddr {
				gap := out[i+1].Entry - out[i].Entry
				if gap > 0 && gap <= 256*1024 {
					out[i].End = out[i+1].Entry
					out[i].Size = gap
				}
			}
		}
	}
	return out
}

func mergePackages(goRes *gorecover.Result, rustRes *rustrecover.Result, funcs []model.Function, goDetected, rustDetected bool) []model.PackageSummary {
	byName := make(map[string]model.PackageSummary)
	if goDetected && goRes != nil {
		for _, p := range goRes.Packages {
			byName[p.Name] = p
		}
	}
	if rustDetected && rustRes != nil {
		for _, p := range rustRes.Packages {
			if _, exists := byName[p.Name]; !exists {
				byName[p.Name] = p
			}
		}
	}
	if len(byName) == 0 && len(funcs) > 0 {
		var total uint64
		for _, fn := range funcs {
			total += fn.Size
		}
		byName["native"] = model.PackageSummary{
			Name:          "native",
			Category:      model.CategoryNative,
			FunctionCount: len(funcs),
			TotalBytes:    total,
		}
	}

	out := make([]model.PackageSummary, 0, len(byName))
	for _, p := range byName {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if categoryRank(out[i].Category) != categoryRank(out[j].Category) {
			return categoryRank(out[i].Category) < categoryRank(out[j].Category)
		}
		if out[i].FunctionCount != out[j].FunctionCount {
			return out[i].FunctionCount > out[j].FunctionCount
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func categoryRank(c model.PackageCategory) int {
	switch c {
	case model.CategoryUser:
		return 0
	case model.CategoryDependency:
		return 1
	case model.CategoryStdlib:
		return 2
	case model.CategoryRuntime:
		return 3
	default:
		return 4
	}
}

func mergeTypes(goRes *gorecover.Result, rustRes *rustrecover.Result, goDetected, rustDetected bool) []model.RecoveredType {
	var out []model.RecoveredType
	if goDetected && goRes != nil {
		out = append(out, goRes.Types...)
	}
	if rustDetected && rustRes != nil {
		out = append(out, rustRes.Types...)
	}
	return out
}

func mergeDependencies(goRes *gorecover.Result, rustRes *rustrecover.Result, goDetected, rustDetected bool) []model.Dependency {
	seen := make(map[string]bool)
	var out []model.Dependency
	add := func(list []model.Dependency) {
		for _, d := range list {
			k := d.Ecosystem + ":" + d.Name + "@" + d.Version
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, d)
		}
	}
	if goDetected && goRes != nil {
		add(goRes.Dependencies)
	}
	if rustDetected && rustRes != nil {
		add(rustRes.Dependencies)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
