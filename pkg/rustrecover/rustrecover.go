package rustrecover

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

// Result holds all Rust metadata, symbolicated/pdata functions, crate summaries,
// trait vtables, Cargo dependencies, and carved core::panic::Location records.
type Result struct {
	Meta         *model.RustMetadata
	Functions    []model.Function
	Packages     []model.PackageSummary
	Types        []model.RecoveredType
	Dependencies []model.Dependency
	Panics       []model.PanicLocation
}

// Analyze inspects lb for Rust artifacts and recovers symbols, crates, dependencies,
// panic locations, and trait vtables. If lb is not a Rust binary, Analyze cleanly returns
// &Result{Meta: &model.RustMetadata{Detected: false}}, nil without error.
func Analyze(lb *loader.LoadedBinary) (*Result, error) {
	if lb == nil {
		return nil, errors.New("rustrecover: nil LoadedBinary")
	}

	compilerVer, compilerCommit, auditable, deps := extractCratesAndToolchain(lb)

	// Merge container symbols + PE export table symbols (for Rust cdylib/DLLs or MSVC exports)
	allSyms := collectAllSymbols(lb)

	var (
		v0Count             int
		strongLegacyCount   int
		rustRuntimeSymCount int
	)
	for i := range allSyms {
		rawName := allSyms[i].Name
		if isKnownRustRuntimeSymbol(rawName) {
			rustRuntimeSymCount++
		}
		if dem, scheme, ok := demangleSymbolFlexible(rawName); ok {
			switch scheme {
			case "v0":
				v0Count++
			case "legacy":
				if isStrongLegacyRust(rawName, dem) {
					strongLegacyCount++
				}
			}
		}
	}

	relMap := buildELFRelativeMap(lb)
	panics, hasPanicMarkers := carvePanicLocations(lb, relMap)

	detected := auditable ||
		compilerCommit != "" ||
		compilerVer != "" ||
		v0Count > 0 ||
		strongLegacyCount > 0 ||
		rustRuntimeSymCount > 0 ||
		len(deps) > 0 ||
		(len(panics) > 0 && hasPanicMarkers)

	if !detected {
		return &Result{
			Meta: &model.RustMetadata{Detected: false},
		}, nil
	}

	manglingScheme := ""
	switch {
	case v0Count > 0:
		manglingScheme = "v0"
	case strongLegacyCount > 0:
		manglingScheme = "legacy"
	}

	depCrateSet := make(map[string]struct{}, len(deps))
	for _, d := range deps {
		norm := normalizeCrateKey(d.Name)
		if norm != "" {
			depCrateSet[norm] = struct{}{}
		}
	}

	pdataMap := make(map[uint64]uint64, len(lb.RuntimeFuncs))
	for _, rf := range lb.RuntimeFuncs {
		if rf.End > rf.Start {
			pdataMap[rf.Start] = rf.End
		}
	}

	funcByEntry := make(map[uint64]model.Function)
	dataSymNames := make(map[uint64]string)

	for _, sym := range allSyms {
		if sym.Addr == 0 || sym.Name == "" {
			continue
		}
		demangled, scheme, isRustSym := demangleSymbolFlexible(sym.Name)
		if isRustSym && scheme == "legacy" && !isStrongLegacyRust(sym.Name, demangled) && v0Count > 0 {
			// Avoid misclassifying incidental C++ helper symbols inside mixed toolchains
			isRustSym = false
			demangled = ""
		}

		if !lb.IsCodeVA(sym.Addr) {
			if isRustSym {
				dataSymNames[sym.Addr] = demangled
			} else if _, exists := dataSymNames[sym.Addr]; !exists && !isNoiseSymbolName(sym.Name) {
				dataSymNames[sym.Addr] = sym.Name
			}
			continue
		}

		if !isRustSym && isNoiseSymbolName(sym.Name) {
			continue
		}

		recFrom := "symtab"
		if sym.Dynamic {
			recFrom = "dynsym"
		}

		fn := model.Function{
			Name:          sym.Name,
			Entry:         sym.Addr,
			RecoveredFrom: recFrom,
			Category:      model.CategoryNative,
		}
		if sym.Size > 0 {
			fn.Size = sym.Size
			fn.End = sym.Addr + sym.Size
		} else if end, ok := pdataMap[sym.Addr]; ok && end > sym.Addr {
			fn.End = end
			fn.Size = end - sym.Addr
		}

		if isRustSym {
			fn.Demangled = demangled
			crateName, pkgPath, recv := splitDemangledCrate(demangled)
			if pkgPath != "" {
				fn.Package = pkgPath
			} else {
				fn.Package = crateName
			}
			fn.Receiver = recv
			fn.Category = classifyRustCrate(crateName, depCrateSet)
		} else if isKnownRustRuntimeSymbol(sym.Name) {
			fn.Package = "rustc_runtime"
			fn.Category = model.CategoryRuntime
		}

		if existing, exists := funcByEntry[sym.Addr]; exists {
			if preferFunction(fn, existing) {
				funcByEntry[sym.Addr] = fn
			}
		} else {
			funcByEntry[sym.Addr] = fn
		}
	}

	// Synthesize functions from exception/unwind bounds (e.g. stripped Windows PE .pdata)
	if lb.Info.Stripped && len(lb.RuntimeFuncs) > 0 {
		entryAssigned := false
		if lb.Info.EntryPoint != 0 {
			if _, ok := funcByEntry[lb.Info.EntryPoint]; ok {
				entryAssigned = true
			}
		}
		for _, rf := range lb.RuntimeFuncs {
			if rf.Start == 0 || rf.End <= rf.Start {
				continue
			}
			if _, exists := funcByEntry[rf.Start]; exists {
				continue
			}
			isEntry := !entryAssigned && lb.Info.EntryPoint != 0 &&
				(rf.Start == lb.Info.EntryPoint || (lb.Info.EntryPoint > rf.Start && lb.Info.EntryPoint < rf.End))

			name := fmt.Sprintf("sub_%x", rf.Start)
			cat := model.CategoryNative
			if isEntry {
				name = "entry"
				cat = model.CategoryRuntime
				entryAssigned = true
			}
			funcByEntry[rf.Start] = model.Function{
				Name:          name,
				Entry:         rf.Start,
				End:           rf.End,
				Size:          rf.End - rf.Start,
				Category:      cat,
				RecoveredFrom: "pdata",
			}
		}
	}

	// Ensure binary EntryPoint is represented when valid
	if lb.Info.EntryPoint != 0 && lb.IsCodeVA(lb.Info.EntryPoint) {
		if _, exists := funcByEntry[lb.Info.EntryPoint]; !exists {
			hasContaining := false
			for _, f := range funcByEntry {
				if f.Name == "entry" || (f.End > f.Entry && lb.Info.EntryPoint >= f.Entry && lb.Info.EntryPoint < f.End) {
					hasContaining = true
					break
				}
			}
			if !hasContaining {
				var end uint64
				var sz uint64
				if pEnd, ok := pdataMap[lb.Info.EntryPoint]; ok && pEnd > lb.Info.EntryPoint {
					end = pEnd
					sz = pEnd - lb.Info.EntryPoint
				}
				funcByEntry[lb.Info.EntryPoint] = model.Function{
					Name:          "entry",
					Entry:         lb.Info.EntryPoint,
					End:           end,
					Size:          sz,
					Category:      model.CategoryRuntime,
					RecoveredFrom: "entrypoint",
				}
			}
		}
	}

	functions := make([]model.Function, 0, len(funcByEntry))
	for _, fn := range funcByEntry {
		functions = append(functions, fn)
	}
	sort.Slice(functions, func(i, j int) bool {
		return functions[i].Entry < functions[j].Entry
	})

	// Estimate End/Size for symbolicated functions whose container format omitted symbol sizes (e.g. COFF/Mach-O)
	fillMissingFunctionSizes(lb, functions)

	// Build address->label lookup for vtable method resolution
	funcNames := make(map[uint64]string, len(functions))
	for i := range functions {
		if functions[i].Demangled != "" {
			funcNames[functions[i].Entry] = functions[i].Demangled
		} else {
			funcNames[functions[i].Entry] = functions[i].Name
		}
	}

	vtables := scanRustVTables(lb, relMap, funcNames, dataSymNames)

	// Infer primary user crate name (if unambiguous) so local user panic paths get Crate attribution
	primaryUserCrate := findPrimaryUserCrate(functions)
	if primaryUserCrate != "" {
		for i := range panics {
			if panics[i].Crate == "" && looksLikeUserPanicPath(panics[i].File) {
				panics[i].Crate = primaryUserCrate
			}
		}
	}

	packages := buildPackageSummaries(functions, panics)

	meta := &model.RustMetadata{
		Detected:        true,
		CompilerVersion: compilerVer,
		CompilerCommit:  compilerCommit,
		ManglingScheme:  manglingScheme,
		AuditableSBOM:   auditable,
		PanicCount:      len(panics),
		VTableCount:     len(vtables),
	}

	return &Result{
		Meta:         meta,
		Functions:    functions,
		Packages:     packages,
		Types:        vtables,
		Dependencies: deps,
		Panics:       panics,
	}, nil
}

func demangleSymbolFlexible(sym string) (string, string, bool) {
	if dem, scheme, ok := Demangle(sym); ok {
		return dem, scheme, true
	}
	// Handle extra leading underscore on Mach-O / 32-bit COFF targets (e.g. "___R..." or "___ZN...E")
	if strings.HasPrefix(sym, "_") {
		if dem, scheme, ok := Demangle(sym[1:]); ok {
			return dem, scheme, true
		}
	}
	return sym, "", false
}

func isKnownRustRuntimeSymbol(name string) bool {
	trimmed := strings.TrimLeft(name, "_")
	trimmed = stripVendorSuffix(trimmed)
	switch trimmed {
	case "rust_begin_unwind",
		"rust_eh_personality",
		"rust_oom",
		"rust_panic",
		"rust_alloc",
		"rust_dealloc",
		"rust_realloc",
		"rust_alloc_zeroed",
		"rust_alloc_error_handler",
		"rust_probestack",
		"rust_no_alloc_shim_is_unstable",
		"rust_no_alloc_shim_is_unstable_v2":
		return true
	}
	return strings.HasPrefix(trimmed, "RNvCs") && strings.Contains(trimmed, "___rust_")
}

func isNoiseSymbolName(name string) bool {
	if strings.HasPrefix(name, ".L") ||
		strings.HasPrefix(name, "LBB") ||
		strings.HasPrefix(name, ".weak.") ||
		strings.HasPrefix(name, ".refptr.") ||
		strings.HasPrefix(name, "__imp_") ||
		strings.HasPrefix(name, ".rdata$") ||
		strings.HasPrefix(name, ".text$") ||
		strings.HasPrefix(name, ".pdata$") ||
		strings.HasPrefix(name, ".xdata$") {
		return true
	}
	if name == ".text" || name == ".data" || name == ".bss" || name == ".rdata" ||
		name == "$x" || name == "$d" {
		return true
	}
	return false
}

func preferFunction(cand, existing model.Function) bool {
	if cand.Demangled != "" && existing.Demangled == "" {
		return true
	}
	if cand.Demangled == "" && existing.Demangled != "" {
		return false
	}
	return categoryPriority(cand.Category) < categoryPriority(existing.Category)
}

func categoryPriority(cat model.PackageCategory) int {
	switch cat {
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

var (
	rustStdlibCrates = map[string]struct{}{
		"std":        {},
		"core":       {},
		"alloc":      {},
		"proc_macro": {},
		"test":       {},
	}

	rustSysrootRuntimeCrates = map[string]struct{}{
		"__rustc":                   {},
		"rustc_std_workspace_core":  {},
		"rustc_std_workspace_alloc": {},
		"rustc_std_workspace_std":   {},
		"panic_unwind":              {},
		"panic_abort":               {},
		"unwind":                    {},
		"compiler_builtins":         {},
		"rustc_demangle":            {},
		"std_detect":                {},
		"addr2line":                 {},
		"gimli":                     {},
		"object":                    {},
		"memchr":                    {},
		"miniz_oxide":               {},
		"adler":                     {},
		"adler2":                    {},
		"hashbrown":                 {},
		"cfg_if":                    {},
		"libc":                      {},
		"windows_targets":           {},
		"windows_link":              {},
	}
)

func classifyRustCrate(crateName string, depCrates map[string]struct{}) model.PackageCategory {
	if crateName == "" {
		return model.CategoryNative
	}
	norm := normalizeCrateKey(crateName)
	if _, ok := rustStdlibCrates[norm]; ok {
		return model.CategoryStdlib
	}
	if _, ok := depCrates[norm]; ok {
		return model.CategoryDependency
	}
	if _, ok := rustSysrootRuntimeCrates[norm]; ok {
		return model.CategoryRuntime
	}
	return model.CategoryUser
}

func normalizeCrateKey(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	return strings.ReplaceAll(s, "-", "_")
}

func fillMissingFunctionSizes(lb *loader.LoadedBinary, funcs []model.Function) {
	const maxInferredFuncSize = 64 * 1024
	for i := range funcs {
		if funcs[i].Size > 0 {
			continue
		}
		sec := lb.SectionContainingVA(funcs[i].Entry)
		if sec == nil {
			continue
		}
		secEnd := sec.VirtualAddr + sec.VirtualSize
		if i+1 < len(funcs) && funcs[i+1].Entry > funcs[i].Entry && funcs[i+1].Entry <= secEnd {
			gap := funcs[i+1].Entry - funcs[i].Entry
			if gap > maxInferredFuncSize {
				gap = maxInferredFuncSize
			}
			funcs[i].Size = gap
			funcs[i].End = funcs[i].Entry + gap
		} else if secEnd > funcs[i].Entry {
			gap := secEnd - funcs[i].Entry
			if gap > maxInferredFuncSize {
				gap = maxInferredFuncSize
			}
			funcs[i].Size = gap
			funcs[i].End = funcs[i].Entry + gap
		}
	}
}

func findPrimaryUserCrate(funcs []model.Function) string {
	counts := make(map[string]int)
	for i := range funcs {
		if funcs[i].Category != model.CategoryUser || funcs[i].Package == "" {
			continue
		}
		root := funcs[i].Package
		if idx := strings.Index(root, "::"); idx > 0 {
			root = root[:idx]
		}
		counts[root]++
	}
	var best string
	var bestCnt int
	for k, c := range counts {
		if c > bestCnt || (c == bestCnt && (best == "" || k < best)) {
			best = k
			bestCnt = c
		}
	}
	return best
}

func looksLikeUserPanicPath(p string) bool {
	norm := strings.ReplaceAll(p, `\`, "/")
	if strings.Contains(norm, "/rustc/") ||
		strings.Contains(norm, ".cargo/registry/") ||
		strings.Contains(norm, ".cargo/git/") ||
		strings.HasPrefix(norm, "library/") ||
		strings.Contains(norm, "/library/core/") ||
		strings.Contains(norm, "/library/std/") ||
		strings.Contains(norm, "/library/alloc/") {
		return false
	}
	base := filepath.Base(norm)
	return strings.HasSuffix(base, ".rs")
}

func buildPackageSummaries(funcs []model.Function, panics []model.PanicLocation) []model.PackageSummary {
	type pkgAcc struct {
		summary model.PackageSummary
		files   map[string]struct{}
	}
	byName := make(map[string]*pkgAcc)

	for i := range funcs {
		pkg := funcs[i].Package
		if pkg == "" {
			continue
		}
		acc, ok := byName[pkg]
		if !ok {
			acc = &pkgAcc{
				summary: model.PackageSummary{
					Name:     pkg,
					Category: funcs[i].Category,
				},
				files: make(map[string]struct{}),
			}
			byName[pkg] = acc
		}
		acc.summary.FunctionCount++
		acc.summary.TotalBytes += funcs[i].Size
		if categoryPriority(funcs[i].Category) < categoryPriority(acc.summary.Category) {
			acc.summary.Category = funcs[i].Category
		}
	}

	for _, pl := range panics {
		if pl.Crate == "" || pl.File == "" {
			continue
		}
		if acc, ok := byName[pl.Crate]; ok {
			acc.files[pl.File] = struct{}{}
		}
	}

	out := make([]model.PackageSummary, 0, len(byName))
	for _, acc := range byName {
		if len(acc.files) > 0 {
			files := make([]string, 0, len(acc.files))
			for f := range acc.files {
				files = append(files, f)
			}
			sort.Strings(files)
			acc.summary.SourceFiles = files
		}
		out = append(out, acc.summary)
	}

	sort.Slice(out, func(i, j int) bool {
		pi := categoryPriority(out[i].Category)
		pj := categoryPriority(out[j].Category)
		if pi != pj {
			return pi < pj
		}
		if out[i].FunctionCount != out[j].FunctionCount {
			return out[i].FunctionCount > out[j].FunctionCount
		}
		return out[i].Name < out[j].Name
	})

	return out
}

// collectAllSymbols returns lb.Symbols supplemented with PE export directory entries when present.
func collectAllSymbols(lb *loader.LoadedBinary) []model.SymbolEntry {
	if lb.Info.Format != model.FormatPE {
		return lb.Symbols
	}
	expSyms := parsePEExports(lb)
	if len(expSyms) == 0 {
		return lb.Symbols
	}
	merged := make([]model.SymbolEntry, 0, len(lb.Symbols)+len(expSyms))
	merged = append(merged, lb.Symbols...)
	merged = append(merged, expSyms...)
	return merged
}

func parsePEExports(lb *loader.LoadedBinary) []model.SymbolEntry {
	raw := lb.Raw()
	pf, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	defer pf.Close()

	var expRVA, expSize uint32
	switch opt := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(opt.DataDirectory) > 0 {
			expRVA = opt.DataDirectory[0].VirtualAddress
			expSize = opt.DataDirectory[0].Size
		}
	case *pe.OptionalHeader32:
		if len(opt.DataDirectory) > 0 {
			expRVA = opt.DataDirectory[0].VirtualAddress
			expSize = opt.DataDirectory[0].Size
		}
	}
	if expRVA == 0 || expSize < 40 {
		return nil
	}

	base := lb.Info.ImageBase
	hdr, ok := lb.ReadAtVA(base+uint64(expRVA), 40)
	if !ok {
		return nil
	}

	numFuncs := lb.Order.Uint32(hdr[20:24])
	numNames := lb.Order.Uint32(hdr[24:28])
	addrFuncsRVA := lb.Order.Uint32(hdr[28:32])
	addrNamesRVA := lb.Order.Uint32(hdr[32:36])
	addrOrdsRVA := lb.Order.Uint32(hdr[36:40])

	if numNames == 0 || numNames > 65536 || numFuncs == 0 || numFuncs > 65536 {
		return nil
	}

	namesBuf, ok1 := lb.ReadAtVA(base+uint64(addrNamesRVA), int(numNames)*4)
	ordsBuf, ok2 := lb.ReadAtVA(base+uint64(addrOrdsRVA), int(numNames)*2)
	funcsBuf, ok3 := lb.ReadAtVA(base+uint64(addrFuncsRVA), int(numFuncs)*4)
	if !ok1 || !ok2 || !ok3 {
		return nil
	}

	var out []model.SymbolEntry
	for i := uint32(0); i < numNames; i++ {
		nameRVA := lb.Order.Uint32(namesBuf[i*4 : i*4+4])
		ordIdx := lb.Order.Uint16(ordsBuf[i*2 : i*2+2])
		if uint32(ordIdx) >= numFuncs {
			continue
		}
		fnRVA := lb.Order.Uint32(funcsBuf[uint32(ordIdx)*4 : uint32(ordIdx)*4+4])
		// Skip forwarded exports (whose RVA points inside the export directory itself)
		if fnRVA >= expRVA && fnRVA < expRVA+expSize {
			continue
		}
		name, ok := lb.ReadCStringAtVA(base+uint64(nameRVA), 2048)
		if !ok || name == "" {
			continue
		}
		out = append(out, model.SymbolEntry{
			Name:    name,
			Addr:    base + uint64(fnRVA),
			Dynamic: true,
		})
	}
	return out
}
