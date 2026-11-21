// Package diff performs structural patch and version diffing between two
// analyzed binaries (including stripped Go, Rust, and native executables).
package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aloneangel45/symforge/pkg/model"
)

// Options controls filtering and output bounds when diffing two binaries.
type Options struct {
	UserOnly bool
	Limit    int
}

// FuncSummary is a compact representation of an added or removed function.
type FuncSummary struct {
	Name       string                `json:"name"`
	Demangled  string                `json:"demangled,omitempty"`
	Package    string                `json:"package,omitempty"`
	Category   model.PackageCategory `json:"category"`
	Entry      uint64                `json:"entry"`
	Size       uint64                `json:"size,omitempty"`
	SourceFile string                `json:"source_file,omitempty"`
	Line       int                   `json:"line,omitempty"`
}

// ModifiedFunc describes a function present in both binaries whose size, category,
// or cryptographic references changed.
type ModifiedFunc struct {
	Name        string                `json:"name"`
	Demangled   string                `json:"demangled,omitempty"`
	Package     string                `json:"package,omitempty"`
	OldCategory model.PackageCategory `json:"old_category"`
	NewCategory model.PackageCategory `json:"new_category"`
	OldEntry    uint64                `json:"old_entry"`
	NewEntry    uint64                `json:"new_entry"`
	OldSize     uint64                `json:"old_size"`
	NewSize     uint64                `json:"new_size"`
	SizeDelta   int64                 `json:"size_delta"`
	Reasons     []string              `json:"reasons"`
}

// PackageDiff lists added and removed Go packages or Rust crates.
type PackageDiff struct {
	Added   []model.PackageSummary `json:"added,omitempty"`
	Removed []model.PackageSummary `json:"removed,omitempty"`
}

// DepVersionChange records a dependency whose version changed between binA and binB.
type DepVersionChange struct {
	Ecosystem  string `json:"ecosystem"`
	Name       string `json:"name"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
}

// DepDiff lists added, removed, and version-changed dependencies.
type DepDiff struct {
	Added   []model.Dependency `json:"added,omitempty"`
	Removed []model.Dependency `json:"removed,omitempty"`
	Changed []DepVersionChange `json:"changed,omitempty"`
}

// ImportDiff lists added and removed native dynamic libraries / API imports.
type ImportDiff struct {
	Added   []model.ImportSymbol `json:"added,omitempty"`
	Removed []model.ImportSymbol `json:"removed,omitempty"`
}

// StringDiff lists added and removed high-signal strings.
type StringDiff struct {
	Added   []model.ExtractedString `json:"added,omitempty"`
	Removed []model.ExtractedString `json:"removed,omitempty"`
}

// CryptoDiff lists added and removed cryptographic constants.
type CryptoDiff struct {
	Added   []model.CryptoDetection `json:"added,omitempty"`
	Removed []model.CryptoDetection `json:"removed,omitempty"`
}

// RiskHighlight flags security- or patch-relevant changes discovered during diffing.
type RiskHighlight struct {
	Severity string `json:"severity"` // critical, high, medium, info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// Summary holds aggregate counters across the full diff before per-section truncation.
type Summary struct {
	FunctionsA         int   `json:"functions_a"`
	FunctionsB         int   `json:"functions_b"`
	AddedFunctions     int   `json:"added_functions"`
	RemovedFunctions   int   `json:"removed_functions"`
	ModifiedFunctions  int   `json:"modified_functions"`
	UnchangedFunctions int   `json:"unchanged_functions"`
	AddedPackages      int   `json:"added_packages"`
	RemovedPackages    int   `json:"removed_packages"`
	AddedDeps          int   `json:"added_deps"`
	RemovedDeps        int   `json:"removed_deps"`
	ChangedDeps        int   `json:"changed_deps"`
	AddedImports       int   `json:"added_imports"`
	RemovedImports     int   `json:"removed_imports"`
	AddedStrings       int   `json:"added_strings"`
	RemovedStrings     int   `json:"removed_strings"`
	AddedCrypto        int   `json:"added_crypto"`
	RemovedCrypto      int   `json:"removed_crypto"`
	SizeDeltaBytes     int64 `json:"size_delta_bytes"`
}

// DiffResult is the complete structured patch comparison between BinaryA (old/base) and BinaryB (new/target).
type DiffResult struct {
	BinaryA           model.BinaryInfo `json:"binary_a"`
	BinaryB           model.BinaryInfo `json:"binary_b"`
	Identical         bool             `json:"identical"`
	UserOnly          bool             `json:"user_only"`
	Limit             int              `json:"limit,omitempty"`
	Summary           Summary          `json:"summary"`
	AddedFunctions    []FuncSummary    `json:"added_functions,omitempty"`
	RemovedFunctions  []FuncSummary    `json:"removed_functions,omitempty"`
	ModifiedFunctions []ModifiedFunc   `json:"modified_functions,omitempty"`
	Packages          PackageDiff      `json:"packages"`
	Dependencies      DepDiff          `json:"dependencies"`
	Imports           ImportDiff       `json:"imports"`
	Strings           StringDiff       `json:"strings"`
	Crypto            CryptoDiff       `json:"crypto"`
	RiskHighlights    []RiskHighlight  `json:"risk_highlights,omitempty"`
}

// Compare computes a structured binary diff between base (binA) and target (binB).
func Compare(binA, binB *model.AnalysisResult, opts Options) (*DiffResult, error) {
	if binA == nil || binB == nil {
		return nil, fmt.Errorf("diff requires two non-nil analysis results")
	}

	limit := opts.Limit
	if limit < 0 {
		limit = 0
	}

	out := &DiffResult{
		BinaryA:  binA.Binary,
		BinaryB:  binB.Binary,
		UserOnly: opts.UserOnly,
		Limit:    limit,
		Summary: Summary{
			SizeDeltaBytes: binB.Binary.SizeBytes - binA.Binary.SizeBytes,
		},
	}

	// 1. Diff functions matched deterministically by canonical recovered/demangled name
	// (handling duplicate names such as Go init/closures, Rust monomorphizations, or stripped symbols).
	groupsA, countA := indexFunctionGroups(binA.Functions, opts.UserOnly)
	groupsB, countB := indexFunctionGroups(binB.Functions, opts.UserOnly)
	out.Summary.FunctionsA = countA
	out.Summary.FunctionsB = countB

	addedFns := make([]FuncSummary, 0)
	removedFns := make([]FuncSummary, 0)
	modifiedFns := make([]ModifiedFunc, 0)
	unchanged := 0

	allKeysMap := make(map[string]struct{}, len(groupsA)+len(groupsB))
	for k := range groupsA {
		allKeysMap[k] = struct{}{}
	}
	for k := range groupsB {
		allKeysMap[k] = struct{}{}
	}
	allKeys := make([]string, 0, len(allKeysMap))
	for k := range allKeysMap {
		allKeys = append(allKeys, k)
	}
	sort.Strings(allKeys)

	for _, key := range allKeys {
		listA := groupsA[key]
		listB := groupsB[key]
		switch {
		case len(listA) == 0:
			for _, fnB := range listB {
				addedFns = append(addedFns, toFuncSummary(fnB))
			}
		case len(listB) == 0:
			for _, fnA := range listA {
				removedFns = append(removedFns, toFuncSummary(fnA))
			}
		case len(listA) == 1 && len(listB) == 1:
			if mod, changed := compareFunctionPair(listA[0], listB[0]); changed {
				modifiedFns = append(modifiedFns, mod)
			} else {
				unchanged++
			}
		default:
			aAdd, aRem, aMod, aUnch := diffFunctionGroup(listA, listB)
			addedFns = append(addedFns, aAdd...)
			removedFns = append(removedFns, aRem...)
			modifiedFns = append(modifiedFns, aMod...)
			unchanged += aUnch
		}
	}

	sortFuncSummaries(addedFns)
	sortFuncSummaries(removedFns)
	sort.Slice(modifiedFns, func(i, j int) bool {
		ai := absInt64(modifiedFns[i].SizeDelta)
		aj := absInt64(modifiedFns[j].SizeDelta)
		if ai != aj {
			return ai > aj
		}
		if modifiedFns[i].Name != modifiedFns[j].Name {
			return modifiedFns[i].Name < modifiedFns[j].Name
		}
		if modifiedFns[i].NewEntry != modifiedFns[j].NewEntry {
			return modifiedFns[i].NewEntry < modifiedFns[j].NewEntry
		}
		return modifiedFns[i].OldEntry < modifiedFns[j].OldEntry
	})

	out.Summary.AddedFunctions = len(addedFns)
	out.Summary.RemovedFunctions = len(removedFns)
	out.Summary.ModifiedFunctions = len(modifiedFns)
	out.Summary.UnchangedFunctions = unchanged

	// 2. Diff packages.
	pkgA := indexPackages(binA.Packages, opts.UserOnly)
	pkgB := indexPackages(binB.Packages, opts.UserOnly)
	var addedPkgs, removedPkgs []model.PackageSummary
	for name, p := range pkgB {
		if _, ok := pkgA[name]; !ok {
			addedPkgs = append(addedPkgs, p)
		}
	}
	for name, p := range pkgA {
		if _, ok := pkgB[name]; !ok {
			removedPkgs = append(removedPkgs, p)
		}
	}
	sort.Slice(addedPkgs, func(i, j int) bool { return addedPkgs[i].Name < addedPkgs[j].Name })
	sort.Slice(removedPkgs, func(i, j int) bool { return removedPkgs[i].Name < removedPkgs[j].Name })
	out.Summary.AddedPackages = len(addedPkgs)
	out.Summary.RemovedPackages = len(removedPkgs)

	// 3. Diff dependencies (Go modules / Rust crates).
	depA := indexDeps(binA.Dependencies)
	depB := indexDeps(binB.Dependencies)
	var addedDeps, removedDeps []model.Dependency
	var changedDeps []DepVersionChange
	for key, dB := range depB {
		dA, ok := depA[key]
		if !ok {
			addedDeps = append(addedDeps, dB)
			continue
		}
		if dA.Version != dB.Version {
			changedDeps = append(changedDeps, DepVersionChange{
				Ecosystem:  dB.Ecosystem,
				Name:       dB.Name,
				OldVersion: dA.Version,
				NewVersion: dB.Version,
			})
		}
	}
	for key, dA := range depA {
		if _, ok := depB[key]; !ok {
			removedDeps = append(removedDeps, dA)
		}
	}
	sort.Slice(addedDeps, func(i, j int) bool { return addedDeps[i].Name < addedDeps[j].Name })
	sort.Slice(removedDeps, func(i, j int) bool { return removedDeps[i].Name < removedDeps[j].Name })
	sort.Slice(changedDeps, func(i, j int) bool { return changedDeps[i].Name < changedDeps[j].Name })
	out.Summary.AddedDeps = len(addedDeps)
	out.Summary.RemovedDeps = len(removedDeps)
	out.Summary.ChangedDeps = len(changedDeps)

	// 4. Diff native imports.
	impA := indexImports(binA.Imports)
	impB := indexImports(binB.Imports)
	var addedImps, removedImps []model.ImportSymbol
	for key, imp := range impB {
		if _, ok := impA[key]; !ok {
			addedImps = append(addedImps, imp)
		}
	}
	for key, imp := range impA {
		if _, ok := impB[key]; !ok {
			removedImps = append(removedImps, imp)
		}
	}
	sortImports(addedImps)
	sortImports(removedImps)
	out.Summary.AddedImports = len(addedImps)
	out.Summary.RemovedImports = len(removedImps)

	// 5. Diff high-signal strings.
	strA := indexHighSignalStrings(binA.Strings)
	strB := indexHighSignalStrings(binB.Strings)
	var addedStrs, removedStrs []model.ExtractedString
	for key, s := range strB {
		if _, ok := strA[key]; !ok {
			addedStrs = append(addedStrs, s)
		}
	}
	for key, s := range strA {
		if _, ok := strB[key]; !ok {
			removedStrs = append(removedStrs, s)
		}
	}
	sortStrings(addedStrs)
	sortStrings(removedStrs)
	out.Summary.AddedStrings = len(addedStrs)
	out.Summary.RemovedStrings = len(removedStrs)

	// 6. Diff cryptographic constants.
	cryA := indexCrypto(binA.Crypto)
	cryB := indexCrypto(binB.Crypto)
	var addedCrypto, removedCrypto []model.CryptoDetection
	for key, c := range cryB {
		if _, ok := cryA[key]; !ok {
			addedCrypto = append(addedCrypto, c)
		}
	}
	for key, c := range cryA {
		if _, ok := cryB[key]; !ok {
			removedCrypto = append(removedCrypto, c)
		}
	}
	sort.Slice(addedCrypto, func(i, j int) bool { return addedCrypto[i].Name < addedCrypto[j].Name })
	sort.Slice(removedCrypto, func(i, j int) bool { return removedCrypto[i].Name < removedCrypto[j].Name })
	out.Summary.AddedCrypto = len(addedCrypto)
	out.Summary.RemovedCrypto = len(removedCrypto)

	// 7. Compute risk highlights before truncation so critical signals are never dropped.
	out.RiskHighlights = computeRiskHighlights(binA, binB, addedImps, addedStrs, addedCrypto, changedDeps, addedFns)

	// 8. Apply per-section limit if requested.
	out.AddedFunctions = capSlice(addedFns, limit)
	out.RemovedFunctions = capSlice(removedFns, limit)
	out.ModifiedFunctions = capSlice(modifiedFns, limit)
	out.Packages = PackageDiff{
		Added:   capSlice(addedPkgs, limit),
		Removed: capSlice(removedPkgs, limit),
	}
	out.Dependencies = DepDiff{
		Added:   capSlice(addedDeps, limit),
		Removed: capSlice(removedDeps, limit),
		Changed: capSlice(changedDeps, limit),
	}
	out.Imports = ImportDiff{
		Added:   capSlice(addedImps, limit),
		Removed: capSlice(removedImps, limit),
	}
	out.Strings = StringDiff{
		Added:   capSlice(addedStrs, limit),
		Removed: capSlice(removedStrs, limit),
	}
	out.Crypto = CryptoDiff{
		Added:   capSlice(addedCrypto, limit),
		Removed: capSlice(removedCrypto, limit),
	}

	out.Identical = (binA.Binary.SHA256 != "" && binA.Binary.SHA256 == binB.Binary.SHA256 && binA.Binary.Arch == binB.Binary.Arch) ||
		(out.Summary.AddedFunctions == 0 &&
			out.Summary.RemovedFunctions == 0 &&
			out.Summary.ModifiedFunctions == 0 &&
			out.Summary.AddedPackages == 0 &&
			out.Summary.RemovedPackages == 0 &&
			out.Summary.AddedDeps == 0 &&
			out.Summary.RemovedDeps == 0 &&
			out.Summary.ChangedDeps == 0 &&
			out.Summary.AddedImports == 0 &&
			out.Summary.RemovedImports == 0 &&
			out.Summary.AddedStrings == 0 &&
			out.Summary.RemovedStrings == 0 &&
			out.Summary.AddedCrypto == 0 &&
			out.Summary.RemovedCrypto == 0)

	return out, nil
}

func computeRiskHighlights(
	binA, binB *model.AnalysisResult,
	addedImps []model.ImportSymbol,
	addedStrs []model.ExtractedString,
	addedCrypto []model.CryptoDetection,
	changedDeps []DepVersionChange,
	addedFns []FuncSummary,
) []RiskHighlight {
	var highlights []RiskHighlight

	if !binA.Binary.PackedLikely && binB.Binary.PackedLikely {
		highlights = append(highlights, RiskHighlight{
			Severity: "high",
			Title:    "Target binary appears packed or high-entropy",
			Detail:   fmt.Sprintf("PackedLikely changed false -> true (max entropy %.2f -> %.2f)", binA.Binary.MaxEntropy, binB.Binary.MaxEntropy),
		})
	} else if binB.Binary.MaxEntropy-binA.Binary.MaxEntropy >= 1.0 && binB.Binary.MaxEntropy >= 7.0 {
		highlights = append(highlights, RiskHighlight{
			Severity: "medium",
			Title:    "Significant section entropy increase",
			Detail:   fmt.Sprintf("Max section entropy rose from %.2f to %.2f", binA.Binary.MaxEntropy, binB.Binary.MaxEntropy),
		})
	}

	sensitiveSubstrAPIs := []string{
		"virtualalloc", "writeprocessmemory", "createremotethread", "ntcreatethreadex",
		"createprocess", "winexec", "shellexecute", "isdebuggerpresent",
		"checkremotedebuggerpresent", "winhttpopen", "internetopen", "regsetvalue",
		"createservice", "adjusttokenprivileges",
	}
	sensitiveExactAPIs := map[string]bool{
		"system": true, "popen": true, "wpopen": true, "ptrace": true, "mprotect": true,
	}
	var addedSensitive []string
	seenSensitive := make(map[string]struct{})
	for _, imp := range addedImps {
		clean := strings.TrimLeft(strings.ToLower(imp.Name), "_")
		if clean == "" {
			continue
		}
		matched := sensitiveExactAPIs[clean]
		if !matched {
			for _, api := range sensitiveSubstrAPIs {
				if strings.Contains(clean, api) {
					matched = true
					break
				}
			}
		}
		if matched {
			label := imp.Name
			if imp.Library != "" {
				label = imp.Library + "!" + imp.Name
			}
			key := strings.ToLower(label)
			if _, dup := seenSensitive[key]; !dup {
				seenSensitive[key] = struct{}{}
				addedSensitive = append(addedSensitive, label)
			}
		}
	}
	if len(addedSensitive) > 0 {
		sev := "high"
		for _, s := range addedSensitive {
			l := strings.ToLower(s)
			if strings.Contains(l, "writeprocessmemory") || strings.Contains(l, "createremotethread") || strings.Contains(l, "ntcreatethreadex") {
				sev = "critical"
				break
			}
		}
		highlights = append(highlights, RiskHighlight{
			Severity: sev,
			Title:    fmt.Sprintf("Added %d security-sensitive native import(s)", len(addedSensitive)),
			Detail:   strings.Join(capSlice(addedSensitive, 8), ", "),
		})
	}

	var addedSecrets, addedCmds, addedURLs []string
	for _, st := range addedStrs {
		switch st.Kind {
		case model.StringSecretCandidate:
			addedSecrets = append(addedSecrets, truncateStr(st.Value, 48))
		case model.StringCommand:
			addedCmds = append(addedCmds, truncateStr(st.Value, 48))
		case model.StringURL:
			addedURLs = append(addedURLs, truncateStr(st.Value, 64))
		}
	}
	if len(addedSecrets) > 0 {
		highlights = append(highlights, RiskHighlight{
			Severity: "high",
			Title:    fmt.Sprintf("Added %d hardcoded secret candidate(s)", len(addedSecrets)),
			Detail:   strings.Join(capSlice(addedSecrets, 5), "; "),
		})
	}
	if len(addedCmds) > 0 {
		highlights = append(highlights, RiskHighlight{
			Severity: "medium",
			Title:    fmt.Sprintf("Added %d command execution string(s)", len(addedCmds)),
			Detail:   strings.Join(capSlice(addedCmds, 5), "; "),
		})
	}
	if len(addedURLs) > 0 {
		highlights = append(highlights, RiskHighlight{
			Severity: "info",
			Title:    fmt.Sprintf("Added %d URL indicator(s)", len(addedURLs)),
			Detail:   strings.Join(capSlice(addedURLs, 5), "; "),
		})
	}

	if len(addedCrypto) > 0 {
		names := make([]string, 0, len(addedCrypto))
		for _, c := range addedCrypto {
			names = append(names, fmt.Sprintf("%s (%s)", c.Name, c.Algorithm))
		}
		highlights = append(highlights, RiskHighlight{
			Severity: "medium",
			Title:    fmt.Sprintf("Added %d cryptographic constant(s)", len(addedCrypto)),
			Detail:   strings.Join(capSlice(names, 6), ", "),
		})
	}

	if binA.Go != nil && binB.Go != nil && binA.Go.Version != "" && binB.Go.Version != "" && binA.Go.Version != binB.Go.Version {
		highlights = append(highlights, RiskHighlight{
			Severity: "info",
			Title:    "Go toolchain version changed",
			Detail:   fmt.Sprintf("%s -> %s", binA.Go.Version, binB.Go.Version),
		})
	}

	if len(changedDeps) > 0 {
		sample := make([]string, 0, minInt(len(changedDeps), 5))
		for i := 0; i < len(changedDeps) && i < 5; i++ {
			c := changedDeps[i]
			sample = append(sample, fmt.Sprintf("%s (%s -> %s)", c.Name, c.OldVersion, c.NewVersion))
		}
		highlights = append(highlights, RiskHighlight{
			Severity: "info",
			Title:    fmt.Sprintf("%d dependency version(s) updated", len(changedDeps)),
			Detail:   strings.Join(sample, ", "),
		})
	}

	// Highlight newly introduced execution/network packages in added functions
	var execAdded []string
	for _, fn := range addedFns {
		n := strings.ToLower(fn.Name)
		if strings.HasPrefix(n, "os/exec.") || strings.Contains(n, "syscall.exec") || strings.Contains(n, "net/http.") {
			execAdded = append(execAdded, fn.Name)
		}
	}
	if len(execAdded) > 0 {
		highlights = append(highlights, RiskHighlight{
			Severity: "info",
			Title:    fmt.Sprintf("Added %d execution/network runtime function(s)", len(execAdded)),
			Detail:   strings.Join(capSlice(execAdded, 5), ", "),
		})
	}

	return highlights
}

func indexFunctionGroups(funcs []model.Function, userOnly bool) (map[string][]model.Function, int) {
	groups := make(map[string][]model.Function, len(funcs))
	total := 0
	for _, fn := range funcs {
		if userOnly && fn.Category != model.CategoryUser && fn.Category != model.CategoryDependency {
			continue
		}
		key := canonicalFuncName(fn)
		if key == "" {
			continue
		}
		groups[key] = append(groups[key], fn)
		total++
	}
	for k := range groups {
		g := groups[k]
		if len(g) > 1 {
			sort.Slice(g, func(i, j int) bool {
				if g[i].Entry != g[j].Entry {
					return g[i].Entry < g[j].Entry
				}
				if g[i].Size != g[j].Size {
					return g[i].Size < g[j].Size
				}
				if g[i].SourceFile != g[j].SourceFile {
					return g[i].SourceFile < g[j].SourceFile
				}
				if g[i].Line != g[j].Line {
					return g[i].Line < g[j].Line
				}
				return g[i].Name < g[j].Name
			})
		}
	}
	return groups, total
}

func compareFunctionPair(fnA, fnB model.Function) (ModifiedFunc, bool) {
	var reasons []string
	sizeDelta := int64(fnB.Size) - int64(fnA.Size)
	if sizeDelta != 0 {
		reasons = append(reasons, "size_changed")
	}
	if fnA.Category != fnB.Category {
		reasons = append(reasons, "category_changed")
	}
	if !stringSlicesEqualFold(fnA.CryptoRefs, fnB.CryptoRefs) {
		reasons = append(reasons, "crypto_refs_changed")
	}
	if len(reasons) == 0 {
		return ModifiedFunc{}, false
	}
	return ModifiedFunc{
		Name:        fnB.Name,
		Demangled:   fnB.Demangled,
		Package:     fnB.Package,
		OldCategory: fnA.Category,
		NewCategory: fnB.Category,
		OldEntry:    fnA.Entry,
		NewEntry:    fnB.Entry,
		OldSize:     fnA.Size,
		NewSize:     fnB.Size,
		SizeDelta:   sizeDelta,
		Reasons:     reasons,
	}, true
}

func diffFunctionGroup(listA, listB []model.Function) (added []FuncSummary, removed []FuncSummary, modified []ModifiedFunc, unchanged int) {
	usedA := make([]bool, len(listA))
	usedB := make([]bool, len(listB))

	// Pass 1: exact unchanged matches (preferring same SourceFile+Line, then Entry order).
	for bi, fnB := range listB {
		bestA := -1
		for ai, fnA := range listA {
			if usedA[ai] {
				continue
			}
			if _, changed := compareFunctionPair(fnA, fnB); !changed {
				if bestA == -1 {
					bestA = ai
				}
				if fnA.SourceFile != "" && fnA.SourceFile == fnB.SourceFile && fnA.Line == fnB.Line {
					bestA = ai
					break
				}
			}
		}
		if bestA >= 0 {
			usedA[bestA] = true
			usedB[bi] = true
			unchanged++
		}
	}

	// Pass 2: match remaining functions by identical non-empty (SourceFile, Line).
	for bi, fnB := range listB {
		if usedB[bi] || fnB.SourceFile == "" {
			continue
		}
		for ai, fnA := range listA {
			if usedA[ai] {
				continue
			}
			if fnA.SourceFile == fnB.SourceFile && fnA.Line == fnB.Line {
				usedA[ai] = true
				usedB[bi] = true
				if mod, changed := compareFunctionPair(fnA, fnB); changed {
					modified = append(modified, mod)
				} else {
					unchanged++
				}
				break
			}
		}
	}

	// Pass 3: pair remaining unmatched functions deterministically by smallest size delta (breaking ties by Entry).
	for bi, fnB := range listB {
		if usedB[bi] {
			continue
		}
		bestA := -1
		var bestDelta int64
		for ai, fnA := range listA {
			if usedA[ai] {
				continue
			}
			d := absInt64(int64(fnB.Size) - int64(fnA.Size))
			if bestA == -1 || d < bestDelta {
				bestA = ai
				bestDelta = d
			}
		}
		if bestA >= 0 {
			usedA[bestA] = true
			usedB[bi] = true
			if mod, changed := compareFunctionPair(listA[bestA], fnB); changed {
				modified = append(modified, mod)
			} else {
				unchanged++
			}
		}
	}

	// Pass 4: unmatched leftovers become Added or Removed.
	for bi, fnB := range listB {
		if !usedB[bi] {
			added = append(added, toFuncSummary(fnB))
		}
	}
	for ai, fnA := range listA {
		if !usedA[ai] {
			removed = append(removed, toFuncSummary(fnA))
		}
	}
	return added, removed, modified, unchanged
}

func canonicalFuncName(fn model.Function) string {
	if fn.Demangled != "" {
		return fn.Demangled
	}
	return fn.Name
}

func toFuncSummary(fn model.Function) FuncSummary {
	return FuncSummary{
		Name:       fn.Name,
		Demangled:  fn.Demangled,
		Package:    fn.Package,
		Category:   fn.Category,
		Entry:      fn.Entry,
		Size:       fn.Size,
		SourceFile: fn.SourceFile,
		Line:       fn.Line,
	}
}

func indexPackages(pkgs []model.PackageSummary, userOnly bool) map[string]model.PackageSummary {
	m := make(map[string]model.PackageSummary, len(pkgs))
	for _, p := range pkgs {
		if userOnly && p.Category != model.CategoryUser && p.Category != model.CategoryDependency {
			continue
		}
		if p.Name != "" {
			m[p.Name] = p
		}
	}
	return m
}

func indexDeps(deps []model.Dependency) map[string]model.Dependency {
	m := make(map[string]model.Dependency, len(deps))
	for _, d := range deps {
		if d.Name == "" {
			continue
		}
		k := d.Ecosystem + ":" + d.Name
		m[k] = d
	}
	return m
}

func indexImports(imps []model.ImportSymbol) map[string]model.ImportSymbol {
	m := make(map[string]model.ImportSymbol, len(imps))
	for _, imp := range imps {
		k := strings.ToLower(imp.Library) + "!" + imp.Name
		if _, exists := m[k]; !exists {
			m[k] = imp
		}
	}
	return m
}

func indexHighSignalStrings(strs []model.ExtractedString) map[string]model.ExtractedString {
	m := make(map[string]model.ExtractedString)
	for _, s := range strs {
		if s.Kind == model.StringGeneral || s.Value == "" {
			continue
		}
		k := string(s.Kind) + "\x00" + s.Value
		if _, exists := m[k]; !exists {
			m[k] = s
		}
	}
	return m
}

func indexCrypto(crypto []model.CryptoDetection) map[string]model.CryptoDetection {
	m := make(map[string]model.CryptoDetection, len(crypto))
	for _, c := range crypto {
		k := c.Algorithm + ":" + c.Name
		if _, exists := m[k]; !exists {
			m[k] = c
		}
	}
	return m
}

func sortFuncSummaries(list []FuncSummary) {
	sort.Slice(list, func(i, j int) bool {
		if (list[i].Category == model.CategoryUser) != (list[j].Category == model.CategoryUser) {
			return list[i].Category == model.CategoryUser
		}
		if list[i].Size != list[j].Size {
			return list[i].Size > list[j].Size
		}
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].Entry < list[j].Entry
	})
}

func sortImports(list []model.ImportSymbol) {
	sort.Slice(list, func(i, j int) bool {
		li := strings.ToLower(list[i].Library)
		lj := strings.ToLower(list[j].Library)
		if li != lj {
			return li < lj
		}
		if list[i].Library != list[j].Library {
			return list[i].Library < list[j].Library
		}
		return list[i].Name < list[j].Name
	})
}

func sortStrings(list []model.ExtractedString) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Kind != list[j].Kind {
			return list[i].Kind < list[j].Kind
		}
		return list[i].Value < list[j].Value
	})
}

func stringSlicesEqualFold(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	ca := make([]string, len(a))
	cb := make([]string, len(b))
	for i := range a {
		ca[i] = strings.ToLower(a[i])
		cb[i] = strings.ToLower(b[i])
	}
	sort.Strings(ca)
	sort.Strings(cb)
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}

func capSlice[T any](in []T, limit int) []T {
	if limit <= 0 || len(in) <= limit {
		return in
	}
	return in[:limit]
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func truncateStr(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	runes := []rune(s)
	if len(runes) > maxLen && maxLen > 3 {
		return string(runes[:maxLen-3]) + "..."
	}
	return s
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
