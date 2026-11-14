// Package gorecover extracts Go build metadata, module dependencies, stripped
// function symbols, source file/line mappings, package summaries, and runtime
// struct/interface type descriptors from ELF, PE, and Mach-O Go binaries
// across Go 1.2 through Go 1.27+.
package gorecover

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

// Result contains all forensic and symbol artifacts recovered from a Go binary.
type Result struct {
	Meta         *model.GoMetadata
	Functions    []model.Function
	Packages     []model.PackageSummary
	Types        []model.RecoveredType
	Dependencies []model.Dependency
}

// Analyze inspects lb for Go buildinfo, pclntab, and moduledata structures.
// If lb is not a Go binary, Analyze returns &Result{Meta: &model.GoMetadata{Detected: false}}, nil.
func Analyze(lb *loader.LoadedBinary) (*Result, error) {
	if lb == nil {
		return nil, fmt.Errorf("nil LoadedBinary passed to gorecover.Analyze")
	}

	meta := &model.GoMetadata{
		Detected: false,
	}
	res := &Result{
		Meta: meta,
	}

	// 1. Parse Go buildinfo (stdlib primary + raw magic scanner fallback).
	biFound, deps := populateBuildInfo(lb, meta)
	if biFound {
		meta.Detected = true
		res.Dependencies = deps
	}

	// 2. Locate and validate Go pclntab (Go 1.2 through Go 1.27+).
	pcln, pclnFound := locatePCLnTab(lb)
	if pclnFound {
		meta.Detected = true
		meta.PCLnTabVersion = pcln.versionName
		meta.PCLnTabMagic = pcln.magic
		meta.PCLnTabAddr = pcln.va
		meta.PointerSize = pcln.ptrSize
		meta.Quantum = pcln.minLC
	}

	if !meta.Detected {
		return &Result{
			Meta: &model.GoMetadata{Detected: false},
		}, nil
	}

	// 3. Locate firstmoduledata to resolve accurate text base and type regions.
	var md *parsedModuleData
	if pclnFound {
		md = locateModuleData(lb, pcln)
		if md != nil {
			meta.ModuleDataAddr = md.va
			if md.text != 0 {
				meta.TextStart = md.text
			}
			if md.types != 0 && md.etypes > md.types {
				meta.TypesAddr = md.types
				meta.ETypesAddr = md.etypes
			}
		}

		// Resolve TextStart fallback if moduledata was unavailable or had zero text.
		if meta.TextStart == 0 {
			meta.TextStart = resolveTextStartFallback(lb, pcln)
		}

		// 4. Recover stripped functions, entry/end bounds, source files, and line numbers.
		res.Functions = recoverFunctions(lb, pcln, md, meta)
		res.Packages = aggregatePackages(res.Functions)
	}

	// 5. Recover named struct and interface types from moduledata type descriptors.
	if md != nil && md.types != 0 && md.etypes > md.types {
		res.Types = recoverTypes(lb, pcln, md, meta)
	}

	return res, nil
}

// aggregatePackages groups recovered functions into deterministically sorted PackageSummary records.
func aggregatePackages(funcs []model.Function) []model.PackageSummary {
	if len(funcs) == 0 {
		return nil
	}

	type pkgAccum struct {
		name      string
		category  model.PackageCategory
		count     int
		bytes     uint64
		fileSet   map[string]struct{}
		filesList []string
	}

	byName := make(map[string]*pkgAccum)
	for i := range funcs {
		fn := &funcs[i]
		pkgName := fn.Package
		if pkgName == "" {
			pkgName = "runtime"
		}
		acc, ok := byName[pkgName]
		if !ok {
			acc = &pkgAccum{
				name:     pkgName,
				category: fn.Category,
				fileSet:  make(map[string]struct{}),
			}
			byName[pkgName] = acc
		} else if categoryPriority(fn.Category) < categoryPriority(acc.category) {
			acc.category = fn.Category
		}
		acc.count++
		acc.bytes += fn.Size
		if fn.SourceFile != "" && fn.SourceFile != "?" {
			if _, seen := acc.fileSet[fn.SourceFile]; !seen {
				acc.fileSet[fn.SourceFile] = struct{}{}
				acc.filesList = append(acc.filesList, fn.SourceFile)
			}
		}
	}

	out := make([]model.PackageSummary, 0, len(byName))
	for _, acc := range byName {
		sort.Strings(acc.filesList)
		out = append(out, model.PackageSummary{
			Name:          acc.name,
			Category:      acc.category,
			FunctionCount: acc.count,
			TotalBytes:    acc.bytes,
			SourceFiles:   acc.filesList,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		pi, pj := categoryPriority(out[i].Category), categoryPriority(out[j].Category)
		if pi != pj {
			return pi < pj
		}
		return strings.Compare(out[i].Name, out[j].Name) < 0
	})

	return out
}

func categoryPriority(c model.PackageCategory) int {
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
