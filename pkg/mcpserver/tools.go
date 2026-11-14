package mcpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aloneangel45/symforge/pkg/analyzer"
	"github.com/aloneangel45/symforge/pkg/exporter"
	"github.com/aloneangel45/symforge/pkg/model"
	"github.com/aloneangel45/symforge/pkg/rustrecover"
)

func (s *Server) toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "analyze_binary",
			"description": "Analyze a stripped or unstripped ELF, PE, or Mach-O binary (Go, Rust, or Native). Recovers pclntab/Rust metadata, section entropy, package counts, crypto tables, and high-signal string previews.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "Path to the target ELF, PE, or Mach-O binary file."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "list_packages_crates",
			"description": "List recovered Go packages or Rust crates from a binary, separated into user, dependency, stdlib, and runtime categories.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":     map[string]any{"type": "string", "description": "Path to the target binary file."},
					"category": map[string]any{"type": "string", "description": "Optional filter: user, dependency, stdlib, runtime, native, or all (default: all)."},
					"limit":    map[string]any{"type": "integer", "description": "Maximum packages to return (default: 50)."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "search_functions",
			"description": "Search recovered binary functions (including stripped Go pclntab functions and Rust/PE .pdata functions) by name, package, source file, or category.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":     map[string]any{"type": "string", "description": "Path to the target binary file."},
					"query":    map[string]any{"type": "string", "description": "Case-insensitive substring matching function name, demangled name, or source file."},
					"package":  map[string]any{"type": "string", "description": "Optional package/crate substring filter."},
					"category": map[string]any{"type": "string", "description": "Optional category filter: user, dependency, stdlib, runtime, native, or all."},
					"limit":    map[string]any{"type": "integer", "description": "Maximum functions to return (default: 50, max: 500)."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "inspect_function",
			"description": "Inspect a specific binary function by name or virtual address (e.g. '0x401000'): returns source file/line, callers, callees, string/crypto XREFs, and annotated x86_64/ARM64 disassembly.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":             map[string]any{"type": "string", "description": "Path to the target binary file."},
					"target":           map[string]any{"type": "string", "description": "Function name, substring, or hex address (0x...)."},
					"disassemble":      map[string]any{"type": "boolean", "description": "Include decoded machine instructions (default: true)."},
					"max_instructions": map[string]any{"type": "integer", "description": "Maximum instructions to decode (default: 120, max: 1000)."},
				},
				"required": []string{"path", "target"},
			},
		},
		{
			"name":        "find_xrefs",
			"description": "Find classified strings (URLs, API routes, secret candidates, SQL, commands, file paths) and cryptographic constants (AES S-Box, SHA-256, ChaCha20) along with the exact functions referencing them.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":  map[string]any{"type": "string", "description": "Path to the target binary file."},
					"kind":  map[string]any{"type": "string", "description": "Filter: url, api_route, secret_candidate, filepath, sql, command, error_msg, crypto, high_signal, or all (default: high_signal)."},
					"query": map[string]any{"type": "string", "description": "Optional case-insensitive substring filter."},
					"limit": map[string]any{"type": "integer", "description": "Maximum matches to return (default: 50, max: 500)."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "recover_types",
			"description": "Recover Go struct field layouts, Go interface method sets, and Rust trait vtables from read-only binary type metadata.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":  map[string]any{"type": "string", "description": "Path to the target binary file."},
					"kind":  map[string]any{"type": "string", "description": "Optional kind filter: struct, interface, vtable, or all (default: all)."},
					"query": map[string]any{"type": "string", "description": "Optional substring filter on type or package name."},
					"limit": map[string]any{"type": "integer", "description": "Maximum types to return (default: 50, max: 500)."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "demangle_symbols",
			"description": "Demangle Rust v0 (_R...) and Legacy (_ZN...E) mangled symbol names in pure Go.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"symbols": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "List of mangled symbols to demangle.",
					},
				},
				"required": []string{"symbols"},
			},
		},
		{
			"name":        "export_re_script",
			"description": "Export recovered stripped symbols, comments, and types as a Ghidra, IDA Pro, or Binary Ninja script, Markdown forensic report, or CycloneDX 1.5 SBOM.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":        map[string]any{"type": "string", "description": "Path to the target binary file."},
					"format":      map[string]any{"type": "string", "description": "Target format: ghidra, ida, binja, markdown, or sbom."},
					"output_path": map[string]any{"type": "string", "description": "Optional destination file path to write the generated script/report."},
					"user_only":   map[string]any{"type": "boolean", "description": "When true, exclude runtime/stdlib functions from RE scripts (default: false)."},
				},
				"required": []string{"path", "format"},
			},
		},
	}
}

func (s *Server) executeTool(name string, rawArgs json.RawMessage) (string, bool, *rpcError) {
	switch name {
	case "analyze_binary":
		var args struct {
			Path string `json:"path"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil || strings.TrimSpace(args.Path) == "" {
			return "missing required 'path' argument", true, nil
		}
		res, err := s.engine.AnalyzeFile(args.Path, analyzer.Options{})
		if err != nil {
			return fmt.Sprintf("analyze_binary error: %v", err), true, nil
		}
		return marshalCompact(buildExecutiveSummary(res)), false, nil

	case "list_packages_crates":
		var args struct {
			Path     string `json:"path"`
			Category string `json:"category"`
			Limit    int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil || strings.TrimSpace(args.Path) == "" {
			return "missing required 'path' argument", true, nil
		}
		res, err := s.engine.AnalyzeFile(args.Path, analyzer.Options{})
		if err != nil {
			return fmt.Sprintf("list_packages_crates error: %v", err), true, nil
		}
		limit := clampLimit(args.Limit, 50, 500)
		cat := strings.ToLower(strings.TrimSpace(args.Category))
		var out []model.PackageSummary
		for _, p := range res.Packages {
			if cat != "" && cat != "all" && string(p.Category) != cat {
				continue
			}
			out = append(out, p)
			if len(out) >= limit {
				break
			}
		}
		return marshalCompact(map[string]any{
			"total_packages": len(res.Packages),
			"returned":       len(out),
			"packages":       out,
		}), false, nil

	case "search_functions":
		var args struct {
			Path     string `json:"path"`
			Query    string `json:"query"`
			Package  string `json:"package"`
			Category string `json:"category"`
			Limit    int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil || strings.TrimSpace(args.Path) == "" {
			return "missing required 'path' argument", true, nil
		}
		res, err := s.engine.AnalyzeFile(args.Path, analyzer.Options{})
		if err != nil {
			return fmt.Sprintf("search_functions error: %v", err), true, nil
		}
		limit := clampLimit(args.Limit, 50, 500)
		q := strings.ToLower(strings.TrimSpace(args.Query))
		pkgFilter := strings.ToLower(strings.TrimSpace(args.Package))
		cat := strings.ToLower(strings.TrimSpace(args.Category))

		type compactFunc struct {
			Entry      string                `json:"entry"`
			Size       uint64                `json:"size,omitempty"`
			Name       string                `json:"name"`
			Demangled  string                `json:"demangled,omitempty"`
			Package    string                `json:"package,omitempty"`
			Category   model.PackageCategory `json:"category"`
			SourceFile string                `json:"source_file,omitempty"`
			Line       int                   `json:"line,omitempty"`
			Calls      int                   `json:"calls_count"`
			CalledBy   int                   `json:"called_by_count"`
			StringRefs int                   `json:"string_refs_count"`
			CryptoRefs []string              `json:"crypto_refs,omitempty"`
		}

		var matches []compactFunc
		totalMatched := 0
		for _, fn := range res.Functions {
			if cat != "" && cat != "all" && string(fn.Category) != cat {
				continue
			}
			if pkgFilter != "" && !strings.Contains(strings.ToLower(fn.Package), pkgFilter) {
				continue
			}
			if q != "" {
				hay1 := strings.ToLower(fn.Name)
				hay2 := strings.ToLower(fn.Demangled)
				hay3 := strings.ToLower(fn.SourceFile)
				if !strings.Contains(hay1, q) && !strings.Contains(hay2, q) && !strings.Contains(hay3, q) {
					continue
				}
			}
			totalMatched++
			if len(matches) < limit {
				matches = append(matches, compactFunc{
					Entry:      fmt.Sprintf("0x%x", fn.Entry),
					Size:       fn.Size,
					Name:       fn.Name,
					Demangled:  fn.Demangled,
					Package:    fn.Package,
					Category:   fn.Category,
					SourceFile: fn.SourceFile,
					Line:       fn.Line,
					Calls:      len(fn.Calls),
					CalledBy:   len(fn.CalledBy),
					StringRefs: len(fn.StringRefs),
					CryptoRefs: fn.CryptoRefs,
				})
			}
		}
		return marshalCompact(map[string]any{
			"total_functions": len(res.Functions),
			"matched":         totalMatched,
			"returned":        len(matches),
			"functions":       matches,
		}), false, nil

	case "inspect_function":
		var args struct {
			Path            string `json:"path"`
			Target          string `json:"target"`
			Disassemble     *bool  `json:"disassemble"`
			MaxInstructions int    `json:"max_instructions"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil || strings.TrimSpace(args.Path) == "" || strings.TrimSpace(args.Target) == "" {
			return "missing required 'path' or 'target' argument", true, nil
		}
		disasm := true
		if args.Disassemble != nil {
			disasm = *args.Disassemble
		}
		maxInsns := clampLimit(args.MaxInstructions, 120, 1000)
		insp, err := s.engine.InspectFunction(args.Path, args.Target, disasm, maxInsns)
		if err != nil {
			return fmt.Sprintf("inspect_function error: %v", err), true, nil
		}
		return marshalCompact(insp), false, nil

	case "find_xrefs":
		var args struct {
			Path  string `json:"path"`
			Kind  string `json:"kind"`
			Query string `json:"query"`
			Limit int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil || strings.TrimSpace(args.Path) == "" {
			return "missing required 'path' argument", true, nil
		}
		res, err := s.engine.AnalyzeFile(args.Path, analyzer.Options{})
		if err != nil {
			return fmt.Sprintf("find_xrefs error: %v", err), true, nil
		}
		limit := clampLimit(args.Limit, 50, 500)
		kind := strings.ToLower(strings.TrimSpace(args.Kind))
		if kind == "" {
			kind = "high_signal"
		}
		q := strings.ToLower(strings.TrimSpace(args.Query))

		fnNames := make(map[uint64]string, len(res.Functions))
		for _, fn := range res.Functions {
			if fn.Demangled != "" {
				fnNames[fn.Entry] = fn.Demangled
			} else {
				fnNames[fn.Entry] = fn.Name
			}
		}

		resolveCallers := func(addrs []uint64) []string {
			out := make([]string, 0, len(addrs))
			for _, a := range addrs {
				if n, ok := fnNames[a]; ok && n != "" {
					out = append(out, fmt.Sprintf("%s (0x%x)", n, a))
				} else {
					out = append(out, fmt.Sprintf("0x%x", a))
				}
			}
			return out
		}

		var cryptoOut []map[string]any
		if kind == "crypto" || kind == "high_signal" || kind == "all" {
			for _, c := range res.Crypto {
				if q != "" && !strings.Contains(strings.ToLower(c.Name), q) && !strings.Contains(strings.ToLower(c.Algorithm), q) {
					continue
				}
				cryptoOut = append(cryptoOut, map[string]any{
					"addr":          fmt.Sprintf("0x%x", c.Addr),
					"algorithm":     c.Algorithm,
					"name":          c.Name,
					"confidence":    c.Confidence,
					"referenced_by": resolveCallers(c.ReferencedBy),
				})
			}
		}

		var strOut []map[string]any
		if kind != "crypto" {
			for _, st := range res.Strings {
				if kind == "high_signal" {
					if st.Kind == model.StringGeneral && len(st.ReferencedBy) == 0 {
						continue
					}
					if st.Kind == model.StringGeneral {
						continue
					}
				} else if kind != "all" && string(st.Kind) != kind {
					continue
				}
				if q != "" && !strings.Contains(strings.ToLower(st.Value), q) {
					continue
				}
				strOut = append(strOut, map[string]any{
					"addr":          fmt.Sprintf("0x%x", st.Addr),
					"kind":          st.Kind,
					"encoding":      st.Encoding,
					"value":         st.Value,
					"referenced_by": resolveCallers(st.ReferencedBy),
				})
				if len(strOut) >= limit {
					break
				}
			}
		}

		return marshalCompact(map[string]any{
			"crypto":  cryptoOut,
			"strings": strOut,
		}), false, nil

	case "recover_types":
		var args struct {
			Path  string `json:"path"`
			Kind  string `json:"kind"`
			Query string `json:"query"`
			Limit int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil || strings.TrimSpace(args.Path) == "" {
			return "missing required 'path' argument", true, nil
		}
		res, err := s.engine.AnalyzeFile(args.Path, analyzer.Options{})
		if err != nil {
			return fmt.Sprintf("recover_types error: %v", err), true, nil
		}
		limit := clampLimit(args.Limit, 50, 500)
		kind := strings.ToLower(strings.TrimSpace(args.Kind))
		q := strings.ToLower(strings.TrimSpace(args.Query))

		var typesOut []model.RecoveredType
		totalMatched := 0
		for _, t := range res.Types {
			if kind != "" && kind != "all" && strings.ToLower(t.Kind) != kind {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(t.Name), q) && !strings.Contains(strings.ToLower(t.Package), q) {
				continue
			}
			totalMatched++
			if len(typesOut) < limit {
				typesOut = append(typesOut, t)
			}
		}
		return marshalCompact(map[string]any{
			"total_types": len(res.Types),
			"matched":     totalMatched,
			"returned":    len(typesOut),
			"types":       typesOut,
		}), false, nil

	case "demangle_symbols":
		var args struct {
			Symbols []string `json:"symbols"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return fmt.Sprintf("invalid arguments: %v", err), true, nil
		}
		results := make([]map[string]any, 0, len(args.Symbols))
		for _, sym := range args.Symbols {
			dem, scheme, ok := rustrecover.Demangle(sym)
			results = append(results, map[string]any{
				"raw":       sym,
				"demangled": dem,
				"scheme":    scheme,
				"matched":   ok,
			})
		}
		return marshalCompact(map[string]any{"results": results}), false, nil

	case "export_re_script":
		var args struct {
			Path       string `json:"path"`
			Format     string `json:"format"`
			OutputPath string `json:"output_path"`
			UserOnly   bool   `json:"user_only"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil || strings.TrimSpace(args.Path) == "" || strings.TrimSpace(args.Format) == "" {
			return "missing required 'path' or 'format' argument", true, nil
		}
		fmtType, err := exporter.ParseFormat(args.Format)
		if err != nil {
			return err.Error(), true, nil
		}
		res, err := s.engine.AnalyzeFile(args.Path, analyzer.Options{})
		if err != nil {
			return fmt.Sprintf("export_re_script error: %v", err), true, nil
		}
		payload, err := exporter.Export(res, fmtType, exporter.Options{UserOnly: args.UserOnly})
		if err != nil {
			return fmt.Sprintf("export error: %v", err), true, nil
		}
		if strings.TrimSpace(args.OutputPath) != "" {
			if err := os.MkdirAll(filepath.Dir(args.OutputPath), 0o755); err != nil {
				return fmt.Sprintf("mkdir error: %v", err), true, nil
			}
			if err := os.WriteFile(args.OutputPath, payload, 0o644); err != nil {
				return fmt.Sprintf("write error: %v", err), true, nil
			}
			return marshalCompact(map[string]any{
				"written":     true,
				"output_path": args.OutputPath,
				"format":      fmtType,
				"bytes":       len(payload),
			}), false, nil
		}
		return string(payload), false, nil

	default:
		return "", false, &rpcError{Code: -32602, Message: fmt.Sprintf("Unknown tool %q", name)}
	}
}

func buildExecutiveSummary(res *model.AnalysisResult) map[string]any {
	userFuncs := 0
	depFuncs := 0
	for _, fn := range res.Functions {
		switch fn.Category {
		case model.CategoryUser:
			userFuncs++
		case model.CategoryDependency:
			depFuncs++
		}
	}

	var topPkgs []model.PackageSummary
	for _, p := range res.Packages {
		if p.Category == model.CategoryUser || p.Category == model.CategoryDependency {
			topPkgs = append(topPkgs, p)
			if len(topPkgs) >= 15 {
				break
			}
		}
	}

	var notableStrings []map[string]any
	for _, st := range res.Strings {
		if st.Kind == model.StringURL || st.Kind == model.StringAPIRoute || st.Kind == model.StringSecretCandidate || st.Kind == model.StringSQL || st.Kind == model.StringCommand {
			notableStrings = append(notableStrings, map[string]any{
				"addr":  fmt.Sprintf("0x%x", st.Addr),
				"kind":  st.Kind,
				"value": st.Value,
				"xrefs": len(st.ReferencedBy),
			})
			if len(notableStrings) >= 15 {
				break
			}
		}
	}

	return map[string]any{
		"binary":               res.Binary,
		"go":                   res.Go,
		"rust":                 res.Rust,
		"section_count":        len(res.Sections),
		"sections":             res.Sections,
		"total_functions":      len(res.Functions),
		"user_functions":       userFuncs,
		"dependency_functions": depFuncs,
		"recovered_types":      len(res.Types),
		"dependencies":         len(res.Dependencies),
		"panic_locations":      len(res.Panics),
		"crypto_detections":    res.Crypto,
		"top_packages":         topPkgs,
		"high_signal_strings":  notableStrings,
		"analysis_duration_ms": res.AnalysisDurationMs,
	}
}

func decodeArgs(raw json.RawMessage, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func clampLimit(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func marshalCompact(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
