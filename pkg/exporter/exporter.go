// Package exporter renders SymForge's recovered symbols, types, XREFs, and
// dependency metadata into reverse-engineering scripts (Ghidra, IDA Pro,
// Binary Ninja), Markdown forensic triage reports, JSON dumps, and CycloneDX 1.5 SBOMs.
package exporter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aloneangel45/symforge/pkg/model"
)

// Format identifies a supported SymForge export target.
type Format string

const (
	FormatGhidra   Format = "ghidra"
	FormatIDA      Format = "ida"
	FormatBinja    Format = "binja"
	FormatMarkdown Format = "markdown"
	FormatSBOM     Format = "sbom"
	FormatJSON     Format = "json"
)

// Options controls filtering and formatting behavior during export.
type Options struct {
	// UserOnly restricts exported functions in RE scripts and reports to
	// CategoryUser and CategoryDependency (omitting Go/Rust runtime & stdlib noise).
	UserOnly bool
}

// ParseFormat normalizes a user-supplied format name.
func ParseFormat(raw string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ghidra", "pyghidra":
		return FormatGhidra, nil
	case "ida", "idapython":
		return FormatIDA, nil
	case "binja", "binaryninja", "binary-ninja":
		return FormatBinja, nil
	case "markdown", "md", "report":
		return FormatMarkdown, nil
	case "sbom", "cyclonedx", "cdx":
		return FormatSBOM, nil
	case "json":
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("unsupported export format %q (expected ghidra, ida, binja, markdown, sbom, or json)", raw)
	}
}

// Export renders res into the requested target format.
func Export(res *model.AnalysisResult, format Format, opts Options) ([]byte, error) {
	if res == nil {
		return nil, fmt.Errorf("nil analysis result")
	}
	switch format {
	case FormatGhidra:
		return ExportGhidra(res, opts), nil
	case FormatIDA:
		return ExportIDA(res, opts), nil
	case FormatBinja:
		return ExportBinja(res, opts), nil
	case FormatMarkdown:
		return ExportMarkdown(res, opts), nil
	case FormatSBOM:
		return ExportCycloneDX(res)
	case FormatJSON:
		return json.MarshalIndent(res, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported export format %q", format)
	}
}

func selectFunctions(funcs []model.Function, userOnly bool) []model.Function {
	out := make([]model.Function, 0, len(funcs))
	for _, fn := range funcs {
		if fn.Entry == 0 || fn.Name == "" {
			continue
		}
		if userOnly && fn.Category != model.CategoryUser && fn.Category != model.CategoryDependency {
			continue
		}
		out = append(out, fn)
	}
	return out
}

func preferredDisplayName(fn model.Function) string {
	if fn.Demangled != "" {
		return fn.Demangled
	}
	return fn.Name
}

// sanitizeRESymbol converts Go/Rust punctuation into clean identifier characters
// accepted by Ghidra and IDA without losing package/type readability.
func sanitizeRESymbol(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == ':':
			b.WriteRune(r)
		case r == '/' || r == '-' || r == '*' || r == '(' || r == ')' || r == '[' || r == ']' || r == '<' || r == '>' || r == ' ' || r == ',' || r == '$' || r == '&':
			b.WriteByte('_')
		default:
			b.WriteByte('_')
		}
	}
	res := strings.Trim(b.String(), "_")
	for strings.Contains(res, "__") {
		res = strings.ReplaceAll(res, "__", "_")
	}
	if res == "" {
		return "symforge_sub"
	}
	if res[0] >= '0' && res[0] <= '9' {
		res = "_" + res
	}
	return res
}

func buildFunctionComment(fn model.Function) string {
	var parts []string
	if fn.Demangled != "" && fn.Demangled != fn.Name {
		parts = append(parts, fmt.Sprintf("SymForge: %s", fn.Demangled))
	} else {
		parts = append(parts, fmt.Sprintf("SymForge: %s", fn.Name))
	}
	if fn.Package != "" {
		parts = append(parts, fmt.Sprintf("Package: %s (%s)", fn.Package, fn.Category))
	}
	if fn.SourceFile != "" {
		if fn.Line > 0 {
			parts = append(parts, fmt.Sprintf("Source: %s:%d", fn.SourceFile, fn.Line))
		} else {
			parts = append(parts, fmt.Sprintf("Source: %s", fn.SourceFile))
		}
	}
	if len(fn.CryptoRefs) > 0 {
		parts = append(parts, fmt.Sprintf("Crypto: %s", strings.Join(fn.CryptoRefs, ", ")))
	}
	if len(fn.StringRefs) > 0 {
		limit := len(fn.StringRefs)
		if limit > 4 {
			limit = 4
		}
		var srefs []string
		for i := 0; i < limit; i++ {
			v := strings.ReplaceAll(fn.StringRefs[i].Value, "\n", "\\n")
			v = strings.ReplaceAll(v, "\r", "\\r")
			if len(v) > 64 {
				v = v[:61] + "..."
			}
			srefs = append(srefs, fmt.Sprintf("[%s] %q", fn.StringRefs[i].Kind, v))
		}
		parts = append(parts, "Strings: "+strings.Join(srefs, "; "))
	}
	return strings.Join(parts, "\n")
}

func pyQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
