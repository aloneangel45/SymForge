package exporter

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/aloneangel45/symforge/pkg/model"
)

// ExportMarkdown renders a structured, human- and LLM-readable forensic triage report.
func ExportMarkdown(res *model.AnalysisResult, opts Options) []byte {
	var buf bytes.Buffer
	b := res.Binary

	fmt.Fprintf(&buf, "# SymForge Binary Forensics & Symbol Recovery Report\n\n")
	fmt.Fprintf(&buf, "## 1. Binary Summary\n\n")
	fmt.Fprintf(&buf, "| Property | Value |\n|---|---|\n")
	fmt.Fprintf(&buf, "| **Path** | `%s` |\n", b.Path)
	fmt.Fprintf(&buf, "| **SHA-256** | `%s` |\n", b.SHA256)
	fmt.Fprintf(&buf, "| **Size** | `%d` bytes |\n", b.SizeBytes)
	fmt.Fprintf(&buf, "| **Format / Arch** | `%s` / `%s` (%d-bit, %s-endian) |\n", b.Format, b.Arch, b.PointerSize*8, b.Endianness)
	if len(b.AvailableArches) > 0 {
		fmt.Fprintf(&buf, "| **Fat Slices** | `%s` |\n", strings.Join(b.AvailableArches, ", "))
	}
	fmt.Fprintf(&buf, "| **Language** | `%s` |\n", b.Language)
	fmt.Fprintf(&buf, "| **Entry Point / Base** | `0x%x` / `0x%x` (PIE: `%v`) |\n", b.EntryPoint, b.ImageBase, b.PIE)
	fmt.Fprintf(&buf, "| **Stripped / Packed** | Stripped: `%v` / PackedLikely: `%v` (Max Entropy: `%.2f`) |\n", b.Stripped, b.PackedLikely, b.MaxEntropy)
	fmt.Fprintf(&buf, "| **Recovered Artifacts** | `%d` functions, `%d` packages/crates, `%d` types, `%d` deps, `%d` native imports |\n\n",
		len(res.Functions), len(res.Packages), len(res.Types), len(res.Dependencies), len(res.Imports))

	if res.Go != nil && res.Go.Detected {
		fmt.Fprintf(&buf, "## 2. Go Runtime & PCLnTab Metadata\n\n")
		fmt.Fprintf(&buf, "- **Go Version:** `%s`\n", res.Go.Version)
		fmt.Fprintf(&buf, "- **PCLnTab:** `%s` (`0x%x` at `0x%x`, quantum=`%d`, ptrSize=`%d`)\n",
			res.Go.PCLnTabVersion, res.Go.PCLnTabMagic, res.Go.PCLnTabAddr, res.Go.Quantum, res.Go.PointerSize)
		if res.Go.MainModule != "" {
			fmt.Fprintf(&buf, "- **Main Module:** `%s` (`%s`)\n", res.Go.MainModule, res.Go.ModuleVersion)
		}
		if res.Go.ModuleDataAddr != 0 {
			fmt.Fprintf(&buf, "- **ModuleData:** `0x%x` (types `0x%x`..`0x%x`)\n", res.Go.ModuleDataAddr, res.Go.TypesAddr, res.Go.ETypesAddr)
		}
		buf.WriteString("\n")
	}

	if res.Rust != nil && res.Rust.Detected {
		fmt.Fprintf(&buf, "## 2. Rust Toolchain & Panic Metadata\n\n")
		if res.Rust.CompilerVersion != "" {
			fmt.Fprintf(&buf, "- **Compiler:** `rustc %s` (`%s`)\n", res.Rust.CompilerVersion, res.Rust.CompilerCommit)
		}
		fmt.Fprintf(&buf, "- **Mangling / SBOM:** `%s` | `cargo-auditable`: `%v`\n", res.Rust.ManglingScheme, res.Rust.AuditableSBOM)
		fmt.Fprintf(&buf, "- **Carved Artifacts:** `%d` panic locations, `%d` trait vtables\n\n", res.Rust.PanicCount, res.Rust.VTableCount)
	}

	if len(res.Sections) > 0 {
		fmt.Fprintf(&buf, "## 3. Section Map & Entropy\n\n")
		fmt.Fprintf(&buf, "| Section | Virtual Addr | Size | Entropy | Perms |\n|---|---|---|---|---|\n")
		for _, s := range res.Sections {
			perms := ""
			if s.Readable {
				perms += "R"
			}
			if s.Writable {
				perms += "W"
			}
			if s.Executable {
				perms += "X"
			}
			fmt.Fprintf(&buf, "| `%s` | `0x%x` | `%d` | `%.2f` | `%s` |\n", s.Name, s.VirtualAddr, s.FileSize, s.Entropy, perms)
		}
		buf.WriteString("\n")
	}

	if len(res.Packages) > 0 {
		fmt.Fprintf(&buf, "## 4. Recovered Packages & Crates\n\n")
		fmt.Fprintf(&buf, "| Package / Crate | Category | Functions | Code Bytes |\n|---|---|---|---|\n")
		shown := 0
		for _, p := range res.Packages {
			if opts.UserOnly && p.Category != model.CategoryUser && p.Category != model.CategoryDependency {
				continue
			}
			fmt.Fprintf(&buf, "| `%s` | `%s` | `%d` | `%d` |\n", mdEscape(p.Name), p.Category, p.FunctionCount, p.TotalBytes)
			shown++
			if shown >= 40 {
				break
			}
		}
		buf.WriteString("\n")
	}

	funcs := selectFunctions(res.Functions, opts.UserOnly)
	if len(funcs) > 0 {
		fmt.Fprintf(&buf, "## 5. Recovered Functions (Top %d of %d)\n\n", minInt(len(funcs), 50), len(funcs))
		fmt.Fprintf(&buf, "| Entry VA | Size | Category | Function | Source |\n|---|---|---|---|---|\n")
		for i := 0; i < len(funcs) && i < 50; i++ {
			fn := funcs[i]
			src := fn.SourceFile
			if src != "" && fn.Line > 0 {
				src = fmt.Sprintf("%s:%d", src, fn.Line)
			}
			fmt.Fprintf(&buf, "| `0x%x` | `%d` | `%s` | `%s` | `%s` |\n",
				fn.Entry, fn.Size, fn.Category, mdEscape(preferredDisplayName(fn)), mdEscape(src))
		}
		buf.WriteString("\n")
	}

	if len(res.Crypto) > 0 {
		fmt.Fprintf(&buf, "## 6. Cryptographic Constants & XREFs\n\n")
		fmt.Fprintf(&buf, "| Address | Algorithm | Constant | Confidence | Referenced By |\n|---|---|---|---|---|\n")
		for _, c := range res.Crypto {
			fmt.Fprintf(&buf, "| `0x%x` | `%s` | `%s` | `%s` | `%d` function(s) |\n",
				c.Addr, c.Algorithm, mdEscape(c.Name), c.Confidence, len(c.ReferencedBy))
		}
		buf.WriteString("\n")
	}

	var highSignal []model.ExtractedString
	for _, s := range res.Strings {
		if s.Kind == model.StringURL || s.Kind == model.StringAPIRoute || s.Kind == model.StringSecretCandidate || s.Kind == model.StringSQL || s.Kind == model.StringCommand {
			highSignal = append(highSignal, s)
		}
	}
	if len(highSignal) > 0 {
		fmt.Fprintf(&buf, "## 7. High-Signal Strings & XREFs\n\n")
		fmt.Fprintf(&buf, "| Address | Kind | Value | XREFs |\n|---|---|---|---|\n")
		for i := 0; i < len(highSignal) && i < 40; i++ {
			s := highSignal[i]
			val := s.Value
			if len(val) > 80 {
				val = val[:77] + "..."
			}
			fmt.Fprintf(&buf, "| `0x%x` | `%s` | `%s` | `%d` |\n", s.Addr, s.Kind, mdEscape(val), len(s.ReferencedBy))
		}
		buf.WriteString("\n")
	}

	if len(res.Dependencies) > 0 {
		fmt.Fprintf(&buf, "## 8. Recovered SBOM Dependencies (%d)\n\n", len(res.Dependencies))
		fmt.Fprintf(&buf, "| Ecosystem | Name | Version | Source |\n|---|---|---|---|\n")
		for i := 0; i < len(res.Dependencies) && i < 50; i++ {
			d := res.Dependencies[i]
			fmt.Fprintf(&buf, "| `%s` | `%s` | `%s` | `%s` |\n", d.Ecosystem, mdEscape(d.Name), mdEscape(d.Version), d.Source)
		}
		buf.WriteString("\n")
	}

	return buf.Bytes()
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "`", "'")
	return s
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
