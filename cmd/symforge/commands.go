package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/aloneangel45/symforge/pkg/analyzer"
	"github.com/aloneangel45/symforge/pkg/diff"
	"github.com/aloneangel45/symforge/pkg/exporter"
	"github.com/aloneangel45/symforge/pkg/mcpserver"
	"github.com/aloneangel45/symforge/pkg/model"
	"github.com/aloneangel45/symforge/pkg/preset"
	"github.com/aloneangel45/symforge/pkg/rustrecover"
	"github.com/aloneangel45/symforge/pkg/triage"
	"github.com/aloneangel45/symforge/pkg/xref"
	"github.com/spf13/cobra"
)

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newInspectCmd() *cobra.Command {
	var (
		arch   string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "inspect <binary>",
		Short: "Inspect binary format, entropy, imports, Go/Rust metadata, user packages, and XREF highlights",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := analyzer.DefaultEngine.AnalyzeFile(args[0], analyzer.Options{Arch: arch})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return printJSON(out, res)
			}

			b := res.Binary
			fmt.Fprintf(out, "=== SymForge Binary Forensics Summary (%.1f ms) ===\n", res.AnalysisDurationMs)
			fmt.Fprintf(out, "  Path        : %s\n", b.Path)
			fmt.Fprintf(out, "  SHA-256     : %s\n", b.SHA256)
			fmt.Fprintf(out, "  Format/Arch : %s / %s (%d-bit, %s-endian, size=%d bytes)\n",
				b.Format, b.Arch, b.PointerSize*8, b.Endianness, b.SizeBytes)
			if len(b.AvailableArches) > 0 {
				fmt.Fprintf(out, "  Fat Slices  : %s\n", strings.Join(b.AvailableArches, ", "))
			}
			fmt.Fprintf(out, "  Language    : %s\n", b.Language)
			fmt.Fprintf(out, "  Entry/Base  : 0x%x / 0x%x (PIE=%v)\n", b.EntryPoint, b.ImageBase, b.PIE)
			fmt.Fprintf(out, "  Hygiene     : Stripped=%v | PackedLikely=%v | MaxEntropy=%.2f\n",
				b.Stripped, b.PackedLikely, b.MaxEntropy)

			userCount := 0
			for _, fn := range res.Functions {
				if fn.Category == model.CategoryUser {
					userCount++
				}
			}
			fmt.Fprintf(out, "  Recovered   : %d functions (%d user), %d packages, %d types, %d deps, %d imports, %d crypto, %d strings\n",
				len(res.Functions), userCount, len(res.Packages), len(res.Types), len(res.Dependencies), len(res.Imports), len(res.Crypto), len(res.Strings))

			if res.Go != nil && res.Go.Detected {
				fmt.Fprintf(out, "\n[Go Metadata]\n")
				fmt.Fprintf(out, "  Go Version  : %s\n", res.Go.Version)
				fmt.Fprintf(out, "  PCLnTab     : %s (magic=0x%x @ 0x%x, ptr=%d, quantum=%d)\n",
					res.Go.PCLnTabVersion, res.Go.PCLnTabMagic, res.Go.PCLnTabAddr, res.Go.PointerSize, res.Go.Quantum)
				if res.Go.MainModule != "" {
					fmt.Fprintf(out, "  Main Module : %s (%s)\n", res.Go.MainModule, res.Go.ModuleVersion)
				}
				if res.Go.ModuleDataAddr != 0 {
					fmt.Fprintf(out, "  ModuleData  : 0x%x (types 0x%x..0x%x)\n",
						res.Go.ModuleDataAddr, res.Go.TypesAddr, res.Go.ETypesAddr)
				}
			}

			if res.Rust != nil && res.Rust.Detected {
				fmt.Fprintf(out, "\n[Rust Metadata]\n")
				if res.Rust.CompilerVersion != "" || res.Rust.CompilerCommit != "" {
					fmt.Fprintf(out, "  Toolchain   : rustc %s (%s)\n", res.Rust.CompilerVersion, res.Rust.CompilerCommit)
				}
				fmt.Fprintf(out, "  Artifacts   : mangling=%s | cargo-auditable=%v | panics=%d | vtables=%d\n",
					nonEmpty(res.Rust.ManglingScheme, "stripped"), res.Rust.AuditableSBOM, res.Rust.PanicCount, res.Rust.VTableCount)
			}

			if len(res.Imports) > 0 {
				libCounts := make(map[string]int)
				var libs []string
				for _, imp := range res.Imports {
					lib := nonEmpty(imp.Library, "<dynamic>")
					if _, seen := libCounts[lib]; !seen {
						libs = append(libs, lib)
					}
					if imp.Name != "" {
						libCounts[lib]++
					}
				}
				fmt.Fprintf(out, "\n[Native Imports (%d entries across %d libraries)]\n", len(res.Imports), len(libs))
				shown := 0
				for _, lib := range libs {
					fmt.Fprintf(out, "  %-36s (%d symbols)\n", lib, libCounts[lib])
					shown++
					if shown >= 10 {
						break
					}
				}
			}

			if len(res.Packages) > 0 {
				fmt.Fprintf(out, "\n[Top Packages / Crates]\n")
				tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "  CATEGORY\tFUNCTIONS\tBYTES\tPACKAGE")
				shown := 0
				for _, p := range res.Packages {
					fmt.Fprintf(tw, "  %s\t%d\t%d\t%s\n", p.Category, p.FunctionCount, p.TotalBytes, p.Name)
					shown++
					if shown >= 12 {
						break
					}
				}
				_ = tw.Flush()
			}

			if len(res.Crypto) > 0 {
				fmt.Fprintf(out, "\n[Cryptographic Constants]\n")
				for _, c := range res.Crypto {
					fmt.Fprintf(out, "  0x%x  [%s] %s (referenced by %d fn)\n",
						c.Addr, c.Algorithm, c.Name, len(c.ReferencedBy))
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit full AnalysisResult as JSON")
	return cmd
}

func newFunctionsCmd() *cobra.Command {
	var (
		arch     string
		userOnly bool
		category string
		pkgSub   string
		query    string
		limit    int
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:     "functions <binary>",
		Aliases: []string{"funcs"},
		Short:   "List recovered stripped or symbolicated functions",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := analyzer.DefaultEngine.AnalyzeFile(args[0], analyzer.Options{Arch: arch})
			if err != nil {
				return err
			}

			cat := strings.ToLower(strings.TrimSpace(category))
			pkgFilter := strings.ToLower(strings.TrimSpace(pkgSub))
			q := strings.ToLower(strings.TrimSpace(query))

			filtered := make([]model.Function, 0)
			for _, fn := range res.Functions {
				if userOnly && fn.Category != model.CategoryUser && fn.Category != model.CategoryDependency {
					continue
				}
				if cat != "" && cat != "all" && string(fn.Category) != cat {
					continue
				}
				if pkgFilter != "" && !strings.Contains(strings.ToLower(fn.Package), pkgFilter) {
					continue
				}
				if q != "" {
					if !strings.Contains(strings.ToLower(fn.Name), q) &&
						!strings.Contains(strings.ToLower(fn.Demangled), q) &&
						!strings.Contains(strings.ToLower(fn.SourceFile), q) {
						continue
					}
				}
				filtered = append(filtered, fn)
				if limit > 0 && len(filtered) >= limit {
					break
				}
			}

			out := cmd.OutOrStdout()
			if asJSON {
				return printJSON(out, filtered)
			}

			tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ENTRY\tSIZE\tCATEGORY\tFUNCTION\tSOURCE")
			for _, fn := range filtered {
				disp := fn.Name
				if fn.Demangled != "" {
					disp = fn.Demangled
				}
				src := fn.SourceFile
				if src != "" && fn.Line > 0 {
					src = fmt.Sprintf("%s:%d", src, fn.Line)
				}
				fmt.Fprintf(tw, "0x%x\t%d\t%s\t%s\t%s\n", fn.Entry, fn.Size, fn.Category, disp, src)
			}
			_ = tw.Flush()
			fmt.Fprintf(out, "\nShowing %d of %d total recovered functions.\n", len(filtered), len(res.Functions))
			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().BoolVar(&userOnly, "user-only", false, "Only show user and dependency functions")
	cmd.Flags().StringVar(&category, "category", "", "Filter by category (user, dependency, stdlib, runtime, native)")
	cmd.Flags().StringVar(&pkgSub, "package", "", "Filter by package/crate substring")
	cmd.Flags().StringVar(&query, "query", "", "Filter by function name or source file substring")
	cmd.Flags().IntVar(&limit, "limit", 100, "Maximum functions to display (0 for unlimited)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit filtered functions as JSON")
	return cmd
}

func newFnCmd() *cobra.Command {
	var (
		arch     string
		noDisasm bool
		maxInsns int
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "fn <binary> <name_or_hex_addr>",
		Short: "Inspect a single function's metadata, callers, callees, XREFs, and disassembly",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			insp, err := analyzer.DefaultEngine.InspectFunctionWithOptions(args[0], args[1], !noDisasm, maxInsns, analyzer.Options{Arch: arch})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return printJSON(out, insp)
			}

			fn := insp.Function
			fmt.Fprintf(out, "Function    : %s\n", fn.Name)
			if fn.Demangled != "" && fn.Demangled != fn.Name {
				fmt.Fprintf(out, "Demangled   : %s\n", fn.Demangled)
			}
			fmt.Fprintf(out, "Address     : 0x%x .. 0x%x (%d bytes)\n", fn.Entry, fn.End, fn.Size)
			fmt.Fprintf(out, "Package     : %s (%s, via %s)\n", fn.Package, fn.Category, fn.RecoveredFrom)
			if fn.SourceFile != "" {
				fmt.Fprintf(out, "Source      : %s:%d\n", fn.SourceFile, fn.Line)
			}

			if len(insp.Calls) > 0 {
				fmt.Fprintf(out, "\nCalls (%d):\n", len(insp.Calls))
				for _, c := range insp.Calls {
					fmt.Fprintf(out, "  -> 0x%x  %s\n", c.Addr, c.Name)
				}
			}
			if len(insp.CalledBy) > 0 {
				fmt.Fprintf(out, "\nCalled By (%d):\n", len(insp.CalledBy))
				for _, c := range insp.CalledBy {
					fmt.Fprintf(out, "  <- 0x%x  %s\n", c.Addr, c.Name)
				}
			}
			if len(fn.CryptoRefs) > 0 {
				fmt.Fprintf(out, "\nCrypto XREFs: %s\n", strings.Join(fn.CryptoRefs, ", "))
			}
			if len(fn.StringRefs) > 0 {
				fmt.Fprintf(out, "\nString XREFs (%d):\n", len(fn.StringRefs))
				for _, sr := range fn.StringRefs {
					fmt.Fprintf(out, "  [0x%x -> 0x%x] (%s) %q\n", sr.InsnAddr, sr.Addr, sr.Kind, sr.Value)
				}
			}

			if len(insp.Instructions) > 0 {
				fmt.Fprintf(out, "\nDisassembly (%d instructions):\n", len(insp.Instructions))
				for _, ins := range insp.Instructions {
					annot := ""
					if ins.TargetSymbol != "" {
						annot = " ; -> " + ins.TargetSymbol
					}
					if ins.StringRef != "" {
						q := ins.StringRef
						if len(q) > 56 {
							q = q[:53] + "..."
						}
						annot += fmt.Sprintf(" ; %q", q)
					}
					fmt.Fprintf(out, "  0x%08x:  %-20s  %s%s\n", ins.Addr, ins.BytesHex, ins.Text, annot)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().BoolVar(&noDisasm, "no-disasm", false, "Skip machine code disassembly")
	cmd.Flags().IntVar(&maxInsns, "max-insns", 120, "Maximum instructions to decode")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit FunctionInspection as JSON")
	return cmd
}

func newStringsCmd() *cobra.Command {
	var (
		arch   string
		kind   string
		query  string
		limit  int
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "strings <binary>",
		Short: "Extract classified strings (including Go non-null-terminated blobs) and XREFs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := analyzer.DefaultEngine.AnalyzeFile(args[0], analyzer.Options{Arch: arch})
			if err != nil {
				return err
			}
			k := strings.ToLower(strings.TrimSpace(kind))
			q := strings.ToLower(strings.TrimSpace(query))

			outList := make([]model.ExtractedString, 0)
			for _, st := range res.Strings {
				if k != "" && k != "all" {
					if k == "high_signal" {
						if st.Kind == model.StringGeneral {
							continue
						}
					} else if string(st.Kind) != k {
						continue
					}
				}
				if q != "" && !strings.Contains(strings.ToLower(st.Value), q) {
					continue
				}
				outList = append(outList, st)
				if limit > 0 && len(outList) >= limit {
					break
				}
			}

			out := cmd.OutOrStdout()
			if asJSON {
				return printJSON(out, outList)
			}

			tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ADDRESS\tKIND\tXREFS\tVALUE")
			for _, st := range outList {
				val := strings.ReplaceAll(st.Value, "\n", "\\n")
				val = strings.ReplaceAll(val, "\r", "\\r")
				if len(val) > 90 {
					val = val[:87] + "..."
				}
				fmt.Fprintf(tw, "0x%x\t%s\t%d\t%s\n", st.Addr, st.Kind, len(st.ReferencedBy), val)
			}
			_ = tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().StringVar(&kind, "kind", "high_signal", "Filter: high_signal, url, api_route, secret_candidate, filepath, sql, command, error_msg, general, or all")
	cmd.Flags().StringVar(&query, "query", "", "Case-insensitive substring filter")
	cmd.Flags().IntVar(&limit, "limit", 100, "Maximum strings to display")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit strings as JSON")
	return cmd
}

func newTypesCmd() *cobra.Command {
	var (
		arch   string
		kind   string
		query  string
		limit  int
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "types <binary>",
		Short: "Recover Go struct fields, Go interface methods, and Rust trait vtables",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := analyzer.DefaultEngine.AnalyzeFile(args[0], analyzer.Options{Arch: arch})
			if err != nil {
				return err
			}
			k := strings.ToLower(strings.TrimSpace(kind))
			q := strings.ToLower(strings.TrimSpace(query))

			matched := make([]model.RecoveredType, 0)
			for _, t := range res.Types {
				if k != "" && k != "all" && strings.ToLower(t.Kind) != k {
					continue
				}
				if q != "" && !strings.Contains(strings.ToLower(t.Name), q) && !strings.Contains(strings.ToLower(t.Package), q) {
					continue
				}
				matched = append(matched, t)
				if limit > 0 && len(matched) >= limit {
					break
				}
			}

			out := cmd.OutOrStdout()
			if asJSON {
				return printJSON(out, matched)
			}

			for _, t := range matched {
				fmt.Fprintf(out, "type %s %s // @ 0x%x (size=%d, align=%d)\n", t.Name, t.Kind, t.Addr, t.Size, t.Align)
				for _, f := range t.Fields {
					tag := ""
					if f.Tag != "" {
						tag = fmt.Sprintf(" `%s`", f.Tag)
					}
					fmt.Fprintf(out, "    +0x%02x  %-24s %s%s\n", f.Offset, f.Name, f.TypeName, tag)
				}
				for _, m := range t.Methods {
					fmt.Fprintf(out, "    fn %s\n", m)
				}
			}
			fmt.Fprintf(out, "\nShowing %d of %d recovered types.\n", len(matched), len(res.Types))
			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().StringVar(&kind, "kind", "all", "Filter by kind: struct, interface, vtable, or all")
	cmd.Flags().StringVar(&query, "query", "", "Filter by type or package substring")
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum types to display")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit recovered types as JSON")
	return cmd
}

func newDepsCmd() *cobra.Command {
	var (
		arch   string
		asSBOM bool
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "deps <binary>",
		Short: "Extract Go module and Rust crate dependencies (or CycloneDX 1.5 SBOM)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := analyzer.DefaultEngine.AnalyzeFile(args[0], analyzer.Options{Arch: arch})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asSBOM {
				data, err := exporter.ExportCycloneDX(res)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(out, string(data))
				return err
			}
			if asJSON {
				deps := res.Dependencies
				if deps == nil {
					deps = make([]model.Dependency, 0)
				}
				return printJSON(out, deps)
			}

			tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ECOSYSTEM\tNAME\tVERSION\tSOURCE")
			for _, d := range res.Dependencies {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", d.Ecosystem, d.Name, d.Version, d.Source)
			}
			_ = tw.Flush()
			fmt.Fprintf(out, "\nRecovered %d dependencies.\n", len(res.Dependencies))
			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().BoolVar(&asSBOM, "sbom", false, "Emit CycloneDX 1.5 JSON SBOM")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit dependencies array as JSON")
	return cmd
}

func newDemangleCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "demangle [symbols...]",
		Short: "Demangle Rust v0 (_R...) and Legacy (_ZN...E) symbols",
		RunE: func(cmd *cobra.Command, args []string) error {
			inputs := append([]string(nil), args...)
			if len(inputs) == 0 || (len(inputs) == 1 && inputs[0] == "-") {
				inputs = nil
				sc := bufio.NewScanner(cmd.InOrStdin())
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line != "" {
						inputs = append(inputs, line)
					}
				}
			}

			out := cmd.OutOrStdout()
			if asJSON {
				rows := make([]map[string]any, 0, len(inputs))
				for _, sym := range inputs {
					dem, scheme, ok := rustrecover.Demangle(sym)
					rows = append(rows, map[string]any{
						"raw":       sym,
						"demangled": dem,
						"scheme":    scheme,
						"matched":   ok,
					})
				}
				return printJSON(out, rows)
			}

			for _, sym := range inputs {
				dem, _, ok := rustrecover.Demangle(sym)
				if ok {
					fmt.Fprintf(out, "%s -> %s\n", sym, dem)
				} else {
					fmt.Fprintf(out, "%s (unchanged)\n", sym)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit demangled symbols as JSON")
	return cmd
}

func newExportCmd() *cobra.Command {
	var (
		arch       string
		formatRaw  string
		outputPath string
		userOnly   bool
		limit      int
	)
	cmd := &cobra.Command{
		Use:   "export <binary>",
		Short: "Export Ghidra/IDA/Binary Ninja scripts, Graphviz DOT/Mermaid call graphs, Markdown report, or CycloneDX 1.5 SBOM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtType, err := exporter.ParseFormat(formatRaw)
			if err != nil {
				return err
			}
			res, err := analyzer.DefaultEngine.AnalyzeFile(args[0], analyzer.Options{Arch: arch})
			if err != nil {
				return err
			}
			payload, err := exporter.Export(res, fmtType, exporter.Options{
				UserOnly: userOnly,
				Limit:    limit,
			})
			if err != nil {
				return err
			}
			if strings.TrimSpace(outputPath) != "" {
				if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(outputPath, payload, 0o644); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Exported %s (%d bytes) -> %s\n", fmtType, len(payload), outputPath)
				return nil
			}
			_, err = cmd.OutOrStdout().Write(payload)
			if len(payload) > 0 && payload[len(payload)-1] != '\n' {
				_, _ = fmt.Fprintln(cmd.OutOrStdout())
			}
			return err
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().StringVarP(&formatRaw, "format", "f", "ghidra", "Export format: ghidra, ida, binja, markdown, sbom, json, dot, or mermaid")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file path instead of stdout")
	cmd.Flags().BoolVar(&userOnly, "user-only", false, "Exclude runtime/stdlib noise in RE scripts, graphs, and reports")
	cmd.Flags().IntVar(&limit, "limit", 60, "Maximum nodes to emit in dot/mermaid call graph exports")
	return cmd
}

func newDiffCmd() *cobra.Command {
	var (
		arch     string
		userOnly bool
		limit    int
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "diff <binA> <binB>",
		Short: "Diff two stripped or unstripped binaries (functions, packages, deps, imports, strings, crypto)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := analyzer.Options{Arch: arch}
			resA, err := analyzer.DefaultEngine.AnalyzeFile(args[0], opts)
			if err != nil {
				return fmt.Errorf("analyze %s: %w", args[0], err)
			}
			resB, err := analyzer.DefaultEngine.AnalyzeFile(args[1], opts)
			if err != nil {
				return fmt.Errorf("analyze %s: %w", args[1], err)
			}
			dr, err := diff.Compare(resA, resB, diff.Options{
				UserOnly: userOnly,
				Limit:    limit,
			})
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if asJSON {
				return printJSON(out, dr)
			}

			s := dr.Summary
			fmt.Fprintf(out, "=== SymForge Binary Patch Diff ===\n")
			fmt.Fprintf(out, "  Base (A)    : %s (%s/%s, %d bytes, sha256=%s)\n",
				dr.BinaryA.Path, dr.BinaryA.Format, dr.BinaryA.Arch, dr.BinaryA.SizeBytes, shortHash(dr.BinaryA.SHA256))
			fmt.Fprintf(out, "  Target (B)  : %s (%s/%s, %d bytes, sha256=%s)\n",
				dr.BinaryB.Path, dr.BinaryB.Format, dr.BinaryB.Arch, dr.BinaryB.SizeBytes, shortHash(dr.BinaryB.SHA256))
			fmt.Fprintf(out, "  Identical   : %v | Size Delta: %+d bytes\n", dr.Identical, s.SizeDeltaBytes)
			fmt.Fprintf(out, "  Functions   : +%d added, -%d removed, ~%d modified, =%d unchanged\n",
				s.AddedFunctions, s.RemovedFunctions, s.ModifiedFunctions, s.UnchangedFunctions)
			fmt.Fprintf(out, "  Packages    : +%d added, -%d removed | Deps: +%d -%d ~%d\n",
				s.AddedPackages, s.RemovedPackages, s.AddedDeps, s.RemovedDeps, s.ChangedDeps)
			fmt.Fprintf(out, "  Imports     : +%d added, -%d removed | Strings: +%d -%d | Crypto: +%d -%d\n",
				s.AddedImports, s.RemovedImports, s.AddedStrings, s.RemovedStrings, s.AddedCrypto, s.RemovedCrypto)

			if len(dr.RiskHighlights) > 0 {
				fmt.Fprintf(out, "\n[Risk Highlights (%d)]\n", len(dr.RiskHighlights))
				for _, h := range dr.RiskHighlights {
					fmt.Fprintf(out, "  [%s] %s — %s\n", strings.ToUpper(h.Severity), h.Title, h.Detail)
				}
			}

			if len(dr.AddedFunctions) > 0 {
				fmt.Fprintf(out, "\n[Added Functions (%d shown of %d)]\n", len(dr.AddedFunctions), s.AddedFunctions)
				for _, fn := range dr.AddedFunctions {
					fmt.Fprintf(out, "  + 0x%x  (%d B, %s)  %s\n", fn.Entry, fn.Size, fn.Category, nonEmpty(fn.Demangled, fn.Name))
				}
			}

			if len(dr.RemovedFunctions) > 0 {
				fmt.Fprintf(out, "\n[Removed Functions (%d shown of %d)]\n", len(dr.RemovedFunctions), s.RemovedFunctions)
				for _, fn := range dr.RemovedFunctions {
					fmt.Fprintf(out, "  - 0x%x  (%d B, %s)  %s\n", fn.Entry, fn.Size, fn.Category, nonEmpty(fn.Demangled, fn.Name))
				}
			}

			if len(dr.ModifiedFunctions) > 0 {
				fmt.Fprintf(out, "\n[Modified Functions (%d shown of %d)]\n", len(dr.ModifiedFunctions), s.ModifiedFunctions)
				for _, fn := range dr.ModifiedFunctions {
					fmt.Fprintf(out, "  ~ %s  (%d -> %d B, %+d B) [%s]\n",
						nonEmpty(fn.Demangled, fn.Name), fn.OldSize, fn.NewSize, fn.SizeDelta, strings.Join(fn.Reasons, ","))
				}
			}

			if len(dr.Dependencies.Changed) > 0 || len(dr.Dependencies.Added) > 0 || len(dr.Dependencies.Removed) > 0 {
				fmt.Fprintf(out, "\n[Dependency Changes]\n")
				for _, d := range dr.Dependencies.Added {
					fmt.Fprintf(out, "  + [%s] %s@%s\n", d.Ecosystem, d.Name, d.Version)
				}
				for _, d := range dr.Dependencies.Removed {
					fmt.Fprintf(out, "  - [%s] %s@%s\n", d.Ecosystem, d.Name, d.Version)
				}
				for _, c := range dr.Dependencies.Changed {
					fmt.Fprintf(out, "  ~ [%s] %s: %s -> %s\n", c.Ecosystem, c.Name, c.OldVersion, c.NewVersion)
				}
			}

			if len(dr.Imports.Added) > 0 || len(dr.Imports.Removed) > 0 {
				fmt.Fprintf(out, "\n[Native Import Changes]\n")
				for _, imp := range dr.Imports.Added {
					fmt.Fprintf(out, "  + %s!%s\n", nonEmpty(imp.Library, "*"), imp.Name)
				}
				for _, imp := range dr.Imports.Removed {
					fmt.Fprintf(out, "  - %s!%s\n", nonEmpty(imp.Library, "*"), imp.Name)
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().BoolVar(&userOnly, "user-only", false, "Compare only user and dependency functions/packages")
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum entries per diff section (0 for unlimited)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit DiffResult as JSON")
	return cmd
}

func newScanCmd() *cobra.Command {
	var (
		arch   string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "scan <binary>",
		Short: "Scan binary for behavioral capabilities, network IoCs, secrets, packers, and Go garble obfuscation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := analyzer.DefaultEngine.AnalyzeFile(args[0], analyzer.Options{Arch: arch})
			if err != nil {
				return err
			}
			rep, err := triage.Scan(res)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return printJSON(out, rep)
			}

			fmt.Fprintf(out, "=== SymForge Behavioral Capability & Obfuscation Triage ===\n")
			fmt.Fprintf(out, "  Target      : %s (%s/%s, lang=%s)\n", rep.Binary.Path, rep.Binary.Format, rep.Binary.Arch, rep.Binary.Language)
			fmt.Fprintf(out, "  Risk Level  : %s (score=%d/100)\n", strings.ToUpper(string(rep.RiskLevel)), rep.RiskScore)
			fmt.Fprintf(out, "  Findings    : total=%d (critical=%d, high=%d, medium=%d, info=%d)\n",
				rep.Summary["total"], rep.Summary["critical"], rep.Summary["high"], rep.Summary["medium"], rep.Summary["info"])
			fmt.Fprintf(out, "  Obfuscation : PackedLikely=%v | UPX=%v | HighEntropySections=%d | GarbleLikely=%v (score=%d, %s)\n",
				rep.Obfuscation.PackedLikely, rep.Obfuscation.UPXDetected, len(rep.Obfuscation.HighEntropySections),
				rep.Obfuscation.GarbleLikely, rep.Obfuscation.GarbleScore, rep.Obfuscation.GarbleConfidence)

			if len(rep.Findings) > 0 {
				fmt.Fprintf(out, "\n[Findings]\n")
				for _, f := range rep.Findings {
					fmt.Fprintf(out, "  [%s] %s (%s) — %s (%d matches)\n",
						strings.ToUpper(string(f.Severity)), f.ID, f.Category, f.Title, f.MatchCount)
					for i, ev := range f.Evidence {
						if i >= 6 {
							fmt.Fprintf(out, "      ... (+%d more)\n", len(f.Evidence)-6)
							break
						}
						fmt.Fprintf(out, "      - %s\n", ev)
					}
				}
			}

			if len(rep.NetworkIoCs.URLs) > 0 || len(rep.NetworkIoCs.PublicIPv4) > 0 || len(rep.NetworkIoCs.PrivateIPv4) > 0 || len(rep.NetworkIoCs.IPv6) > 0 {
				fmt.Fprintf(out, "\n[Network IoCs]\n")
				if len(rep.NetworkIoCs.URLs) > 0 {
					fmt.Fprintf(out, "  URLs (%d)         : %s\n", len(rep.NetworkIoCs.URLs), strings.Join(firstN(rep.NetworkIoCs.URLs, 6), ", "))
				}
				if len(rep.NetworkIoCs.PublicIPv4) > 0 {
					fmt.Fprintf(out, "  Public IPv4 (%d)  : %s\n", len(rep.NetworkIoCs.PublicIPv4), strings.Join(firstN(rep.NetworkIoCs.PublicIPv4, 8), ", "))
				}
				if len(rep.NetworkIoCs.PrivateIPv4) > 0 {
					fmt.Fprintf(out, "  Private IPv4 (%d) : %s\n", len(rep.NetworkIoCs.PrivateIPv4), strings.Join(firstN(rep.NetworkIoCs.PrivateIPv4, 8), ", "))
				}
				if len(rep.NetworkIoCs.IPv6) > 0 {
					fmt.Fprintf(out, "  IPv6 (%d)         : %s\n", len(rep.NetworkIoCs.IPv6), strings.Join(firstN(rep.NetworkIoCs.IPv6, 6), ", "))
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit ScanReport as JSON")
	return cmd
}

func newPathCmd() *cobra.Command {
	var (
		fromFn   string
		toFn     string
		maxDepth int
		arch     string
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "path <binary>",
		Short: "Find shortest call-graph path (BFS) between two recovered functions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(fromFn) == "" || strings.TrimSpace(toFn) == "" {
				return fmt.Errorf("both --from and --to are required")
			}
			if maxDepth <= 0 {
				return fmt.Errorf("--max-depth must be > 0 (got %d)", maxDepth)
			}
			res, err := analyzer.DefaultEngine.AnalyzeFile(args[0], analyzer.Options{Arch: arch})
			if err != nil {
				return err
			}
			pathRes, err := xref.FindCallPath(res.Functions, fromFn, toFn, maxDepth)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if asJSON {
				return printJSON(out, pathRes)
			}

			fmt.Fprintf(out, "=== SymForge Call-Graph Shortest Path ===\n")
			fmt.Fprintf(out, "  From    : %s (%s)\n", nonEmpty(pathRes.From.Demangled, pathRes.From.Name), pathRes.From.EntryHex)
			fmt.Fprintf(out, "  To      : %s (%s)\n", nonEmpty(pathRes.To.Demangled, pathRes.To.Name), pathRes.To.EntryHex)
			fmt.Fprintf(out, "  Status  : found=%v | hops=%d | max_depth=%d | visited=%d\n",
				pathRes.Found, pathRes.Hops, pathRes.MaxDepth, pathRes.NodesVisited)

			if !pathRes.Found {
				if pathRes.Message != "" {
					fmt.Fprintf(out, "  Detail  : %s\n", pathRes.Message)
				}
				return nil
			}

			fmt.Fprintf(out, "\n[Shortest Call Chain]\n")
			for _, hop := range pathRes.Path {
				prefix := "  "
				if hop.Depth > 0 {
					prefix = "  -> "
				}
				loc := ""
				if hop.SourceFile != "" {
					loc = fmt.Sprintf("  (%s:%d)", hop.SourceFile, hop.Line)
				}
				fmt.Fprintf(out, "%s[%d] %s  %-10s  %s%s\n",
					prefix, hop.Depth, hop.EntryHex, "["+string(hop.Category)+"]", nonEmpty(hop.Demangled, hop.Name), loc)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&fromFn, "from", "", "Source function name, substring, or hex address (required)")
	cmd.Flags().StringVar(&toFn, "to", "", "Target function name, substring, or hex address (required)")
	cmd.Flags().IntVar(&maxDepth, "max-depth", xref.DefaultMaxPathDepth, "Maximum BFS hop depth")
	cmd.Flags().StringVar(&arch, "arch", "", "Select architecture slice for Universal/Fat Mach-O (e.g. arm64, amd64)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit CallPathResult as JSON")
	return cmd
}

func newMCPCmd() *cobra.Command {
	var httpAddr string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the SymForge Model Context Protocol (MCP) server over stdio or HTTP/SSE",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			srv := mcpserver.New(Version, analyzer.DefaultEngine)
			if strings.TrimSpace(httpAddr) != "" {
				fmt.Fprintf(os.Stderr, "[symforge] MCP Streamable HTTP & SSE server listening on http://%s\n", httpAddr)
				return srv.ListenAndServeHTTP(ctx, httpAddr)
			}
			return srv.ServeStdio(ctx, os.Stdin, os.Stdout)
		},
	}
	cmd.Flags().StringVar(&httpAddr, "http", "", "Listen on loopback HTTP/SSE address (e.g. 127.0.0.1:8085) instead of stdio")
	return cmd
}

func newPresetCmd() *cobra.Command {
	var (
		workspaceDir string
		configPath   string
		binaryPath   string
		printOnly    bool
	)
	cmd := &cobra.Command{
		Use:   "preset <claude-code|cursor|vscode|windsurf|zed>",
		Short: "Configure SymForge MCP server in Claude Code, Cursor, VS Code, Windsurf, or Zed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := preset.ParseClient(args[0])
			if err != nil {
				return err
			}
			bin := strings.TrimSpace(binaryPath)
			if bin == "" {
				if exe, err := os.Executable(); err == nil && exe != "" {
					bin = exe
				} else {
					bin = "symforge"
				}
			}

			if printOnly {
				merged, err := preset.BuildMergedConfig(client, bin, nil)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(merged)
				return err
			}

			targetCfg := strings.TrimSpace(configPath)
			if targetCfg == "" {
				targetCfg, err = preset.DefaultConfigPath(client, "", workspaceDir)
				if err != nil {
					return err
				}
			}
			if _, err := preset.Apply(client, targetCfg, bin); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Configured SymForge MCP server for %s -> %s\n", client, targetCfg)
			return nil
		},
	}
	cmd.Flags().StringVar(&workspaceDir, "workspace", "", "Write project-scoped MCP config inside workspace directory")
	cmd.Flags().StringVar(&configPath, "config", "", "Explicit configuration file path override")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "Explicit path to symforge executable")
	cmd.Flags().BoolVar(&printOnly, "print", false, "Print generated JSON configuration to stdout without writing")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print SymForge version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "symforge v%s\n", Version)
		},
	}
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func firstN(vals []string, n int) []string {
	if len(vals) <= n {
		return vals
	}
	return vals[:n]
}
