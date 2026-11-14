// Command symforge is a zero-dependency Go & Rust stripped binary forensics,
// symbol/type/SBOM recovery, multi-arch XREF disassembler, Ghidra/IDA/Binary Ninja
// script exporter, and Model Context Protocol (MCP) server.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is stamped at build time via -ldflags "-X main.Version=..."
var Version = "1.0.1"

func main() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "symforge",
		Short: "SymForge — Stripped Go & Rust Binary Forensics, Symbol/Type Recovery & MCP Server",
		Long: `SymForge recovers stripped Go (pclntab/moduledata/typelinks) and Rust (v0/legacy demangling,
cargo-auditable SBOM, panic locations, trait vtables) metadata across ELF, PE, and Mach-O
binaries, builds pure-Go x86_64 & ARM64 call/string/crypto XREF graphs, exports Ghidra/IDA/Binja
scripts and CycloneDX 1.5 SBOMs, and serves native MCP tools for AI coding agents.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}

	root.AddCommand(
		newInspectCmd(),
		newFunctionsCmd(),
		newFnCmd(),
		newStringsCmd(),
		newTypesCmd(),
		newDepsCmd(),
		newDemangleCmd(),
		newExportCmd(),
		newMCPCmd(),
		newPresetCmd(),
		newVersionCmd(),
	)
	return root
}
