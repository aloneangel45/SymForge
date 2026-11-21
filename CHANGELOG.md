# Changelog

All notable changes to **SymForge** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-21

### Added
- **Native Import / IAT / Dylib Recovery & Universal Fat Mach-O Slice Selection (`pkg/loader`, `pkg/model`, `pkg/analyzer`)**:
  - Extended `model.AnalysisResult` with `Imports []model.ImportSymbol` (`Library`, `Name`, `Address`) and `model.BinaryInfo` with `AvailableArches []string`.
  - **ELF**: Recovers `DT_NEEDED` shared libraries and undefined dynamic symbols (`ImportedSymbols()` + `DynamicSymbols()` fallback).
  - **PE (`PE32`/`PE32+`)**: Pure-Go `IMAGE_DIRECTORY_ENTRY_IMPORT` parser recovering DLL names, API names/ordinals, and IAT virtual addresses with graceful `debug/pe` fallback.
  - **Mach-O**: Recovers `LC_LOAD_DYLIB` (including weak/reexport/lazy dylibs) and undefined external symbols with two-level namespace dylib ordinal attribution, plus Universal/Fat Mach-O (`0xCAFEBABE`) slice listing and selection (`--arch` CLI flag & MCP `"arch"` parameter, defaulting to host architecture if present else first slice) backed by arch-aware analysis cache keys.
- **Stripped Binary Patch / Version Diffing (`pkg/diff`, `symforge diff`, MCP `diff_binaries`)**:
  - Compares two binaries across added/removed/modified functions (size delta, category change, crypto reference deltas), packages, Go/Rust dependencies (added/removed/version-bumped), native imports, high-signal strings, cryptographic constants, and automated risk highlights.
- **Pure-Go Behavioral Capability, Network IoC & Go `garble` Obfuscation Triage (`pkg/triage`, `symforge scan`, MCP `scan_capabilities`)**:
  - Structured severity-scored (`critical|high|medium|info`) findings across process execution, network/C2/TLS (with URL, public/private IPv4, and IPv6 extraction), memory injection, anti-debug, persistence, privilege escalation, crypto primitives, hardcoded secrets, UPX/high-entropy sections (`>= 7.0`), and Go `garble` obfuscation heuristics (stripped `BuildInfo`, randomized base64-like package/function tokens, stripped/obfuscated source paths).
- **BFS Call-Graph Shortest Path & Visual Graph Exports (`pkg/xref/path.go`, `pkg/exporter/graph.go`, `symforge path`, `symforge export -f dot|mermaid`, MCP `trace_call_path`)**:
  - Breadth-first shortest path (`FindCallPath`) between any two recovered functions (by name, substring, or hex VA) with `--max-depth` (default `12`).
  - Clean Graphviz DOT (`digraph`) and Mermaid (`flowchart LR`) call-graph exporters with `--user-only` and `--limit` node caps and category styling.
  - Expanded SymForge MCP server to **11 native tools** with universal `"arch"` support.

## [1.0.1] - 2026-11-14

### Fixed
- **CycloneDX 1.5 SBOM Go Module PURLs (`pkg/exporter`)**: Mapped `gomod` ecosystem entries emitted by `gorecover` `buildinfo` extraction to canonical `pkg:golang/...` Package URLs instead of `pkg:gomod/...`, and populated root application component versions from recovered Go module metadata.
- **Rust 1.77+ `None`-Drop Trait VTable Recovery (`pkg/rustrecover`)**: Added support for `Option<fn(*mut ())>::None` (`drop_in_place == 0`) trait object vtables in explicit const/RELRO sections with code-entry alignment & padding guards, recovering non-`Drop` concrete trait implementations (e.g., `HmacVerifier`) alongside `Drop`-bearing types, plus 32-bit ELF `.rela` relocation support (`R_386_RELATIVE`, `R_ARM_RELATIVE`).
- **Mach-O `LC_DYLD_CHAINED_FIXUPS` & `arm64e` Pointer Normalization (`pkg/loader`, `pkg/gorecover`, `pkg/xref`)**: Unified 64-bit Mach-O chained rebase and `arm64e` PAC pointer normalization on `LoadedBinary.NormalizePointer`, fixing static `(ptr, len)` string slicing, indirect string XREFs, section stem lookup (`__TEXT.__gopclntab`, `__DATA,.dep-v0`), and `uint64` VA range wraparound edge cases.
- **Go <= 1.16 Type Name & Nested Anonymous Type Recovery (`pkg/gorecover`)**: Added legacy big-endian `uint16` `abi.Name` length/tag decoding alongside Go 1.17+ varints and traversed anonymous `struct`/`interface` wrappers when discovering nested named types.
- **JSON-RPC 2.0 Batch & Explicit `null` ID Compliance (`pkg/mcpserver`)**: Distinguished omitted `"id"` notifications from explicit `"id": null` requests and added JSON-RPC 2.0 batch request array (`[...]`) handling across `stdio` and HTTP transports.
- **Zero-Disk-Reread Function Disassembly & Cold-Cache Stampede Protection (`pkg/analyzer`, `pkg/exporter`)**: Retained `LoadedBinary` in the bounded analysis cache for in-memory `InspectFunction` disassembly, deduplicated concurrent cold-cache `AnalyzeFile` calls per `(path, size, mtime)`, and added PyGhidra (Python 3) `println` compatibility to Ghidra script exports.
- **CI / Release Workflow Resilience (`.github/workflows`)**: Eliminated external `sh.rustup.rs` network flakiness when `rustc` is preinstalled on GitHub-hosted runners and enabled Node 24 execution for JavaScript Actions.

## [1.0.0] - 2026-11-14

### Added
- **Unified Multi-Format Binary Loader (`pkg/loader`)**: Pure-Go (`CGO_ENABLED=0`) reader for `ELF` (32/64-bit, `sstrip` segment fallback), `PE` (`PE32`/`PE32+`, x64 `.pdata` `RUNTIME_FUNCTION` bounds), and `Mach-O` (thin + universal Fat `0xCAFEBABE`), with virtual-address translation, Shannon section entropy, and UPX/packer heuristics.
- **Go Stripped Binary Recovery Engine (`pkg/gorecover`)**: Multi-version `gopclntab` scanner & parser across Go 1.2–1.27+ (`0xfffffffb`, `0xfffffffa`, `0xfffffff0`, `0xfffffff1`), `runtime.buildinfo` module/dependency extractor, and `firstmoduledata` + `typelinks` `struct` field & `interface` method recovery.
- **Rust Stripped Binary Recovery Engine (`pkg/rustrecover`)**: Pure-Go RFC 2603 `_R` (`v0`) + legacy `_ZN` symbol demangler, `cargo-auditable` `.dep-v0` zlib SBOM + `.cargo/registry/src/...` crate extractor, binary `core::panic::Location` (`{file_ptr, file_len, line, col}`) carver, and `.rodata` trait vtable scanner.
- **Pure-Go Multi-Arch XREF & Disassembly Engine (`pkg/xref`)**: `x86_64` (`golang.org/x/arch/x86/x86asm`) and `ARM64` (`golang.org/x/arch/arm64/arm64asm`) call-graph builder (`CALL`/`BL`, `RIP`-relative `LEA`, `ADRP`+`ADD`/`LDR` pair tracking), Go `(ptr, len)` contiguous `.rodata` string splitter, URL/API/secret classifier, and AES/SHA-256/ChaCha20 constant detector.
- **RE Script & CycloneDX 1.5 Exporters (`pkg/exporter`)**: Image-base-rebasing Python scripts for **Ghidra**, **IDA Pro**, and **Binary Ninja**, plus structured Markdown forensic reports and **CycloneDX 1.5** JSON SBOMs (`pkg:golang/...` and `pkg:cargo/...`).
- **Model Context Protocol (MCP) Server (`pkg/mcpserver`)**: Dual-framing `stdio` (NDJSON + `Content-Length`) and loopback-guarded Streamable HTTP/SSE server exposing 8 forensic tools (`analyze_binary`, `list_packages_crates`, `search_functions`, `inspect_function`, `find_xrefs`, `recover_types`, `demangle_symbols`, `export_re_script`) backed by an SHA-256 analysis cache.
- **CLI & IDE Presets (`cmd/symforge`)**: Full Cobra CLI (`inspect`, `functions`, `fn`, `strings`, `types`, `deps`, `demangle`, `export`, `mcp`, `preset`, `version`) with one-command MCP config writers for Claude Code, Cursor, VS Code, Windsurf, and Zed.
