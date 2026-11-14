# Changelog

All notable changes to **SymForge** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-14

### Added
- **Unified Multi-Format Binary Loader (`pkg/loader`)**: Pure-Go (`CGO_ENABLED=0`) reader for `ELF` (32/64-bit, `sstrip` segment fallback), `PE` (`PE32`/`PE32+`, x64 `.pdata` `RUNTIME_FUNCTION` bounds), and `Mach-O` (thin + universal Fat `0xCAFEBABE`), with virtual-address translation, Shannon section entropy, and UPX/packer heuristics.
- **Go Stripped Binary Recovery Engine (`pkg/gorecover`)**: Multi-version `gopclntab` scanner & parser across Go 1.2–1.27+ (`0xfffffffb`, `0xfffffffa`, `0xfffffff0`, `0xfffffff1`), `runtime.buildinfo` module/dependency extractor, and `firstmoduledata` + `typelinks` `struct` field & `interface` method recovery.
- **Rust Stripped Binary Recovery Engine (`pkg/rustrecover`)**: Pure-Go RFC 2603 `_R` (`v0`) + legacy `_ZN` symbol demangler, `cargo-auditable` `.dep-v0` zlib SBOM + `.cargo/registry/src/...` crate extractor, binary `core::panic::Location` (`{file_ptr, file_len, line, col}`) carver, and `.rodata` trait vtable scanner.
- **Pure-Go Multi-Arch XREF & Disassembly Engine (`pkg/xref`)**: `x86_64` (`golang.org/x/arch/x86/x86asm`) and `ARM64` (`golang.org/x/arch/arm64/arm64asm`) call-graph builder (`CALL`/`BL`, `RIP`-relative `LEA`, `ADRP`+`ADD`/`LDR` pair tracking), Go `(ptr, len)` contiguous `.rodata` string splitter, URL/API/secret classifier, and AES/SHA-256/ChaCha20 constant detector.
- **RE Script & CycloneDX 1.5 Exporters (`pkg/exporter`)**: Image-base-rebasing Python scripts for **Ghidra**, **IDA Pro**, and **Binary Ninja**, plus structured Markdown forensic reports and **CycloneDX 1.5** JSON SBOMs (`pkg:golang/...` and `pkg:cargo/...`).
- **Model Context Protocol (MCP) Server (`pkg/mcpserver`)**: Dual-framing `stdio` (NDJSON + `Content-Length`) and loopback-guarded Streamable HTTP/SSE server exposing 8 forensic tools (`analyze_binary`, `list_packages_crates`, `search_functions`, `inspect_function`, `find_xrefs`, `recover_types`, `demangle_symbols`, `export_re_script`) backed by an SHA-256 analysis cache.
- **CLI & IDE Presets (`cmd/symforge`)**: Full Cobra CLI (`inspect`, `functions`, `fn`, `strings`, `types`, `deps`, `demangle`, `export`, `mcp`, `preset`, `version`) with one-command MCP config writers for Claude Code, Cursor, VS Code, Windsurf, and Zed.
