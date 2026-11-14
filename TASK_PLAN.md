# SymForge v1.0.0 — Architecture & Execution Plan

> Zero-Dependency (`CGO_ENABLED=0`) Go & Rust Stripped Binary Symbol/Type Recovery, Pure-Go `x86_64`/`ARM64` XREF & Call-Graph Analyzer, Ghidra/IDA/Binja Exporter, and Model Context Protocol (MCP) Server.

## Phase 1: Foundation & Unified Binary Loader
- [x] Initialize `C:\Users\Arda\Desktop\SymForge`, `go.mod`, and `TASK_PLAN.md`
- [x] Design shared domain model `pkg/model/types.go`
- [x] Implement `pkg/loader` (`ELF`, `PE` + `.pdata`, `Mach-O` Thin & Fat, VA <-> FileOffset, Shannon entropy, strip/packer heuristics)
- [x] Generate studio hero banner `assets/banner.png`

## Phase 2: Stripped Go, Stripped Rust & Pure-Go XREF Engines
- [x] `pkg/gorecover`: `buildinfo`, multi-generation `gopclntab` (`0xfffffffb`/`a`/`0`/`1` for Go 1.2–1.27+), `firstmoduledata` & `typelinks` struct/interface recovery
- [x] `pkg/rustrecover`: Pure-Go Rust `v0` + Legacy demangler, `cargo-auditable` `.dep-v0` + `.cargo/registry` SBOM, `core::panic::Location` struct carver, `.rodata` vtables
- [x] `pkg/xref`: ASCII/UTF-8/UTF-16LE + Go `(ptr, len)` string slicer, URL/secret/crypto classifier, `x86asm` & `arm64asm` call graph & string/data XREFs

## Phase 3: Analyzer, Exporters, Native MCP Server & CLI
- [x] `pkg/analyzer`: Unified analysis orchestrator + thread-safe LRU cache
- [x] `pkg/exporter`: Ghidra Python, IDA Pro IDAPython, Binary Ninja Python, Markdown report, JSON, CycloneDX 1.5 SBOM
- [x] `pkg/mcpserver`: Stdio (`NDJSON` + `Content-Length`) & Streamable HTTP/SSE (`127.0.0.1`) MCP server with 8 compact high-signal tools
- [x] `cmd/symforge`: Full Cobra CLI (`inspect`, `functions`, `fn`, `strings`, `types`, `deps`, `demangle`, `export`, `mcp`, `preset`, `version`)

## Phase 4: Real Stripped Binary Test Matrix, GitHub Repo & v1.0.0 Release
- [x] Cross-compiled stripped Go binary test suite (`ELF`, `PE`, `Mach-O` x `amd64`, `arm64`) + real `rustc -C strip=symbols` test suite + adversarial edge cases
- [x] Community standards, `Dockerfile`, `install.sh` (POSIX LF), `install.ps1` (pure `.NET` SHA-256)
- [x] GitHub Actions `ci.yml` & `release.yml`, create `aloneangel45/SymForge`, push `main` + `v1.0.0`, verify 100% green CI & published release assets
