# Contributing to SymForge

Thank you for your interest in contributing to **SymForge**!

## Development Prerequisites

- **Go 1.27+** (`CGO_ENABLED=0` pure-Go build)
- **Rust (`rustc`)** *(optional, enables live stripped Rust binary integration tests in `pkg/rustrecover`)*

## Running Tests Locally

```bash
go vet ./...
go test -v -race ./...
```

## Architecture Guidelines

1. **Zero CGO (`CGO_ENABLED=0`)**: All binary loaders, metadata parsers, demanglers, and disassemblers must compile cleanly as static pure-Go binaries across Linux, macOS, and Windows (`amd64` & `arm64`).
2. **Untrusted Input Safety**: Treat every binary input (`ELF`, `PE`, `Mach-O`) as potentially malformed or adversarial. Guard every virtual-address read, slice bound, pointer dereference, and recursion depth.
3. **Real Compiler Verification**: New recovery features for Go (`pclntab`, `moduledata`, `typelinks`) or Rust (`v0` demangling, `.dep-v0`, panic locations, vtables) must include tests against real compiled and stripped binaries.
4. **Defensive Scope**: SymForge focuses strictly on binary forensics, symbol/type recovery, SBOM transparency, secret-hygiene auditing, and RE script/MCP interoperability.
