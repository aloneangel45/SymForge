# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |

## Threat Model & Parser Hardening

SymForge parses untrusted `ELF`, `PE`, and `Mach-O` binaries strictly as inert byte arrays—it **never executes** analyzed binaries or loads dynamic libraries from them. All pointer walks, `pclntab` tables, `zlib` streams (`.dep-v0`), and demangler recursion depths are bounded to prevent out-of-bounds panics or decompression bombs.

## Reporting a Vulnerability

If you discover a memory-exhaustion bug, infinite loop, path traversal issue, or DNS-rebinding bypass in SymForge's parser or HTTP MCP server:

1. **Do not** open a public GitHub issue with crash-inducing PoCs before a fix is available.
2. Report privately via [GitHub Security Advisories](https://github.com/aloneangel45/SymForge/security/advisories/new).
3. Include minimal reproduction steps or a synthetic test fixture. We aim to triage within 48 hours.
