package rustrecover

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

const maxAuditableSBOMBytes = 16 * 1024 * 1024 // 16 MiB decompression cap

type auditableSBOM struct {
	Packages []auditablePkg `json:"packages"`
}

type auditablePkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  any    `json:"source,omitempty"`
	Kind    any    `json:"kind,omitempty"`
	Root    bool   `json:"root,omitempty"`
}

// extractCratesAndToolchain recovers cargo-auditable (.dep-v0) SBOM dependencies,
// rustc compiler version/commit banners, and Cargo registry path dependencies.
func extractCratesAndToolchain(lb *loader.LoadedBinary) (
	compilerVer string,
	compilerCommit string,
	auditable bool,
	deps []model.Dependency,
) {
	seenDeps := make(map[string]struct{})
	addDep := func(name, version, source string) {
		if name == "" {
			return
		}
		key := name + "@" + version
		if _, exists := seenDeps[key]; exists {
			return
		}
		seenDeps[key] = struct{}{}
		deps = append(deps, model.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "cargo",
			Source:    source,
		})
	}

	// 1. Check .dep-v0 / __DATA,.dep-v0 section for cargo-auditable zlib-compressed JSON
	if depData, ok := findDepV0Section(lb); ok {
		if pkgs, parsedOK := decodeAuditableSection(depData); parsedOK {
			auditable = true
			for _, pkg := range pkgs {
				if isValidCrateIdent(pkg.Name) {
					addDep(pkg.Name, pkg.Version, "cargo-auditable")
				}
			}
		}
	}

	// 2. Scan raw binary (which covers all read-only data + .comment sections) for toolchain & registry paths
	raw := lb.Raw()
	compilerVer, compilerCommit = carveRustcToolchain(raw)
	for _, regDep := range carveCargoRegistryPaths(raw) {
		addDep(regDep.Name, regDep.Version, "registry-path")
	}

	sort.SliceStable(deps, func(i, j int) bool {
		if deps[i].Source != deps[j].Source {
			return deps[i].Source < deps[j].Source
		}
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})

	return compilerVer, compilerCommit, auditable, deps
}

func findDepV0Section(lb *loader.LoadedBinary) ([]byte, bool) {
	if _, data, ok := lb.SectionByName(".dep-v0", "__DATA,.dep-v0", "__DATA..dep-v0", "dep-v0"); ok && len(data) > 2 {
		return data, true
	}
	for i := range lb.Sections {
		s := &lb.Sections[i]
		lower := strings.ToLower(s.Name)
		if strings.Contains(lower, "dep-v0") {
			if data, ok := lb.SectionBytes(s); ok && len(data) > 2 {
				return data, true
			}
		}
	}
	return nil, false
}

func decodeAuditableSection(secData []byte) ([]auditablePkg, bool) {
	// Trim trailing zero padding common in PE/COFF FileAlignment-padded sections,
	// though compress/zlib also stops cleanly at the zlib stream trailer.
	zr, err := zlib.NewReader(bytes.NewReader(secData))
	if err != nil {
		return nil, false
	}
	defer zr.Close()

	limited := io.LimitReader(zr, maxAuditableSBOMBytes+1)
	jsonBytes, err := io.ReadAll(limited)
	if err != nil || int64(len(jsonBytes)) > maxAuditableSBOMBytes || len(jsonBytes) == 0 {
		return nil, false
	}

	var sbom auditableSBOM
	if err := json.Unmarshal(jsonBytes, &sbom); err != nil {
		return nil, false
	}
	if sbom.Packages == nil {
		return nil, false
	}
	return sbom.Packages, true
}

func carveRustcToolchain(data []byte) (version, commit string) {
	// Pattern A: /rustc/<hex-hash>/ or \rustc\<hex-hash>\
	for _, needle := range [][]byte{[]byte("/rustc/"), []byte(`\rustc\`)} {
		off := 0
		for off < len(data) {
			idx := bytes.Index(data[off:], needle)
			if idx < 0 {
				break
			}
			start := off + idx + len(needle)
			off = start
			end := start
			for end < len(data) && end-start < 40 && isLowerHex(data[end]) {
				end++
			}
			hashLen := end - start
			if hashLen >= 7 && end < len(data) && (data[end] == '/' || data[end] == '\\') {
				cand := string(data[start:end])
				if len(cand) > len(commit) {
					commit = cand
					if len(commit) == 40 {
						break
					}
				}
			}
		}
	}

	// Pattern B: "rustc 1.xx.x" (e.g. "rustc version 1.85.0 (4d91de4e4 2025-02-17)" or "rustc 1.99.1 (58cf8f9c3 2026-10-13)")
	rustcNeedle := []byte("rustc ")
	off := 0
	for off < len(data) {
		idx := bytes.Index(data[off:], rustcNeedle)
		if idx < 0 {
			break
		}
		cur := off + idx + len(rustcNeedle)
		off = cur
		if bytes.HasPrefix(data[cur:], []byte("version ")) {
			cur += len("version ")
		}
		if cur >= len(data) || data[cur] < '0' || data[cur] > '9' {
			continue
		}
		verEnd := cur
		for verEnd < len(data) && verEnd-cur < 32 && isSemverBannerChar(data[verEnd]) {
			verEnd++
		}
		candVer := string(data[cur:verEnd])
		if !looksLikeSemverPrefix(candVer) {
			continue
		}
		if version == "" {
			version = candVer
		}
		// Check optional " (<short-hash> <date>)" right after version
		rem := data[verEnd:]
		if len(rem) >= 10 && rem[0] == ' ' && rem[1] == '(' {
			hStart := 2
			hEnd := hStart
			for hEnd < len(rem) && hEnd-hStart <= 40 && isLowerHex(rem[hEnd]) {
				hEnd++
			}
			if hEnd-hStart >= 7 && hEnd < len(rem) && (rem[hEnd] == ' ' || rem[hEnd] == ')') {
				if commit == "" {
					commit = string(rem[hStart:hEnd])
				}
			}
		}
		if version != "" && len(commit) == 40 {
			break
		}
	}

	return version, commit
}

func carveCargoRegistryPaths(data []byte) []model.Dependency {
	var out []model.Dependency
	needles := [][]byte{
		[]byte(".cargo/registry/src/"),
		[]byte(`.cargo\registry\src\`),
	}
	for _, needle := range needles {
		off := 0
		for off < len(data) {
			idx := bytes.Index(data[off:], needle)
			if idx < 0 {
				break
			}
			cur := off + idx + len(needle)
			off = cur

			// Skip registry host directory (e.g. "index.crates.io-6f17d22bba15001f" or "github.com-1ecc6299db9ec823")
			sep1 := nextPathSep(data[cur:], 128)
			if sep1 <= 0 {
				continue
			}
			crateDirStart := cur + sep1 + 1
			if crateDirStart >= len(data) {
				continue
			}
			sep2 := nextPathSep(data[crateDirStart:], 160)
			if sep2 <= 0 {
				continue
			}
			crateDir := string(data[crateDirStart : crateDirStart+sep2])
			if name, ver, ok := splitCrateAndSemver(crateDir); ok {
				out = append(out, model.Dependency{
					Name:      name,
					Version:   ver,
					Ecosystem: "cargo",
					Source:    "registry-path",
				})
			}
		}
	}
	return out
}

func nextPathSep(b []byte, maxScan int) int {
	limit := len(b)
	if limit > maxScan {
		limit = maxScan
	}
	for i := 0; i < limit; i++ {
		c := b[i]
		if c == '/' || c == '\\' {
			return i
		}
		if c < 0x20 || c >= 0x7f {
			return -1
		}
	}
	return -1
}

// splitCrateAndSemver splits "<crate>-<major>.<minor>.<patch>[prerelease/build]" cleanly,
// supporting hyphenated crate names like "tokio-util-0.7.12-alpha.1".
func splitCrateAndSemver(dir string) (name, version string, ok bool) {
	for i := 1; i < len(dir)-5; i++ {
		if dir[i] != '-' {
			continue
		}
		candName := dir[:i]
		candVer := dir[i+1:]
		if isValidCrateIdent(candName) && isValidSemver(candVer) {
			return candName, candVer, true
		}
	}
	return "", "", false
}

func isValidCrateIdent(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func isValidSemver(v string) bool {
	if len(v) < 5 || len(v) > 64 || !looksLikeSemverPrefix(v) {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			c == '.' || c == '-' || c == '+' || c == '_') {
			return false
		}
	}
	return true
}

func looksLikeSemverPrefix(v string) bool {
	// Require <digits>.<digits>.<digits> at start
	p := 0
	for seg := 0; seg < 3; seg++ {
		start := p
		for p < len(v) && v[p] >= '0' && v[p] <= '9' {
			p++
		}
		if p == start {
			return false
		}
		if seg < 2 {
			if p >= len(v) || v[p] != '.' {
				return false
			}
			p++
		}
	}
	return p == len(v) || v[p] == '-' || v[p] == '+'
}

func isSemverBannerChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		c == '.' || c == '-' || c == '+'
}

func isLowerHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}
