package gorecover

import (
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"runtime/debug"
	"sort"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

var goBuildInfoMagic = []byte("\xff Go buildinf:")

const (
	buildInfoHeaderLen   = 32
	buildInfoFlagEndian  = 0x1
	buildInfoFlagInline  = 0x2
	maxBuildInfoStrBytes = 4 * 1024 * 1024
)

// populateBuildInfo parses Go build metadata using debug/buildinfo first, falling back to
// a raw "\xff Go buildinf:" signature scanner if container headers were stripped or altered.
func populateBuildInfo(lb *loader.LoadedBinary, meta *model.GoMetadata) (bool, []model.Dependency) {
	raw := lb.Raw()
	if len(raw) < buildInfoHeaderLen {
		return false, nil
	}

	info, err := buildinfo.Read(bytes.NewReader(raw))
	if err != nil || info == nil || info.GoVersion == "" {
		info = scanRawBuildInfo(lb)
	}
	if info == nil || info.GoVersion == "" {
		return false, nil
	}

	meta.Version = info.GoVersion
	if info.Main.Path != "" {
		meta.MainModule = info.Main.Path
		meta.ModuleVersion = info.Main.Version
	} else if info.Path != "" && info.Path != "command-line-arguments" {
		meta.MainModule = info.Path
	}

	if len(info.Settings) > 0 {
		settings := make(map[string]string, len(info.Settings))
		for _, kv := range info.Settings {
			if kv.Key != "" {
				settings[kv.Key] = kv.Value
			}
		}
		if len(settings) > 0 {
			meta.BuildSettings = settings
		}
	}

	deps := extractGoDependencies(info.Deps)
	return true, deps
}

func extractGoDependencies(mods []*debug.Module) []model.Dependency {
	if len(mods) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(mods))
	out := make([]model.Dependency, 0, len(mods))

	for _, m := range mods {
		if m == nil {
			continue
		}
		effective := m
		if m.Replace != nil {
			effective = m.Replace
		}
		name := effective.Path
		if name == "" {
			name = m.Path
		}
		if name == "" {
			continue
		}
		ver := effective.Version
		if ver == "" && m.Replace == nil {
			ver = m.Version
		}
		sum := effective.Sum

		key := name + "@" + ver
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		out = append(out, model.Dependency{
			Name:      name,
			Version:   ver,
			Sum:       sum,
			Ecosystem: "gomod",
			Source:    "buildinfo",
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// scanRawBuildInfo scans raw binary bytes directly for the 14-byte "\xff Go buildinf:" magic
// so sstrip'd ELF binaries or custom-packed segments still yield full build metadata.
func scanRawBuildInfo(lb *loader.LoadedBinary) *debug.BuildInfo {
	raw := lb.Raw()
	searchFrom := 0
	for searchFrom+buildInfoHeaderLen <= len(raw) {
		rel := bytes.Index(raw[searchFrom:], goBuildInfoMagic)
		if rel < 0 {
			break
		}
		pos := searchFrom + rel
		searchFrom = pos + len(goBuildInfoMagic)

		if pos+buildInfoHeaderLen > len(raw) {
			break
		}
		hdr := raw[pos : pos+buildInfoHeaderLen]
		ptrSize := int(hdr[14])
		flags := hdr[15]

		var vers, mod string
		if (flags & buildInfoFlagInline) != 0 {
			// Go 1.18+: inline uvarint-prefixed version and module info strings immediately follow 32-byte header.
			cur := pos + buildInfoHeaderLen
			var ok bool
			vers, cur, ok = readInlineVarintString(raw, cur)
			if !ok || vers == "" {
				continue
			}
			mod, _, _ = readInlineVarintString(raw, cur)
		} else {
			// Go <1.18: pointer-based Go string headers at offsets 16 and 16+ptrSize.
			if ptrSize != 4 && ptrSize != 8 {
				continue
			}
			var bo binary.ByteOrder = binary.LittleEndian
			if (flags & buildInfoFlagEndian) != 0 {
				bo = binary.BigEndian
			}
			versAddr := readUintPtr(hdr[16:], ptrSize, bo)
			modAddr := readUintPtr(hdr[16+ptrSize:], ptrSize, bo)
			vers = readGoStringHeaderAtVA(lb, versAddr, ptrSize, bo)
			if vers == "" {
				continue
			}
			mod = readGoStringHeaderAtVA(lb, modAddr, ptrSize, bo)
		}

		mod = stripBuildInfoSentinel(mod)
		if mod != "" {
			if bi, err := debug.ParseBuildInfo(mod); err == nil && bi != nil {
				bi.GoVersion = vers
				return bi
			}
		}
		return &debug.BuildInfo{
			GoVersion: vers,
		}
	}
	return nil
}

func readInlineVarintString(raw []byte, offset int) (string, int, bool) {
	if offset < 0 || offset >= len(raw) {
		return "", offset, false
	}
	endWindow := offset + binary.MaxVarintLen64
	if endWindow > len(raw) {
		endWindow = len(raw)
	}
	strLen, n := binary.Uvarint(raw[offset:endWindow])
	if n <= 0 || strLen > maxBuildInfoStrBytes {
		return "", offset, false
	}
	start := offset + n
	end := start + int(strLen)
	if end < start || end > len(raw) {
		return "", offset, false
	}
	return string(raw[start:end]), end, true
}

func readGoStringHeaderAtVA(lb *loader.LoadedBinary, strHdrVA uint64, ptrSize int, bo binary.ByteOrder) string {
	if strHdrVA == 0 {
		return ""
	}
	va := normalizePointer(lb, strHdrVA)
	hdr, ok := lb.ReadAtVA(va, 2*ptrSize)
	if !ok {
		return ""
	}
	dataPtr := normalizePointer(lb, readUintPtr(hdr, ptrSize, bo))
	dataLen := readUintPtr(hdr[ptrSize:], ptrSize, bo)
	if dataPtr == 0 || dataLen == 0 || dataLen > maxBuildInfoStrBytes {
		return ""
	}
	strBytes, ok := lb.ReadAtVA(dataPtr, int(dataLen))
	if !ok {
		return ""
	}
	return string(strBytes)
}

func stripBuildInfoSentinel(mod string) string {
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		return mod[16 : len(mod)-16]
	}
	return ""
}

func readUintPtr(b []byte, ptrSize int, bo binary.ByteOrder) uint64 {
	if ptrSize == 4 {
		if len(b) < 4 {
			return 0
		}
		return uint64(bo.Uint32(b[:4]))
	}
	if len(b) < 8 {
		return 0
	}
	return bo.Uint64(b[:8])
}
