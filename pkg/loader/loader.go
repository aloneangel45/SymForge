// Package loader parses ELF, PE, and Mach-O (thin & universal fat) binaries
// into a unified, immutable, bounds-checked LoadedBinary view with virtual-address
// translation, section entropy, symbol tables, and exception-table function bounds.
package loader

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/aloneangel45/symforge/pkg/model"
)

// MaxBinarySize caps loaded binaries at 512 MiB to prevent unbounded memory exhaustion.
const MaxBinarySize = 512 * 1024 * 1024

// LoadedBinary provides immutable, zero-copy access to a parsed executable container.
type LoadedBinary struct {
	Info         model.BinaryInfo
	Sections     []model.SectionInfo
	Symbols      []model.SymbolEntry
	RuntimeFuncs []model.RuntimeBounds
	Order        binary.ByteOrder
	raw          []byte
}

// LoadFile reads path from disk and parses it as ELF, PE, or Mach-O (including Fat universal binaries).
func LoadFile(path string) (*LoadedBinary, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory, expected executable file", path)
	}
	if st.Size() > MaxBinarySize {
		return nil, fmt.Errorf("binary %s exceeds maximum size (%d > %d bytes)", path, st.Size(), MaxBinarySize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return LoadBytes(path, data)
}

// LoadBytes parses an in-memory executable image.
func LoadBytes(path string, data []byte) (*LoadedBinary, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("file %s too small to be a valid executable (%d bytes)", path, len(data))
	}

	sum := sha256.Sum256(data)
	shaHex := hex.EncodeToString(sum[:])

	var (
		lb  *LoadedBinary
		err error
	)

	switch {
	case bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}):
		lb, err = loadELF(path, data)
	case bytes.HasPrefix(data, []byte{'M', 'Z'}):
		lb, err = loadPE(path, data)
	case isMachOMagic(data):
		lb, err = loadMachO(path, data)
	default:
		return nil, fmt.Errorf("unsupported executable format in %s (expected ELF, PE, or Mach-O)", path)
	}
	if err != nil {
		return nil, err
	}

	lb.Info.Path = path
	lb.Info.SHA256 = shaHex
	lb.Info.SizeBytes = int64(len(data))

	var maxEnt float64
	hasUPXSection := false
	for _, s := range lb.Sections {
		if s.Entropy > maxEnt {
			maxEnt = s.Entropy
		}
		up := strings.ToUpper(s.Name)
		if strings.HasPrefix(up, "UPX") || strings.Contains(up, ".MPRESS") || strings.Contains(up, ".ASPACK") {
			hasUPXSection = true
		}
	}
	lb.Info.MaxEntropy = math.Round(maxEnt*1000) / 1000
	// Flag high-entropy executable section (> 7.45 bits/byte on >= 16 KiB code section)
	if hasUPXSection || bytes.Contains(data[:minInt(len(data), 4096)], []byte("UPX!")) {
		lb.Info.PackedLikely = true
	} else {
		for _, s := range lb.Sections {
			if s.Executable && s.FileSize >= 16384 && s.Entropy > 7.45 {
				lb.Info.PackedLikely = true
				break
			}
		}
	}

	return lb, nil
}

// Raw returns the underlying immutable file bytes (for thin binaries or the selected Fat slice).
func (b *LoadedBinary) Raw() []byte {
	return b.raw
}

// NormalizePointer decodes platform-encoded raw pointer words (such as Apple Mach-O 64-bit
// LC_DYLD_CHAINED_FIXUPS rebase and arm64e PAC rebase pointers) into canonical virtual addresses.
func (b *LoadedBinary) NormalizePointer(ptr uint64) uint64 {
	if ptr == 0 || b == nil {
		return 0
	}
	if b.SectionContainingVA(ptr) != nil {
		return ptr
	}
	if (b.Info.Format == model.FormatMachO || b.Info.Format == model.FormatMachOFat) && b.Info.PointerSize == 8 {
		if (ptr >> 63) == 0 {
			low36 := ptr & 0xfffffffff
			if b.SectionContainingVA(low36) != nil {
				return low36
			}
			candOffset := b.Info.ImageBase + low36
			if candOffset >= b.Info.ImageBase && b.SectionContainingVA(candOffset) != nil {
				return candOffset
			}
			high8 := (ptr >> 36) & 0xff
			candTarget := (high8 << 56) | low36
			if b.SectionContainingVA(candTarget) != nil {
				return candTarget
			}
		} else if (ptr >> 62) == 2 {
			// arm64e authenticated rebase pointer (auth=1, bind=0): low 32 bits = offset from ImageBase
			candPAC := b.Info.ImageBase + (ptr & 0xffffffff)
			if candPAC >= b.Info.ImageBase && b.SectionContainingVA(candPAC) != nil {
				return candPAC
			}
		}
	}
	return ptr
}

// VAToOffset converts a virtual address to a file byte offset within b.raw.
func (b *LoadedBinary) VAToOffset(va uint64) (uint64, bool) {
	for i := range b.Sections {
		s := &b.Sections[i]
		if s.FileSize == 0 {
			continue
		}
		span := s.VirtualSize
		if span < s.FileSize {
			span = s.FileSize
		}
		if span == 0 {
			continue
		}
		if va >= s.VirtualAddr && va-s.VirtualAddr < span {
			delta := va - s.VirtualAddr
			if delta >= s.FileSize {
				return 0, false
			}
			if s.FileOffset > uint64(len(b.raw)) || delta >= uint64(len(b.raw))-s.FileOffset {
				return 0, false
			}
			return s.FileOffset + delta, true
		}
	}
	return 0, false
}

// OffsetToVA converts a file byte offset within b.raw to a mapped virtual address.
func (b *LoadedBinary) OffsetToVA(off uint64) (uint64, bool) {
	for i := range b.Sections {
		s := &b.Sections[i]
		if s.FileSize == 0 {
			continue
		}
		if off >= s.FileOffset && off-s.FileOffset < s.FileSize {
			return s.VirtualAddr + (off - s.FileOffset), true
		}
	}
	return 0, false
}

// ReadAtVA returns a read-only byte slice of length n starting at virtual address va.
func (b *LoadedBinary) ReadAtVA(va uint64, n int) ([]byte, bool) {
	if n < 0 {
		return nil, false
	}
	if n == 0 {
		return []byte{}, true
	}
	off, ok := b.VAToOffset(va)
	if !ok {
		return nil, false
	}
	if uint64(n) > uint64(len(b.raw))-off {
		return nil, false
	}
	return b.raw[off : off+uint64(n)], true
}

// ReadPtrAtVA reads a pointer-sized unsigned integer at virtual address va and normalizes chained fixups.
func (b *LoadedBinary) ReadPtrAtVA(va uint64) (uint64, bool) {
	ps := b.Info.PointerSize
	if ps != 4 && ps != 8 {
		return 0, false
	}
	buf, ok := b.ReadAtVA(va, ps)
	if !ok {
		return 0, false
	}
	if ps == 8 {
		return b.NormalizePointer(b.Order.Uint64(buf)), true
	}
	return uint64(b.Order.Uint32(buf)), true
}

// ReadUint32AtVA reads a 32-bit unsigned integer at virtual address va.
func (b *LoadedBinary) ReadUint32AtVA(va uint64) (uint32, bool) {
	buf, ok := b.ReadAtVA(va, 4)
	if !ok {
		return 0, false
	}
	return b.Order.Uint32(buf), true
}

// ReadCStringAtVA reads a null-terminated string up to maxLen bytes starting at va.
func (b *LoadedBinary) ReadCStringAtVA(va uint64, maxLen int) (string, bool) {
	off, ok := b.VAToOffset(va)
	if !ok || maxLen <= 0 {
		return "", false
	}
	avail := uint64(len(b.raw)) - off
	limit := off + avail
	if uint64(maxLen) < avail {
		limit = off + uint64(maxLen)
	}
	slice := b.raw[off:limit]
	idx := bytes.IndexByte(slice, 0)
	if idx < 0 {
		return "", false
	}
	return string(slice[:idx]), true
}

// SectionByName looks up the first section matching any of names (case-insensitive, ignoring leading '.' or '__' differences when exact fails).
func (b *LoadedBinary) SectionByName(names ...string) (*model.SectionInfo, []byte, bool) {
	// Pass 1: exact case-insensitive match.
	for _, want := range names {
		for i := range b.Sections {
			s := &b.Sections[i]
			if strings.EqualFold(s.Name, want) {
				if data, ok := b.SectionBytes(s); ok {
					return s, data, true
				}
			}
		}
	}
	// Pass 2: normalized stem match (e.g. "__TEXT.__gopclntab" or "__DATA,.dep-v0" matching ".gopclntab" or ".dep-v0").
	for _, want := range names {
		wantStem := canonicalSectionStem(want)
		if wantStem == "" {
			continue
		}
		for i := range b.Sections {
			s := &b.Sections[i]
			if canonicalSectionStem(s.Name) == wantStem {
				if data, ok := b.SectionBytes(s); ok {
					return s, data, true
				}
			}
		}
	}
	return nil, nil, false
}

func canonicalSectionStem(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if comma := strings.IndexByte(n, ','); comma >= 0 {
		n = n[comma+1:]
	} else if strings.HasPrefix(n, "__") {
		if dot := strings.IndexByte(n, '.'); dot > 2 {
			n = n[dot+1:]
		}
	}
	return strings.TrimLeft(n, "._")
}

// SectionBytes returns the raw file bytes backing section s.
func (b *LoadedBinary) SectionBytes(s *model.SectionInfo) ([]byte, bool) {
	if s == nil || s.FileSize == 0 {
		return nil, false
	}
	if s.FileOffset > uint64(len(b.raw)) || s.FileSize > uint64(len(b.raw))-s.FileOffset {
		return nil, false
	}
	return b.raw[s.FileOffset : s.FileOffset+s.FileSize], true
}

// SectionContainingVA returns the section whose virtual range contains va, or nil.
func (b *LoadedBinary) SectionContainingVA(va uint64) *model.SectionInfo {
	for i := range b.Sections {
		s := &b.Sections[i]
		span := s.VirtualSize
		if span < s.FileSize {
			span = s.FileSize
		}
		if span > 0 && va >= s.VirtualAddr && va-s.VirtualAddr < span {
			return s
		}
	}
	return nil
}

// IsCodeVA reports whether va lies inside an executable section.
func (b *LoadedBinary) IsCodeVA(va uint64) bool {
	s := b.SectionContainingVA(va)
	return s != nil && s.Executable
}

// IsReadableVA reports whether va maps to backed readable bytes in the image.
func (b *LoadedBinary) IsReadableVA(va uint64) bool {
	_, ok := b.VAToOffset(va)
	return ok
}

// ShannonEntropy computes the Shannon entropy in [0.0, 8.0] bits/byte of data.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range data {
		counts[c]++
	}
	invLen := 1.0 / float64(len(data))
	var ent float64
	for _, cnt := range counts {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) * invLen
		ent -= p * math.Log2(p)
	}
	return math.Round(ent*1000) / 1000
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
