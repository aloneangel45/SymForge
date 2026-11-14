package xref

import (
	"bytes"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

const (
	defaultMinStringLen = 4
	defaultMaxStrings   = 10000
	maxGoHeaderStrLen   = 4096
	maxInsnSliceStrLen  = 2048
	maxRawUnboundedRun  = 1024
)

// dataSecView caches a mapped non-code readable section for O(1) slice lookups.
type dataSecView struct {
	name     string
	vaStart  uint64
	vaEnd    uint64
	data     []byte
	readOnly bool
}

// stringExtractor collects exact (ptr, len) string slices and raw printable strings.
type stringExtractor struct {
	lb          *loader.LoadedBinary
	minLen      int
	sections    []dataSecView
	exactSlices map[uint64]int // VA -> exact byte length
	isGoLike    bool
}

func newStringExtractor(lb *loader.LoadedBinary, minLen int) *stringExtractor {
	if minLen <= 0 {
		minLen = defaultMinStringLen
	}
	se := &stringExtractor{
		lb:          lb,
		minLen:      minLen,
		exactSlices: make(map[uint64]int, 1024),
		isGoLike:    lb.Info.Language == model.LangGo || lb.Info.Language == model.LangGoRust,
	}

	for i := range lb.Sections {
		s := &lb.Sections[i]
		low := strings.ToLower(s.Name)
		if strings.Contains(low, "gopclntab") || strings.Contains(low, "go.buildinfo") || strings.Contains(low, "go_buildinfo") {
			se.isGoLike = true
		}
		if !isCandidateDataSection(s) {
			continue
		}
		secBytes, ok := lb.SectionBytes(s)
		if !ok || len(secBytes) == 0 {
			continue
		}
		se.sections = append(se.sections, dataSecView{
			name:     s.Name,
			vaStart:  s.VirtualAddr,
			vaEnd:    s.VirtualAddr + uint64(len(secBytes)),
			data:     secBytes,
			readOnly: !s.Writable || strings.Contains(low, "rel.ro") || strings.Contains(low, "__const"),
		})
	}
	return se
}

// isCandidateDataSection selects non-executable readable string/data sections while
// excluding container symbol/relocation/debug/unwind tables and allowing Mach-O __TEXT consts.
func isCandidateDataSection(s *model.SectionInfo) bool {
	if s == nil || s.FileSize == 0 || !s.Readable {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(s.Name))

	// Exclude non-program metadata/debug/symbol/unwind sections.
	excludedPrefixes := []string{
		".symtab", ".strtab", ".shstrtab", ".dynsym", ".dynstr",
		".rela", ".rel.", ".debug", ".zdebug", ".eh_frame",
		".gcc_except", ".gopclntab", ".gosymtab", ".pdata", ".xdata",
		".gnu.", ".note", ".comment", ".plt", ".init", ".fini", ".bss",
		"__linkedit", "__text.__eh_frame", "__text.__unwind_info", "__text.__stubs",
	}
	for _, p := range excludedPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}

	// Explicit data/string sections (note: Mach-O __TEXT.__cstring and __TEXT.__const
	// inherit segment VM_PROT_EXECUTE on macOS even though they hold pure read-only data).
	explicitAllow := []string{
		".rodata", ".rdata", ".data.rel.ro", ".data", ".noptrdata",
		"__text.__cstring", "__text.__const", "__text.__rodata", "__text.__ustring",
		"__data.__const", "__data_const.__const", "__data.__data",
		"__rodata",
	}
	for _, allow := range explicitAllow {
		if name == allow || strings.HasPrefix(name, allow+".") {
			return true
		}
	}

	if s.Executable {
		// Allow synthesized PT_LOAD segments only when no non-exec section exists (handled if !Executable).
		return false
	}
	return true
}

// sliceAtVA returns the backing byte slice starting at va up to maxBytes within a candidate data section.
func (se *stringExtractor) sliceAtVA(va uint64, maxBytes int) ([]byte, *dataSecView, bool) {
	for i := range se.sections {
		sec := &se.sections[i]
		if va >= sec.vaStart && va < sec.vaEnd {
			off := int(va - sec.vaStart)
			rem := len(sec.data) - off
			if maxBytes > 0 && rem > maxBytes {
				rem = maxBytes
			}
			return sec.data[off : off+rem], sec, true
		}
	}
	return nil, nil, false
}

// scanStaticGoStringHeaders scans read-only/data sections on pointer alignment for valid
// Go/Rust (strPtr, strLen) headers so concatenated string tables are split into exact slices.
func (se *stringExtractor) scanStaticGoStringHeaders() {
	ptrSize := se.lb.Info.PointerSize
	if ptrSize != 4 && ptrSize != 8 {
		ptrSize = 8
	}
	order := se.lb.Order
	if order == nil {
		order = model.ByteOrderFromName(se.lb.Info.Endianness)
	}
	minHdrLen := se.minLen
	if minHdrLen < 4 {
		minHdrLen = 4
	}

	headerSize := ptrSize * 2
	for i := range se.sections {
		sec := &se.sections[i]
		buf := sec.data
		limit := len(buf) - headerSize
		for off := 0; off <= limit; off += ptrSize {
			var strPtr, strLen uint64
			if ptrSize == 8 {
				strPtr = se.lb.NormalizePointer(order.Uint64(buf[off : off+8]))
				strLen = order.Uint64(buf[off+8 : off+16])
			} else {
				strPtr = uint64(order.Uint32(buf[off : off+4]))
				strLen = uint64(order.Uint32(buf[off+4 : off+8]))
			}
			if strLen < uint64(minHdrLen) || strLen > maxGoHeaderStrLen {
				continue
			}
			// Avoid treating self-referential ASCII text as a pointer pair.
			raw, targetSec, ok := se.sliceAtVA(strPtr, int(strLen))
			if !ok || len(raw) < int(strLen) || !targetSec.readOnly {
				continue
			}
			if !isPrintableUTF8Strict(raw[:int(strLen)]) {
				continue
			}
			se.recordExactSlice(strPtr, int(strLen))
		}
	}
}

// trySliceInstructionString validates a candidate (targetVA, immLen) discovered during disassembly.
// When pairedABI is true, the immediate was loaded into the exact ABI-paired length register/slot.
func (se *stringExtractor) trySliceInstructionString(targetVA uint64, immLen int, pairedABI bool) bool {
	if immLen < 4 || immLen > maxInsnSliceStrLen || immLen < se.minLen {
		return false
	}
	// Look ahead slightly beyond immLen so we can inspect whether a C null terminator follows.
	raw, _, ok := se.sliceAtVA(targetVA, immLen+257)
	if !ok || len(raw) < immLen {
		return false
	}
	if !isPrintableUTF8Strict(raw[:immLen]) {
		return false
	}
	if !pairedABI {
		// Guard against truncating a null-terminated C string when an unrelated integer constant is nearby:
		// if there is a '\x00' terminator shortly after immLen (at nullIdx > immLen), only slice if Go-like
		// and there is no null terminator right after a short printable C string.
		nullIdx := bytes.IndexByte(raw, 0)
		if nullIdx > immLen && nullIdx <= 256 && isPrintableUTF8Strict(raw[:nullIdx]) && !se.isGoLike {
			return false
		}
	}
	se.recordExactSlice(targetVA, immLen)
	return true
}

func (se *stringExtractor) recordExactSlice(va uint64, n int) {
	if existing, ok := se.exactSlices[va]; ok {
		// Prefer tighter valid slice when splitting concatenated blobs.
		if n < existing {
			se.exactSlices[va] = n
		}
		return
	}
	se.exactSlices[va] = n
}

// extractedEntry holds an ExtractedString along with metadata for XREF range indexing.
type extractedEntry struct {
	str           model.ExtractedString
	rawByteSpan   uint64
	allowInterior bool
}

// finalize extracts all exact slices, remaining printable UTF-8/ASCII runs, and UTF-16LE wide strings,
// classifies them, applies MaxStrings (preserving referenced & high-signal strings), and builds stringIndex.
func (se *stringExtractor) finalize(maxStrings int, referencedAddrs map[uint64]struct{}) ([]model.ExtractedString, *stringIndex) {
	if maxStrings <= 0 {
		maxStrings = defaultMaxStrings
	}

	var entries []extractedEntry
	seenAddr := make(map[uint64]int, len(se.exactSlices)+1024)

	// Per-section split boundaries and covered intervals from exact (ptr, len) slices.
	for secIdx := range se.sections {
		sec := &se.sections[secIdx]
		data := sec.data
		n := len(data)
		if n == 0 {
			continue
		}

		type span struct {
			start int
			end   int
		}
		var exactSpans []span
		for va, byteLen := range se.exactSlices {
			if va >= sec.vaStart && va+uint64(byteLen) <= sec.vaEnd {
				st := int(va - sec.vaStart)
				exactSpans = append(exactSpans, span{start: st, end: st + byteLen})
			}
		}
		sort.Slice(exactSpans, func(i, j int) bool {
			if exactSpans[i].start != exactSpans[j].start {
				return exactSpans[i].start < exactSpans[j].start
			}
			return exactSpans[i].end < exactSpans[j].end
		})

		// Emit exact Go/Rust strings first and mark covered bytes + boundary points.
		covered := make([]bool, n)
		boundary := make([]bool, n+1)
		for _, sp := range exactSpans {
			va := sec.vaStart + uint64(sp.start)
			if _, dup := seenAddr[va]; dup {
				continue
			}
			val := string(data[sp.start:sp.end])
			seenAddr[va] = len(entries)
			entries = append(entries, extractedEntry{
				str: model.ExtractedString{
					Value:    val,
					Addr:     va,
					Length:   len(val),
					Encoding: "utf-8",
					Kind:     ClassifyString(val),
				},
				rawByteSpan:   uint64(sp.end - sp.start),
				allowInterior: sp.end < n && data[sp.end] == 0,
			})
			boundary[sp.start] = true
			boundary[sp.end] = true
			for k := sp.start; k < sp.end; k++ {
				covered[k] = true
			}
		}

		// Scan uncovered bytes for UTF-8 / ASCII printable strings, stopping at '\x00',
		// non-printable bytes, or exact string split boundaries.
		i := 0
		for i < n {
			if covered[i] || data[i] == 0 {
				i++
				continue
			}
			// Check for UTF-16LE sequence starting at i (printable ASCII + 0x00 pairs) before 1-byte scan.
			if u16Val, u16Bytes, ok := tryScanUTF16LE(data[i:], se.minLen); ok {
				// Ensure none of the UTF-16LE bytes were already covered.
				overlap := false
				for k := 0; k < u16Bytes; k++ {
					if covered[i+k] {
						overlap = true
						break
					}
				}
				if !overlap {
					va := sec.vaStart + uint64(i)
					if _, dup := seenAddr[va]; !dup {
						seenAddr[va] = len(entries)
						entries = append(entries, extractedEntry{
							str: model.ExtractedString{
								Value:    u16Val,
								Addr:     va,
								Length:   len(u16Val),
								Encoding: "utf-16le",
								Kind:     ClassifyString(u16Val),
							},
							rawByteSpan:   uint64(u16Bytes),
							allowInterior: true,
						})
					}
					for k := 0; k < u16Bytes; k++ {
						covered[i+k] = true
					}
					i += u16Bytes
					continue
				}
			}

			start := i
			charCount := 0
			for i < n && !covered[i] && (i == start || !boundary[i]) {
				b := data[i]
				if b < 0x80 {
					if isPrintableASCIIByte(b) {
						i++
						charCount++
						if i-start >= maxRawUnboundedRun {
							break
						}
						continue
					}
					break
				}
				r, width := utf8.DecodeRune(data[i:])
				if r == utf8.RuneError || width <= 1 || !isPrintableUnicodeRune(r) {
					break
				}
				// Stop if multi-byte rune crosses a covered or boundary offset.
				cross := false
				for k := 1; k < width; k++ {
					if i+k >= n || covered[i+k] || boundary[i+k] {
						cross = true
						break
					}
				}
				if cross {
					break
				}
				i += width
				charCount++
				if i-start >= maxRawUnboundedRun {
					break
				}
			}

			byteLen := i - start
			if charCount >= se.minLen && byteLen >= se.minLen {
				rawSlice := data[start:i]
				if looksMeaningfulString(rawSlice) {
					va := sec.vaStart + uint64(start)
					nullTerm := i < n && data[i] == 0
					if _, dup := seenAddr[va]; !dup {
						val := string(rawSlice)
						seenAddr[va] = len(entries)
						entries = append(entries, extractedEntry{
							str: model.ExtractedString{
								Value:    val,
								Addr:     va,
								Length:   len(val),
								Encoding: "utf-8",
								Kind:     ClassifyString(val),
							},
							rawByteSpan:   uint64(byteLen),
							allowInterior: nullTerm,
						})
					}
				}
			}

			if i == start {
				i++
			}
		}
	}

	// Sort deterministically by virtual address.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].str.Addr < entries[j].str.Addr
	})

	// Cap to maxStrings while guaranteeing XREF-referenced and classified high-signal strings survive.
	if len(entries) > maxStrings {
		entries = trimExtractedEntries(entries, maxStrings, referencedAddrs)
	}

	out := make([]model.ExtractedString, len(entries))
	for i := range entries {
		out[i] = entries[i].str
	}
	idx := buildStringIndex(out, entries)
	return out, idx
}

func trimExtractedEntries(entries []extractedEntry, maxStrings int, referencedAddrs map[uint64]struct{}) []extractedEntry {
	selected := make([]extractedEntry, 0, maxStrings)
	used := make([]bool, len(entries))

	// Tier 1: Direct XREF target strings (exact or interior).
	if len(referencedAddrs) > 0 {
		for i := range entries {
			if len(selected) >= maxStrings {
				break
			}
			e := &entries[i]
			if _, ok := referencedAddrs[e.str.Addr]; ok {
				selected = append(selected, *e)
				used[i] = true
			}
		}
	}

	// Tier 2: High-signal semantic strings (URLs, secrets, API routes, SQL, commands, paths, errors).
	for i := range entries {
		if len(selected) >= maxStrings {
			break
		}
		if used[i] {
			continue
		}
		if entries[i].str.Kind != model.StringGeneral {
			selected = append(selected, entries[i])
			used[i] = true
		}
	}

	// Tier 3: Remaining general strings in address order.
	for i := range entries {
		if len(selected) >= maxStrings {
			break
		}
		if !used[i] {
			selected = append(selected, entries[i])
		}
	}

	sort.Slice(selected, func(i, j int) bool {
		return selected[i].str.Addr < selected[j].str.Addr
	})
	return selected
}

func tryScanUTF16LE(buf []byte, minChars int) (string, int, bool) {
	if len(buf) < minChars*2 {
		return "", 0, false
	}
	// Quick reject: require first two code units to be printable ASCII with 0x00 high byte.
	if !isPrintableUTF16ASCII(buf[0]) || buf[1] != 0 || !isPrintableUTF16ASCII(buf[2]) || buf[3] != 0 {
		return "", 0, false
	}

	var units []uint16
	asciiUnits := 0
	maxUnits := len(buf) / 2
	if maxUnits > 512 {
		maxUnits = 512
	}

	units = make([]uint16, 0, 32)
	for u := 0; u < maxUnits; u++ {
		lo := buf[u*2]
		hi := buf[u*2+1]
		code := uint16(lo) | (uint16(hi) << 8)
		if code == 0 {
			break
		}
		if hi == 0 {
			if !isPrintableUTF16ASCII(lo) {
				break
			}
			asciiUnits++
		} else if code >= 0xd800 && code <= 0xdfff {
			// Skip lone surrogates for clean high-confidence wide strings.
			break
		} else if !isPrintableUnicodeRune(rune(code)) {
			break
		}
		units = append(units, code)
	}

	if len(units) < minChars {
		return "", 0, false
	}
	// Require majority ASCII wide units to suppress false positives on random 16-bit integer tables.
	if asciiUnits*5 < len(units)*4 {
		return "", 0, false
	}
	decoded := string(utf16.Decode(units))
	if !looksMeaningfulString([]byte(decoded)) {
		return "", 0, false
	}
	return decoded, len(units) * 2, true
}

func isPrintableASCIIByte(b byte) bool {
	return (b >= 0x20 && b <= 0x7e) || b == '\t' || b == '\n' || b == '\r'
}

func isPrintableUTF16ASCII(b byte) bool {
	return (b >= 0x20 && b <= 0x7e) || b == '\t' || b == '\n' || b == '\r'
}

func isPrintableUnicodeRune(r rune) bool {
	if r < 0x20 {
		return r == '\t' || r == '\n' || r == '\r'
	}
	if r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0xfffd {
		return false
	}
	return true
}

// isPrintableUTF8Strict checks that raw is valid UTF-8 with zero NUL or control bytes
// (other than \t, \n, \r) and contains predominantly human-readable characters.
func isPrintableUTF8Strict(raw []byte) bool {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return false
	}
	alphaNumOrSpace := 0
	runeCount := 0
	for i := 0; i < len(raw); {
		b := raw[i]
		if b < 0x80 {
			if !isPrintableASCIIByte(b) {
				return false
			}
			if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == ' ' || b == '/' || b == '_' || b == '-' || b == '.' || b == ':' {
				alphaNumOrSpace++
			}
			i++
			runeCount++
			continue
		}
		r, w := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError || w <= 1 || !isPrintableUnicodeRune(r) {
			return false
		}
		alphaNumOrSpace++
		i += w
		runeCount++
	}
	if runeCount == 0 {
		return false
	}
	return alphaNumOrSpace*2 >= runeCount
}

func looksMeaningfulString(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	useful := 0
	for _, b := range raw {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			useful++
		}
	}
	return useful >= 2
}

// ClassifyString assigns a forensic StringKind category to an extracted string.
// Secret candidate checks are strictly defensive for build secret-leak auditing.
func ClassifyString(s string) model.StringKind {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 4 {
		return model.StringGeneral
	}

	// 1. Defensive secret-leak auditing candidates (highest priority).
	if isSecretCandidate(trimmed) {
		return model.StringSecretCandidate
	}

	low := strings.ToLower(trimmed)

	// 2. URLs (http, https, ws, wss, grpc, postgres, redis, mongodb).
	if hasURLScheme(low) {
		return model.StringURL
	}

	// 3. API Routes (/api/v, /v1/, /v2/, /graphql, /oauth/, /webhook).
	if isAPIRoute(low) {
		return model.StringAPIRoute
	}

	// 4. SQL statements (SELECT ... FROM, INSERT INTO, CREATE TABLE, UPDATE ... SET).
	if isSQLQuery(low) {
		return model.StringSQL
	}

	// 5. Shell / OS Commands (cmd.exe, /bin/sh, powershell, systemctl, ipconfig).
	if isCommandString(low) {
		return model.StringCommand
	}

	// 6. File paths vs error messages:
	// Multi-word prose containing explicit error phrases is an error message even if it mentions a filename.
	hasSpace := strings.ContainsAny(trimmed, " \t\r\n")
	if hasSpace && isErrorMessage(low) {
		return model.StringErrorMsg
	}
	if isFilePath(trimmed, low) {
		return model.StringFilePath
	}
	if isErrorMessage(low) {
		return model.StringErrorMsg
	}

	return model.StringGeneral
}

func isSecretCandidate(s string) bool {
	// AWS Access Key ID: AKIA[0-9A-Z]{16}
	if idx := strings.Index(s, "AKIA"); idx >= 0 && len(s)-idx >= 20 {
		sub := s[idx+4 : idx+20]
		allOK := true
		for i := 0; i < 16; i++ {
			c := sub[i]
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')) {
				allOK = false
				break
			}
		}
		if allOK && (len(s) == idx+20 || !isAlphaNumASCII(s[idx+20])) {
			return true
		}
	}

	// Google API Key: AIza[0-9A-Za-z_-]{35}
	if idx := strings.Index(s, "AIza"); idx >= 0 && len(s)-idx >= 39 {
		sub := s[idx+4 : idx+39]
		allOK := true
		for i := 0; i < 35; i++ {
			if !isTokenChar(sub[i]) {
				allOK = false
				break
			}
		}
		if allOK {
			return true
		}
	}

	// GitHub Classic PAT: ghp_[0-9A-Za-z]{36}
	if idx := strings.Index(s, "ghp_"); idx >= 0 && len(s)-idx >= 40 {
		sub := s[idx+4 : idx+40]
		allOK := true
		for i := 0; i < 36; i++ {
			if !isAlphaNumASCII(sub[i]) {
				allOK = false
				break
			}
		}
		if allOK {
			return true
		}
	}

	// GitHub Fine-Grained PAT: github_pat_
	if idx := strings.Index(s, "github_pat_"); idx >= 0 && hasTokenRun(s[idx+11:], 8) {
		return true
	}

	// Anthropic / OpenAI project keys: sk-ant-, sk-proj-
	if idx := strings.Index(s, "sk-ant-"); idx >= 0 && hasTokenRun(s[idx+7:], 8) {
		return true
	}
	if idx := strings.Index(s, "sk-proj-"); idx >= 0 && hasTokenRun(s[idx+8:], 8) {
		return true
	}

	// Slack tokens: xox[baprs]-
	if idx := strings.Index(s, "xox"); idx >= 0 && len(s)-idx >= 12 {
		kind := s[idx+3]
		if (kind == 'b' || kind == 'a' || kind == 'p' || kind == 'r' || kind == 's') && s[idx+4] == '-' {
			if hasTokenRun(s[idx+5:], 6) {
				return true
			}
		}
	}

	// PEM blocks & JWT Bearer tokens.
	if strings.Contains(s, "-----BEGIN ") {
		return true
	}
	if strings.Contains(s, "Bearer eyJ") {
		return true
	}

	return false
}

func isAlphaNumASCII(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isTokenChar(c byte) bool {
	return isAlphaNumASCII(c) || c == '_' || c == '-'
}

func hasTokenRun(s string, minRun int) bool {
	if len(s) < minRun {
		return false
	}
	for i := 0; i < minRun; i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

var urlSchemes = []string{
	"https://",
	"http://",
	"wss://",
	"ws://",
	"grpc://",
	"postgres://",
	"postgresql://",
	"redis://",
	"mongodb://",
	"mongodb+srv://",
}

func hasURLScheme(low string) bool {
	for _, sch := range urlSchemes {
		if idx := strings.Index(low, sch); idx >= 0 {
			rest := low[idx+len(sch):]
			if len(rest) >= 1 && (isAlphaNumASCII(rest[0]) || rest[0] == '[' || rest[0] == '%') {
				return true
			}
		}
	}
	return false
}

var apiRouteMarkers = []string{
	"/api/v",
	"/v1/",
	"/v2/",
	"/graphql",
	"/oauth/",
	"/webhook",
}

func isAPIRoute(low string) bool {
	for _, m := range apiRouteMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

func isSQLQuery(low string) bool {
	if idx := strings.Index(low, "select "); idx >= 0 {
		if strings.Contains(low[idx+7:], " from ") {
			return true
		}
	}
	if strings.Contains(low, "insert into ") || strings.Contains(low, "create table ") {
		return true
	}
	if idx := strings.Index(low, "update "); idx >= 0 {
		if strings.Contains(low[idx+7:], " set ") {
			return true
		}
	}
	return false
}

var commandMarkers = []string{
	"cmd.exe",
	"/bin/sh",
	"/bin/bash",
	"powershell",
	"systemctl",
	"ipconfig",
}

func isCommandString(low string) bool {
	for _, m := range commandMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

func isFilePath(orig, low string) bool {
	if strings.Contains(low, "/etc/") || strings.Contains(low, "/proc/") || strings.Contains(low, "/usr/") {
		return true
	}
	if strings.Contains(orig, `C:\`) || strings.Contains(orig, `c:\`) {
		return true
	}
	// Source or config file paths without spaces (e.g. "pkg/xref/xref.go", "main.rs", "cert.pem").
	if !strings.ContainsAny(orig, " \t\r\n") {
		check := low
		// Strip optional ":line" suffix common in Go/Rust panic locations.
		if colon := strings.LastIndexByte(check, ':'); colon > 0 {
			allDigits := true
			for i := colon + 1; i < len(check); i++ {
				if check[i] < '0' || check[i] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits && colon+1 < len(check) {
				check = check[:colon]
			}
		}
		exts := []string{".go", ".rs", ".pem", ".json", ".yaml", ".yml"}
		for _, ext := range exts {
			if strings.HasSuffix(check, ext) && len(check) > len(ext) {
				return true
			}
		}
	}
	return false
}

var errorMarkers = []string{
	"error:",
	"failed to ",
	"panic:",
	"invalid ",
	"unauthorized",
}

func isErrorMessage(low string) bool {
	for _, m := range errorMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}
