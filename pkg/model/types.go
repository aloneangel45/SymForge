// Package model defines the canonical, JSON-serializable data structures
// produced by SymForge's binary loader, Go/Rust recovery engines, XREF analyzer,
// script exporters, and MCP server.
package model

import "encoding/binary"

// BinaryFormat identifies the executable container format.
type BinaryFormat string

const (
	FormatELF      BinaryFormat = "elf"
	FormatPE       BinaryFormat = "pe"
	FormatMachO    BinaryFormat = "macho"
	FormatMachOFat BinaryFormat = "macho-fat"
	FormatUnknown  BinaryFormat = "unknown"
)

// Architecture identifies the target CPU instruction set.
type Architecture string

const (
	ArchX86_64  Architecture = "x86_64"
	ArchARM64   Architecture = "arm64"
	ArchX86     Architecture = "x86"
	ArchARM     Architecture = "arm"
	ArchUnknown Architecture = "unknown"
)

// Language identifies the primary source toolchain inferred from binary artifacts.
type Language string

const (
	LangGo     Language = "go"
	LangRust   Language = "rust"
	LangGoRust Language = "go+rust"
	LangNative Language = "native"
)

// PackageCategory classifies recovered packages/crates to separate user logic from runtime noise.
type PackageCategory string

const (
	CategoryUser       PackageCategory = "user"
	CategoryDependency PackageCategory = "dependency"
	CategoryStdlib     PackageCategory = "stdlib"
	CategoryRuntime    PackageCategory = "runtime"
	CategoryNative     PackageCategory = "native"
)

// StringKind classifies extracted strings for high-signal forensic triage.
type StringKind string

const (
	StringURL             StringKind = "url"
	StringAPIRoute        StringKind = "api_route"
	StringSecretCandidate StringKind = "secret_candidate"
	StringFilePath        StringKind = "filepath"
	StringSQL             StringKind = "sql"
	StringCommand         StringKind = "command"
	StringErrorMsg        StringKind = "error_msg"
	StringGeneral         StringKind = "general"
)

// BinaryInfo holds container-level metadata and structural heuristics.
type BinaryInfo struct {
	Path         string       `json:"path"`
	SHA256       string       `json:"sha256"`
	SizeBytes    int64        `json:"size_bytes"`
	Format       BinaryFormat `json:"format"`
	Arch         Architecture `json:"arch"`
	Endianness   string       `json:"endianness"`
	PointerSize  int          `json:"pointer_size"`
	EntryPoint   uint64       `json:"entry_point"`
	ImageBase    uint64       `json:"image_base"`
	PIE          bool         `json:"pie"`
	Stripped     bool         `json:"stripped"`
	PackedLikely bool         `json:"packed_likely"`
	MaxEntropy   float64      `json:"max_entropy"`
	Language     Language     `json:"language"`
}

// SectionInfo describes a mapped executable or data section with Shannon entropy.
type SectionInfo struct {
	Name        string  `json:"name"`
	VirtualAddr uint64  `json:"virtual_addr"`
	VirtualSize uint64  `json:"virtual_size"`
	FileOffset  uint64  `json:"file_offset"`
	FileSize    uint64  `json:"file_size"`
	Entropy     float64 `json:"entropy"`
	Executable  bool    `json:"executable"`
	Readable    bool    `json:"readable"`
	Writable    bool    `json:"writable"`
}

// SymbolEntry represents an unstripped or dynamic symbol present in container tables.
type SymbolEntry struct {
	Name      string `json:"name"`
	Demangled string `json:"demangled,omitempty"`
	Addr      uint64 `json:"addr"`
	Size      uint64 `json:"size,omitempty"`
	Section   string `json:"section,omitempty"`
	Dynamic   bool   `json:"dynamic,omitempty"`
}

// RuntimeBounds represents an exception/unwind function range (e.g. PE .pdata).
type RuntimeBounds struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// StringRef links a function instruction to a referenced read-only string.
type StringRef struct {
	Addr     uint64     `json:"addr"`
	InsnAddr uint64     `json:"insn_addr"`
	Value    string     `json:"value"`
	Kind     StringKind `json:"kind"`
}

// Function represents a recovered or symbolicated binary function and its cross-references.
type Function struct {
	Name          string          `json:"name"`
	Demangled     string          `json:"demangled,omitempty"`
	Package       string          `json:"package,omitempty"`
	Receiver      string          `json:"receiver,omitempty"`
	SourceFile    string          `json:"source_file,omitempty"`
	Line          int             `json:"line,omitempty"`
	Entry         uint64          `json:"entry"`
	End           uint64          `json:"end,omitempty"`
	Size          uint64          `json:"size,omitempty"`
	Category      PackageCategory `json:"category"`
	RecoveredFrom string          `json:"recovered_from"`
	Calls         []uint64        `json:"calls,omitempty"`
	CalledBy      []uint64        `json:"called_by,omitempty"`
	StringRefs    []StringRef     `json:"string_refs,omitempty"`
	CryptoRefs    []string        `json:"crypto_refs,omitempty"`
}

// PackageSummary aggregates recovered functions by Go package or Rust crate/module.
type PackageSummary struct {
	Name          string          `json:"name"`
	Category      PackageCategory `json:"category"`
	FunctionCount int             `json:"function_count"`
	TotalBytes    uint64          `json:"total_bytes"`
	SourceFiles   []string        `json:"source_files,omitempty"`
}

// GoMetadata captures Go runtime, pclntab, buildinfo, and moduledata artifacts.
type GoMetadata struct {
	Detected       bool              `json:"detected"`
	Version        string            `json:"version,omitempty"`
	PCLnTabVersion string            `json:"pclntab_version,omitempty"`
	PCLnTabMagic   uint32            `json:"pclntab_magic,omitempty"`
	PCLnTabAddr    uint64            `json:"pclntab_addr,omitempty"`
	PointerSize    uint8             `json:"pointer_size,omitempty"`
	Quantum        uint8             `json:"quantum,omitempty"`
	TextStart      uint64            `json:"text_start,omitempty"`
	MainModule     string            `json:"main_module,omitempty"`
	ModuleVersion  string            `json:"module_version,omitempty"`
	BuildSettings  map[string]string `json:"build_settings,omitempty"`
	ModuleDataAddr uint64            `json:"moduledata_addr,omitempty"`
	TypesAddr      uint64            `json:"types_addr,omitempty"`
	ETypesAddr     uint64            `json:"etypes_addr,omitempty"`
}

// RustMetadata captures Rust toolchain, mangling, cargo-auditable, and panic artifacts.
type RustMetadata struct {
	Detected        bool   `json:"detected"`
	CompilerVersion string `json:"compiler_version,omitempty"`
	CompilerCommit  string `json:"compiler_commit,omitempty"`
	ManglingScheme  string `json:"mangling_scheme,omitempty"`
	AuditableSBOM   bool   `json:"auditable_sbom"`
	PanicCount      int    `json:"panic_count"`
	VTableCount     int    `json:"vtable_count"`
}

// StructField describes a single field recovered from a Go struct type descriptor.
type StructField struct {
	Name     string `json:"name"`
	TypeName string `json:"type_name,omitempty"`
	Offset   uint64 `json:"offset"`
	Embedded bool   `json:"embedded,omitempty"`
	Tag      string `json:"tag,omitempty"`
}

// RecoveredType represents a Go struct/interface or Rust trait vtable recovered from read-only metadata.
type RecoveredType struct {
	Name    string        `json:"name"`
	Package string        `json:"package,omitempty"`
	Kind    string        `json:"kind"`
	Size    uint64        `json:"size,omitempty"`
	Align   uint8         `json:"align,omitempty"`
	Addr    uint64        `json:"addr"`
	Fields  []StructField `json:"fields,omitempty"`
	Methods []string      `json:"methods,omitempty"`
}

// Dependency represents a Go module or Rust crate dependency recovered from binary metadata.
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Sum       string `json:"sum,omitempty"`
	Ecosystem string `json:"ecosystem"`
	Source    string `json:"source"`
}

// PanicLocation represents a carved Rust core::panic::Location record or source location string.
type PanicLocation struct {
	File        string `json:"file"`
	Crate       string `json:"crate,omitempty"`
	Line        uint32 `json:"line,omitempty"`
	Column      uint32 `json:"column,omitempty"`
	StructAddr  uint64 `json:"struct_addr,omitempty"`
	FileStrAddr uint64 `json:"file_str_addr,omitempty"`
}

// ExtractedString represents a string recovered via null-terminated, UTF-16LE, or Go (ptr,len) slicing.
type ExtractedString struct {
	Value        string     `json:"value"`
	Addr         uint64     `json:"addr"`
	Length       int        `json:"length"`
	Encoding     string     `json:"encoding"`
	Kind         StringKind `json:"kind"`
	ReferencedBy []uint64   `json:"referenced_by,omitempty"`
}

// CryptoDetection records a recognized cryptographic table or initialization vector in read-only data.
type CryptoDetection struct {
	Name         string   `json:"name"`
	Algorithm    string   `json:"algorithm"`
	Addr         uint64   `json:"addr"`
	Section      string   `json:"section,omitempty"`
	Confidence   string   `json:"confidence"`
	ReferencedBy []uint64 `json:"referenced_by,omitempty"`
}

// DisasmInstruction represents a single decoded machine instruction with resolved branch/XREF annotations.
type DisasmInstruction struct {
	Addr         uint64 `json:"addr"`
	BytesHex     string `json:"bytes_hex"`
	Text         string `json:"text"`
	TargetAddr   uint64 `json:"target_addr,omitempty"`
	TargetSymbol string `json:"target_symbol,omitempty"`
	StringRef    string `json:"string_ref,omitempty"`
}

// AnalysisResult is the complete forensic and symbol-recovery output for a target binary.
type AnalysisResult struct {
	Binary             BinaryInfo        `json:"binary"`
	Sections           []SectionInfo     `json:"sections"`
	Go                 *GoMetadata       `json:"go,omitempty"`
	Rust               *RustMetadata     `json:"rust,omitempty"`
	Packages           []PackageSummary  `json:"packages,omitempty"`
	Functions          []Function        `json:"functions,omitempty"`
	Types              []RecoveredType   `json:"types,omitempty"`
	Dependencies       []Dependency      `json:"dependencies,omitempty"`
	Panics             []PanicLocation   `json:"panics,omitempty"`
	Strings            []ExtractedString `json:"strings,omitempty"`
	Crypto             []CryptoDetection `json:"crypto,omitempty"`
	AnalysisDurationMs float64           `json:"analysis_duration_ms"`
}

// ByteOrderHelper returns binary.ByteOrder from endianness label ("little" or "big").
func ByteOrderFromName(endian string) binary.ByteOrder {
	if endian == "big" {
		return binary.BigEndian
	}
	return binary.LittleEndian
}
