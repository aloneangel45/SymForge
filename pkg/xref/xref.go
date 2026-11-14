// Package xref implements SymForge's pure-Go multi-architecture disassembly,
// call-graph builder, Go/Rust non-null-terminated string blob slicer, semantic
// string classifier, and cryptographic constant detector across x86/x86_64 and ARM64.
package xref

import (
	"fmt"

	"github.com/aloneangel45/symforge/pkg/loader"
	"github.com/aloneangel45/symforge/pkg/model"
)

// Options configures string extraction and XREF bounds.
type Options struct {
	MinStringLen int // default 4
	MaxStrings   int // default 10000
}

// Result contains the cross-referenced functions, classified strings, and detected crypto constants.
type Result struct {
	Functions []model.Function
	Strings   []model.ExtractedString
	Crypto    []model.CryptoDetection
}

// Analyze extracts and classifies read-only strings (including Go non-null-terminated string blobs),
// detects canonical cryptographic constants, disassembles functions on x86/x86_64/ARM64, and populates
// bidirectional call graphs, StringRefs, and CryptoRefs.
func Analyze(lb *loader.LoadedBinary, funcs []model.Function, opts Options) (*Result, error) {
	if lb == nil {
		return nil, fmt.Errorf("xref: nil LoadedBinary")
	}
	if opts.MinStringLen <= 0 {
		opts.MinStringLen = defaultMinStringLen
	}
	if opts.MaxStrings <= 0 {
		opts.MaxStrings = defaultMaxStrings
	}

	a := newAnalyzer(lb, funcs, opts)
	return a.run(opts), nil
}

// DisassembleFunction decodes up to maxInsns instructions of fn on x86, x86_64, or ARM64
// and annotates resolved branch/XREF targets using symMap and strMap.
func DisassembleFunction(
	lb *loader.LoadedBinary,
	fn model.Function,
	symMap map[uint64]string,
	strMap map[uint64]string,
	maxInsns int,
) ([]model.DisasmInstruction, error) {
	if lb == nil {
		return nil, fmt.Errorf("xref: nil LoadedBinary")
	}
	if fn.Entry == 0 {
		return nil, fmt.Errorf("xref: function %q has zero entry address", fn.Name)
	}
	if maxInsns <= 0 {
		if fn.Size > 0 || fn.End > fn.Entry {
			maxInsns = 4096
		} else {
			maxInsns = 256
		}
	}

	span := fn.Size
	if span == 0 && fn.End > fn.Entry {
		span = fn.End - fn.Entry
	}
	if span > maxFuncScanBytes {
		span = maxFuncScanBytes
	}
	if span == 0 {
		// Bound unknown-size disassembly by maxInsns * maxInsnBytes and containing section end.
		bytesPerInsn := uint64(15)
		if lb.Info.Arch == model.ArchARM64 {
			bytesPerInsn = 4
		}
		span = uint64(maxInsns) * bytesPerInsn
		if span > 64*1024 {
			span = 64 * 1024
		}
	}

	sec := lb.SectionContainingVA(fn.Entry)
	if sec != nil && sec.FileSize > 0 && fn.Entry >= sec.VirtualAddr {
		secEnd := sec.VirtualAddr + sec.FileSize
		if fn.Entry >= secEnd {
			return nil, fmt.Errorf("xref: function %q entry 0x%x outside backed section %s", fn.Name, fn.Entry, sec.Name)
		}
		if avail := secEnd - fn.Entry; span > avail {
			span = avail
		}
	}

	code, ok := lb.ReadAtVA(fn.Entry, int(span))
	if !ok {
		return nil, fmt.Errorf("xref: unable to read machine code at 0x%x (%d bytes)", fn.Entry, span)
	}

	switch lb.Info.Arch {
	case model.ArchX86_64:
		return disassembleX86(lb, fn, code, 64, symMap, strMap, maxInsns), nil
	case model.ArchX86:
		return disassembleX86(lb, fn, code, 32, symMap, strMap, maxInsns), nil
	case model.ArchARM64:
		return disassembleARM64(lb, fn, code, symMap, strMap, maxInsns), nil
	default:
		return nil, fmt.Errorf("xref: unsupported architecture %q for disassembly", lb.Info.Arch)
	}
}

func minIntVal(a, b int) int {
	if a < b {
		return a
	}
	return b
}
