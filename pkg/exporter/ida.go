package exporter

import (
	"bytes"
	"fmt"

	"github.com/aloneangel45/symforge/pkg/model"
)

// ExportIDA produces an IDAPython 7.x/8.x/9.x script that rebases virtual addresses,
// defines missing functions, restores symbol names, and attaches repeatable comments.
func ExportIDA(res *model.AnalysisResult, opts Options) []byte {
	var buf bytes.Buffer
	funcs := selectFunctions(res.Functions, opts.UserOnly)

	fmt.Fprintf(&buf, "# SymForge IDAPython Symbol, Type & XREF Recovery Script\n")
	fmt.Fprintf(&buf, "# Target SHA-256: %s\n", res.Binary.SHA256)
	fmt.Fprintf(&buf, "# Format: %s | Arch: %s | Language: %s\n\n", res.Binary.Format, res.Binary.Arch, res.Binary.Language)

	buf.WriteString(`import idc
import ida_funcs
import ida_nalt

ORIG_IMAGE_BASE = `)
	fmt.Fprintf(&buf, "0x%x\n\n", res.Binary.ImageBase)

	buf.WriteString("FUNCTIONS = [\n")
	for _, fn := range funcs {
		cleanName := sanitizeRESymbol(preferredDisplayName(fn))
		comment := buildFunctionComment(fn)
		fmt.Fprintf(&buf, "    (0x%x, %s, %s),\n", fn.Entry, pyQuote(cleanName), pyQuote(comment))
	}
	buf.WriteString("]\n\n")

	buf.WriteString("ANNOTATIONS = [\n")
	for _, c := range res.Crypto {
		if c.Addr != 0 {
			fmt.Fprintf(&buf, "    (0x%x, %s),\n", c.Addr, pyQuote(fmt.Sprintf("[SymForge Crypto] %s (%s)", c.Name, c.Algorithm)))
		}
	}
	for _, t := range res.Types {
		if t.Addr != 0 {
			fmt.Fprintf(&buf, "    (0x%x, %s),\n", t.Addr, pyQuote(fmt.Sprintf("[SymForge Type] %s %s (size=%d)", t.Kind, t.Name, t.Size)))
		}
	}
	buf.WriteString("]\n\n")

	buf.WriteString(`def apply_symforge():
    base = ida_nalt.get_imagebase()
    delta = 0
    if ORIG_IMAGE_BASE == 0 and base != 0:
        delta = base
    elif ORIG_IMAGE_BASE != 0 and base != ORIG_IMAGE_BASE:
        delta = base - ORIG_IMAGE_BASE

    renamed = 0
    for va, name, comment in FUNCTIONS:
        ea = va + delta
        ida_funcs.add_func(ea)
        if idc.set_name(ea, name, idc.SN_NOWARN | idc.SN_FORCE):
            renamed += 1
        if comment:
            idc.set_func_cmt(ea, comment, 1)

    for va, note in ANNOTATIONS:
        idc.set_cmt(va + delta, note, 1)

    print(f"[SymForge] Restored {renamed}/{len(FUNCTIONS)} functions and {len(ANNOTATIONS)} data annotations (delta=0x{delta:x})")

if __name__ == "__main__":
    apply_symforge()
`)
	return buf.Bytes()
}
