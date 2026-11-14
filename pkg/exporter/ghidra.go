package exporter

import (
	"bytes"
	"fmt"

	"github.com/aloneangel45/symforge/pkg/model"
)

// ExportGhidra produces a self-contained Jython / PyGhidra script compatible with
// Ghidra 10.x and 11.x Script Manager and analyzeHeadless.
func ExportGhidra(res *model.AnalysisResult, opts Options) []byte {
	var buf bytes.Buffer
	funcs := selectFunctions(res.Functions, opts.UserOnly)

	fmt.Fprintf(&buf, "# SymForge Ghidra Symbol, Type & XREF Recovery Script\n")
	fmt.Fprintf(&buf, "# Target SHA-256: %s\n", res.Binary.SHA256)
	fmt.Fprintf(&buf, "# Format: %s | Arch: %s | Language: %s\n", res.Binary.Format, res.Binary.Arch, res.Binary.Language)
	fmt.Fprintf(&buf, "# @category SymForge\n\n")

	buf.WriteString(`from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

try:
    println
except NameError:
    println = print

ORIG_IMAGE_BASE = `)
	fmt.Fprintf(&buf, "0x%x\n", res.Binary.ImageBase)
	buf.WriteString(`
FUNCTIONS = [
`)
	for _, fn := range funcs {
		cleanName := sanitizeRESymbol(preferredDisplayName(fn))
		comment := buildFunctionComment(fn)
		fmt.Fprintf(&buf, "    (0x%x, %s, %s),\n", fn.Entry, pyQuote(cleanName), pyQuote(comment))
	}
	buf.WriteString("]\n\n")

	buf.WriteString("BOOKMARKS = [\n")
	for _, c := range res.Crypto {
		if c.Addr != 0 {
			fmt.Fprintf(&buf, "    (0x%x, \"SymForge-Crypto\", %s),\n", c.Addr, pyQuote(fmt.Sprintf("%s (%s)", c.Name, c.Algorithm)))
		}
	}
	for _, t := range res.Types {
		if t.Addr != 0 {
			fmt.Fprintf(&buf, "    (0x%x, \"SymForge-Type\", %s),\n", t.Addr, pyQuote(fmt.Sprintf("%s %s (size=%d)", t.Kind, t.Name, t.Size)))
		}
	}
	buf.WriteString("]\n\n")

	buf.WriteString(`def apply_symforge():
    listing = currentProgram.getListing()
    symtab = currentProgram.getSymbolTable()
    bm = currentProgram.getBookmarkManager()
    base = currentProgram.getImageBase().getOffset()
    delta = 0
    if ORIG_IMAGE_BASE == 0 and base != 0:
        delta = base
    elif ORIG_IMAGE_BASE != 0 and base != ORIG_IMAGE_BASE:
        delta = base - ORIG_IMAGE_BASE

    tx = currentProgram.startTransaction("SymForge Symbol & Type Recovery")
    renamed = 0
    created = 0
    try:
        for va, name, comment in FUNCTIONS:
            addr = toAddr(va + delta)
            fn = getFunctionAt(addr)
            if fn is None:
                try:
                    fn = createFunction(addr, name)
                    if fn is not None:
                        created += 1
                except Exception:
                    pass
            if fn is not None:
                try:
                    fn.setName(name, SourceType.USER_DEFINED)
                    renamed += 1
                except Exception:
                    symtab.createLabel(addr, name, SourceType.USER_DEFINED)
            else:
                symtab.createLabel(addr, name, SourceType.USER_DEFINED)
            cu = listing.getCodeUnitAt(addr)
            if cu is not None and comment:
                cu.setComment(CodeUnit.PLATE_COMMENT, comment)

        for va, cat, note in BOOKMARKS:
            addr = toAddr(va + delta)
            bm.setBookmark(addr, "Analysis", cat, note)
    finally:
        currentProgram.endTransaction(tx, True)

    println("[SymForge] Restored %d functions (%d newly created), %d bookmarks (rebase delta=0x%x)" % (
        renamed, created, len(BOOKMARKS), delta
    ))

if __name__ == "__main__":
    apply_symforge()
`)
	return buf.Bytes()
}
