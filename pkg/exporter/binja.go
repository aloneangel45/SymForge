package exporter

import (
	"bytes"
	"fmt"

	"github.com/aloneangel45/symforge/pkg/model"
)

// ExportBinja produces a Binary Ninja Python script (`bv` console or headless plugin)
// that restores stripped functions, user symbols, comments, and data tags.
func ExportBinja(res *model.AnalysisResult, opts Options) []byte {
	var buf bytes.Buffer
	funcs := selectFunctions(res.Functions, opts.UserOnly)

	fmt.Fprintf(&buf, "# SymForge Binary Ninja Symbol, Type & XREF Recovery Script\n")
	fmt.Fprintf(&buf, "# Target SHA-256: %s\n", res.Binary.SHA256)
	fmt.Fprintf(&buf, "# Format: %s | Arch: %s | Language: %s\n\n", res.Binary.Format, res.Binary.Arch, res.Binary.Language)

	buf.WriteString(`from binaryninja import Symbol, SymbolType

ORIG_IMAGE_BASE = `)
	fmt.Fprintf(&buf, "0x%x\n\n", res.Binary.ImageBase)

	buf.WriteString("FUNCTIONS = [\n")
	for _, fn := range funcs {
		display := preferredDisplayName(fn)
		raw := sanitizeRESymbol(display)
		comment := buildFunctionComment(fn)
		fmt.Fprintf(&buf, "    (0x%x, %s, %s, %s),\n", fn.Entry, pyQuote(raw), pyQuote(display), pyQuote(comment))
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

	buf.WriteString(`def apply_symforge(view):
    delta = 0
    if ORIG_IMAGE_BASE == 0 and view.start != 0:
        delta = view.start
    elif ORIG_IMAGE_BASE != 0 and view.start != ORIG_IMAGE_BASE:
        delta = view.start - ORIG_IMAGE_BASE

    state = view.begin_undo_actions()
    restored = 0
    try:
        for va, raw_name, full_name, comment in FUNCTIONS:
            ea = va + delta
            view.add_function(ea)
            fn = view.get_function_at(ea)
            view.define_user_symbol(Symbol(SymbolType.FunctionSymbol, ea, raw_name, full_name))
            if fn is not None and comment:
                fn.comment = comment
            restored += 1

        for va, note in ANNOTATIONS:
            view.set_comment_at(va + delta, note)
    finally:
        view.commit_undo_actions(state)
        view.update_analysis()

    print(f"[SymForge] Restored {restored} functions and {len(ANNOTATIONS)} annotations (delta=0x{delta:x})")

if "bv" in globals():
    apply_symforge(bv)
`)
	return buf.Bytes()
}
