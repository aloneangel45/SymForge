package exporter

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/aloneangel45/symforge/pkg/model"
)

const defaultGraphLimit = 60

// ExportDOT renders a Graphviz DOT directed call graph (digraph) suitable for dot/svg rendering.
func ExportDOT(res *model.AnalysisResult, opts Options) []byte {
	nodes, edges := buildGraphSubset(res, opts)

	var buf bytes.Buffer
	buf.WriteString("digraph SymForgeCallGraph {\n")
	buf.WriteString("  rankdir=LR;\n")
	buf.WriteString("  graph [fontname=\"Helvetica\", pad=\"0.4\", nodesep=\"0.35\", ranksep=\"0.6\"];\n")
	buf.WriteString("  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\", fontsize=10];\n")
	buf.WriteString("  edge [color=\"#64748b\", arrowsize=0.75];\n")
	fmt.Fprintf(&buf, "  // Binary: %s (%s/%s) | Nodes: %d | Edges: %d\n\n",
		dotEscape(res.Binary.Path), res.Binary.Format, res.Binary.Arch, len(nodes), len(edges))

	for _, fn := range nodes {
		fill, stroke := dotCategoryColors(fn.Category)
		label := fmt.Sprintf("%s\\n0x%x", dotEscape(shortGraphLabel(preferredDisplayName(fn))), fn.Entry)
		fmt.Fprintf(&buf, "  fn_%x [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
			fn.Entry, label, fill, stroke)
	}
	if len(edges) > 0 {
		buf.WriteByte('\n')
		for _, e := range edges {
			fmt.Fprintf(&buf, "  fn_%x -> fn_%x;\n", e.from, e.to)
		}
	}
	buf.WriteString("}\n")
	return buf.Bytes()
}

// ExportMermaid renders a Mermaid flowchart LR call graph with category styling.
func ExportMermaid(res *model.AnalysisResult, opts Options) []byte {
	nodes, edges := buildGraphSubset(res, opts)

	var buf bytes.Buffer
	buf.WriteString("flowchart LR\n")
	fmt.Fprintf(&buf, "  %%%% SymForge Call Graph: %s (%s/%s) | Nodes: %d | Edges: %d\n",
		mermaidCommentSafe(res.Binary.Path), res.Binary.Format, res.Binary.Arch, len(nodes), len(edges))
	buf.WriteString("  classDef user fill:#dbeafe,stroke:#2563eb,color:#1e3a8a\n")
	buf.WriteString("  classDef dependency fill:#fef3c7,stroke:#d97706,color:#78350f\n")
	buf.WriteString("  classDef stdlib fill:#e2e8f0,stroke:#475569,color:#0f172a\n")
	buf.WriteString("  classDef runtime fill:#f3e8ff,stroke:#7c3aed,color:#4c1d95\n")
	buf.WriteString("  classDef native fill:#dcfce7,stroke:#16a34a,color:#14532d\n\n")

	for _, fn := range nodes {
		cls := mermaidCategoryClass(fn.Category)
		label := fmt.Sprintf("%s (0x%x)", mermaidLabelEscape(shortGraphLabel(preferredDisplayName(fn))), fn.Entry)
		fmt.Fprintf(&buf, "  fn_%x[\"%s\"]:::%s\n", fn.Entry, label, cls)
	}
	if len(edges) > 0 {
		buf.WriteByte('\n')
		for _, e := range edges {
			fmt.Fprintf(&buf, "  fn_%x --> fn_%x\n", e.from, e.to)
		}
	}
	return buf.Bytes()
}

type graphEdge struct {
	from uint64
	to   uint64
}

func buildGraphSubset(res *model.AnalysisResult, opts Options) ([]model.Function, []graphEdge) {
	candidates := selectFunctions(res.Functions, opts.UserOnly)
	if len(candidates) == 0 {
		return nil, nil
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = defaultGraphLimit
	}

	inCand := make(map[uint64]bool, len(candidates))
	for _, fn := range candidates {
		inCand[fn.Entry] = true
	}

	// Score candidates by internal graph connectivity and category priority so diagrams highlight meaningful call chains.
	degree := make(map[uint64]int, len(candidates))
	for _, fn := range candidates {
		for _, target := range fn.Calls {
			if inCand[target] && target != fn.Entry {
				degree[fn.Entry]++
				degree[target]++
			}
		}
	}

	if len(candidates) > limit {
		ranked := append([]model.Function(nil), candidates...)
		sort.Slice(ranked, func(i, j int) bool {
			di := degree[ranked[i].Entry]
			dj := degree[ranked[j].Entry]
			if (di > 0) != (dj > 0) {
				return di > 0
			}
			ri := graphCategoryRank(ranked[i].Category)
			rj := graphCategoryRank(ranked[j].Category)
			if ri != rj {
				return ri < rj
			}
			if di != dj {
				return di > dj
			}
			return ranked[i].Entry < ranked[j].Entry
		})
		candidates = ranked[:limit]
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Entry < candidates[j].Entry
	})

	selected := make(map[uint64]bool, len(candidates))
	for _, fn := range candidates {
		selected[fn.Entry] = true
	}

	var edges []graphEdge
	seenEdge := make(map[graphEdge]struct{})
	for _, fn := range candidates {
		for _, target := range fn.Calls {
			if !selected[target] {
				continue
			}
			e := graphEdge{from: fn.Entry, to: target}
			if _, dup := seenEdge[e]; dup {
				continue
			}
			seenEdge[e] = struct{}{}
			edges = append(edges, e)
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].from != edges[j].from {
			return edges[i].from < edges[j].from
		}
		return edges[i].to < edges[j].to
	})

	return candidates, edges
}

func graphCategoryRank(c model.PackageCategory) int {
	switch c {
	case model.CategoryUser:
		return 0
	case model.CategoryDependency:
		return 1
	case model.CategoryNative:
		return 2
	case model.CategoryStdlib:
		return 3
	default:
		return 4
	}
}

func dotCategoryColors(c model.PackageCategory) (fill, stroke string) {
	switch c {
	case model.CategoryUser:
		return "#dbeafe", "#2563eb"
	case model.CategoryDependency:
		return "#fef3c7", "#d97706"
	case model.CategoryStdlib:
		return "#e2e8f0", "#475569"
	case model.CategoryRuntime:
		return "#f3e8ff", "#7c3aed"
	default:
		return "#dcfce7", "#16a34a"
	}
}

func mermaidCategoryClass(c model.PackageCategory) string {
	switch c {
	case model.CategoryUser:
		return "user"
	case model.CategoryDependency:
		return "dependency"
	case model.CategoryStdlib:
		return "stdlib"
	case model.CategoryRuntime:
		return "runtime"
	default:
		return "native"
	}
}

func shortGraphLabel(name string) string {
	// Trim long Go module prefixes (e.g., "github.com/org/repo/pkg/foo.Bar" -> "pkg/foo.Bar") for crisp diagrams.
	if idx := strings.LastIndex(name, "/"); idx >= 0 && idx+1 < len(name) {
		if prev := strings.LastIndex(name[:idx], "/"); prev >= 0 {
			name = name[prev+1:]
		}
	}
	if len(name) > 56 {
		return name[:53] + "..."
	}
	return name
}

func dotEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func mermaidLabelEscape(s string) string {
	repl := strings.NewReplacer(
		`"`, `'`,
		`\`, `/`,
		"\n", " ",
		"\r", "",
		"[", "(",
		"]", ")",
		"<", "&lt;",
		">", "&gt;",
	)
	return repl.Replace(s)
}

func mermaidCommentSafe(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
