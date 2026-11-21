package xref

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aloneangel45/symforge/pkg/model"
)

// DefaultMaxPathDepth bounds BFS call-graph traversal when callers pass <= 0.
const DefaultMaxPathDepth = 12

// PathHop represents one function node along a call-graph shortest path.
type PathHop struct {
	Depth      int                   `json:"depth"`
	Entry      uint64                `json:"entry"`
	EntryHex   string                `json:"entry_hex"`
	Name       string                `json:"name"`
	Demangled  string                `json:"demangled,omitempty"`
	Package    string                `json:"package,omitempty"`
	Category   model.PackageCategory `json:"category"`
	SourceFile string                `json:"source_file,omitempty"`
	Line       int                   `json:"line,omitempty"`
}

// CallPathResult describes the result of a BFS shortest-path search between two functions.
type CallPathResult struct {
	Found        bool      `json:"found"`
	From         PathHop   `json:"from"`
	To           PathHop   `json:"to"`
	Hops         int       `json:"hops"`
	MaxDepth     int       `json:"max_depth"`
	NodesVisited int       `json:"nodes_visited"`
	Path         []PathHop `json:"path,omitempty"`
	Message      string    `json:"message,omitempty"`
}

// ResolveFunction locates a function by hex address, exact name/demangled name,
// case-insensitive exact match, or substring (preferring CategoryUser then shortest name).
func ResolveFunction(funcs []model.Function, target string) (*model.Function, error) {
	q := strings.TrimSpace(target)
	if q == "" {
		return nil, fmt.Errorf("empty function target")
	}

	// 1. Hex address lookup
	addrStr := strings.TrimPrefix(strings.ToLower(q), "0x")
	if va, err := strconv.ParseUint(addrStr, 16, 64); err == nil && (strings.HasPrefix(strings.ToLower(q), "0x") || len(addrStr) >= 5) {
		for i := range funcs {
			if funcs[i].Entry == va {
				cp := funcs[i]
				return &cp, nil
			}
		}
		for i := range funcs {
			if funcs[i].End > funcs[i].Entry && va >= funcs[i].Entry && va < funcs[i].End {
				cp := funcs[i]
				return &cp, nil
			}
		}
	}

	// 2. Exact match
	for i := range funcs {
		if funcs[i].Name == q || (funcs[i].Demangled != "" && funcs[i].Demangled == q) {
			cp := funcs[i]
			return &cp, nil
		}
	}

	// 3. Case-insensitive exact match
	ql := strings.ToLower(q)
	for i := range funcs {
		if strings.ToLower(funcs[i].Name) == ql || (funcs[i].Demangled != "" && strings.ToLower(funcs[i].Demangled) == ql) {
			cp := funcs[i]
			return &cp, nil
		}
	}

	// 4. Substring match (prefer CategoryUser, then shortest name)
	var matches []model.Function
	for _, fn := range funcs {
		if strings.Contains(strings.ToLower(fn.Name), ql) || (fn.Demangled != "" && strings.Contains(strings.ToLower(fn.Demangled), ql)) {
			matches = append(matches, fn)
		}
	}
	if len(matches) > 0 {
		sort.Slice(matches, func(i, j int) bool {
			if (matches[i].Category == model.CategoryUser) != (matches[j].Category == model.CategoryUser) {
				return matches[i].Category == model.CategoryUser
			}
			if len(matches[i].Name) != len(matches[j].Name) {
				return len(matches[i].Name) < len(matches[j].Name)
			}
			return matches[i].Entry < matches[j].Entry
		})
		cp := matches[0]
		return &cp, nil
	}

	return nil, fmt.Errorf("function %q not found among %d recovered functions", target, len(funcs))
}

// FindCallPath runs breadth-first search (BFS) from fromQuery to toQuery over the
// recovered function call graph, returning the exact shortest hop-by-hop chain.
func FindCallPath(funcs []model.Function, fromQuery, toQuery string, maxDepth int) (*CallPathResult, error) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxPathDepth
	}
	fromFn, err := ResolveFunction(funcs, fromQuery)
	if err != nil {
		return nil, fmt.Errorf("resolve --from %q: %w", fromQuery, err)
	}
	toFn, err := ResolveFunction(funcs, toQuery)
	if err != nil {
		return nil, fmt.Errorf("resolve --to %q: %w", toQuery, err)
	}

	byEntry := make(map[uint64]*model.Function, len(funcs))
	for i := range funcs {
		if funcs[i].Entry != 0 {
			byEntry[funcs[i].Entry] = &funcs[i]
		}
	}

	res := &CallPathResult{
		From:     makePathHop(fromFn, 0),
		To:       makePathHop(toFn, 0),
		MaxDepth: maxDepth,
	}

	if fromFn.Entry == toFn.Entry {
		res.Found = true
		res.Hops = 0
		res.NodesVisited = 1
		res.Path = []PathHop{makePathHop(fromFn, 0)}
		return res, nil
	}

	type queueItem struct {
		entry uint64
		depth int
	}

	visited := make(map[uint64]bool, 64)
	parent := make(map[uint64]uint64, 64)
	queue := []queueItem{{entry: fromFn.Entry, depth: 0}}
	visited[fromFn.Entry] = true

	found := false
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		if cur.depth >= maxDepth {
			continue
		}
		fn := byEntry[cur.entry]
		if fn == nil {
			continue
		}
		for _, nextVA := range fn.Calls {
			if visited[nextVA] {
				continue
			}
			if _, exists := byEntry[nextVA]; !exists {
				continue
			}
			visited[nextVA] = true
			parent[nextVA] = cur.entry
			if nextVA == toFn.Entry {
				found = true
				break
			}
			queue = append(queue, queueItem{entry: nextVA, depth: cur.depth + 1})
		}
		if found {
			break
		}
	}

	res.NodesVisited = len(visited)
	if !found {
		res.Found = false
		res.Message = fmt.Sprintf("no call path found from %s (0x%x) to %s (0x%x) within max depth %d",
			displayFuncName(fromFn), fromFn.Entry, displayFuncName(toFn), toFn.Entry, maxDepth)
		return res, nil
	}

	// Reconstruct chain from target back to source.
	var chain []uint64
	for cur := toFn.Entry; ; {
		chain = append(chain, cur)
		if cur == fromFn.Entry {
			break
		}
		p, ok := parent[cur]
		if !ok {
			break
		}
		cur = p
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	pathHops := make([]PathHop, 0, len(chain))
	for depth, va := range chain {
		fn := byEntry[va]
		pathHops = append(pathHops, makePathHop(fn, depth))
	}

	res.Found = true
	res.Hops = len(pathHops) - 1
	res.Path = pathHops
	res.To = pathHops[len(pathHops)-1]
	return res, nil
}

func makePathHop(fn *model.Function, depth int) PathHop {
	if fn == nil {
		return PathHop{Depth: depth}
	}
	return PathHop{
		Depth:      depth,
		Entry:      fn.Entry,
		EntryHex:   fmt.Sprintf("0x%x", fn.Entry),
		Name:       fn.Name,
		Demangled:  fn.Demangled,
		Package:    fn.Package,
		Category:   fn.Category,
		SourceFile: fn.SourceFile,
		Line:       fn.Line,
	}
}

func displayFuncName(fn *model.Function) string {
	if fn == nil {
		return ""
	}
	if fn.Demangled != "" {
		return fn.Demangled
	}
	return fn.Name
}
