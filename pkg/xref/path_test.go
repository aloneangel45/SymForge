package xref_test

import (
	"testing"

	"github.com/aloneangel45/symforge/pkg/model"
	"github.com/aloneangel45/symforge/pkg/xref"
)

func TestFindCallPathBFS(t *testing.T) {
	// Graph:
	// main (0x1000) -> dispatch (0x2000), helper (0x3000)
	// dispatch (0x2000) -> auth (0x4000)
	// auth (0x4000) -> sink (0x5000), main (0x1000) [cycle!]
	// helper (0x3000) -> sink (0x5000)  [shorter 2-hop path: main -> helper -> sink]
	// isolated (0x6000)
	funcs := []model.Function{
		{Name: "main.main", Package: "main", Category: model.CategoryUser, Entry: 0x1000, Calls: []uint64{0x2000, 0x3000}},
		{Name: "main.dispatch", Package: "main", Category: model.CategoryUser, Entry: 0x2000, Calls: []uint64{0x4000}},
		{Name: "main.helper", Package: "main", Category: model.CategoryUser, Entry: 0x3000, Calls: []uint64{0x5000}},
		{Name: "main.auth", Package: "main", Category: model.CategoryUser, Entry: 0x4000, Calls: []uint64{0x5000, 0x1000}},
		{Name: "os/exec.(*Cmd).Run", Package: "os/exec", Category: model.CategoryStdlib, Entry: 0x5000},
		{Name: "main.isolated", Package: "main", Category: model.CategoryUser, Entry: 0x6000},
	}

	// 1. Shortest path should pick 2 hops (main -> helper -> sink), not 3 hops (main -> dispatch -> auth -> sink)
	res, err := xref.FindCallPath(funcs, "main.main", "0x5000", 12)
	if err != nil {
		t.Fatalf("FindCallPath failed: %v", err)
	}
	if !res.Found || res.Hops != 2 || len(res.Path) != 3 {
		t.Fatalf("expected 2-hop shortest path, got found=%v hops=%d path=%+v", res.Found, res.Hops, res.Path)
	}
	if res.Path[1].Name != "main.helper" {
		t.Fatalf("expected middle hop main.helper, got %s", res.Path[1].Name)
	}

	// 2. Max depth cut-off (maxDepth=1 cannot reach 2-hop target)
	cut, err := xref.FindCallPath(funcs, "main.main", "Cmd).Run", 1)
	if err != nil {
		t.Fatalf("FindCallPath maxDepth=1 failed: %v", err)
	}
	if cut.Found {
		t.Fatalf("expected Found=false with maxDepth=1, got %+v", cut)
	}

	// 3. Unreachable node with cycle safety
	unreach, err := xref.FindCallPath(funcs, "main.main", "isolated", 12)
	if err != nil {
		t.Fatalf("FindCallPath isolated failed: %v", err)
	}
	if unreach.Found {
		t.Fatalf("expected Found=false for isolated function")
	}

	// 4. Zero-hop self path
	self, err := xref.FindCallPath(funcs, "0x1000", "main.main", 12)
	if err != nil || !self.Found || self.Hops != 0 || len(self.Path) != 1 {
		t.Fatalf("unexpected self-path result: err=%v res=%+v", err, self)
	}

	// 5. Missing function error
	if _, err := xref.FindCallPath(funcs, "nonexistent", "main.main", 12); err == nil {
		t.Fatalf("expected error for missing source function")
	}

	// 6. maxDepth <= 0 falls back cleanly to DefaultMaxPathDepth; huge maxDepth clamped to MaxPathDepth
	defZero, err := xref.FindCallPath(funcs, "main.main", "0x5000", 0)
	if err != nil || !defZero.Found || defZero.MaxDepth != xref.DefaultMaxPathDepth {
		t.Fatalf("expected maxDepth=0 fallback to %d, got err=%v res=%+v", xref.DefaultMaxPathDepth, err, defZero)
	}
	defNeg, err := xref.FindCallPath(funcs, "main.main", "0x5000", -5)
	if err != nil || !defNeg.Found || defNeg.MaxDepth != xref.DefaultMaxPathDepth {
		t.Fatalf("expected maxDepth=-5 fallback to %d, got err=%v res=%+v", xref.DefaultMaxPathDepth, err, defNeg)
	}
	clampedHuge, err := xref.FindCallPath(funcs, "main.main", "0x5000", 99999)
	if err != nil || !clampedHuge.Found || clampedHuge.MaxDepth != xref.MaxPathDepth {
		t.Fatalf("expected huge maxDepth clamped to %d, got err=%v res=%+v", xref.MaxPathDepth, err, clampedHuge)
	}

	// 7. Distinct functions with zero Entry must NOT falsely match as 0-hop self-path
	zeroFuncs := []model.Function{
		{Name: "alpha", Entry: 0},
		{Name: "beta", Entry: 0},
	}
	zRes, err := xref.FindCallPath(zeroFuncs, "alpha", "beta", 6)
	if err != nil {
		t.Fatalf("FindCallPath zero-entry failed: %v", err)
	}
	if zRes.Found {
		t.Fatalf("expected Found=false for distinct zero-entry functions, got %+v", zRes)
	}

	// 8. Pure mutual cycles + self-loops with unreachable target must terminate safely
	cyclic := []model.Function{
		{Name: "n1", Entry: 0x100, Calls: []uint64{0x100, 0x200}},
		{Name: "n2", Entry: 0x200, Calls: []uint64{0x300, 0x100}},
		{Name: "n3", Entry: 0x300, Calls: []uint64{0x100, 0x200, 0x300}},
		{Name: "n4", Entry: 0x400},
	}
	cRes, err := xref.FindCallPath(cyclic, "n1", "n4", 64)
	if err != nil || cRes.Found || cRes.NodesVisited != 3 {
		t.Fatalf("unexpected cyclic unreachable result: err=%v res=%+v", err, cRes)
	}
}
