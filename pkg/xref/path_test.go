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
}
