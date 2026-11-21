package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLISubcommands(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/clisample\n\ngo 1.24.0\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "fmt"
type AuthHeader struct { Token string }
//go:noinline
func RunCheck(h AuthHeader) string { return "https://auth.symforge.io/" + h.Token }
func main() { fmt.Println(RunCheck(AuthHeader{Token: "ok"})) }
`), 0o644)

	sampleBin := filepath.Join(dir, "clisample")
	build := exec.Command("go", "build", "-ldflags=-s -w", "-o", sampleBin, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed building sample arm64 binary: %v\n%s", err, string(out))
	}

	runCLI := func(args ...string) string {
		t.Helper()
		var buf bytes.Buffer
		cmd := newRootCommand()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("symforge %v failed: %v\n%s", args, err, buf.String())
		}
		return buf.String()
	}

	if out := runCLI("version"); !strings.Contains(out, "symforge v") {
		t.Fatalf("unexpected version output: %s", out)
	}
	if out := runCLI("inspect", sampleBin); !strings.Contains(out, "arm64") || !strings.Contains(out, "Stripped=true") {
		t.Fatalf("unexpected inspect output:\n%s", out)
	}
	if out := runCLI("functions", sampleBin, "--user-only"); !strings.Contains(out, "RunCheck") {
		t.Fatalf("unexpected functions output:\n%s", out)
	}
	if out := runCLI("fn", sampleBin, "RunCheck"); !strings.Contains(out, "Disassembly") {
		t.Fatalf("unexpected fn output:\n%s", out)
	}
	if out := runCLI("strings", sampleBin, "--kind", "url"); !strings.Contains(out, "https://auth.symforge.io/") {
		t.Fatalf("unexpected strings output:\n%s", out)
	}
	if out := runCLI("demangle", "_RNvNtCs73fAdSrgOJL_4core3fmt5write"); !strings.Contains(out, "core::fmt::write") {
		t.Fatalf("unexpected demangle output:\n%s", out)
	}
	if out := runCLI("preset", "cursor", "--print"); !strings.Contains(out, `"symforge"`) {
		t.Fatalf("unexpected preset output:\n%s", out)
	}
	sbomPath := filepath.Join(dir, "bom.cdx.json")
	if out := runCLI("export", sampleBin, "-f", "sbom", "-o", sbomPath); !strings.Contains(out, "Exported sbom") {
		t.Fatalf("unexpected export output:\n%s", out)
	}
	if out := runCLI("export", sampleBin, "-f", "mermaid", "--user-only", "--limit", "15"); !strings.Contains(out, "flowchart LR") {
		t.Fatalf("unexpected mermaid export output:\n%s", out)
	}
	if out := runCLI("export", sampleBin, "-f", "dot", "--user-only", "--limit", "15"); !strings.Contains(out, "digraph SymForgeCallGraph") {
		t.Fatalf("unexpected dot export output:\n%s", out)
	}
	if out := runCLI("scan", sampleBin, "--arch", "arm64"); !strings.Contains(out, "https://auth.symforge.io/") {
		t.Fatalf("unexpected scan output:\n%s", out)
	}
	if out := runCLI("diff", sampleBin, sampleBin, "--user-only"); !strings.Contains(out, "Identical   : true") {
		t.Fatalf("unexpected diff output:\n%s", out)
	}
	if out := runCLI("path", sampleBin, "--from", "main.main", "--to", "RunCheck", "--max-depth", "8"); !strings.Contains(out, "found=true") || !strings.Contains(out, "RunCheck") {
		t.Fatalf("unexpected path output:\n%s", out)
	}
}
