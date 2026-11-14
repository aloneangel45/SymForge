package analyzer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloneangel45/symforge/pkg/model"
)

func buildStrippedGoSample(t *testing.T, goos, goarch string) string {
	t.Helper()
	dir := t.TempDir()
	mod := "module example.com/vaultprobe\n\ngo 1.24.0\n"
	src := `package main

import (
	"crypto/sha256"
	"fmt"
)

type VaultConfig struct {
	Endpoint string ` + "`json:\"endpoint\"`" + `
	Retries  int    ` + "`json:\"retries\"`" + `
}

//go:noinline
func VerifyEndpoint(cfg VaultConfig) [32]byte {
	msg := cfg.Endpoint + "/v1/health"
	return sha256.Sum256([]byte(msg))
}

func main() {
	cfg := VaultConfig{Endpoint: "https://vault.symforge.internal", Retries: 3}
	sum := VerifyEndpoint(cfg)
	fmt.Printf("%x\n", sum[0])
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	outBin := filepath.Join(dir, "vaultprobe")
	if goos == "windows" {
		outBin += ".exe"
	}
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", outBin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build (%s/%s) failed: %v\n%s", goos, goarch, err, string(out))
	}
	return outBin
}

func TestEngineAnalyzeAndInspectStrippedGo(t *testing.T) {
	binPath := buildStrippedGoSample(t, "linux", "amd64")
	eng := NewEngine(4)

	res, err := eng.AnalyzeFile(binPath, Options{})
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}
	if res.Binary.Language != model.LangGo {
		t.Fatalf("expected LangGo, got %s", res.Binary.Language)
	}
	if !res.Binary.Stripped {
		t.Fatalf("expected stripped=true")
	}
	if res.Go == nil || !res.Go.Detected {
		t.Fatalf("expected Go metadata detected")
	}

	// Second call must hit cache cleanly and return identical pointer/data
	resCached, err := eng.AnalyzeFile(binPath, Options{})
	if err != nil {
		t.Fatalf("cached AnalyzeFile failed: %v", err)
	}
	if resCached.Binary.SHA256 != res.Binary.SHA256 {
		t.Fatalf("cache mismatch")
	}

	insp, err := eng.InspectFunction(binPath, "VerifyEndpoint", true, 80)
	if err != nil {
		t.Fatalf("InspectFunction(VerifyEndpoint) failed: %v", err)
	}
	if !strings.Contains(insp.Function.Name, "VerifyEndpoint") {
		t.Fatalf("unexpected function %q", insp.Function.Name)
	}
	if len(insp.Instructions) == 0 {
		t.Fatalf("expected decoded x86_64 instructions for VerifyEndpoint")
	}
}
