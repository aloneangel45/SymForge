package test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallerIntegrityAndLF(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	shBytes, err := os.ReadFile(filepath.Join(repoRoot, "install.sh"))
	if err != nil {
		t.Fatalf("missing install.sh: %v", err)
	}
	if bytes.Contains(shBytes, []byte("\r")) {
		t.Fatalf("install.sh contains CR (\\r) characters; must be pure LF for POSIX shells")
	}

	if runtime.GOOS != "windows" {
		if shPath, err := exec.LookPath("sh"); err == nil {
			chk := exec.Command(shPath, "-n", filepath.Join(repoRoot, "install.sh"))
			if out, err := chk.CombinedOutput(); err != nil {
				t.Fatalf("sh -n install.sh failed: %v\n%s", err, string(out))
			}
		}
		return
	}

	// On Windows: verify install.ps1 works end-to-end even when PSModulePath is completely empty!
	tmp := t.TempDir()
	relDir := filepath.Join(tmp, "releases", "latest", "download")
	if err := os.MkdirAll(relDir, 0o755); err != nil {
		t.Fatal(err)
	}

	zipName := "symforge-windows-amd64.zip"
	zipPath := filepath.Join(relDir, zipName)
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	fw, err := zw.Create("symforge.exe")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("MZ-dummy-symforge-binary"))
	_ = zw.Close()
	_ = zf.Close()

	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(zipData)
	sumLine := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), zipName)
	if err := os.WriteFile(filepath.Join(relDir, "checksums.txt"), []byte(sumLine), 0o644); err != nil {
		t.Fatal(err)
	}

	installDir := filepath.Join(tmp, "installed-bin")
	baseURI := "file:///" + filepath.ToSlash(filepath.Join(tmp, "releases"))

	psPath, err := exec.LookPath("powershell")
	if err != nil {
		t.Skip("powershell not found")
	}

	cmd := exec.Command(psPath, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(repoRoot, "install.ps1"))
	cmd.Env = append(os.Environ(),
		"PSModulePath=",
		"SYMFORGE_BASE_URL="+baseURI,
		"SYMFORGE_ARCH_OVERRIDE=amd64",
		"SYMFORGE_INSTALL_DIR="+installDir,
		"SYMFORGE_SKIP_PATH=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.ps1 with stripped PSModulePath failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Installed successfully") {
		t.Fatalf("unexpected install.ps1 output:\n%s", string(out))
	}
	if _, err := os.Stat(filepath.Join(installDir, "symforge.exe")); err != nil {
		t.Fatalf("installed symforge.exe missing: %v", err)
	}
}
