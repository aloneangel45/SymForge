package preset

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildMergedConfigPreservesJSONCAndExistingServers(t *testing.T) {
	zedJSONC := []byte(`{
  // Existing Zed user settings
  "theme": "One Dark",
  "context_servers": {
    "github": {
      "command": { "path": "gh-mcp", "args": ["serve"], },
    },
  },
}`)

	merged, err := BuildMergedConfig(ClientZed, "/usr/local/bin/symforge", zedJSONC)
	if err != nil {
		t.Fatalf("BuildMergedConfig failed on JSONC: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(merged, &parsed); err != nil {
		t.Fatalf("merged output invalid JSON: %v", err)
	}
	if parsed["theme"] != "One Dark" {
		t.Fatalf("lost top-level theme setting: %+v", parsed)
	}
	cs := parsed["context_servers"].(map[string]any)
	if _, ok := cs["github"]; !ok {
		t.Fatalf("lost existing github context server")
	}
	if _, ok := cs["symforge"]; !ok {
		t.Fatalf("missing symforge context server")
	}
}

func TestApplyAllClients(t *testing.T) {
	tmp := t.TempDir()
	for _, c := range SupportedClients() {
		cfgPath, err := DefaultConfigPath(c, tmp, filepath.Join(tmp, "ws"))
		if err != nil {
			t.Fatalf("DefaultConfigPath(%s): %v", c, err)
		}
		out, err := Apply(c, cfgPath, "symforge")
		if err != nil {
			t.Fatalf("Apply(%s): %v", c, err)
		}
		if !strings.Contains(string(out), `"symforge"`) {
			t.Fatalf("client %s output missing symforge entry:\n%s", c, string(out))
		}
	}
}
