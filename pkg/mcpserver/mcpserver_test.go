package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloneangel45/symforge/pkg/analyzer"
)

func compileSampleBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/mcpsample\n\ngo 1.24.0\n"), 0o644)
	src := `package main

import "fmt"

//go:noinline
func DispatchBeacon(url string) string {
	return "POST " + url
}

func main() {
	fmt.Println(DispatchBeacon("https://api.symforge.dev/v1/ping"))
}
`
	_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644)
	out := filepath.Join(dir, "mcpsample")
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build sample failed: %v\n%s", err, string(b))
	}
	return out
}

func TestStdioNDJSONAndContentLengthFraming(t *testing.T) {
	srv := New("1.0.0", analyzer.NewEngine(4))

	// 1. NDJSON framing with 64-bit integer ID + notification
	ndjsonIn := strings.Join([]string{
		`{"jsonrpc":"2.0","id":9007199254740993,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"demangle_symbols","arguments":{"symbols":["_RNvNtCs73fAdSrgOJL_4core3fmt5write"]}}}`,
	}, "\n") + "\n"

	var outBuf bytes.Buffer
	if err := srv.ServeStdio(context.Background(), strings.NewReader(ndjsonIn), &outBuf); err != nil {
		t.Fatalf("ServeStdio NDJSON failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 responses (notification skipped), got %d:\n%s", len(lines), outBuf.String())
	}
	if !strings.Contains(lines[0], "9007199254740993") {
		t.Fatalf("64-bit JSON-RPC ID lost precision: %s", lines[0])
	}
	if !strings.Contains(lines[2], "core::fmt::write") {
		t.Fatalf("expected demangled core::fmt::write, got: %s", lines[2])
	}

	// 2. Content-Length framing
	body := `{"jsonrpc":"2.0","id":10,"method":"ping"}`
	clFrame := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
	outBuf.Reset()
	if err := srv.ServeStdio(context.Background(), strings.NewReader(clFrame), &outBuf); err != nil {
		t.Fatalf("ServeStdio Content-Length failed: %v", err)
	}
	if !strings.HasPrefix(outBuf.String(), "Content-Length:") {
		t.Fatalf("expected Content-Length response header, got: %q", outBuf.String())
	}
}

func TestHTTPStreamableAndAllTools(t *testing.T) {
	binPath := compileSampleBinary(t)
	srv := New("1.0.0", analyzer.NewEngine(4))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Verify DNS-rebinding protection blocks foreign Host headers
	badReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
	badReq.Host = "evil.attacker.example"
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for non-loopback Host, got %d", badResp.StatusCode)
	}

	callTool := func(name string, args map[string]any) string {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      name,
				"arguments": args,
			},
		})
		resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var parsed struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Result.IsError || len(parsed.Result.Content) == 0 {
			t.Fatalf("tool %s returned error: %+v", name, parsed)
		}
		return parsed.Result.Content[0].Text
	}

	outAnalyze := callTool("analyze_binary", map[string]any{"path": binPath})
	if !strings.Contains(outAnalyze, `"language": "go"`) {
		t.Fatalf("unexpected analyze_binary output:\n%s", outAnalyze)
	}

	outPkgs := callTool("list_packages_crates", map[string]any{"path": binPath, "category": "user"})
	if !strings.Contains(outPkgs, "main") {
		t.Fatalf("unexpected list_packages_crates output:\n%s", outPkgs)
	}

	outSearch := callTool("search_functions", map[string]any{"path": binPath, "query": "DispatchBeacon"})
	if !strings.Contains(outSearch, "DispatchBeacon") {
		t.Fatalf("unexpected search_functions output:\n%s", outSearch)
	}

	outInspect := callTool("inspect_function", map[string]any{"path": binPath, "target": "DispatchBeacon", "disassemble": true})
	if !strings.Contains(outInspect, "instructions") {
		t.Fatalf("unexpected inspect_function output:\n%s", outInspect)
	}

	outXrefs := callTool("find_xrefs", map[string]any{"path": binPath, "kind": "url"})
	if !strings.Contains(outXrefs, "https://api.symforge.dev/v1/ping") {
		t.Fatalf("unexpected find_xrefs output:\n%s", outXrefs)
	}

	ghidraScript := filepath.Join(t.TempDir(), "restore.py")
	outExport := callTool("export_re_script", map[string]any{
		"path":        binPath,
		"format":      "ghidra",
		"output_path": ghidraScript,
		"user_only":   true,
	})
	if !strings.Contains(outExport, `"written": true`) {
		t.Fatalf("unexpected export_re_script output:\n%s", outExport)
	}

	// Verify explicit "id": null produces a response with "id": null (JSON-RPC 2.0 spec)
	nullIDResp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":null,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer nullIDResp.Body.Close()
	if nullIDResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for explicit id:null, got %d", nullIDResp.StatusCode)
	}
	var nullBody map[string]any
	if err := json.NewDecoder(nullIDResp.Body).Decode(&nullBody); err != nil {
		t.Fatal(err)
	}
	if v, exists := nullBody["id"]; !exists || v != nil {
		t.Fatalf("expected explicit id:null in response, got %+v", nullBody)
	}

	// Verify JSON-RPC 2.0 batch array (1 ping + 1 notification + 1 tools/list -> 2 responses)
	batchPayload := `[
		{"jsonrpc":"2.0","id":101,"method":"ping"},
		{"jsonrpc":"2.0","method":"notifications/initialized"},
		{"jsonrpc":"2.0","id":102,"method":"tools/list"}
	]`
	batchResp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(batchPayload))
	if err != nil {
		t.Fatal(err)
	}
	defer batchResp.Body.Close()
	var batchOut []map[string]any
	if err := json.NewDecoder(batchResp.Body).Decode(&batchOut); err != nil {
		t.Fatalf("failed to decode batch response array: %v", err)
	}
	if len(batchOut) != 2 {
		t.Fatalf("expected 2 responses in batch (notification omitted), got %d: %+v", len(batchOut), batchOut)
	}

	// Empty batch [] must return -32600 Invalid Request
	emptyBatchResp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	defer emptyBatchResp.Body.Close()
	var emptyErr map[string]any
	if err := json.NewDecoder(emptyBatchResp.Body).Decode(&emptyErr); err != nil {
		t.Fatal(err)
	}
	if emptyErr["error"] == nil {
		t.Fatalf("expected JSON-RPC error for empty batch [], got %+v", emptyErr)
	}
}
