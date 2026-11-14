// Package preset installs or previews SymForge MCP server configurations for
// popular AI coding environments (Claude Code, Cursor, VS Code, Windsurf, Zed)
// while preserving existing servers and tolerating JSONC comments/trailing commas.
package preset

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Client identifies a supported MCP host IDE or CLI.
type Client string

const (
	ClientClaudeCode Client = "claude-code"
	ClientCursor     Client = "cursor"
	ClientVSCode     Client = "vscode"
	ClientWindsurf   Client = "windsurf"
	ClientZed        Client = "zed"
)

// SupportedClients lists all valid preset targets.
func SupportedClients() []Client {
	return []Client{
		ClientClaudeCode,
		ClientCursor,
		ClientVSCode,
		ClientWindsurf,
		ClientZed,
	}
}

// ParseClient normalizes a user-supplied client name.
func ParseClient(raw string) (Client, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "claude", "claude-code", "claudecode":
		return ClientClaudeCode, nil
	case "cursor":
		return ClientCursor, nil
	case "vscode", "vs-code", "code":
		return ClientVSCode, nil
	case "windsurf":
		return ClientWindsurf, nil
	case "zed":
		return ClientZed, nil
	default:
		return "", fmt.Errorf("unsupported MCP client %q (expected claude-code, cursor, vscode, windsurf, or zed)", raw)
	}
}

// DefaultConfigPath resolves the target config path for client.
// When workspaceDir is non-empty, project-scoped config paths are returned where supported.
func DefaultConfigPath(client Client, homeDir, workspaceDir string) (string, error) {
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}
	switch client {
	case ClientClaudeCode:
		if workspaceDir != "" {
			return filepath.Join(workspaceDir, ".mcp.json"), nil
		}
		return filepath.Join(homeDir, ".claude.json"), nil
	case ClientCursor:
		if workspaceDir != "" {
			return filepath.Join(workspaceDir, ".cursor", "mcp.json"), nil
		}
		return filepath.Join(homeDir, ".cursor", "mcp.json"), nil
	case ClientVSCode:
		if workspaceDir != "" {
			return filepath.Join(workspaceDir, ".vscode", "mcp.json"), nil
		}
		if runtime.GOOS == "windows" {
			appData := os.Getenv("APPDATA")
			if appData == "" {
				appData = filepath.Join(homeDir, "AppData", "Roaming")
			}
			return filepath.Join(appData, "Code", "User", "mcp.json"), nil
		}
		if runtime.GOOS == "darwin" {
			return filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "mcp.json"), nil
		}
		return filepath.Join(homeDir, ".config", "Code", "User", "mcp.json"), nil
	case ClientWindsurf:
		return filepath.Join(homeDir, ".codeium", "windsurf", "mcp_config.json"), nil
	case ClientZed:
		if runtime.GOOS == "windows" {
			appData := os.Getenv("APPDATA")
			if appData == "" {
				appData = filepath.Join(homeDir, "AppData", "Roaming")
			}
			return filepath.Join(appData, "Zed", "settings.json"), nil
		}
		return filepath.Join(homeDir, ".config", "zed", "settings.json"), nil
	default:
		return "", fmt.Errorf("unsupported client %q", client)
	}
}

// BuildMergedConfig merges the symforge MCP server entry into existingData (which may be
// empty or contain JSONC line/block comments and trailing commas).
func BuildMergedConfig(client Client, binaryPath string, existingData []byte) ([]byte, error) {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = "symforge"
	}

	root := make(map[string]any)
	cleaned := strings.TrimSpace(string(stripJSONC(existingData)))
	if cleaned != "" {
		if err := json.Unmarshal([]byte(cleaned), &root); err != nil {
			return nil, fmt.Errorf("failed to parse existing %s configuration: %w", client, err)
		}
	}

	switch client {
	case ClientVSCode:
		servers := ensureMap(root, "servers")
		servers["symforge"] = map[string]any{
			"type":    "stdio",
			"command": binaryPath,
			"args":    []string{"mcp"},
		}
	case ClientZed:
		servers := ensureMap(root, "context_servers")
		servers["symforge"] = map[string]any{
			"command": map[string]any{
				"path": binaryPath,
				"args": []string{"mcp"},
			},
		}
	default:
		servers := ensureMap(root, "mcpServers")
		servers["symforge"] = map[string]any{
			"command": binaryPath,
			"args":    []string{"mcp"},
		}
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Apply writes or updates the MCP configuration file on disk atomically.
func Apply(client Client, configPath, binaryPath string) ([]byte, error) {
	var existing []byte
	if data, err := os.ReadFile(configPath); err == nil {
		existing = data
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	merged, err := BuildMergedConfig(client, binaryPath, existing)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return nil, err
	}
	tmp := configPath + ".symforge.tmp"
	if err := os.WriteFile(tmp, merged, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, configPath); err != nil {
		// Windows fallback if destination is locked/special
		if werr := os.WriteFile(configPath, merged, 0o600); werr != nil {
			_ = os.Remove(tmp)
			return nil, err
		}
		_ = os.Remove(tmp)
	}
	return merged, nil
}

func ensureMap(parent map[string]any, key string) map[string]any {
	if existing, ok := parent[key].(map[string]any); ok && existing != nil {
		return existing
	}
	m := make(map[string]any)
	parent[key] = m
	return m
}

// stripJSONC removes // line comments, /* */ block comments, and trailing commas
// outside JSON string literals so Zed and VS Code JSONC settings parse cleanly.
func stripJSONC(src []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(src))
	inString := false
	escaped := false

	for i := 0; i < len(src); i++ {
		c := src[i]
		if inString {
			out.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}

		if c == '"' {
			inString = true
			out.WriteByte(c)
			continue
		}

		if c == '/' && i+1 < len(src) {
			if src[i+1] == '/' {
				i += 2
				for i < len(src) && src[i] != '\n' {
					i++
				}
				if i < len(src) {
					out.WriteByte('\n')
				}
				continue
			}
			if src[i+1] == '*' {
				i += 2
				for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
					i++
				}
				i++
				continue
			}
		}

		out.WriteByte(c)
	}

	// Remove trailing commas before } or ] outside strings.
	clean := out.Bytes()
	var final bytes.Buffer
	final.Grow(len(clean))
	inString = false
	escaped = false
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if inString {
			final.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			final.WriteByte(c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(clean) && (clean[j] == ' ' || clean[j] == '\t' || clean[j] == '\r' || clean[j] == '\n') {
				j++
			}
			if j < len(clean) && (clean[j] == '}' || clean[j] == ']') {
				continue
			}
		}
		final.WriteByte(c)
	}

	return final.Bytes()
}
