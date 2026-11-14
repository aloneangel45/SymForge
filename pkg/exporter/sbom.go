package exporter

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/aloneangel45/symforge/pkg/model"
)

type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	Version      int            `json:"version"`
	SerialNumber string         `json:"serialNumber"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     []cdxTool    `json:"tools"`
	Component cdxComponent `json:"component"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	Hashes     []cdxHash     `json:"hashes,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

// ExportCycloneDX serializes recovered Go modules and Rust crates into a
// valid CycloneDX 1.5 JSON Software Bill of Materials (SBOM).
func ExportCycloneDX(res *model.AnalysisResult) ([]byte, error) {
	normPath := strings.ReplaceAll(res.Binary.Path, "\\", "/")
	appName := filepath.Base(normPath)
	if appName == "" || appName == "." || appName == "/" {
		appName = "binary"
	}

	rootProps := []cdxProperty{
		{Name: "symforge:format", Value: string(res.Binary.Format)},
		{Name: "symforge:arch", Value: string(res.Binary.Arch)},
		{Name: "symforge:language", Value: string(res.Binary.Language)},
		{Name: "symforge:stripped", Value: fmt.Sprintf("%v", res.Binary.Stripped)},
	}
	if res.Go != nil && res.Go.Version != "" {
		rootProps = append(rootProps, cdxProperty{Name: "symforge:go.version", Value: res.Go.Version})
	}
	if res.Rust != nil && res.Rust.CompilerVersion != "" {
		rootProps = append(rootProps, cdxProperty{Name: "symforge:rust.compiler", Value: res.Rust.CompilerVersion})
	}

	var hashes []cdxHash
	if res.Binary.SHA256 != "" {
		hashes = append(hashes, cdxHash{Alg: "SHA-256", Content: res.Binary.SHA256})
	}

	serialHash := res.Binary.SHA256
	if len(serialHash) < 32 {
		serialHash = "00000000000000000000000000000000"
	}

	seen := make(map[string]bool)
	components := make([]cdxComponent, 0, len(res.Dependencies))
	for _, dep := range res.Dependencies {
		if dep.Name == "" {
			continue
		}
		key := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		purl := buildPURL(dep)
		comp := cdxComponent{
			Type:    "library",
			BOMRef:  purl,
			Name:    dep.Name,
			Version: dep.Version,
			PURL:    purl,
			Properties: []cdxProperty{
				{Name: "symforge:source", Value: dep.Source},
			},
		}
		if dep.Sum != "" {
			comp.Properties = append(comp.Properties, cdxProperty{Name: "symforge:sum", Value: dep.Sum})
		}
		components = append(components, comp)
	}

	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		SerialNumber: fmt.Sprintf("urn:uuid:%s-%s-4%s-8%s-%s",
			serialHash[0:8], serialHash[8:12], serialHash[13:16], serialHash[17:20], serialHash[20:32]),
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cdxTool{
				{Vendor: "SymForge", Name: "symforge", Version: "1.0.0"},
			},
			Component: cdxComponent{
				Type:       "application",
				Name:       appName,
				Hashes:     hashes,
				Properties: rootProps,
			},
		},
		Components: components,
	}

	return json.MarshalIndent(bom, "", "  ")
}

func buildPURL(dep model.Dependency) string {
	ver := strings.TrimPrefix(dep.Version, "v")
	switch strings.ToLower(dep.Ecosystem) {
	case "go", "golang":
		if dep.Version != "" {
			return fmt.Sprintf("pkg:golang/%s@%s", dep.Name, dep.Version)
		}
		return fmt.Sprintf("pkg:golang/%s", dep.Name)
	case "cargo", "rust", "crates.io":
		if ver != "" {
			return fmt.Sprintf("pkg:cargo/%s@%s", dep.Name, ver)
		}
		return fmt.Sprintf("pkg:cargo/%s", dep.Name)
	default:
		eco := dep.Ecosystem
		if eco == "" {
			eco = "generic"
		}
		if dep.Version != "" {
			return fmt.Sprintf("pkg:%s/%s@%s", eco, dep.Name, dep.Version)
		}
		return fmt.Sprintf("pkg:%s/%s", eco, dep.Name)
	}
}
