package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FetchOffline reads a specific package version's metadata from the local
// node_modules/.pnpm tree, used when --offline is set.
// Path pattern: <NodeModDir>/node_modules/.pnpm/<dirName>/node_modules/<pkg>/package.json
func (c *Client) FetchOffline(pkg, version string) (*PackageVersion, error) {
	dir := c.NodeModDir
	if dir == "" {
		dir = "."
	}
	pkgJSONPath := filepath.Join(dir, "node_modules", ".pnpm",
		pnpmDirName(pkg, version), "node_modules", pkg, "package.json")

	f, err := os.Open(pkgJSONPath)
	if err != nil {
		return nil, fmt.Errorf("offline lookup %s@%s: %w", pkg, version, err)
	}
	defer f.Close()

	var pv PackageVersion
	if err := json.NewDecoder(f).Decode(&pv); err != nil {
		return nil, fmt.Errorf("decode offline package.json for %s@%s: %w", pkg, version, err)
	}
	return &pv, nil
}

// pnpmDirName returns the directory name pnpm uses under node_modules/.pnpm.
// Scoped packages replace / with +: @scope/name → scope+name@version
func pnpmDirName(pkg, version string) string {
	if strings.HasPrefix(pkg, "@") {
		return strings.ReplaceAll(pkg[1:], "/", "+") + "@" + version
	}
	return pkg + "@" + version
}

// pnpmDirPrefix returns the prefix used to match all versions of pkg under .pnpm.
func pnpmDirPrefix(pkg string) string {
	if strings.HasPrefix(pkg, "@") {
		return strings.ReplaceAll(pkg[1:], "/", "+") + "@"
	}
	return pkg + "@"
}

// buildOfflineMeta scans node_modules/.pnpm for all installed versions of pkg
// and assembles an AbbrevMeta from their package.json files.
func (c *Client) buildOfflineMeta(pkg string) (*AbbrevMeta, error) {
	dir := c.NodeModDir
	if dir == "" {
		dir = "."
	}
	pnpmDir := filepath.Join(dir, "node_modules", ".pnpm")
	entries, err := os.ReadDir(pnpmDir)
	if err != nil {
		return nil, fmt.Errorf("offline lookup for %q: reading %s: %w", pkg, pnpmDir, err)
	}

	prefix := pnpmDirPrefix(pkg)
	meta := &AbbrevMeta{Name: pkg, Versions: make(map[string]*PackageVersion)}

	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		version := entry.Name()[len(prefix):]
		pkgJSONPath := filepath.Join(pnpmDir, entry.Name(), "node_modules", pkg, "package.json")
		f, err := os.Open(pkgJSONPath)
		if err != nil {
			continue
		}
		var pv PackageVersion
		if decodeErr := json.NewDecoder(f).Decode(&pv); decodeErr == nil {
			meta.Versions[version] = &pv
		}
		f.Close()
	}

	if len(meta.Versions) == 0 {
		return nil, fmt.Errorf("offline lookup for %q: package not found in %s", pkg, pnpmDir)
	}
	return meta, nil
}
