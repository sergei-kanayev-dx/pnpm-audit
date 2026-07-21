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
