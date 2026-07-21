package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PackageVersion holds the per-version dependency metadata from npm abbreviated metadata.
type PackageVersion struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Engines              map[string]string `json:"engines"`
	Deprecated           string            `json:"deprecated"`
}

// AbbrevMeta is the abbreviated npm registry response for a package.
type AbbrevMeta struct {
	Name     string                     `json:"name"`
	Versions map[string]*PackageVersion `json:"versions"`
}

// Client fetches npm abbreviated package metadata with in-memory caching.
type Client struct {
	httpClient *http.Client
	baseURL    string
	cache      map[string]*AbbrevMeta
	// NodeModDir is the project root used for offline fallback (default ".").
	NodeModDir string
	// Offline skips network requests and reads from node_modules/.pnpm instead.
	Offline bool
}

// NewClient creates a Client targeting the given registry base URL.
func NewClient(baseURL string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    strings.TrimRight(baseURL, "/"),
		cache:      make(map[string]*AbbrevMeta),
		NodeModDir: ".",
	}
}

// FetchAbbrevMeta returns abbreviated metadata for pkg.
// Results are cached in memory; subsequent calls for the same package return
// the cached value without a network request.
// When c.Offline is true, reads from node_modules/.pnpm instead of the network.
func (c *Client) FetchAbbrevMeta(pkg string) (*AbbrevMeta, error) {
	if m, ok := c.cache[pkg]; ok {
		return m, nil
	}

	if c.Offline {
		meta, err := c.buildOfflineMeta(pkg)
		if err != nil {
			return nil, err
		}
		c.cache[pkg] = meta
		return meta, nil
	}

	url := c.baseURL + "/" + encodePkgPath(pkg)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %q: %w", pkg, err)
	}
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", pkg, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found in registry (404)", pkg)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned HTTP %d for %q", resp.StatusCode, pkg)
	}

	var meta AbbrevMeta
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decode registry response for %q: %w", pkg, err)
	}

	c.cache[pkg] = &meta
	return &meta, nil
}

// encodePkgPath returns the URL path segment for a package name.
// Scoped names encode the slash: @scope/name → @scope%2Fname
func encodePkgPath(pkg string) string {
	if !strings.HasPrefix(pkg, "@") {
		return pkg
	}
	rest := pkg[1:]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return pkg
	}
	return "@" + rest[:slash] + "%2F" + rest[slash+1:]
}
