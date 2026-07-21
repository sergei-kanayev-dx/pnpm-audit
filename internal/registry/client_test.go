package registry_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/user/pnpm-vuln-fixer/internal/registry"
)

// serve returns an httptest.Server that dispatches registry-like requests.
// routes maps URL path → JSON body. Anything else returns 404.
func serve(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
}

func TestFetchAbbrevMeta_Simple(t *testing.T) {
	srv := serve(t, map[string]string{
		"/lodash": `{"name":"lodash","versions":{"4.17.10":{"dependencies":{}},"4.17.21":{"dependencies":{}}}}`,
	})
	defer srv.Close()

	c := registry.NewClient(srv.URL)
	meta, err := c.FetchAbbrevMeta("lodash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Name != "lodash" {
		t.Errorf("name = %q, want %q", meta.Name, "lodash")
	}
	if len(meta.Versions) != 2 {
		t.Errorf("len(versions) = %d, want 2", len(meta.Versions))
	}
	if _, ok := meta.Versions["4.17.21"]; !ok {
		t.Error("missing version 4.17.21")
	}
}

func TestFetchAbbrevMeta_ScopedName(t *testing.T) {
	var gotRawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RawPath preserves percent-encoding; fall back to Path when not set.
		gotRawPath = r.URL.RawPath
		if gotRawPath == "" {
			gotRawPath = r.URL.Path
		}
		body := `{"name":"@babel/traverse","versions":{"7.22.0":{"dependencies":{}}}}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := registry.NewClient(srv.URL)
	meta, err := c.FetchAbbrevMeta("@babel/traverse")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Name != "@babel/traverse" {
		t.Errorf("name = %q", meta.Name)
	}
	// The slash between scope and name must be percent-encoded in the URL path.
	wantPath := "/@babel%2Ftraverse"
	if gotRawPath != wantPath {
		t.Errorf("request raw path = %q, want %q", gotRawPath, wantPath)
	}
}

func TestFetchAbbrevMeta_CacheHit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"lodash","versions":{}}`))
	}))
	defer srv.Close()

	c := registry.NewClient(srv.URL)
	if _, err := c.FetchAbbrevMeta("lodash"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.FetchAbbrevMeta("lodash"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("server called %d times, want 1 (cache should prevent second call)", calls)
	}
}

func TestFetchAbbrevMeta_NotFound(t *testing.T) {
	srv := serve(t, map[string]string{})
	defer srv.Close()

	c := registry.NewClient(srv.URL)
	_, err := c.FetchAbbrevMeta("no-such-package")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestFetchAbbrevMeta_AcceptHeader(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"lodash","versions":{}}`))
	}))
	defer srv.Close()

	c := registry.NewClient(srv.URL)
	if _, err := c.FetchAbbrevMeta("lodash"); err != nil {
		t.Fatal(err)
	}
	if gotAccept == "" {
		t.Error("Accept header not sent")
	}
}

func TestFetchAbbrevMeta_DependenciesPopulated(t *testing.T) {
	body := `{
		"name": "express",
		"versions": {
			"4.16.0": {
				"dependencies": { "lodash": "~4.17.4" }
			}
		}
	}`
	srv := serve(t, map[string]string{"/express": body})
	defer srv.Close()

	c := registry.NewClient(srv.URL)
	meta, err := c.FetchAbbrevMeta("express")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v := meta.Versions["4.16.0"]
	if v == nil {
		t.Fatal("version 4.16.0 missing")
	}
	if v.Dependencies["lodash"] != "~4.17.4" {
		t.Errorf("lodash range = %q, want %q", v.Dependencies["lodash"], "~4.17.4")
	}
}

func TestFetchOffline(t *testing.T) {
	// Build a temporary node_modules/.pnpm tree.
	tmpDir := t.TempDir()
	pv := registry.PackageVersion{
		Dependencies: map[string]string{"lodash": "^4.17.0"},
	}
	pkgDir := filepath.Join(tmpDir, "node_modules", ".pnpm", "express@4.16.0", "node_modules", "express")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(pkgDir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(f).Encode(pv); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c := registry.NewClient("http://unused")
	c.NodeModDir = tmpDir

	got, err := c.FetchOffline("express", "4.16.0")
	if err != nil {
		t.Fatalf("FetchOffline: %v", err)
	}
	if got.Dependencies["lodash"] != "^4.17.0" {
		t.Errorf("lodash = %q, want %q", got.Dependencies["lodash"], "^4.17.0")
	}
}

func TestFetchOffline_ScopedPackage(t *testing.T) {
	tmpDir := t.TempDir()
	pv := registry.PackageVersion{
		Dependencies: map[string]string{"semver": "^7.0.0"},
	}
	// Scoped: @babel/traverse@7.22.0 → .pnpm/babel+traverse@7.22.0/node_modules/@babel/traverse/
	pkgDir := filepath.Join(tmpDir, "node_modules", ".pnpm", "babel+traverse@7.22.0", "node_modules", "@babel", "traverse")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(pkgDir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(f).Encode(pv); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c := registry.NewClient("http://unused")
	c.NodeModDir = tmpDir

	got, err := c.FetchOffline("@babel/traverse", "7.22.0")
	if err != nil {
		t.Fatalf("FetchOffline scoped: %v", err)
	}
	if got.Dependencies["semver"] != "^7.0.0" {
		t.Errorf("semver = %q, want %q", got.Dependencies["semver"], "^7.0.0")
	}
}

func TestFetchOffline_MissingFile(t *testing.T) {
	c := registry.NewClient("http://unused")
	c.NodeModDir = t.TempDir()

	_, err := c.FetchOffline("nonexistent", "1.0.0")
	if err == nil {
		t.Error("expected error for missing package.json")
	}
}
