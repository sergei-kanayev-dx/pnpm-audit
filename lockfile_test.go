package main

import (
	"strings"
	"testing"
)

func TestBareVersion(t *testing.T) {
	tests := []struct{ in, want string }{
		{"4.17.21", "4.17.21"},
		{"5.4.21(@types/node@22.20.1)", "5.4.21"},
		// Peer suffixes nest, so the cut must be at the first paren.
		{"2.1.9(@types/node@22.20.1)(jsdom@25.0.1(supports-color@7.2.0))", "2.1.9"},
		{"link:../shared", "link:../shared"},
	}
	for _, tt := range tests {
		if got := bareVersion(tt.in); got != tt.want {
			t.Errorf("bareVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLinkTarget(t *testing.T) {
	tests := []struct{ from, version, want string }{
		{"backend", "link:../shared", "shared"},
		{"packages/a", "link:../b", "packages/b"},
		{".", "link:packages/x", "packages/x"},
		{"backend", "link:..", "."},
	}
	for _, tt := range tests {
		if got := linkTarget(tt.from, tt.version); got != tt.want {
			t.Errorf("linkTarget(%q, %q) = %q, want %q", tt.from, tt.version, got, tt.want)
		}
	}
}

// fixture mirrors the shapes verified in a real pnpm 9 lockfile: a "." root importer,
// a workspace-to-workspace "link:" edge, and peer-suffixed snapshot keys.
func fixture() *lockfile {
	return &lockfile{
		Importers: map[string]importer{
			".": {
				DevDependencies: map[string]importerDep{
					"typescript": {Specifier: "^5.6.3", Version: "5.9.3"},
				},
			},
			"backend": {
				Dependencies: map[string]importerDep{
					"@app/shared": {Specifier: "workspace:*", Version: "link:../shared"},
					"vite":        {Specifier: "^5.0.0", Version: "5.4.21(@types/node@22.20.1)"},
				},
				OptionalDependencies: map[string]importerDep{
					"fsevents": {Specifier: "^2.3.3", Version: "2.3.3"},
				},
			},
			"shared": {
				Dependencies: map[string]importerDep{
					"ajv": {Specifier: "^8.0.0", Version: "8.20.0"},
				},
			},
			// A nested importer: audit paths spell this one "apps__dev-app".
			"apps/dev-app": {
				Dependencies: map[string]importerDep{
					"postcss": {Specifier: "catalog:", Version: "8.5.26"},
					"rxjs":    {Specifier: "catalog:angular", Version: "7.8.2"},
					"lodash":  {Specifier: "catalog:missing", Version: "4.17.21"},
				},
			},
		},
		Catalogs: map[string]map[string]catalog{
			"default": {"postcss": {Specifier: "^8.5.0"}},
			"angular": {"rxjs": {Specifier: "~7.8.0"}},
		},
		Snapshots: map[string]snapshot{
			"vite@5.4.21(@types/node@22.20.1)": {
				Dependencies:         map[string]string{"postcss": "8.5.26"},
				OptionalDependencies: map[string]string{"fsevents": "2.3.3"},
			},
			"ajv@8.20.0": {
				Dependencies: map[string]string{"fast-uri": "3.1.5"},
			},
		},
	}
}

// render reduces a chain to "name@version wants range" per hop so assertions stay
// readable; "-" stands for an unresolved field.
func render(hops []hop) string {
	var parts []string
	for _, h := range hops {
		parts = append(parts, h.Name+"@"+dash(h.Version)+" wants "+dash(h.Range))
	}
	return strings.Join(parts, " | ")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func TestBuildChain(t *testing.T) {
	l := fixture()

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "root importer",
			path: ".>typescript",
			want: ".@- wants - | typescript@5.9.3 wants ^5.6.3",
		},
		{
			// The peer suffix must be stripped for display but kept as the snapshot key.
			name: "peer suffixed snapshot key",
			path: "backend>vite>postcss",
			want: "backend@- wants - | vite@5.4.21 wants ^5.0.0 | postcss@8.5.26 wants -",
		},
		{
			// A "link:" edge stays in importer context, so ajv's range still comes
			// from the shared package's package.json rather than the registry.
			name: "workspace link edge",
			path: "backend>@app/shared>ajv>fast-uri",
			want: "backend@- wants - | @app/shared@- wants workspace:* | ajv@8.20.0 wants ^8.0.0 | fast-uri@3.1.5 wants -",
		},
		{
			name: "optional dependency edge",
			path: "backend>vite>fsevents",
			want: "backend@- wants - | vite@5.4.21 wants ^5.0.0 | fsevents@2.3.3 wants -",
		},
		{
			// An unknown segment must not abort the walk.
			name: "unresolvable segment",
			path: "backend>nope>deeper",
			want: "backend@- wants - | nope@- wants - | deeper@- wants -",
		},
		{
			name: "unknown importer",
			path: "ghost>vite",
			want: "ghost@- wants - | vite@- wants -",
		},
		{
			// pnpm reports "apps/dev-app" as "apps__dev-app"; without mapping it
			// back, every hop below the importer resolves to nothing.
			name: "nested importer id mangled by the audit endpoint",
			path: "apps__dev-app>postcss",
			want: "apps/dev-app@- wants - | postcss@8.5.26 wants ^8.5.0",
		},
		{
			name: "named catalog specifier",
			path: "apps__dev-app>rxjs",
			want: "apps/dev-app@- wants - | rxjs@7.8.2 wants ~7.8.0",
		},
		{
			// Nothing to resolve it to, so the indirection is shown as written
			// rather than reported as unknown.
			name: "catalog entry missing",
			path: "apps__dev-app>lodash",
			want: "apps/dev-app@- wants - | lodash@4.17.21 wants catalog:missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := render(buildChain(l, tt.path)); got != tt.want {
				t.Errorf("buildChain(%q)\n got: %s\nwant: %s", tt.path, got, tt.want)
			}
		})
	}
}

func TestBuildChainRejectsSingleSegment(t *testing.T) {
	if got := buildChain(fixture(), "backend"); got != nil {
		t.Errorf("buildChain with no dependency segment = %v, want nil", got)
	}
}

// Registry lookups are needed only inside the package graph; workspace edges already
// carry their range, and hops whose parent version is unknown cannot be looked up.
func TestBuildChainMarksOnlyRegistryEdges(t *testing.T) {
	l := fixture()

	chain := buildChain(l, "backend>vite>postcss")
	for i, h := range chain[:2] {
		if h.parentName != "" {
			t.Errorf("hop %d (%s) wants a registry lookup, but its range comes from the lockfile", i, h.Name)
		}
	}
	last := chain[2]
	if last.parentName != "vite" || last.parentVersion != "5.4.21" {
		t.Errorf("postcss parent = %s@%s, want vite@5.4.21", last.parentName, last.parentVersion)
	}

	// The link: edge keeps the walk in importer context, so nothing in it is a lookup.
	for i, h := range buildChain(l, "backend>@app/shared>ajv") {
		if h.parentName != "" {
			t.Errorf("hop %d (%s) in a workspace chain should not need a registry lookup", i, h.Name)
		}
	}
}

func TestParseLockfile(t *testing.T) {
	// Verbatim shapes from a lockfileVersion 9 file.
	const src = "lockfileVersion: '9.0'\n" +
		"\n" +
		"importers:\n" +
		"\n" +
		"  .:\n" +
		"    devDependencies:\n" +
		"      typescript:\n" +
		"        specifier: ^5.6.3\n" +
		"        version: 5.9.3\n" +
		"\n" +
		"  backend:\n" +
		"    dependencies:\n" +
		"      '@app/shared':\n" +
		"        specifier: workspace:*\n" +
		"        version: link:../shared\n" +
		"\n" +
		"snapshots:\n" +
		"\n" +
		"  'vite@5.4.21(@types/node@22.20.1)':\n" +
		"    dependencies:\n" +
		"      postcss: 8.5.26\n"

	l, err := parseLockfile([]byte(src))
	if err != nil {
		t.Fatalf("parseLockfile: %v", err)
	}

	if d, ok := l.dep(".", "typescript"); !ok || d.Specifier != "^5.6.3" || d.Version != "5.9.3" {
		t.Errorf("root importer dep = %+v (ok=%v), want {^5.6.3 5.9.3}", d, ok)
	}
	if d, _ := l.dep("backend", "@app/shared"); d.Version != "link:../shared" {
		t.Errorf("scoped workspace dep version = %q, want link:../shared", d.Version)
	}
	if v, ok := l.snapshotDep("vite@5.4.21(@types/node@22.20.1)", "postcss"); !ok || v != "8.5.26" {
		t.Errorf("snapshot dep = %q (ok=%v), want 8.5.26", v, ok)
	}
}

func TestImporterKey(t *testing.T) {
	l := fixture()

	tests := []struct{ in, want string }{
		{"backend", "backend"}, // unnested ids arrive verbatim
		{".", "."},             // so does the workspace root
		{"apps__dev-app", "apps/dev-app"},
		{"apps/dev-app", "apps/dev-app"}, // an unmangled id still resolves
		{"ghost", ""},
		{"apps__ghost", ""},
	}
	for _, tt := range tests {
		if got := l.importerKey(tt.in); got != tt.want {
			t.Errorf("importerKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// An importer whose own directory name contains "__" must win over one that merely
// mangles to the same string, since the report spells the former verbatim.
func TestImporterKeyPrefersExactMatch(t *testing.T) {
	l := &lockfile{Importers: map[string]importer{"a__b": {}, "a/b": {}}}
	if got := l.importerKey("a__b"); got != "a__b" {
		t.Errorf("importerKey(a__b) = %q, want a__b", got)
	}
}

func TestCatalogRange(t *testing.T) {
	l := fixture()

	tests := []struct{ name, spec, want string }{
		{"postcss", "catalog:", "^8.5.0"},
		{"rxjs", "catalog:angular", "~7.8.0"},
		{"postcss", "^8.0.0", "^8.0.0"},        // a plain range passes through
		{"vite", "workspace:*", "workspace:*"}, // so does a workspace protocol
		{"nope", "catalog:", "catalog:"},       // unresolvable: shown as written
	}
	for _, tt := range tests {
		if got := l.catalogRange(tt.name, tt.spec); got != tt.want {
			t.Errorf("catalogRange(%q, %q) = %q, want %q", tt.name, tt.spec, got, tt.want)
		}
	}
}

// The fix report has to name the package.json that declares a range, and a "link:" edge
// keeps the walk in importer context -- so the declaring workspace is not always the
// first segment of the path.
func TestBuildChainAttributesRangesToTheDeclaringImporter(t *testing.T) {
	l := fixture()

	tests := []struct {
		name string
		path string
		want []string // ImporterKey per hop, "-" when the hop carries no workspace range
	}{
		{
			name: "direct dependency of the importer named in the path",
			path: "backend>vite>postcss",
			want: []string{"-", "backend", "-"},
		},
		{
			// ajv is declared by shared/package.json, not by backend's.
			name: "across a workspace link",
			path: "backend>@app/shared>ajv>fast-uri",
			want: []string{"-", "backend", "shared", "-"},
		},
		{
			name: "nested importer",
			path: "apps__dev-app>postcss",
			want: []string{"-", "apps/dev-app"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hops := buildChain(l, tt.path)
			if len(hops) != len(tt.want) {
				t.Fatalf("got %d hops, want %d", len(hops), len(tt.want))
			}
			for i, want := range tt.want {
				if got := dash(hops[i].ImporterKey); got != want {
					t.Errorf("hop %d (%s) importer = %s, want %s", i, hops[i].Name, got, want)
				}
			}
		})
	}
}
