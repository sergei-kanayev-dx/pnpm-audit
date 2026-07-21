package graph_test

import (
	"errors"
	"testing"

	"github.com/user/pnpm-vuln-fixer/internal/graph"
	"github.com/user/pnpm-vuln-fixer/internal/lockfile"
)

// makeSimpleLF builds a lockfile:
//   importer "." → express@4.18.2 → lodash@4.17.10
//   importer "." --dev--> lodash@4.17.21
func makeSimpleLF() *lockfile.Lockfile {
	return &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".": {
				Dependencies: map[string]*lockfile.DepEntry{
					"express": {Specifier: "^4.18.0", Version: "4.18.2"},
				},
				DevDependencies: map[string]*lockfile.DepEntry{
					"lodash": {Specifier: "^4.17.21", Version: "4.17.21"},
				},
			},
		},
		Snapshots: map[string]*lockfile.Snapshot{
			"express@4.18.2":  {Dependencies: map[string]string{"lodash": "4.17.10"}},
			"lodash@4.17.10":  {},
			"lodash@4.17.21":  {},
		},
	}
}

// makeMultiParentLF builds:
//   "." → A@1.0.0 → C@1.0.0
//   "." → B@1.0.0 → C@1.0.0
func makeMultiParentLF() *lockfile.Lockfile {
	return &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".": {
				Dependencies: map[string]*lockfile.DepEntry{
					"a": {Version: "1.0.0"},
					"b": {Version: "1.0.0"},
				},
			},
		},
		Snapshots: map[string]*lockfile.Snapshot{
			"a@1.0.0": {Dependencies: map[string]string{"c": "1.0.0"}},
			"b@1.0.0": {Dependencies: map[string]string{"c": "1.0.0"}},
			"c@1.0.0": {},
		},
	}
}

// makeDeepLF builds: "." → a@1 → b@1 → c@1 → d@1 (4 hops to root)
func makeDeepLF() *lockfile.Lockfile {
	return &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".": {
				Dependencies: map[string]*lockfile.DepEntry{
					"a": {Version: "1.0.0"},
				},
			},
		},
		Snapshots: map[string]*lockfile.Snapshot{
			"a@1.0.0": {Dependencies: map[string]string{"b": "1.0.0"}},
			"b@1.0.0": {Dependencies: map[string]string{"c": "1.0.0"}},
			"c@1.0.0": {Dependencies: map[string]string{"d": "1.0.0"}},
			"d@1.0.0": {},
		},
	}
}

// makeCycleLF builds: "." → a@1 → b@1 → a@1 (cycle)
func makeCycleLF() *lockfile.Lockfile {
	return &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".": {
				Dependencies: map[string]*lockfile.DepEntry{
					"a": {Version: "1.0.0"},
				},
			},
		},
		Snapshots: map[string]*lockfile.Snapshot{
			"a@1.0.0": {Dependencies: map[string]string{"b": "1.0.0"}},
			"b@1.0.0": {Dependencies: map[string]string{"a": "1.0.0"}},
		},
	}
}

// makeScopedLF builds: "." → @scope/pkg@1.0.0 → util@2.0.0
func makeScopedLF() *lockfile.Lockfile {
	return &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".": {
				Dependencies: map[string]*lockfile.DepEntry{
					"@scope/pkg": {Version: "1.0.0"},
				},
			},
		},
		Snapshots: map[string]*lockfile.Snapshot{
			"@scope/pkg@1.0.0": {Dependencies: map[string]string{"util": "2.0.0"}},
			"util@2.0.0":       {},
		},
	}
}

// makePeerLF builds:
//   "." → react@18.2.0 → loose-envify@1.4.0
//   "." → react-dom@18.2.0(react@18.2.0) → react@18.2.0 → loose-envify@1.4.0
// (react-dom does NOT directly list loose-envify, only through react)
func makePeerLF() *lockfile.Lockfile {
	return &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".": {
				Dependencies: map[string]*lockfile.DepEntry{
					"react":     {Version: "18.2.0"},
					"react-dom": {Version: "18.2.0(react@18.2.0)"},
				},
			},
		},
		Snapshots: map[string]*lockfile.Snapshot{
			"react@18.2.0":                    {Dependencies: map[string]string{"loose-envify": "1.4.0"}},
			"react-dom@18.2.0(react@18.2.0)": {Dependencies: map[string]string{"react": "18.2.0"}},
			"loose-envify@1.4.0":              {},
		},
	}
}

var allOpts = graph.BuildOpts{IncludeDev: true, IncludeOptional: true}

// ---- Build tests --------------------------------------------------------

func TestBuildNodeCount(t *testing.T) {
	g := graph.Build(makeSimpleLF(), allOpts)
	// 1 importer + 3 snapshots = 4 nodes
	if len(g.Nodes) != 4 {
		t.Errorf("len(Nodes) = %d, want 4", len(g.Nodes))
	}
	if len(g.Roots) != 1 {
		t.Errorf("len(Roots) = %d, want 1", len(g.Roots))
	}
	if !g.Roots[0].IsRoot {
		t.Error("root node IsRoot = false")
	}
}

func TestBuildEdgesSimple(t *testing.T) {
	g := graph.Build(makeSimpleLF(), allOpts)
	// "." should have 2 children (express + lodash dev)
	if len(g.Children["."]) != 2 {
		t.Errorf("children of '.' = %d, want 2", len(g.Children["."]))
	}
	// express@4.18.2 should have 1 child: lodash@4.17.10
	if len(g.Children["express@4.18.2"]) != 1 {
		t.Errorf("children of express@4.18.2 = %d, want 1", len(g.Children["express@4.18.2"]))
	}
	// lodash@4.17.10 parent is express@4.18.2
	parents := g.Parents["lodash@4.17.10"]
	if len(parents) != 1 {
		t.Fatalf("parents of lodash@4.17.10 = %d, want 1", len(parents))
	}
	if parents[0].DepPath != "express@4.18.2" {
		t.Errorf("parent = %q, want express@4.18.2", parents[0].DepPath)
	}
}

func TestBuildExcludeDevEdge(t *testing.T) {
	opts := graph.BuildOpts{IncludeDev: false, IncludeOptional: false}
	g := graph.Build(makeSimpleLF(), opts)
	// "." should have only 1 child (express, not the dev lodash)
	if len(g.Children["."]) != 1 {
		t.Errorf("children of '.' without dev = %d, want 1", len(g.Children["."]))
	}
}

func TestBuildPeerSuffixNode(t *testing.T) {
	g := graph.Build(makePeerLF(), graph.BuildOpts{})
	n, ok := g.Nodes["react-dom@18.2.0(react@18.2.0)"]
	if !ok {
		t.Fatal("node react-dom@18.2.0(react@18.2.0) missing")
	}
	if n.Name != "react-dom" {
		t.Errorf("Name = %q, want react-dom", n.Name)
	}
	if n.Version != "18.2.0" {
		t.Errorf("Version = %q, want 18.2.0", n.Version)
	}
}

func TestBuildByBaseVersionIndexPeerSuffix(t *testing.T) {
	g := graph.Build(makePeerLF(), graph.BuildOpts{})
	nodes := g.ByBaseVersion["react-dom@18.2.0"]
	if len(nodes) != 1 {
		t.Fatalf("ByBaseVersion[react-dom@18.2.0] = %d, want 1", len(nodes))
	}
	if nodes[0].DepPath != "react-dom@18.2.0(react@18.2.0)" {
		t.Errorf("DepPath = %q", nodes[0].DepPath)
	}
}

func TestBuildDeduplicatesEdges(t *testing.T) {
	// Two importers depend on the same snapshot; edges must not be duplicated.
	lf := &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".":     {Dependencies: map[string]*lockfile.DepEntry{"shared": {Version: "1.0.0"}}},
			"pkgs/a": {Dependencies: map[string]*lockfile.DepEntry{"shared": {Version: "1.0.0"}}},
		},
		Snapshots: map[string]*lockfile.Snapshot{
			"shared@1.0.0": {},
		},
	}
	g := graph.Build(lf, graph.BuildOpts{})
	parents := g.Parents["shared@1.0.0"]
	if len(parents) != 2 {
		t.Errorf("parents of shared@1.0.0 = %d, want 2 (one per importer)", len(parents))
	}
}

// ---- FindVulnerable tests -----------------------------------------------

func TestFindVulnerableFound(t *testing.T) {
	g := graph.Build(makeSimpleLF(), allOpts)
	nodes, err := graph.FindVulnerable(g, "lodash", "4.17.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 || nodes[0].DepPath != "lodash@4.17.10" {
		t.Errorf("nodes = %v", nodes)
	}
}

func TestFindVulnerableWrongVersion(t *testing.T) {
	g := graph.Build(makeSimpleLF(), allOpts)
	_, err := graph.FindVulnerable(g, "lodash", "4.17.99")
	var wv *graph.ErrPkgWrongVersion
	if !errors.As(err, &wv) {
		t.Fatalf("want ErrPkgWrongVersion, got %T: %v", err, err)
	}
	if wv.WantVersion != "4.17.99" {
		t.Errorf("WantVersion = %q", wv.WantVersion)
	}
	if len(wv.FoundVersions) == 0 {
		t.Error("FoundVersions is empty")
	}
}

func TestFindVulnerableNotFound(t *testing.T) {
	g := graph.Build(makeSimpleLF(), allOpts)
	_, err := graph.FindVulnerable(g, "nonexistent", "1.0.0")
	var nf *graph.ErrPkgNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("want ErrPkgNotFound, got %T: %v", err, err)
	}
}

func TestFindVulnerableScoped(t *testing.T) {
	g := graph.Build(makeScopedLF(), allOpts)
	nodes, err := graph.FindVulnerable(g, "@scope/pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 || nodes[0].DepPath != "@scope/pkg@1.0.0" {
		t.Errorf("nodes = %v", nodes)
	}
}

func TestFindVulnerablePeerMultipleNodes(t *testing.T) {
	// Two DepPaths for the same base: loose-envify@1.4.0 appears once (no peer suffix),
	// but react-dom@18.2.0 appears with peer suffix.
	g := graph.Build(makePeerLF(), graph.BuildOpts{})
	nodes, err := graph.FindVulnerable(g, "loose-envify", "1.4.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodes))
	}
}

// ---- PathsToRoot tests --------------------------------------------------

func depPaths(paths [][]*graph.Node) [][]string {
	out := make([][]string, len(paths))
	for i, p := range paths {
		out[i] = make([]string, len(p))
		for j, n := range p {
			out[j] = append(out[j][:0:0], n.DepPath) // reuse storage via overwrite is safe
			out[i][j] = n.DepPath
		}
	}
	return out
}

func TestPathsToRootSingleParent(t *testing.T) {
	g := graph.Build(makeSimpleLF(), allOpts)
	node := g.Nodes["lodash@4.17.10"]
	paths := graph.PathsToRoot(g, node, 0)
	if len(paths) != 1 {
		t.Fatalf("len(paths) = %d, want 1", len(paths))
	}
	p := paths[0]
	if len(p) != 3 {
		t.Fatalf("path length = %d, want 3", len(p))
	}
	if p[0].DepPath != "." {
		t.Errorf("path[0] = %q, want .", p[0].DepPath)
	}
	if p[1].DepPath != "express@4.18.2" {
		t.Errorf("path[1] = %q, want express@4.18.2", p[1].DepPath)
	}
	if p[2].DepPath != "lodash@4.17.10" {
		t.Errorf("path[2] = %q, want lodash@4.17.10", p[2].DepPath)
	}
}

func TestPathsToRootMultiParent(t *testing.T) {
	g := graph.Build(makeMultiParentLF(), graph.BuildOpts{})
	node := g.Nodes["c@1.0.0"]
	paths := graph.PathsToRoot(g, node, 0)
	if len(paths) != 2 {
		t.Fatalf("len(paths) = %d, want 2", len(paths))
	}
	// Each path must start at "." and end at "c@1.0.0".
	for i, p := range paths {
		if p[0].DepPath != "." {
			t.Errorf("path %d first = %q, want .", i, p[0].DepPath)
		}
		if p[len(p)-1].DepPath != "c@1.0.0" {
			t.Errorf("path %d last = %q, want c@1.0.0", i, p[len(p)-1].DepPath)
		}
	}
}

func TestPathsToRootCycle(t *testing.T) {
	g := graph.Build(makeCycleLF(), graph.BuildOpts{})
	node := g.Nodes["b@1.0.0"]
	// Should terminate and return the one valid path: [. → a@1.0.0 → b@1.0.0]
	paths := graph.PathsToRoot(g, node, 0)
	if len(paths) != 1 {
		t.Fatalf("len(paths) = %d, want 1 (cycle must be detected)", len(paths))
	}
	p := paths[0]
	if p[0].DepPath != "." || p[len(p)-1].DepPath != "b@1.0.0" {
		t.Errorf("unexpected path: %v", p)
	}
}

func TestPathsToRootMaxDepth(t *testing.T) {
	// Deep chain: . → a → b → c → d (4 hops)
	g := graph.Build(makeDeepLF(), graph.BuildOpts{})
	node := g.Nodes["d@1.0.0"]

	// maxDepth=2 from d: can reach at most b@1.0.0 but not "." (needs 4 hops)
	paths := graph.PathsToRoot(g, node, 2)
	if len(paths) != 0 {
		t.Errorf("maxDepth=2 should yield 0 paths, got %d", len(paths))
	}

	// maxDepth=4 allows reaching "."
	paths = graph.PathsToRoot(g, node, 4)
	if len(paths) != 1 {
		t.Fatalf("maxDepth=4 should yield 1 path, got %d", len(paths))
	}
	if len(paths[0]) != 5 {
		t.Errorf("path length = %d, want 5", len(paths[0]))
	}
}

func TestPathsToRootNoPath(t *testing.T) {
	// Isolated node: exists in snapshots but nothing references it.
	lf := &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".": {Dependencies: map[string]*lockfile.DepEntry{"a": {Version: "1.0.0"}}},
		},
		Snapshots: map[string]*lockfile.Snapshot{
			"a@1.0.0":    {},
			"orphan@1.0": {},
		},
	}
	g := graph.Build(lf, graph.BuildOpts{})
	node := g.Nodes["orphan@1.0"]
	paths := graph.PathsToRoot(g, node, 0)
	if len(paths) != 0 {
		t.Errorf("isolated node should have 0 paths, got %d", len(paths))
	}
}

func TestPathsToRootPeerSuffix(t *testing.T) {
	g := graph.Build(makePeerLF(), graph.BuildOpts{})
	// loose-envify@1.4.0 is reachable via both react@18.2.0 and react-dom@18.2.0(react@18.2.0)
	node := g.Nodes["loose-envify@1.4.0"]
	paths := graph.PathsToRoot(g, node, 0)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths to root, got %d", len(paths))
	}
	for _, p := range paths {
		if p[0].DepPath != "." {
			t.Errorf("path does not start at '.', got %q", p[0].DepPath)
		}
		if p[len(p)-1].DepPath != "loose-envify@1.4.0" {
			t.Errorf("path does not end at loose-envify@1.4.0")
		}
	}
}
