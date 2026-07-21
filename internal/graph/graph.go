package graph

import (
	"fmt"
	"strings"

	"github.com/user/pnpm-vuln-fixer/internal/lockfile"
)

// Node is a single resolved package instance in the dependency graph.
type Node struct {
	DepPath string // full snapshot key, may include peer suffix
	Name    string // package name (e.g. "@scope/pkg" or "lodash")
	Version string // resolved version without peer suffix
	IsRoot  bool   // true for importer (workspace) nodes
}

// BuildOpts controls which edge types are included in the graph.
type BuildOpts struct {
	IncludeDev      bool // include importer devDependencies edges
	IncludeOptional bool // include optional dependency edges
	IncludePeer     bool // include snapshot peerDependencies edges
}

// Graph holds the full forward+reverse dependency graph.
type Graph struct {
	Nodes         map[string]*Node   // DepPath → Node
	ByBaseVersion map[string][]*Node // "name@version" (no peer suffix) → Nodes
	ByName        map[string][]*Node // package name → all Nodes (all versions)
	Children      map[string][]*Node // DepPath → child Nodes
	Parents       map[string][]*Node // DepPath → parent Nodes
	Roots         []*Node            // importer nodes
}

// ErrPkgNotFound is returned when the named package has no entry in the lockfile.
type ErrPkgNotFound struct{ Pkg string }

func (e *ErrPkgNotFound) Error() string {
	return fmt.Sprintf("package %q not found in lockfile", e.Pkg)
}

// ErrPkgWrongVersion is returned when the package exists but not at the requested version.
type ErrPkgWrongVersion struct {
	Pkg           string
	WantVersion   string
	FoundVersions []string
}

func (e *ErrPkgWrongVersion) Error() string {
	return fmt.Sprintf("package %q found at %v but not at %q", e.Pkg, e.FoundVersions, e.WantVersion)
}

// Build constructs a Graph from a parsed Lockfile using the given options.
func Build(lf *lockfile.Lockfile, opts BuildOpts) *Graph {
	g := &Graph{
		Nodes:         make(map[string]*Node),
		ByBaseVersion: make(map[string][]*Node),
		ByName:        make(map[string][]*Node),
		Children:      make(map[string][]*Node),
		Parents:       make(map[string][]*Node),
	}

	// Root nodes: one per importer workspace path.
	for path := range lf.Importers {
		node := &Node{DepPath: path, Name: path, IsRoot: true}
		g.Nodes[path] = node
		g.Roots = append(g.Roots, node)
	}

	// Snapshot nodes: one per resolved DepPath.
	for depPath := range lf.Snapshots {
		name, version, base := parseDepPath(depPath)
		node := &Node{DepPath: depPath, Name: name, Version: version}
		g.Nodes[depPath] = node
		g.ByBaseVersion[base] = append(g.ByBaseVersion[base], node)
		g.ByName[name] = append(g.ByName[name], node)
	}

	// Track edges already added to avoid duplicates (e.g. same dep in two importers).
	seen := make(map[string]map[string]bool) // child DepPath → set of parent DepPaths
	addEdge := func(parentDP, childDP string) {
		parent := g.Nodes[parentDP]
		child := g.Nodes[childDP]
		if parent == nil || child == nil {
			return
		}
		if seen[childDP] == nil {
			seen[childDP] = make(map[string]bool)
		}
		if seen[childDP][parentDP] {
			return
		}
		seen[childDP][parentDP] = true
		g.Children[parentDP] = append(g.Children[parentDP], child)
		g.Parents[childDP] = append(g.Parents[childDP], parent)
	}

	// Importer → snapshot edges.
	for path, imp := range lf.Importers {
		addDeps := func(deps map[string]*lockfile.DepEntry) {
			for depName, entry := range deps {
				if entry.IsLocal {
					// workspace: and link: deps are local packages; skip registry edge.
					continue
				}
				var childDP string
				if entry.IsAlias {
					// npm: alias: entry.Version is the real package's DepPath ("pkgname@version").
					childDP = entry.Version
				} else {
					childDP = depName + "@" + entry.Version
				}
				addEdge(path, childDP)
			}
		}
		addDeps(imp.Dependencies)
		if opts.IncludeDev {
			addDeps(imp.DevDependencies)
		}
		if opts.IncludeOptional {
			addDeps(imp.OptionalDependencies)
		}
	}

	// Snapshot → snapshot edges.
	for depPath, snap := range lf.Snapshots {
		for childName, childVer := range snap.Dependencies {
			addEdge(depPath, childName+"@"+childVer)
		}
		if opts.IncludeOptional {
			for childName, childVer := range snap.OptionalDependencies {
				addEdge(depPath, childName+"@"+childVer)
			}
		}
		if opts.IncludePeer {
			for childName, childVer := range snap.PeerDependencies {
				addEdge(depPath, childName+"@"+childVer)
			}
		}
	}

	return g
}

// FindVulnerable returns all Nodes whose base identity equals pkg@version.
// Returns ErrPkgWrongVersion if pkg exists at other versions.
// Returns ErrPkgNotFound if pkg is absent entirely.
func FindVulnerable(g *Graph, pkg, version string) ([]*Node, error) {
	key := pkg + "@" + version
	if nodes := g.ByBaseVersion[key]; len(nodes) > 0 {
		return nodes, nil
	}
	if all := g.ByName[pkg]; len(all) > 0 {
		seen := make(map[string]bool)
		var found []string
		for _, n := range all {
			if !seen[n.Version] {
				seen[n.Version] = true
				found = append(found, n.Version)
			}
		}
		return nil, &ErrPkgWrongVersion{Pkg: pkg, WantVersion: version, FoundVersions: found}
	}
	return nil, &ErrPkgNotFound{Pkg: pkg}
}

// PathsToRoot returns all simple paths from start up to importer root nodes,
// oriented as [importer, ..., start]. maxDepth caps the number of upward hops
// from start; 0 means unlimited.
func PathsToRoot(g *Graph, start *Node, maxDepth int) [][]*Node {
	var result [][]*Node
	inPath := make(map[string]bool)

	var dfs func(current *Node, path []*Node)
	dfs = func(current *Node, path []*Node) {
		if current.IsRoot {
			cp := make([]*Node, len(path))
			copy(cp, path)
			for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
				cp[i], cp[j] = cp[j], cp[i]
			}
			result = append(result, cp)
			return
		}
		parents := g.Parents[current.DepPath]
		if len(parents) == 0 {
			return
		}
		hops := len(path) - 1 // hops taken so far (path[0] = start)
		for _, parent := range parents {
			if inPath[parent.DepPath] {
				continue
			}
			if maxDepth > 0 && hops >= maxDepth {
				continue
			}
			inPath[parent.DepPath] = true
			// Use cap-limiting append to avoid aliasing between DFS branches.
			dfs(parent, append(path[:len(path):len(path)], parent))
			inPath[parent.DepPath] = false
		}
	}

	inPath[start.DepPath] = true
	dfs(start, []*Node{start})
	return result
}

// parseDepPath splits a DepPath into (name, version, base) where base omits
// the peer suffix. Handles scoped names (@scope/name@ver).
func parseDepPath(depPath string) (name, version, base string) {
	base = depPath
	if idx := strings.Index(depPath, "("); idx >= 0 {
		base = depPath[:idx]
	}
	if strings.HasPrefix(base, "@") {
		idx := strings.Index(base[1:], "@")
		if idx < 0 {
			return base, "", base
		}
		name = base[:idx+1]
		version = base[idx+2:]
	} else {
		idx := strings.Index(base, "@")
		if idx < 0 {
			return base, "", base
		}
		name = base[:idx]
		version = base[idx+1:]
	}
	return
}
