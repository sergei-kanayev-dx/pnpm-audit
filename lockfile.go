package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpm-lock.yaml (lockfileVersion 9) already holds everything needed to resolve an
// audit usage path to the versions actually on disk: `importers` maps each workspace
// directory to its declared dependencies — carrying both the package.json range and
// the resolved version — and `snapshots` holds the resolved graph for every package.
//
// Only the fields used here are declared; yaml.v3 ignores the rest.
type lockfile struct {
	Importers map[string]importer           `yaml:"importers"`
	Snapshots map[string]snapshot           `yaml:"snapshots"`
	Catalogs  map[string]map[string]catalog `yaml:"catalogs"`

	// mangled maps an audit-report importer id back to its lockfile key; see
	// importerKey. Built on first use, which is single-threaded.
	mangled map[string]string
}

type importer struct {
	Dependencies         map[string]importerDep `yaml:"dependencies"`
	DevDependencies      map[string]importerDep `yaml:"devDependencies"`
	OptionalDependencies map[string]importerDep `yaml:"optionalDependencies"`
}

type importerDep struct {
	Specifier string `yaml:"specifier"` // the range exactly as written in package.json
	Version   string `yaml:"version"`   // resolved; "link:../shared" for workspace deps
}

// catalog is one entry of the lockfile's catalogs section, which holds the real range
// behind every "catalog:" specifier.
type catalog struct {
	Specifier string `yaml:"specifier"`
}

type snapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

func loadLockfile(dir string) (*lockfile, error) {
	p := filepath.Join(dir, "pnpm-lock.yaml")
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no lockfile at %s - run `pnpm install` there first", p)
		}
		return nil, fmt.Errorf("reading %s: %w", p, err)
	}

	l, err := parseLockfile(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return l, nil
}

func parseLockfile(raw []byte) (*lockfile, error) {
	var l lockfile
	if err := yaml.Unmarshal(raw, &l); err != nil {
		return nil, err
	}
	if len(l.Importers) == 0 {
		return nil, errors.New("no importers section; is it a pnpm 9+ lockfile?")
	}
	return &l, nil
}

// importerKey maps the first segment of an audit usage path back to a lockfile
// importer key, returning "" when no importer matches.
//
// pnpm submits importer ids to the audit endpoint with every "/" replaced by "__",
// because the registry rejects a tree whose keys contain slashes. Paths therefore come
// back naming "apps__dev-app" where the lockfile says "apps/dev-app", and a nested
// workspace would otherwise resolve to nothing -- taking every version and range below
// it down with it.
func (l *lockfile) importerKey(seg string) string {
	// An unnested importer ("backend", ".") is reported verbatim.
	if _, ok := l.Importers[seg]; ok {
		return seg
	}

	if l.mangled == nil {
		l.mangled = make(map[string]string, len(l.Importers))
		for k := range l.Importers {
			m := strings.ReplaceAll(k, "/", "__")
			if m == k {
				continue
			}
			// Two keys can mangle alike ("a/b" and "a__b"); pick one deterministically.
			if prev, ok := l.mangled[m]; !ok || k < prev {
				l.mangled[m] = k
			}
		}
	}
	return l.mangled[seg]
}

// catalogRange resolves a "catalog:" or "catalog:<name>" specifier to the range the
// catalog actually declares. pnpm stores only the indirection on the importer entry and
// keeps the range in the lockfile's catalogs section, so the specifier alone says
// nothing about which versions are allowed. Any other specifier is returned unchanged,
// as is one naming a catalog entry that is missing.
func (l *lockfile) catalogRange(name, specifier string) string {
	cat, ok := strings.CutPrefix(specifier, "catalog:")
	if !ok {
		return specifier
	}
	if cat == "" {
		cat = "default"
	}
	if e, ok := l.Catalogs[cat][name]; ok && e.Specifier != "" {
		return e.Specifier
	}
	return specifier
}

// dep looks up a direct dependency of a workspace importer. Audit paths traverse dev
// and optional edges as readily as regular ones, so all three maps are searched.
func (l *lockfile) dep(importerKey, child string) (importerDep, bool) {
	imp, ok := l.Importers[importerKey]
	if !ok {
		return importerDep{}, false
	}
	for _, m := range []map[string]importerDep{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
		if d, ok := m[child]; ok {
			return d, true
		}
	}
	return importerDep{}, false
}

// snapshotDep resolves child's version inside an already-resolved package.
func (l *lockfile) snapshotDep(snapKey, child string) (string, bool) {
	s, ok := l.Snapshots[snapKey]
	if !ok {
		return "", false
	}
	for _, m := range []map[string]string{s.Dependencies, s.OptionalDependencies} {
		if v, ok := m[child]; ok {
			return v, true
		}
	}
	return "", false
}

// bareVersion strips the peer-dependency suffix pnpm appends to snapshot keys, e.g.
// "2.1.9(@types/node@22.20.1)(jsdom@25.0.1(supports-color@7.2.0))" -> "2.1.9".
// The suffixes nest, so the cut is at the first "(" rather than a paren match.
func bareVersion(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		return v[:i]
	}
	return v
}

// linkTarget resolves a "link:../shared" version to the importer key of the workspace
// package it points at. Importer keys are slash-separated paths relative to the
// workspace root, with the root itself spelled ".".
func linkTarget(fromImporter, version string) string {
	rel := strings.TrimPrefix(version, "link:")
	if fromImporter == "." {
		fromImporter = ""
	}
	switch joined := path.Join(fromImporter, rel); joined {
	case "", ".":
		return "."
	default:
		return joined
	}
}

// hop is one step along a usage path: the package at that level, the version actually
// installed, and the range its parent declares for it.
type hop struct {
	Name      string
	Version   string // bare installed version; "" when it could not be resolved
	Range     string // range the parent declares; "" at the root or when unknown
	Workspace bool   // a workspace importer rather than a package from the registry

	// ImporterKey names the workspace whose package.json declares Range, and is set only
	// on a workspace edge. A "link:" edge keeps the walk in importer context, so the
	// declaring workspace is not always the first segment of the path -- without this the
	// fix report cannot say which package.json to edit.
	ImporterKey string

	// parentName/parentVersion identify the package whose manifest declares Range.
	// They are set only when the range still has to be fetched from the registry --
	// workspace edges carry their range in the lockfile already.
	parentName    string
	parentVersion string
}

// buildChain expands one ">"-joined usage path into a hop per segment, resolving each
// version from the lockfile. The first segment is a workspace importer directory
// (e.g. "backend", or "." for the workspace root), not a package name.
//
// A segment that cannot be resolved does not abort the walk: its hop is left blank and
// the remaining hops render as unknown, which is more useful than dropping the path.
func buildChain(l *lockfile, usagePath string) []hop {
	segs := strings.Split(usagePath, ">")
	if len(segs) < 2 {
		return nil
	}

	// The audit report spells a nested importer id with "__" for "/", so resolve it
	// back to the lockfile key and display that -- it is the directory the user has.
	importerKey, snapKey := l.importerKey(segs[0]), ""
	root := importerKey
	if root == "" {
		root = segs[0]
	}

	hops := make([]hop, 0, len(segs))
	hops = append(hops, hop{Name: root, Workspace: true})

	for _, name := range segs[1:] {
		h := hop{Name: name}

		switch {
		case importerKey != "":
			if d, ok := l.dep(importerKey, name); ok {
				// Straight from package.json; no registry call. A "catalog:" specifier
				// is an indirection that has to be followed to mean anything.
				h.Range = l.catalogRange(name, d.Specifier)
				h.ImporterKey = importerKey
				if strings.HasPrefix(d.Version, "link:") {
					// A workspace package depending on another workspace package.
					h.Workspace = true
					importerKey = linkTarget(importerKey, d.Version)
				} else {
					h.Version = bareVersion(d.Version)
					importerKey, snapKey = "", name+"@"+d.Version
				}
			} else {
				importerKey = ""
			}

		case snapKey != "":
			// Inside the package graph the declared range lives in the parent's
			// published manifest, so it has to come from the registry.
			prev := hops[len(hops)-1]
			h.parentName, h.parentVersion = prev.Name, prev.Version

			if v, ok := l.snapshotDep(snapKey, name); ok {
				h.Version = bareVersion(v)
				snapKey = name + "@" + v
			} else {
				snapKey = ""
			}
		}

		hops = append(hops, h)
	}
	return hops
}
