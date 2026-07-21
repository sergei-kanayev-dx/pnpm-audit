package lockfile

import "io"

// Parser parses a pnpm lockfile format into a Lockfile.
type Parser interface {
	Parse(r io.Reader) (*Lockfile, error)
}

// Lockfile is the parsed representation of a pnpm-lock.yaml.
type Lockfile struct {
	LockfileVersion string
	Settings        Settings
	Importers       map[string]*Importer // key: workspace path ("." for root)
	Snapshots       map[string]*Snapshot // key: DepPath (may include peer suffix)
}

// Settings holds global lockfile settings.
type Settings struct {
	AutoInstallPeers        bool
	ExcludeLinksFromLockfile bool
}

// Importer represents a workspace project root.
type Importer struct {
	Dependencies         map[string]*DepEntry
	DevDependencies      map[string]*DepEntry
	OptionalDependencies map[string]*DepEntry
}

// DepEntry is a resolved dependency entry in an importer.
type DepEntry struct {
	Specifier string // range from package.json, e.g. "^4.18.0"
	Version   string // resolved DepPath key or version; alias deps use "pkgname@version" format
	IsLocal   bool   // true when specifier is workspace: or link: (local, not registry-resolvable)
	IsAlias   bool   // true when specifier is npm:pkgname@range
	AliasOf   string // real package name when IsAlias is true, e.g. "express" for npm:express@^4
}

// Snapshot is a resolved dependency instance from the snapshots section.
// Its DepPath key may include a peer suffix: "name@version(peer@ver)".
type Snapshot struct {
	Dependencies         map[string]string // name → resolved version string
	OptionalDependencies map[string]string // name → resolved version string
	PeerDependencies     map[string]string // name → resolved version string
}
