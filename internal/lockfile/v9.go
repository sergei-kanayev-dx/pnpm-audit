package lockfile

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// NewParser returns a Parser for the given lockfile version string.
// Returns an error for unsupported versions.
func NewParser(version string) (Parser, error) {
	switch version {
	case "9.0":
		return &v9Parser{}, nil
	default:
		return nil, fmt.Errorf("unsupported lockfile version %q", version)
	}
}

type v9Parser struct{}

func (p *v9Parser) Parse(r io.Reader) (*Lockfile, error) { return ParseV9(r) }

// ParseV9 decodes a pnpm v9.0 lockfile from r.
func ParseV9(r io.Reader) (*Lockfile, error) {
	var raw rawV9
	if err := yaml.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding v9 lockfile: %w", err)
	}

	lf := &Lockfile{
		LockfileVersion: raw.LockfileVersion,
		Settings: Settings{
			AutoInstallPeers:        raw.Settings.AutoInstallPeers,
			ExcludeLinksFromLockfile: raw.Settings.ExcludeLinksFromLockfile,
		},
		Importers: make(map[string]*Importer, len(raw.Importers)),
		Packages:  make(map[string]*Package, len(raw.Packages)),
		Snapshots: make(map[string]*Snapshot, len(raw.Snapshots)),
	}

	for path, ri := range raw.Importers {
		lf.Importers[path] = &Importer{
			Dependencies:         convertDepEntries(ri.Dependencies),
			DevDependencies:      convertDepEntries(ri.DevDependencies),
			OptionalDependencies: convertDepEntries(ri.OptionalDependencies),
		}
	}

	for key, rp := range raw.Packages {
		lf.Packages[key] = &Package{
			Resolution: rp.Resolution,
			Engines:    rp.Engines,
		}
	}

	for key, rs := range raw.Snapshots {
		snap := &Snapshot{}
		if len(rs.Dependencies) > 0 {
			snap.Dependencies = copyStrMap(rs.Dependencies)
		}
		if len(rs.OptionalDependencies) > 0 {
			snap.OptionalDependencies = copyStrMap(rs.OptionalDependencies)
		}
		lf.Snapshots[key] = snap
	}

	return lf, nil
}

func convertDepEntries(raw map[string]rawV9DepEntry) map[string]*DepEntry {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]*DepEntry, len(raw))
	for name, e := range raw {
		out[name] = &DepEntry{Specifier: e.Specifier, Version: e.Version}
	}
	return out
}

func copyStrMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// raw YAML types for v9 deserialization

type rawV9 struct {
	LockfileVersion string                   `yaml:"lockfileVersion"`
	Settings        rawV9Settings            `yaml:"settings"`
	Importers       map[string]rawV9Importer `yaml:"importers"`
	Packages        map[string]rawV9Package  `yaml:"packages"`
	Snapshots       map[string]rawV9Snapshot `yaml:"snapshots"`
}

type rawV9Settings struct {
	AutoInstallPeers        bool `yaml:"autoInstallPeers"`
	ExcludeLinksFromLockfile bool `yaml:"excludeLinksFromLockfile"`
}

type rawV9Importer struct {
	Dependencies         map[string]rawV9DepEntry `yaml:"dependencies"`
	DevDependencies      map[string]rawV9DepEntry `yaml:"devDependencies"`
	OptionalDependencies map[string]rawV9DepEntry `yaml:"optionalDependencies"`
}

type rawV9DepEntry struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

type rawV9Package struct {
	Resolution map[string]string `yaml:"resolution"`
	Engines    map[string]string `yaml:"engines"`
}

type rawV9Snapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}
