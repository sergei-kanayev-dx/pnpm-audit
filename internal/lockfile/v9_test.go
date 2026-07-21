package lockfile_test

import (
	"os"
	"testing"

	"github.com/user/pnpm-vuln-fixer/internal/lockfile"
)

func openFixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("../../testdata/lockfiles/" + name)
	if err != nil {
		t.Fatalf("opening fixture %s: %v", name, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseV9Simple(t *testing.T) {
	f := openFixture(t, "v9-simple.yaml")
	lf, err := lockfile.ParseV9(f)
	if err != nil {
		t.Fatalf("ParseV9: %v", err)
	}

	if lf.LockfileVersion != "9.0" {
		t.Errorf("LockfileVersion = %q, want %q", lf.LockfileVersion, "9.0")
	}
	if !lf.Settings.AutoInstallPeers {
		t.Error("Settings.AutoInstallPeers = false, want true")
	}

	if len(lf.Importers) != 1 {
		t.Fatalf("len(Importers) = %d, want 1", len(lf.Importers))
	}
	root, ok := lf.Importers["."]
	if !ok {
		t.Fatal(`Importers["."] missing`)
	}
	expEntry, ok := root.Dependencies["express"]
	if !ok {
		t.Fatal(`root.Dependencies["express"] missing`)
	}
	if expEntry.Specifier != "^4.18.0" {
		t.Errorf("express specifier = %q, want %q", expEntry.Specifier, "^4.18.0")
	}
	if expEntry.Version != "4.18.2" {
		t.Errorf("express version = %q, want %q", expEntry.Version, "4.18.2")
	}
	if _, ok := root.DevDependencies["lodash"]; !ok {
		t.Error(`root.DevDependencies["lodash"] missing`)
	}

	expSnap, ok := lf.Snapshots["express@4.18.2"]
	if !ok {
		t.Fatal(`Snapshots["express@4.18.2"] missing`)
	}
	if expSnap.Dependencies["lodash"] != "4.17.10" {
		t.Errorf("express snapshot deps[lodash] = %q, want %q", expSnap.Dependencies["lodash"], "4.17.10")
	}

	if _, ok := lf.Snapshots["lodash@4.17.10"]; !ok {
		t.Error(`Snapshots["lodash@4.17.10"] missing`)
	}
	if _, ok := lf.Snapshots["lodash@4.17.21"]; !ok {
		t.Error(`Snapshots["lodash@4.17.21"] missing`)
	}
}

func TestParseV9Scoped(t *testing.T) {
	f := openFixture(t, "v9-scoped.yaml")
	lf, err := lockfile.ParseV9(f)
	if err != nil {
		t.Fatalf("ParseV9: %v", err)
	}

	root, ok := lf.Importers["."]
	if !ok {
		t.Fatal(`Importers["."] missing`)
	}

	coreEntry, ok := root.Dependencies["@babel/core"]
	if !ok {
		t.Fatal(`root.Dependencies["@babel/core"] missing`)
	}
	if coreEntry.Specifier != "^7.22.0" {
		t.Errorf("@babel/core specifier = %q, want %q", coreEntry.Specifier, "^7.22.0")
	}
	if coreEntry.Version != "7.22.5" {
		t.Errorf("@babel/core version = %q, want %q", coreEntry.Version, "7.22.5")
	}

	if _, ok := root.DevDependencies["@types/node"]; !ok {
		t.Error(`root.DevDependencies["@types/node"] missing`)
	}

	coreSnap, ok := lf.Snapshots["@babel/core@7.22.5"]
	if !ok {
		t.Fatal(`Snapshots["@babel/core@7.22.5"] missing`)
	}
	if coreSnap.Dependencies["@babel/helper-module-imports"] != "7.22.5" {
		t.Errorf(`@babel/core snap deps[@babel/helper-module-imports] = %q, want "7.22.5"`,
			coreSnap.Dependencies["@babel/helper-module-imports"])
	}

	if _, ok := lf.Snapshots["@babel/helper-module-imports@7.22.5"]; !ok {
		t.Error(`Snapshots["@babel/helper-module-imports@7.22.5"] missing`)
	}
	if _, ok := lf.Snapshots["@types/node@20.0.0"]; !ok {
		t.Error(`Snapshots["@types/node@20.0.0"] missing`)
	}
}

func TestParseV9Peers(t *testing.T) {
	f := openFixture(t, "v9-peers.yaml")
	lf, err := lockfile.ParseV9(f)
	if err != nil {
		t.Fatalf("ParseV9: %v", err)
	}

	root, ok := lf.Importers["."]
	if !ok {
		t.Fatal(`Importers["."] missing`)
	}

	reactEntry, ok := root.Dependencies["react"]
	if !ok {
		t.Fatal(`root.Dependencies["react"] missing`)
	}
	if reactEntry.Version != "18.2.0" {
		t.Errorf("react version = %q, want %q", reactEntry.Version, "18.2.0")
	}

	rdEntry, ok := root.Dependencies["react-dom"]
	if !ok {
		t.Fatal(`root.Dependencies["react-dom"] missing`)
	}
	// Importer version field contains the peer-suffixed DepPath key.
	if rdEntry.Version != "18.2.0(react@18.2.0)" {
		t.Errorf("react-dom version = %q, want %q", rdEntry.Version, "18.2.0(react@18.2.0)")
	}

	if _, ok := lf.Snapshots["react@18.2.0"]; !ok {
		t.Error(`Snapshots["react@18.2.0"] missing`)
	}

	rdSnap, ok := lf.Snapshots["react-dom@18.2.0(react@18.2.0)"]
	if !ok {
		t.Fatal(`Snapshots["react-dom@18.2.0(react@18.2.0)"] missing`)
	}
	if rdSnap.Dependencies["react"] != "18.2.0" {
		t.Errorf("react-dom snap deps[react] = %q, want %q", rdSnap.Dependencies["react"], "18.2.0")
	}

	// Unaffixed key must NOT be present (peer-suffixed is a distinct DepPath).
	if _, ok := lf.Snapshots["react-dom@18.2.0"]; ok {
		t.Error(`Snapshots["react-dom@18.2.0"] present without peer suffix — should not exist`)
	}
}

func TestParseV9Monorepo(t *testing.T) {
	f := openFixture(t, "v9-monorepo.yaml")
	lf, err := lockfile.ParseV9(f)
	if err != nil {
		t.Fatalf("ParseV9: %v", err)
	}

	wantImporters := []string{".", "packages/app", "packages/shared"}
	for _, path := range wantImporters {
		if _, ok := lf.Importers[path]; !ok {
			t.Errorf("Importers[%q] missing", path)
		}
	}
	if len(lf.Importers) != len(wantImporters) {
		t.Errorf("len(Importers) = %d, want %d", len(lf.Importers), len(wantImporters))
	}

	appImp := lf.Importers["packages/app"]
	if _, ok := appImp.Dependencies["react"]; !ok {
		t.Error(`packages/app Dependencies["react"] missing`)
	}
	sharedDep, ok := appImp.Dependencies["shared"]
	if !ok {
		t.Error(`packages/app Dependencies["shared"] missing`)
	} else if sharedDep.Specifier != "workspace:*" {
		t.Errorf("shared specifier = %q, want %q", sharedDep.Specifier, "workspace:*")
	}

	sharedImp := lf.Importers["packages/shared"]
	if _, ok := sharedImp.Dependencies["lodash"]; !ok {
		t.Error(`packages/shared Dependencies["lodash"] missing`)
	}

	rootImp := lf.Importers["."]
	if _, ok := rootImp.DevDependencies["typescript"]; !ok {
		t.Error(`root DevDependencies["typescript"] missing`)
	}
}

func TestParseV9Aliases(t *testing.T) {
	f := openFixture(t, "v9-aliases.yaml")
	lf, err := lockfile.ParseV9(f)
	if err != nil {
		t.Fatalf("ParseV9: %v", err)
	}

	root, ok := lf.Importers["."]
	if !ok {
		t.Fatal(`Importers["."] missing`)
	}

	// npm: alias — IsAlias=true, AliasOf="express", Version is the real DepPath.
	myExpress, ok := root.Dependencies["my-express"]
	if !ok {
		t.Fatal(`root.Dependencies["my-express"] missing`)
	}
	if !myExpress.IsAlias {
		t.Error("my-express: IsAlias = false, want true")
	}
	if myExpress.AliasOf != "express" {
		t.Errorf("my-express: AliasOf = %q, want %q", myExpress.AliasOf, "express")
	}
	if myExpress.IsLocal {
		t.Error("my-express: IsLocal = true, want false")
	}
	if myExpress.Version != "express@4.18.2" {
		t.Errorf("my-express: Version = %q, want %q", myExpress.Version, "express@4.18.2")
	}

	// workspace: specifier — IsLocal=true.
	localUtils, ok := root.Dependencies["local-utils"]
	if !ok {
		t.Fatal(`root.Dependencies["local-utils"] missing`)
	}
	if !localUtils.IsLocal {
		t.Error("local-utils: IsLocal = false, want true")
	}
	if localUtils.IsAlias {
		t.Error("local-utils: IsAlias = true, want false")
	}

	// link: specifier — IsLocal=true.
	linkedPkg, ok := root.Dependencies["linked-pkg"]
	if !ok {
		t.Fatal(`root.Dependencies["linked-pkg"] missing`)
	}
	if !linkedPkg.IsLocal {
		t.Error("linked-pkg: IsLocal = false, want true")
	}

	// Normal dep — neither flag set.
	qs, ok := root.Dependencies["qs"]
	if !ok {
		t.Fatal(`root.Dependencies["qs"] missing`)
	}
	if qs.IsLocal || qs.IsAlias {
		t.Errorf("qs: IsLocal=%v IsAlias=%v, want both false", qs.IsLocal, qs.IsAlias)
	}

	// Alias node's snapshot: express@4.18.2 should exist.
	if _, ok := lf.Snapshots["express@4.18.2"]; !ok {
		t.Error(`Snapshots["express@4.18.2"] missing`)
	}
}

func TestNewParser(t *testing.T) {
	tests := []struct {
		version string
		wantErr bool
	}{
		{"9.0", false},
		{"6.0", true},
		{"5.4", true},
		{"", true},
		{"10.0", true},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			p, err := lockfile.NewParser(tc.version)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewParser(%q) returned non-nil parser, want error", tc.version)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewParser(%q) unexpected error: %v", tc.version, err)
			}
			if p == nil {
				t.Fatalf("NewParser(%q) = nil, want non-nil Parser", tc.version)
			}
		})
	}
}

func TestParserInterfaceParsesSimple(t *testing.T) {
	p, err := lockfile.NewParser("9.0")
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}
	f := openFixture(t, "v9-simple.yaml")
	lf, err := p.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if lf.LockfileVersion != "9.0" {
		t.Errorf("LockfileVersion = %q, want %q", lf.LockfileVersion, "9.0")
	}
	if len(lf.Importers) == 0 {
		t.Error("Importers is empty")
	}
}
