package analyzer_test

import (
	"fmt"
	"testing"

	"github.com/user/pnpm-vuln-fixer/internal/analyzer"
	"github.com/user/pnpm-vuln-fixer/internal/graph"
	"github.com/user/pnpm-vuln-fixer/internal/lockfile"
	"github.com/user/pnpm-vuln-fixer/internal/registry"
)

// mockRegistry implements analyzer.RegistryClient for tests.
type mockRegistry struct {
	data map[string]*registry.AbbrevMeta
}

func (m *mockRegistry) FetchAbbrevMeta(pkg string) (*registry.AbbrevMeta, error) {
	if meta, ok := m.data[pkg]; ok {
		return meta, nil
	}
	return nil, fmt.Errorf("package %q not found in mock registry", pkg)
}

// node constructors.

func importerNode(path string) *graph.Node {
	return &graph.Node{DepPath: path, Name: path, IsRoot: true}
}

func pkgNode(name, version string) *graph.Node {
	return &graph.Node{
		DepPath: name + "@" + version,
		Name:    name,
		Version: version,
	}
}

func simpleLockfile(importerPath, directDepName, directDepSpecifier string) *lockfile.Lockfile {
	return &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			importerPath: {
				Dependencies: map[string]*lockfile.DepEntry{
					directDepName: {Specifier: directDepSpecifier},
				},
			},
		},
	}
}

func pkgVersion(deps map[string]string) *registry.PackageVersion {
	return &registry.PackageVersion{Dependencies: deps}
}

// Semver note for test ranges:
//   "^1.0.0"  → >=1.0.0 <2.0.0  (blocks 2.x)
//   "^2.0.0"  → >=2.0.0 <3.0.0  (admits 2.x)
//   "~4.16.0" → >=4.16.0 <4.17.0 (blocks 4.17.x)
//   "^4.17.0" → >=4.17.0 <5.0.0  (admits 4.17.21)

// TestAnalyzeChain_DirectDep: vuln is a direct dep; importer specifier blocks fixedVersion.
// "~4.16.0" = >=4.16.0 <4.17.0, does not admit 4.17.21 → DirectDep verdict.
func TestAnalyzeChain_DirectDep(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("lodash", "4.17.10"),
	}
	lf := simpleLockfile(".", "lodash", "~4.16.0")
	reg := &mockRegistry{}

	cr, err := analyzer.AnalyzeChain(chain, lf, "lodash", "4.17.21", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictDirectDep {
		t.Errorf("verdict = %v, want VerdictDirectDep", cr.Verdict)
	}
	if len(cr.Actions) != 1 {
		t.Fatalf("len(actions) = %d, want 1", len(cr.Actions))
	}
	if cr.Actions[0].Package != "lodash" || cr.Actions[0].ToVer != "4.17.21" {
		t.Errorf("action = %+v, want {lodash -> 4.17.21}", cr.Actions[0])
	}
}

// TestAnalyzeChain_DirectDep_NoBumpNeeded: vuln is a direct dep; importer specifier
// already admits fixedVersion ("~4.17.0" = >=4.17.0 <4.18.0 admits 4.17.21) → NoBumpNeeded.
func TestAnalyzeChain_DirectDep_NoBumpNeeded(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("lodash", "4.17.10"),
	}
	lf := simpleLockfile(".", "lodash", "~4.17.0")
	reg := &mockRegistry{}

	cr, err := analyzer.AnalyzeChain(chain, lf, "lodash", "4.17.21", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictNoBumpNeeded {
		t.Errorf("verdict = %v, want VerdictNoBumpNeeded", cr.Verdict)
	}
	if len(cr.Actions) != 0 {
		t.Errorf("expected no actions, got %v", cr.Actions)
	}
}

// TestAnalyzeChain_AlreadySatisfiable: parent range already admits fixedVersion.
// express@4.16.0 declares lodash "^4.17.0" which admits 4.17.21 → no bump.
func TestAnalyzeChain_AlreadySatisfiable(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("express", "4.16.0"),
		pkgNode("lodash", "4.17.10"),
	}
	lf := simpleLockfile(".", "express", "^4.16.0")
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Name: "express",
				Versions: map[string]*registry.PackageVersion{
					"4.16.0": pkgVersion(map[string]string{"lodash": "^4.17.0"}), // >=4.17.0 <5 → admits 4.17.21
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "lodash", "4.17.21", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictNoBumpNeeded {
		t.Errorf("verdict = %v, want VerdictNoBumpNeeded", cr.Verdict)
	}
	if len(cr.Actions) != 0 {
		t.Errorf("expected no actions, got %v", cr.Actions)
	}
}

// TestAnalyzeChain_SingleBump: parent range pins lodash below fixedVersion.
// express@4.16.0 declares lodash "~4.16.0" (>=4.16.0 <4.17.0), blocks 4.17.21.
// express@4.17.1 declares lodash "^4.17.0" (>=4.17.0 <5), admits 4.17.21.
// Importer specifier "^4.16.0" admits 4.17.1 → no specifier update needed.
func TestAnalyzeChain_SingleBump(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("express", "4.16.0"),
		pkgNode("lodash", "4.17.10"),
	}
	lf := simpleLockfile(".", "express", "^4.16.0") // ^4.16.0 → >=4.16.0 <5, admits 4.17.1
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Name: "express",
				Versions: map[string]*registry.PackageVersion{
					"4.16.0": pkgVersion(map[string]string{"lodash": "~4.16.0"}),  // blocks 4.17.21
					"4.17.1": pkgVersion(map[string]string{"lodash": "^4.17.0"}),  // admits 4.17.21
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "lodash", "4.17.21", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictBump {
		t.Errorf("verdict = %v, want VerdictBump", cr.Verdict)
	}
	if len(cr.Actions) == 0 {
		t.Fatal("expected at least one action")
	}
	a := cr.Actions[0]
	if a.Package != "express" || a.ToVer != "4.17.1" {
		t.Errorf("action = %+v, want {express -> 4.17.1}", a)
	}
}

// TestAnalyzeChain_SingleBump_SpecifierUpdate: importer specifier is too tight and must be widened.
// express@4.16.0 declares lodash "~4.16.0" (blocks 4.17.21).
// express@4.17.1 admits 4.17.21.
// Importer specifier "~4.16.0" does NOT admit 4.17.1 → specifier update required.
func TestAnalyzeChain_SingleBump_SpecifierUpdate(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("express", "4.16.0"),
		pkgNode("lodash", "4.17.10"),
	}
	lf := simpleLockfile(".", "express", "~4.16.0") // ~4.16.0 → >=4.16.0 <4.17.0, blocks 4.17.1
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Name: "express",
				Versions: map[string]*registry.PackageVersion{
					"4.16.0": pkgVersion(map[string]string{"lodash": "~4.16.0"}),
					"4.17.1": pkgVersion(map[string]string{"lodash": "^4.17.0"}),
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "lodash", "4.17.21", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictBump {
		t.Errorf("verdict = %v, want VerdictBump", cr.Verdict)
	}

	var bumpAction, specAction *analyzer.FixAction
	for i := range cr.Actions {
		if cr.Actions[i].IsSpecifier {
			specAction = &cr.Actions[i]
		} else {
			bumpAction = &cr.Actions[i]
		}
	}
	if bumpAction == nil {
		t.Error("expected a bump action for express")
	} else if bumpAction.Package != "express" || bumpAction.ToVer != "4.17.1" {
		t.Errorf("bump action = %+v, want {express -> 4.17.1}", *bumpAction)
	}
	if specAction == nil {
		t.Error("expected a specifier update action for express")
	} else if specAction.Package != "express" {
		t.Errorf("specifier action = %+v, want package=express", *specAction)
	}
}

// TestAnalyzeChain_DeadEnd: no version of express admits lodash@2.0.0 → dead end.
func TestAnalyzeChain_DeadEnd(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("express", "4.16.0"),
		pkgNode("lodash", "1.0.0"),
	}
	lf := simpleLockfile(".", "express", "^4.16.0")
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Name: "express",
				Versions: map[string]*registry.PackageVersion{
					"4.16.0": pkgVersion(map[string]string{"lodash": "^1.0.0"}), // >=1 <2, blocks 2.0.0
					"4.17.0": pkgVersion(map[string]string{"lodash": "^1.0.0"}), // still blocks 2.0.0
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "lodash", "2.0.0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictDeadEnd {
		t.Errorf("verdict = %v, want VerdictDeadEnd", cr.Verdict)
	}
	if cr.BlockedBy != "express" {
		t.Errorf("BlockedBy = %q, want %q", cr.BlockedBy, "express")
	}
}

// TestAnalyzeChain_CascadeToRoot: parent AND grandparent must be bumped, specifier needs widening.
// chain: importer → grandparent@1.0.0 → parent@1.0.0 → vuln@1.0.0
// vuln fixed to 2.0.0.
func TestAnalyzeChain_CascadeToRoot(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("grandparent", "1.0.0"),
		pkgNode("parent", "1.0.0"),
		pkgNode("vuln", "1.0.0"),
	}
	// Importer specifier "^1.0.0" does NOT admit grandparent@3.0.0 (different major).
	lf := simpleLockfile(".", "grandparent", "^1.0.0")
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"grandparent": {
				Name: "grandparent",
				Versions: map[string]*registry.PackageVersion{
					"1.0.0": pkgVersion(map[string]string{"parent": "^1.0.0"}), // blocks parent@2.0.0
					"3.0.0": pkgVersion(map[string]string{"parent": "^2.0.0"}), // admits parent@2.0.0
				},
			},
			"parent": {
				Name: "parent",
				Versions: map[string]*registry.PackageVersion{
					"1.0.0": pkgVersion(map[string]string{"vuln": "^1.0.0"}), // blocks vuln@2.0.0
					"2.0.0": pkgVersion(map[string]string{"vuln": "^2.0.0"}), // admits vuln@2.0.0
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "vuln", "2.0.0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictBump {
		t.Errorf("verdict = %v, want VerdictBump", cr.Verdict)
	}
	if len(cr.Actions) < 2 {
		t.Fatalf("expected >=2 actions, got %d: %+v", len(cr.Actions), cr.Actions)
	}
	if cr.Actions[0].Package != "parent" || cr.Actions[0].ToVer != "2.0.0" {
		t.Errorf("actions[0] = %+v, want {parent -> 2.0.0}", cr.Actions[0])
	}
	if cr.Actions[1].Package != "grandparent" || cr.Actions[1].ToVer != "3.0.0" {
		t.Errorf("actions[1] = %+v, want {grandparent -> 3.0.0}", cr.Actions[1])
	}
}

// TestAnalyzeChain_CascadeGrandparentAlreadyAdmits: grandparent range admits parent@1.5.0 → stop early.
func TestAnalyzeChain_CascadeGrandparentAlreadyAdmits(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("grandparent", "1.0.0"),
		pkgNode("parent", "1.0.0"),
		pkgNode("vuln", "1.0.0"),
	}
	lf := simpleLockfile(".", "grandparent", "^1.0.0")
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"grandparent": {
				Name: "grandparent",
				Versions: map[string]*registry.PackageVersion{
					// ^1.0.0 admits parent@1.5.0 → no grandparent bump needed.
					"1.0.0": pkgVersion(map[string]string{"parent": "^1.0.0"}),
				},
			},
			"parent": {
				Name: "parent",
				Versions: map[string]*registry.PackageVersion{
					"1.0.0": pkgVersion(map[string]string{"vuln": "^1.0.0"}), // blocks vuln@2.0.0
					"1.5.0": pkgVersion(map[string]string{"vuln": "^2.0.0"}), // admits vuln@2.0.0
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "vuln", "2.0.0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictBump {
		t.Errorf("verdict = %v, want VerdictBump", cr.Verdict)
	}
	// Only parent bump; grandparent already admits parent@1.5.0.
	if len(cr.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d: %+v", len(cr.Actions), cr.Actions)
	}
	if cr.Actions[0].Package != "parent" || cr.Actions[0].ToVer != "1.5.0" {
		t.Errorf("action = %+v, want {parent -> 1.5.0}", cr.Actions[0])
	}
}

// TestAnalyzeChain_NewerVersionDropsDep: a newer express drops its lodash dep entirely.
func TestAnalyzeChain_NewerVersionDropsDep(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("express", "4.16.0"),
		pkgNode("lodash", "1.0.0"),
	}
	lf := simpleLockfile(".", "express", "^4.16.0")
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Name: "express",
				Versions: map[string]*registry.PackageVersion{
					"4.16.0": pkgVersion(map[string]string{"lodash": "^1.0.0"}), // blocks 2.0.0
					// 5.0.0 has no lodash dep → treated as fixable (chain eliminated).
					"5.0.0": pkgVersion(map[string]string{}),
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "lodash", "2.0.0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictBump {
		t.Errorf("verdict = %v, want VerdictBump", cr.Verdict)
	}
	if len(cr.Actions) == 0 || cr.Actions[0].ToVer != "5.0.0" {
		t.Errorf("expected action bumping to 5.0.0, got %+v", cr.Actions)
	}
}

// TestAnalyze_AllFixable: all chains are fixable; MinUnion is deduplicated.
func TestAnalyze_AllFixable(t *testing.T) {
	// Two chains through the same parent (express@4.16.0), different importers.
	chains := [][]*graph.Node{
		{importerNode("."), pkgNode("express", "4.16.0"), pkgNode("lodash", "1.0.0")},
		{importerNode("apps/web"), pkgNode("express", "4.16.0"), pkgNode("lodash", "1.0.0")},
	}
	lf := &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".":        {Dependencies: map[string]*lockfile.DepEntry{"express": {Specifier: "^4.16.0"}}},
			"apps/web": {Dependencies: map[string]*lockfile.DepEntry{"express": {Specifier: "^4.16.0"}}},
		},
	}
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Name: "express",
				Versions: map[string]*registry.PackageVersion{
					"4.16.0": pkgVersion(map[string]string{"lodash": "^1.0.0"}), // blocks 2.0.0
					"4.17.1": pkgVersion(map[string]string{"lodash": "^2.0.0"}), // admits 2.0.0
				},
			},
		},
	}

	report, err := analyzer.Analyze(chains, lf, "lodash", "1.0.0", "2.0.0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.AllFixable {
		t.Error("expected AllFixable = true")
	}
	if report.NeedsOverride {
		t.Error("expected NeedsOverride = false")
	}
	// Both chains need express@4.17.1 — MinUnion should deduplicate to one entry.
	if len(report.MinUnion) != 1 {
		t.Fatalf("MinUnion len = %d, want 1", len(report.MinUnion))
	}
	if report.MinUnion[0].Package != "express" || report.MinUnion[0].ToVer != "4.17.1" {
		t.Errorf("MinUnion[0] = %+v, want {express -> 4.17.1}", report.MinUnion[0])
	}
}

// TestAnalyze_PartialFix: one chain is fixable, one is a dead end → NeedsOverride.
func TestAnalyze_PartialFix(t *testing.T) {
	chains := [][]*graph.Node{
		{importerNode("."), pkgNode("express", "4.16.0"), pkgNode("lodash", "1.0.0")},
		{importerNode("."), pkgNode("blocker", "1.0.0"), pkgNode("lodash", "1.0.0")},
	}
	lf := &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".": {
				Dependencies: map[string]*lockfile.DepEntry{
					"express": {Specifier: "^4.16.0"},
					"blocker": {Specifier: "^1.0.0"},
				},
			},
		},
	}
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Versions: map[string]*registry.PackageVersion{
					"4.16.0": pkgVersion(map[string]string{"lodash": "^1.0.0"}), // blocks 2.0.0
					"4.17.1": pkgVersion(map[string]string{"lodash": "^2.0.0"}), // admits 2.0.0
				},
			},
			"blocker": {
				Versions: map[string]*registry.PackageVersion{
					// No version admits lodash@2.0.0.
					"1.0.0": pkgVersion(map[string]string{"lodash": "^1.0.0"}),
					"1.1.0": pkgVersion(map[string]string{"lodash": "^1.0.0"}),
				},
			},
		},
	}

	report, err := analyzer.Analyze(chains, lf, "lodash", "1.0.0", "2.0.0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.AllFixable {
		t.Error("expected AllFixable = false")
	}
	if !report.NeedsOverride {
		t.Error("expected NeedsOverride = true")
	}

	var deadEnd *analyzer.ChainResult
	for _, cr := range report.Chains {
		if cr.Verdict == analyzer.VerdictDeadEnd {
			deadEnd = cr
		}
	}
	if deadEnd == nil {
		t.Error("expected at least one dead-end chain result")
	} else if deadEnd.BlockedBy != "blocker" {
		t.Errorf("BlockedBy = %q, want %q", deadEnd.BlockedBy, "blocker")
	}
}

// TestAnalyze_MinUnionTakesHighestVersion: two chains need different versions of the
// same package; MinUnion records the higher one.
func TestAnalyze_MinUnionTakesHighestVersion(t *testing.T) {
	// Chain 1: express blocks lodash@2.0.0; minimal fix is express@4.17.1.
	// Chain 2: same express blocks lodash@3.0.0; minimal fix is express@4.18.0.
	// MinUnion should pick express@4.18.0 (satisfies both requirements).
	chains := [][]*graph.Node{
		{importerNode("."), pkgNode("express", "4.16.0"), pkgNode("lodash", "1.0.0")},
		{importerNode("."), pkgNode("express", "4.16.0"), pkgNode("other", "1.0.0")},
	}
	lf := &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			".": {Dependencies: map[string]*lockfile.DepEntry{"express": {Specifier: "^4.0.0"}}},
		},
	}
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Versions: map[string]*registry.PackageVersion{
					"4.16.0": pkgVersion(map[string]string{
						"lodash": "^1.0.0", // blocks 2.0.0
						"other":  "^1.0.0", // blocks 2.0.0
					}),
					// 4.17.1 admits lodash@2.0.0 but still blocks other@2.0.0.
					"4.17.1": pkgVersion(map[string]string{
						"lodash": "^2.0.0",
						"other":  "^1.0.0",
					}),
					// 4.18.0 admits both.
					"4.18.0": pkgVersion(map[string]string{
						"lodash": "^2.0.0",
						"other":  "^2.0.0",
					}),
				},
			},
			"other": {
				Versions: map[string]*registry.PackageVersion{
					"1.0.0": {}, // placeholder (not fetched in this test)
				},
			},
		},
	}

	// Chain 1 needs express@4.17.1 (first version admitting lodash@2.0.0).
	// Chain 2 needs express@4.18.0 (first version admitting other@2.0.0).
	// MinUnion must pick express@4.18.0 — the higher of the two requirements.
	rpt, err := analyzer.Analyze(chains, lf, "lodash", "1.0.0", "2.0.0", reg)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(rpt.MinUnion) != 1 {
		t.Fatalf("MinUnion length = %d, want 1; MinUnion = %v", len(rpt.MinUnion), rpt.MinUnion)
	}
	if rpt.MinUnion[0].Package != "express" {
		t.Errorf("MinUnion[0].Package = %q, want %q", rpt.MinUnion[0].Package, "express")
	}
	if rpt.MinUnion[0].ToVer != "4.18.0" {
		t.Errorf("MinUnion[0].ToVer = %q, want %q", rpt.MinUnion[0].ToVer, "4.18.0")
	}
}

// TestAnalyzeChain_EmptyChain: degenerate empty input, no crash.
func TestAnalyzeChain_EmptyChain(t *testing.T) {
	cr, err := analyzer.AnalyzeChain(nil, &lockfile.Lockfile{}, "pkg", "1.0.0", &mockRegistry{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictNoBumpNeeded {
		t.Errorf("verdict = %v, want VerdictNoBumpNeeded", cr.Verdict)
	}
}

// TestAnalyzeChain_RegistryError: registry failure propagates as error.
func TestAnalyzeChain_RegistryError(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("express", "4.16.0"),
		pkgNode("lodash", "4.17.10"),
	}
	lf := simpleLockfile(".", "express", "^4.16.0")
	reg := &mockRegistry{data: map[string]*registry.AbbrevMeta{}}

	_, err := analyzer.AnalyzeChain(chain, lf, "lodash", "4.17.21", reg)
	if err == nil {
		t.Error("expected error when registry lookup fails")
	}
}

// TestAnalyzeChain_NoDeclaredRange: parent doesn't list child in deps → treated as satisfiable.
func TestAnalyzeChain_NoDeclaredRange(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("express", "4.16.0"),
		pkgNode("lodash", "1.0.0"),
	}
	lf := simpleLockfile(".", "express", "^4.16.0")
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Name: "express",
				Versions: map[string]*registry.PackageVersion{
					// express doesn't list lodash at all.
					"4.16.0": pkgVersion(map[string]string{}),
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "lodash", "2.0.0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No range declared → treat as already satisfiable.
	if cr.Verdict != analyzer.VerdictNoBumpNeeded {
		t.Errorf("verdict = %v, want VerdictNoBumpNeeded", cr.Verdict)
	}
}

// simpleLockfileWithLocal creates a lockfile where the importer's dep entry is a workspace dep.
func simpleLockfileWithLocal(importerPath, directDepName string) *lockfile.Lockfile {
	return &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			importerPath: {
				Dependencies: map[string]*lockfile.DepEntry{
					directDepName: {
						Specifier: "workspace:^",
						Version:   "link:packages/" + directDepName,
						IsLocal:   true,
					},
				},
			},
		},
	}
}

// simpleLockfileWithAlias creates a lockfile where an alias (npm:realPkg@range) maps to realPkg.
func simpleLockfileWithAlias(importerPath, aliasName, realPkg, specifierRange string) *lockfile.Lockfile {
	return &lockfile.Lockfile{
		Importers: map[string]*lockfile.Importer{
			importerPath: {
				Dependencies: map[string]*lockfile.DepEntry{
					aliasName: {
						Specifier: "npm:" + realPkg + "@" + specifierRange,
						Version:   realPkg + "@4.17.1",
						IsAlias:   true,
						AliasOf:   realPkg,
					},
				},
			},
		},
	}
}

// TestAnalyzeChain_WorkspaceDep: when the importer's specifier for a direct parent is
// workspace:, the chain cannot be fixed via registry → VerdictDeadEnd.
func TestAnalyzeChain_WorkspaceDep(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("local-utils", "1.0.0"),
		pkgNode("vuln", "1.0.0"),
	}
	lf := simpleLockfileWithLocal(".", "local-utils")
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"local-utils": {
				Name: "local-utils",
				Versions: map[string]*registry.PackageVersion{
					"1.0.0": pkgVersion(map[string]string{"vuln": "^1.0.0"}),
					"2.0.0": pkgVersion(map[string]string{"vuln": "^2.0.0"}),
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "vuln", "2.0.0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Verdict != analyzer.VerdictDeadEnd {
		t.Errorf("verdict = %v, want VerdictDeadEnd (workspace dep can't be registry-fixed)", cr.Verdict)
	}
	if cr.BlockedBy != "local-utils" {
		t.Errorf("BlockedBy = %q, want %q", cr.BlockedBy, "local-utils")
	}
}

// TestAnalyzeChain_AliasDep: when the importer uses npm:express@range as alias "my-express",
// importerDepEntry finds the specifier via AliasOf match.
func TestAnalyzeChain_AliasDep(t *testing.T) {
	chain := []*graph.Node{
		importerNode("."),
		pkgNode("express", "4.16.0"),
		pkgNode("lodash", "4.17.10"),
	}
	// Importer has alias "my-express" → npm:express@^4.16.0
	lf := simpleLockfileWithAlias(".", "my-express", "express", "^4.16.0")
	reg := &mockRegistry{
		data: map[string]*registry.AbbrevMeta{
			"express": {
				Name: "express",
				Versions: map[string]*registry.PackageVersion{
					"4.16.0": pkgVersion(map[string]string{"lodash": "~4.16.0"}),  // blocks 4.17.21
					"4.17.1": pkgVersion(map[string]string{"lodash": "^4.17.0"}),  // admits 4.17.21
				},
			},
		},
	}

	cr, err := analyzer.AnalyzeChain(chain, lf, "lodash", "4.17.21", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should resolve by bumping express; alias lookup should find the entry.
	if cr.Verdict != analyzer.VerdictBump {
		t.Errorf("verdict = %v, want VerdictBump", cr.Verdict)
	}
	if len(cr.Actions) == 0 || cr.Actions[0].Package != "express" {
		t.Errorf("expected action for express, got %+v", cr.Actions)
	}
	// The alias specifier "npm:express@^4.16.0" admits newVer 4.17.1 (caret constraint),
	// so no additional IsSpecifier action should be produced.
	for _, a := range cr.Actions {
		if a.IsSpecifier {
			t.Errorf("unexpected IsSpecifier action for alias dep: %+v", a)
		}
	}
}
