package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
)

// fakeRegistry stands in for `pnpm view`. It also counts lookups, so a test can assert
// that a short-circuit really avoided the registry rather than merely producing the right
// answer expensively.
type fakeRegistry struct {
	versions map[string][]string          // package -> published versions
	deps     map[string]map[string]string // "pkg@version" -> child -> declared range
	broken   map[string]bool              // "pkg@version" or "pkg": lookup fails
	rangeN   int                          // declaredRange calls
	verN     int                          // publishedVersions calls
}

func (f *fakeRegistry) publishedVersions(pkg string) ([]*semver.Version, error) {
	f.verN++
	if f.broken[pkg] {
		return nil, errors.New("registry unreachable")
	}
	raw, ok := f.versions[pkg]
	if !ok {
		return nil, errors.New("no such package: " + pkg)
	}
	out := make([]*semver.Version, 0, len(raw))
	for _, s := range raw {
		v, err := semver.NewVersion(s)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (f *fakeRegistry) declaredRange(parent, version, child string) (string, bool, error) {
	f.rangeN++
	spec := parent + "@" + version
	if f.broken[spec] {
		return "", false, errors.New("registry unreachable")
	}
	m, ok := f.deps[spec]
	if !ok {
		return "", false, errors.New("no such version: " + spec)
	}
	rng, present := m[child]
	return rng, present, nil
}

// lodashAdvisory is the ordinary shape: one contiguous patched range.
func lodashAdvisory() advisory {
	return advisory{
		ID:                 1523,
		ModuleName:         "lodash",
		Severity:           "high",
		VulnerableVersions: "<4.17.21",
		PatchedVersions:    ">=4.17.21",
	}
}

// chain builds backend > utils@1.0.0 > lodash@4.17.15, the shape every solver test uses.
// utilsRange is what backend/package.json declares for utils.
func chain(utilsRange string) []hop {
	return []hop{
		{Name: "backend", Workspace: true},
		{Name: "utils", Version: "1.0.0", Range: utilsRange, ImporterKey: "backend"},
		{Name: "lodash", Version: "4.17.15", parentName: "utils", parentVersion: "1.0.0"},
	}
}

func baseRegistry() *fakeRegistry {
	return &fakeRegistry{
		versions: map[string][]string{
			"utils":  {"1.0.0", "1.1.0", "2.0.0"},
			"lodash": {"4.17.15", "4.17.20", "4.17.21", "4.17.22"},
		},
		deps: map[string]map[string]string{
			"utils@1.0.0": {"lodash": "4.17.15"},
			"utils@1.1.0": {"lodash": "4.17.15"},
			"utils@2.0.0": {"lodash": "^4.17.21"},
		},
		broken: map[string]bool{},
	}
}

func solve(t *testing.T, reg registryClient, a advisory, f finding, c []hop) chainFix {
	t.Helper()
	return newSolver(reg).solveChain(a, f, c)
}

func TestSolveChainBump(t *testing.T) {
	reg := baseRegistry()
	// The parent's range already admits a patched version, so nothing above has to move.
	reg.deps["utils@1.0.0"]["lodash"] = "^4.17.0"

	got := solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, chain("^1.0.0"))

	if got.kind != resBump || got.pkg != "lodash" || got.to != "4.17.21" {
		t.Fatalf("got %+v, want bump lodash -> 4.17.21", got)
	}
}

func TestSolveChainUpdateParentWithinDeclaredRange(t *testing.T) {
	reg := baseRegistry()
	// 1.0.0 pins a vulnerable lodash; 1.1.0 is inside backend's "^1.0.0" and frees it.
	reg.deps["utils@1.1.0"]["lodash"] = "^4.17.21"

	got := solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, chain("^1.0.0"))

	if got.kind != resUpdateParent || got.pkg != "utils" || got.to != "1.1.0" {
		t.Fatalf("got %+v, want update-parent utils -> 1.1.0", got)
	}
	if got.importer != "" {
		t.Errorf("a move inside the declared range needs no package.json edit, got importer %q", got.importer)
	}
}

func TestSolveChainPrefersLowestFixingVersion(t *testing.T) {
	reg := baseRegistry()
	// Both 1.1.0 and 2.0.0 would fix it; the lower one wins, and "^1.0.0" is not even a
	// barrier for it.
	reg.deps["utils@1.1.0"]["lodash"] = "^4.17.21"
	reg.deps["utils@2.0.0"]["lodash"] = "^4.17.22"

	got := solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, chain("^1.0.0"))

	if got.to != "1.1.0" {
		t.Fatalf("got %+v, want the lowest fixing version 1.1.0", got)
	}
}

func TestSolveChainWidensWorkspaceSpecifier(t *testing.T) {
	reg := baseRegistry()
	// Nothing inside "^1.0.0" fixes it, but utils@2.0.0 does -- which means editing
	// backend/package.json.
	got := solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, chain("^1.0.0"))

	if got.kind != resUpdateParent || got.pkg != "utils" || got.to != "2.0.0" {
		t.Fatalf("got %+v, want update-parent utils -> 2.0.0", got)
	}
	if got.importer != "backend" {
		t.Errorf("importer = %q, want backend so the report can name the package.json", got.importer)
	}
	if !strings.Contains(got.reason, "backend/package.json") {
		t.Errorf("reason = %q, want it to name the manifest to edit", got.reason)
	}
}

func TestSolveChainDroppedDependencyCountsAsFixed(t *testing.T) {
	reg := baseRegistry()
	// utils@1.1.0 stopped depending on lodash at all: the path is severed.
	delete(reg.deps["utils@1.1.0"], "lodash")

	got := solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, chain("^1.0.0"))

	if got.kind != resUpdateParent || got.to != "1.1.0" {
		t.Fatalf("got %+v, want update-parent utils -> 1.1.0", got)
	}
}

func TestSolveChainOverrideWhenNothingCanMove(t *testing.T) {
	reg := baseRegistry()
	// Every version of utils pins the vulnerable lodash.
	reg.deps["utils@2.0.0"]["lodash"] = "4.17.15"

	got := solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, chain("^1.0.0"))

	if got.kind != resOverride {
		t.Fatalf("got %+v, want override", got)
	}
}

func TestSolveChainOverrideWhenNoPatchExists(t *testing.T) {
	reg := baseRegistry()
	a := lodashAdvisory()
	// npm spells "no fix has been published" as this.
	a.VulnerableVersions = ">=0.0.0"
	a.PatchedVersions = "<0.0.0"

	got := solve(t, reg, a, finding{Version: "4.17.15"}, chain("^1.0.0"))

	if got.kind != resOverride {
		t.Fatalf("got %+v, want override", got)
	}
	if !strings.Contains(got.reason, "no published version") {
		t.Errorf("reason = %q, want it to say no fix exists", got.reason)
	}
}

func TestSolveChainRegistryFailureIsUnknownNotOverride(t *testing.T) {
	reg := baseRegistry()
	reg.broken["utils@1.1.0"] = true
	reg.broken["utils@2.0.0"] = true

	got := solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, chain("^1.0.0"))

	// Reporting "fix by overriding" here would be a confident wrong answer built on a
	// registry outage.
	if got.kind != resUnknown {
		t.Fatalf("got %+v, want unknown", got)
	}
}

func TestSolveChainUnresolvedHopIsUnknown(t *testing.T) {
	reg := baseRegistry()
	c := chain("^1.0.0")
	c[1].Version = "" // buildChain leaves a hop blank rather than dropping the path

	got := solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, c)

	if got.kind != resUnknown {
		t.Fatalf("got %+v, want unknown", got)
	}
}

// A patched range is not upward-closed: pnpm installs the highest version a range allows,
// and that version can be vulnerable again even though a patched one sits inside the same
// range. "Some patched version satisfies the range" is therefore the wrong test.
func TestSolveChainResolvesDescendantsTheWayPnpmWould(t *testing.T) {
	a := advisory{
		ID:                 42,
		ModuleName:         "tricky",
		Severity:           "critical",
		VulnerableVersions: "<1.2.3 || >=2.0.0 <2.1.0",
		PatchedVersions:    ">=1.2.3 <2.0.0 || >=2.1.0",
	}
	reg := &fakeRegistry{
		versions: map[string][]string{
			"utils":  {"1.0.0", "1.1.0", "1.2.0"},
			"tricky": {"1.0.0", "1.2.3", "2.0.5", "2.1.0"},
		},
		deps: map[string]map[string]string{
			"utils@1.0.0": {"tricky": "1.0.0"},
			// 2.0.5 is the highest version this range allows and it is vulnerable again,
			// even though the patched 1.2.3 also satisfies ">=1.2.3 <2.1.0".
			"utils@1.1.0": {"tricky": ">=1.2.3 <2.1.0"},
			"utils@1.2.0": {"tricky": "^2.1.0"},
		},
		broken: map[string]bool{},
	}
	c := []hop{
		{Name: "backend", Workspace: true},
		{Name: "utils", Version: "1.0.0", Range: "^1.0.0", ImporterKey: "backend"},
		{Name: "tricky", Version: "1.0.0", parentName: "utils", parentVersion: "1.0.0"},
	}

	got := solve(t, reg, a, finding{Version: "1.0.0"}, c)

	if got.to != "1.2.0" {
		t.Fatalf("got %+v, want utils -> 1.2.0; 1.1.0 resolves to the re-vulnerable tricky@2.0.5", got)
	}
}

// A fix that only exists far above the installed version must still be found, and the
// version actually installed for the vulnerable package must be the audit report's, which
// is authoritative even when the lockfile walk came up blank.
func TestSolveChainUsesFindingVersionForTheLeaf(t *testing.T) {
	reg := baseRegistry()
	reg.deps["utils@1.0.0"]["lodash"] = "^4.17.0"
	c := chain("^1.0.0")
	c[2].Version = ""

	got := solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, c)

	if got.kind != resBump || got.from != "4.17.15" {
		t.Fatalf("got %+v, want bump from the finding's 4.17.15", got)
	}
}

func TestSolveChainSkipsRegistryWhenTheLeafNeedsNoWork(t *testing.T) {
	reg := baseRegistry()
	reg.deps["utils@1.0.0"]["lodash"] = "^4.17.0"

	_ = solve(t, reg, lodashAdvisory(), finding{Version: "4.17.15"}, chain("^1.0.0"))

	// The leaf's own range is already known from the parent's manifest, so a bump costs
	// exactly that one edge lookup -- no walk up the chain.
	if reg.rangeN != 1 {
		t.Errorf("declaredRange called %d times, want 1", reg.rangeN)
	}
}

func TestPlanFixesCollapsesIdenticalOutcomes(t *testing.T) {
	reg := baseRegistry()
	reg.deps["utils@1.0.0"]["lodash"] = "^4.17.0"

	a := lodashAdvisory()
	f := finding{Version: "4.17.15"}
	blocks := []block{{
		advisory: a,
		finding:  f,
		chains:   [][]hop{chain("^1.0.0"), chain("^1.0.0")},
	}}

	fixes := planFixes(blocks, reg)

	if len(fixes) != 1 {
		t.Fatalf("got %d entries, want 1", len(fixes))
	}
	if fixes[0].PathCount != 2 {
		t.Errorf("pathCount = %d, want 2", fixes[0].PathCount)
	}
	if fixes[0].Update == nil || fixes[0].Update.To != "4.17.21" {
		t.Errorf("update = %+v, want lodash -> 4.17.21", fixes[0].Update)
	}
}

func TestPlanFixesKeepsDistinctOutcomesApart(t *testing.T) {
	reg := baseRegistry()
	reg.deps["utils@1.0.0"]["lodash"] = "^4.17.0"
	reg.deps["other@1.0.0"] = map[string]string{"lodash": "4.17.15"}
	reg.versions["other"] = []string{"1.0.0"}

	second := []hop{
		{Name: "backend", Workspace: true},
		{Name: "other", Version: "1.0.0", Range: "^1.0.0", ImporterKey: "backend"},
		{Name: "lodash", Version: "4.17.15", parentName: "other", parentVersion: "1.0.0"},
	}
	blocks := []block{{
		advisory: lodashAdvisory(),
		finding:  finding{Version: "4.17.15"},
		chains:   [][]hop{chain("^1.0.0"), second},
	}}

	fixes := planFixes(blocks, reg)

	if len(fixes) != 2 {
		t.Fatalf("got %d entries, want 2 (one path is fixed by a bump, the other is not)", len(fixes))
	}
}

func TestPlanFixesEmptyMarshalsAsArray(t *testing.T) {
	out, err := json.Marshal(fixReport{Fixes: planFixes(nil, baseRegistry())})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"fixes":[]`) {
		t.Errorf("got %s, want an empty array rather than null", out)
	}
}

func TestParseConstraint(t *testing.T) {
	// Anything that is not a semver range must read as "cannot tell", never as
	// "unsatisfiable" -- the latter would turn a workspace edge into bogus override advice.
	unknown := []string{
		"", "workspace:*", "workspace:^", "catalog:", "catalog:angular",
		"npm:other@^1", "file:../x", "link:../shared",
		"git+https://github.com/x/y.git", "latest",
	}
	for _, s := range unknown {
		if _, ok := parseConstraint(s); ok {
			t.Errorf("parseConstraint(%q) = ok, want unknown", s)
		}
	}

	known := []string{"^1.2.3", "~4.17.0", ">=1.2.3 <2.0.0", "1.x", "*", "4.17.15"}
	for _, s := range known {
		if _, ok := parseConstraint(s); !ok {
			t.Errorf("parseConstraint(%q) = unknown, want a usable constraint", s)
		}
	}
}

func TestIsPatched(t *testing.T) {
	a := advisory{
		VulnerableVersions: "<1.2.3 || >=2.0.0 <2.1.0",
		PatchedVersions:    ">=1.2.3 <2.0.0 || >=2.1.0",
	}
	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.0", false},
		{"1.2.3", true},
		{"1.9.9", true},
		{"2.0.5", false}, // vulnerable again
		{"2.1.0", true},
	}
	for _, tt := range tests {
		v := semver.MustParse(tt.version)
		if got := isPatched(v, a); got != tt.want {
			t.Errorf("isPatched(%s) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestIsPatchedNoFixPublished(t *testing.T) {
	a := advisory{VulnerableVersions: ">=0.0.0", PatchedVersions: "<0.0.0"}
	if isPatched(semver.MustParse("9.9.9"), a) {
		t.Error("no version can be patched when patched_versions is <0.0.0")
	}
}

func TestCapCandidates(t *testing.T) {
	var all []*semver.Version
	for i := 0; i < 200; i++ {
		all = append(all, semver.MustParse("1.0."+itoa(i)))
	}
	got, truncated := capCandidates(all, true)

	if !truncated {
		t.Error("truncated = false, want true so a fruitless search is not reported as certain")
	}
	if len(got) != candidateCap {
		t.Fatalf("len = %d, want %d", len(got), candidateCap)
	}
	// The lowest candidates are where the minimal upgrade lives; the highest few are kept
	// so a fix released only in a much later version is still reachable.
	if got[0].Original() != "1.0.0" {
		t.Errorf("first = %s, want the lowest candidate", got[0])
	}
	if last := got[len(got)-1].Original(); last != "1.0.199" {
		t.Errorf("last = %s, want the highest candidate", last)
	}
}

// Scanning versions of the vulnerable package itself costs no registry calls, so that
// scan must be exhaustive: capping it would report the lowest version *examined* rather
// than the lowest version that actually fixes the advisory.
func TestCapCandidatesLeavesFreeScansExhaustive(t *testing.T) {
	var all []*semver.Version
	for i := 0; i < 200; i++ {
		all = append(all, semver.MustParse("1.0."+itoa(i)))
	}

	got, truncated := capCandidates(all, false)

	if len(got) != 200 || truncated {
		t.Errorf("len = %d, truncated = %v; want 200, false", len(got), truncated)
	}
}

// The fix for a vulnerable package often sits well past the first handful of releases.
func TestSolveChainFindsTheLowestFixEvenFarUpTheList(t *testing.T) {
	reg := baseRegistry()
	reg.versions["lodash"] = nil
	for minor := 0; minor < 40; minor++ {
		reg.versions["lodash"] = append(reg.versions["lodash"], "4."+itoa(minor)+".0")
	}
	reg.deps["utils@1.0.0"]["lodash"] = "^4.0.0"
	a := lodashAdvisory()
	a.VulnerableVersions = "<4.30.0"
	a.PatchedVersions = ">=4.30.0"

	got := solve(t, reg, a, finding{Version: "4.0.0"}, chain("^1.0.0"))

	if got.kind != resBump || got.to != "4.30.0" {
		t.Fatalf("got %+v, want bump lodash -> 4.30.0", got)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
