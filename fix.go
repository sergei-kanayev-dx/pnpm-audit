package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// The fix search answers, for every vulnerable package, the one question the tree output
// leaves to the reader: what is the smallest change that actually resolves this?
//
// Three things make the answer less obvious than "install the patched version":
//
//   - pnpm installs the *highest* version satisfying a declared range, so it is not
//     enough for a patched version to exist somewhere inside the range -- the version
//     that would actually be installed has to be patched. Advisories are routinely
//     non-contiguous (">=1.2.3 <2.0.0 || >=2.1.0"), so a later version can be vulnerable
//     again.
//   - a range that excludes every patched version can only be widened by changing the
//     package that declares it, which means walking up the chain.
//   - only a workspace package.json is freely editable; every range above it belongs to
//     a published manifest and can only be changed by moving to another published version.
type resolutionKind string

const (
	// resBump: the vulnerable package itself can move to a patched version.
	resBump resolutionKind = "bump"
	// resUpdateParent: an ancestor has to move before a patched version is reachable.
	resUpdateParent resolutionKind = "update-parent"
	// resOverride: nothing on this path can move; only a pnpm `overrides` entry helps.
	resOverride resolutionKind = "override"
	// resUnknown: the chain or the registry could not be resolved far enough to decide.
	// Never collapse this into resOverride -- a confident wrong answer is the worst output.
	resUnknown resolutionKind = "unknown"
)

// Candidates are scanned ascending so the first hit is the lowest fixing version.
//
// Examining a candidate of the vulnerable package itself is free -- it is a range check,
// no registry call -- so that scan is exhaustive. Examining a candidate *ancestor* costs
// at least one manifest fetch, so those are capped, and the highest few are kept as well
// so a fix that only exists in a much later major is still found. A cap that cut out the
// middle of the list would report a version that is merely the lowest one looked at,
// which is not the same thing as the lowest one that works.
const (
	candidateCap  = 60
	candidateTail = 5
	// warmBatch is how many candidate manifests are fetched concurrently before the
	// sequential scan reaches them. The scan usually stops early, so warming the whole
	// candidate list up front would waste most of it.
	warmBatch = 16
)

// manifestWarmer is implemented by a registry that can fetch manifests concurrently.
// It is an optional interface so the seam the solver requires stays small.
type manifestWarmer interface {
	warmManifests(pkg string, versions []string)
}

// errUnknown marks "the registry or the lockfile could not tell us", as opposed to a
// definite negative answer.
var errUnknown = errors.New("unresolved")

// registryClient is the seam the solver talks to, so the whole search is testable
// without a network or a pnpm binary. *rangeLookup implements it.
type registryClient interface {
	publishedVersions(pkg string) ([]*semver.Version, error)
	declaredRange(parent, version, child string) (rng string, present bool, err error)
}

type solver struct {
	reg registryClient

	fixedMemo map[string]bool   // "pkg@version|rest" -> does this subtree end up patched?
	maxMemo   map[string]string // "pkg|range" -> version pnpm would install

	// truncated records that a capped scan left versions unexamined while solving the
	// current chain, so a negative answer can be reported as less than certain.
	truncated bool
}

func newSolver(reg registryClient) *solver {
	return &solver{
		reg:       reg,
		fixedMemo: make(map[string]bool),
		maxMemo:   make(map[string]string),
	}
}

// parseConstraint turns a declared range into a semver constraint. ok is false for
// anything that is not a semver range at all -- "workspace:*", "catalog:angular",
// "npm:other@^1", "file:../x", a git URL, "latest". Those mean "we cannot tell", never
// "nothing satisfies this": reading them as unsatisfiable would produce confident
// "fix by overriding" advice for edges that have no registry versions in the first place.
func parseConstraint(s string) (*semver.Constraints, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if s == "*" || s == "x" || s == "X" {
		c, err := semver.NewConstraint("*")
		return c, err == nil
	}
	if strings.ContainsAny(s, ":/") {
		// workspace:, catalog:, npm:, file:, link:, git URLs.
		return nil, false
	}
	c, err := semver.NewConstraint(s)
	if err != nil {
		return nil, false
	}
	return c, true
}

// isPatched reports whether v resolves the advisory: inside the patched range and outside
// the vulnerable one. Both are checked because patched ranges are not upward-closed.
func isPatched(v *semver.Version, a advisory) bool {
	patched, ok := parseConstraint(a.PatchedVersions)
	if !ok {
		// "<0.0.0" parses and matches nothing, which is the npm convention for "no fix
		// published"; anything unparseable means we cannot claim a version is patched.
		return false
	}
	if !patched.Check(v) {
		return false
	}
	if vulnerable, ok := parseConstraint(a.VulnerableVersions); ok && vulnerable.Check(v) {
		return false
	}
	return true
}

// resolveMax returns the version pnpm would install for a declared range: the highest
// published non-prerelease version satisfying it.
func (s *solver) resolveMax(pkg, rng string) (string, error) {
	key := pkg + "|" + rng
	if v, ok := s.maxMemo[key]; ok {
		if v == "" {
			return "", errUnknown
		}
		return v, nil
	}

	c, ok := parseConstraint(rng)
	if !ok {
		s.maxMemo[key] = ""
		return "", errUnknown
	}
	versions, err := s.reg.publishedVersions(pkg)
	if err != nil {
		return "", errUnknown
	}

	for i := len(versions) - 1; i >= 0; i-- {
		v := versions[i]
		if v.Prerelease() != "" {
			continue
		}
		if c.Check(v) {
			s.maxMemo[key] = v.Original()
			return v.Original(), nil
		}
	}
	s.maxMemo[key] = ""
	return "", errUnknown
}

// endsPatched reports whether installing pkg@version leaves the vulnerable package at the
// end of rest patched. rest is the remaining chain below pkg; an empty rest means pkg is
// the vulnerable package itself.
//
// Each level below the one being changed is resolved the way pnpm would resolve it --
// highest version satisfying the declared range -- rather than "some satisfying version
// is patched", which would claim fixes that a real install does not produce.
func (s *solver) endsPatched(pkg, version string, rest []string, a advisory) (bool, error) {
	if len(rest) == 0 {
		v, err := semver.NewVersion(version)
		if err != nil {
			return false, errUnknown
		}
		return isPatched(v, a), nil
	}

	key := fmt.Sprintf("%d|%s@%s|%s", a.ID, pkg, version, strings.Join(rest, ">"))
	if got, ok := s.fixedMemo[key]; ok {
		return got, nil
	}

	child := rest[0]
	rng, present, err := s.reg.declaredRange(pkg, version, child)
	if err != nil {
		return false, errUnknown
	}
	if !present {
		// This version does not depend on the child at all: the path is severed, which
		// resolves the advisory along it just as surely as a patched version would.
		s.fixedMemo[key] = true
		return true, nil
	}

	resolved, err := s.resolveMax(child, rng)
	if err != nil {
		return false, errUnknown
	}

	got, err := s.endsPatched(child, resolved, rest[1:], a)
	if err != nil {
		return false, err
	}
	s.fixedMemo[key] = got
	return got, nil
}

// lowestFix returns the lowest version of pkg that satisfies constraint, is newer than
// floor, and leaves the chain below it patched. floor may be empty to consider every
// published version, which is what the relaxed search at a workspace package.json does.
func (s *solver) lowestFix(pkg, rng, floor string, rest []string, a advisory) (string, error) {
	c, ok := parseConstraint(rng)
	if !ok {
		return "", errUnknown
	}
	versions, err := s.reg.publishedVersions(pkg)
	if err != nil {
		return "", errUnknown
	}

	var floorV *semver.Version
	if floor != "" {
		if fv, err := semver.NewVersion(floor); err == nil {
			floorV = fv
		}
	}

	eligible := make([]*semver.Version, 0, len(versions))
	for _, v := range versions {
		if v.Prerelease() != "" {
			continue
		}
		if floorV != nil && !v.GreaterThan(floorV) {
			continue
		}
		if !c.Check(v) {
			continue
		}
		eligible = append(eligible, v)
	}

	// Only an ancestor costs registry calls per candidate; the vulnerable package itself
	// is decided by a range check.
	costly := len(rest) > 0
	candidates, truncated := capCandidates(eligible, costly)
	if truncated {
		s.truncated = true
	}

	sawUnknown := false
	for i, v := range candidates {
		if costly && i%warmBatch == 0 {
			s.warm(pkg, candidates[i:min(i+warmBatch, len(candidates))])
		}
		ok, err := s.endsPatched(pkg, v.Original(), rest, a)
		if err != nil {
			sawUnknown = true
			continue
		}
		if ok {
			return v.Original(), nil
		}
	}
	if sawUnknown {
		return "", errUnknown
	}
	return "", nil // definitively nothing
}

// warm fetches a batch of candidate manifests concurrently. The scan itself has to stay
// sequential -- it stops at the first version that works -- so this is the only place its
// registry traffic overlaps.
func (s *solver) warm(pkg string, batch []*semver.Version) {
	w, ok := s.reg.(manifestWarmer)
	if !ok {
		return
	}
	versions := make([]string, len(batch))
	for i, v := range batch {
		versions[i] = v.Original()
	}
	w.warmManifests(pkg, versions)
}

// capCandidates bounds a costly scan to the lowest candidates, where the minimal upgrade
// lives, plus the highest few, where a fix released only in a later major would be. A free
// scan is exhaustive. The second result reports whether anything was left out, so a
// fruitless search is not reported as a confident "nothing can fix this".
func capCandidates(v []*semver.Version, costly bool) ([]*semver.Version, bool) {
	if !costly || len(v) <= candidateCap {
		return v, false
	}
	out := make([]*semver.Version, 0, candidateCap)
	out = append(out, v[:candidateCap-candidateTail]...)
	return append(out, v[len(v)-candidateTail:]...), true
}

// chainFix is the verdict for one usage path.
type chainFix struct {
	kind      resolutionKind
	pkg       string // package to change
	from, to  string
	importer  string // workspace whose package.json must be edited, if any
	reason    string
	truncated bool // some candidate versions were not examined
}

// solveChain finds the minimal change along one chain.
//
// The search starts at the vulnerable package and walks up only when forced, because the
// deepest change that works is the least disruptive one. It stops at the first hop whose
// version or declared range is unknown: past that point nothing can be claimed.
func (s *solver) solveChain(a advisory, f finding, c []hop) chainFix {
	s.truncated = false
	leaf := len(c) - 1
	names := make([]string, len(c))
	for i, h := range c {
		names[i] = h.Name
	}

	// The audit report's own version is authoritative for the vulnerable package; the
	// lockfile walk can leave it blank on an unresolvable path.
	installed := make([]string, len(c))
	for i, h := range c {
		installed[i] = h.Version
	}
	if f.Version != "" {
		installed[leaf] = f.Version
	}

	// editSite is the first hop that comes from the registry: everything above it is a
	// workspace package whose package.json the user can edit directly. A "link:" edge
	// keeps the walk in workspace context, so this is not always index 1.
	editSite := -1
	for i := 1; i < len(c); i++ {
		if c[i-1].Workspace && !c[i].Workspace {
			editSite = i
			break
		}
	}
	if editSite < 0 {
		return chainFix{kind: resUnknown, reason: "no registry package on this path"}
	}

	sawUnknown := false

	for i := leaf; i >= editSite; i-- {
		if installed[i] == "" {
			// Unresolvable hop: neither this level nor anything above it can be judged.
			sawUnknown = true
			break
		}
		rng, err := s.constraintFor(c, i)
		if err != nil {
			sawUnknown = true
			break
		}

		v, err := s.lowestFix(names[i], rng, installed[i], names[i+1:], a)
		if err != nil {
			sawUnknown = true
			break
		}
		if v == "" {
			continue // this level cannot absorb the fix; try its parent
		}

		kind := resUpdateParent
		if i == leaf {
			kind = resBump
		}
		return chainFix{
			kind:   kind,
			pkg:    names[i],
			from:   installed[i],
			to:     v,
			reason: fmt.Sprintf("%s@%s satisfies the declared range %q and leaves %s patched", names[i], v, rng, a.ModuleName),
		}
	}

	// Nothing fits inside the ranges as declared. The one range the user can widen is the
	// specifier in the workspace package.json, so retry the edit site unconstrained.
	if installed[editSite] != "" {
		v, err := s.lowestFix(names[editSite], "*", installed[editSite], names[editSite+1:], a)
		switch {
		case err != nil:
			sawUnknown = true
		case v != "":
			kind := resUpdateParent
			if editSite == leaf {
				kind = resBump
			}
			return chainFix{
				kind:     kind,
				pkg:      names[editSite],
				from:     installed[editSite],
				to:       v,
				importer: c[editSite].ImporterKey,
				reason: fmt.Sprintf("outside the declared range %q; widen the specifier in %s",
					c[editSite].Range, manifestOf(c[editSite].ImporterKey)),
			}
		}
	}

	if sawUnknown {
		return chainFix{kind: resUnknown, reason: "chain or registry could not be resolved"}
	}
	if !anyPatchedVersion(s, a) {
		return chainFix{kind: resOverride, reason: "no published version of " + a.ModuleName + " resolves this advisory"}
	}
	return chainFix{
		kind:      resOverride,
		reason:    "no package on this path can move to a version that resolves the advisory",
		truncated: s.truncated,
	}
}

// constraintFor returns the range the parent of hop i declares for it. Workspace edges
// carry it in the lockfile; deeper ones come from the parent's published manifest.
func (s *solver) constraintFor(c []hop, i int) (string, error) {
	if c[i].Range != "" {
		return c[i].Range, nil
	}
	if c[i].parentName == "" || c[i].parentVersion == "" {
		return "", errUnknown
	}
	rng, present, err := s.reg.declaredRange(c[i].parentName, c[i].parentVersion, c[i].Name)
	if err != nil || !present {
		return "", errUnknown
	}
	return rng, nil
}

// anyPatchedVersion reports whether the advisory has a fix published at all. npm spells
// "there is no fix" as patched_versions "<0.0.0".
func anyPatchedVersion(s *solver, a advisory) bool {
	versions, err := s.reg.publishedVersions(a.ModuleName)
	if err != nil {
		return true // unknown; do not claim there is no fix
	}
	for _, v := range versions {
		if v.Prerelease() == "" && isPatched(v, a) {
			return true
		}
	}
	return false
}

func manifestOf(importer string) string {
	switch importer {
	case "":
		return "the workspace package.json"
	case ".":
		return "package.json"
	default:
		return importer + "/package.json"
	}
}

// --- report ---------------------------------------------------------------

type fixReport struct {
	Fixes   []fixEntry `json:"fixes"`
	Summary fixSummary `json:"summary"`
	Notes   []string   `json:"notes,omitempty"`
}

type fixSummary struct {
	Advisories        int            `json:"advisories"`
	BySeverity        map[string]int `json:"bySeverity,omitempty"`
	ByResolution      map[string]int `json:"byResolution"`
	TotalDependencies int            `json:"totalDependencies"`
}

type fixEntry struct {
	Module     string         `json:"module"`
	Current    string         `json:"current"`
	Severity   string         `json:"severity"`
	AdvisoryID int            `json:"advisoryId"`
	Title      string         `json:"title,omitempty"`
	URL        string         `json:"url,omitempty"`
	Patched    string         `json:"patched"`
	Dev        bool           `json:"dev,omitempty"`
	Optional   bool           `json:"optional,omitempty"`
	Resolution resolutionKind `json:"resolution"`
	Update     *fixUpdate     `json:"update,omitempty"`
	Reason     string         `json:"reason"`
	// Truncated marks a verdict reached without examining every published version.
	Truncated bool     `json:"truncated,omitempty"`
	Path      []string `json:"path"`
	PathCount int      `json:"pathCount"`
}

type fixUpdate struct {
	Package  string `json:"package"`
	From     string `json:"from"`
	To       string `json:"to"`
	Importer string `json:"importer,omitempty"`
}

// planFixes solves every chain and collapses identical outcomes, so a vulnerable package
// reached three ways with the same remedy is reported once with pathCount 3.
func planFixes(blocks []block, reg registryClient) []fixEntry {
	s := newSolver(reg)

	type agg struct {
		entry fixEntry
		order int
	}
	seen := make(map[string]*agg)
	var keys []string

	for _, b := range blocks {
		for _, c := range b.chains {
			fix := s.solveChain(b.advisory, b.finding, c)

			key := fmt.Sprintf("%d|%s|%s|%s|%s", b.advisory.ID, fix.kind, fix.pkg, fix.to, fix.importer)
			if a, ok := seen[key]; ok {
				a.entry.PathCount++
				continue
			}

			e := fixEntry{
				Module:     b.advisory.ModuleName,
				Current:    b.finding.Version,
				Severity:   b.advisory.Severity,
				AdvisoryID: b.advisory.ID,
				Title:      b.advisory.Title,
				URL:        b.advisory.URL,
				Patched:    b.advisory.PatchedVersions,
				Dev:        b.finding.Dev,
				Optional:   b.finding.Optional,
				Resolution: fix.kind,
				Reason:     fix.reason,
				Truncated:  fix.truncated,
				Path:       chainNames(c),
				PathCount:  1,
			}
			if fix.pkg != "" {
				e.Update = &fixUpdate{Package: fix.pkg, From: fix.from, To: fix.to, Importer: fix.importer}
			}
			seen[key] = &agg{entry: e, order: len(keys)}
			keys = append(keys, key)
		}
	}

	out := make([]fixEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, seen[k].entry)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank[out[i].Severity], severityRank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].AdvisoryID < out[j].AdvisoryID
	})
	return out
}

func chainNames(c []hop) []string {
	names := make([]string, len(c))
	for i, h := range c {
		names[i] = h.Name
	}
	return names
}

// packagesIn lists every package name appearing below a workspace hop, so their version
// lists can be prefetched before the sequential search begins.
func packagesIn(blocks []block) []string {
	var names []string
	for _, b := range blocks {
		names = append(names, b.advisory.ModuleName)
		for _, c := range b.chains {
			for _, h := range c {
				if !h.Workspace {
					names = append(names, h.Name)
				}
			}
		}
	}
	return names
}

// printFixReport writes the JSON fix report to stdout. Registry failures go into the
// document itself as well as stderr, so a redirected run is self-contained.
func printFixReport(report auditReport, blocks []block, lookup *rangeLookup) error {
	lookup.prefetchVersions(packagesIn(blocks))

	out := fixReport{
		Fixes: planFixes(blocks, lookup),
		Summary: fixSummary{
			Advisories:        len(report.Advisories),
			BySeverity:        report.Metadata.Vulnerabilities,
			ByResolution:      map[string]int{},
			TotalDependencies: report.Metadata.TotalDependencies,
		},
		Notes: lookup.problems(),
	}
	for _, e := range out.Fixes {
		out.Summary.ByResolution[string(e.Resolution)]++
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
