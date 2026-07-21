package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/user/pnpm-vuln-fixer/internal/graph"
	"github.com/user/pnpm-vuln-fixer/internal/lockfile"
	"github.com/user/pnpm-vuln-fixer/internal/npmsemver"
	"github.com/user/pnpm-vuln-fixer/internal/registry"
)

// VerdictKind describes the outcome of a chain analysis.
type VerdictKind int

const (
	VerdictNoBumpNeeded VerdictKind = iota // chain already satisfiable by re-resolution
	VerdictBump                            // one or more ancestors must be bumped
	VerdictDeadEnd                         // no available ancestor version allows the fix
	VerdictDirectDep                       // vuln is a direct dep of the importer
)

// FixAction records a single package update needed to resolve the chain.
type FixAction struct {
	Package     string // package name
	FromVer     string // current resolved version (empty for specifier-only updates)
	ToVer       string // target version (or range when IsSpecifier is true)
	IsSpecifier bool   // true means ToVer is a package.json specifier, not a resolved version
}

// ChainResult is the analysis outcome for one importer-to-vuln path.
type ChainResult struct {
	Chain       []*graph.Node
	Verdict     VerdictKind
	Actions     []FixAction // ordered from leaf toward root
	BlockedBy   string      // dead-end: which package has no viable upgrade
	BlockReason string      // dead-end: human-readable explanation
}

// Report aggregates all per-chain results for a single vulnerability.
type Report struct {
	VulnPkg       string
	VulnVer       string
	FixedVer      string
	Chains        []*ChainResult
	AllFixable    bool        // true only when every chain has a fix
	MinUnion      []FixAction // minimal set of package updates across all chains
	NeedsOverride bool        // true when at least one chain has no ancestor fix
}

// RegistryClient is the interface the analyzer uses to fetch package metadata.
type RegistryClient interface {
	FetchAbbrevMeta(pkg string) (*registry.AbbrevMeta, error)
}

// AnalyzeChain evaluates a single importer-to-vuln chain bottom-up.
// chain must be oriented [importer, ..., directParent, vuln].
func AnalyzeChain(chain []*graph.Node, lf *lockfile.Lockfile, vulnPkg, fixedVersion string, reg RegistryClient) (*ChainResult, error) {
	result := &ChainResult{Chain: chain}

	if len(chain) < 2 {
		result.Verdict = VerdictNoBumpNeeded
		return result, nil
	}

	// Direct-dep short-circuit: vuln is immediately under the importer.
	if len(chain) == 2 {
		if de := importerDepEntry(lf, chain[0].DepPath, vulnPkg); de != nil {
			if de.IsLocal {
				result.Verdict = VerdictDeadEnd
				result.BlockedBy = vulnPkg
				result.BlockReason = fmt.Sprintf(
					"%s is a workspace/local package in %s; use pnpm.overrides instead",
					vulnPkg, chain[0].DepPath,
				)
				return result, nil
			}
			checkSpecifier := de.Specifier
			if de.IsAlias {
				rest := de.Specifier[4:] // strip "npm:"
				if idx := strings.LastIndex(rest, "@"); idx >= 0 {
					checkSpecifier = rest[idx+1:]
				}
			}
			if alreadyOK, _ := npmsemver.Satisfies(fixedVersion, checkSpecifier); alreadyOK {
				result.Verdict = VerdictNoBumpNeeded
				return result, nil
			}
		}
		result.Verdict = VerdictDirectDep
		result.Actions = []FixAction{{Package: vulnPkg, ToVer: fixedVersion, IsSpecifier: true}}
		return result, nil
	}

	// targetChildVer is what version we need the child at the current edge to be.
	// Starts as fixedVersion (we need vuln at fixedVersion).
	targetChildVer := fixedVersion

	// Walk from direct parent of vuln (index len-2) up toward the importer (index 0).
	for i := len(chain) - 2; i >= 1; i-- {
		node := chain[i]
		child := chain[i+1]

		meta, err := reg.FetchAbbrevMeta(node.Name)
		if err != nil {
			return nil, fmt.Errorf("fetch registry metadata for %s: %w", node.Name, err)
		}

		verMeta, ok := meta.Versions[node.Version]
		if !ok {
			return nil, fmt.Errorf("version %s not found in registry for package %s", node.Version, node.Name)
		}

		childRange := getDeclaredRange(verMeta, child.Name)
		if childRange == "" {
			// Node doesn't explicitly list this child; treat as already satisfied.
			if len(result.Actions) == 0 {
				result.Verdict = VerdictNoBumpNeeded
			} else {
				result.Verdict = VerdictBump
			}
			return result, nil
		}

		alreadyOK, err := npmsemver.Satisfies(targetChildVer, childRange)
		if err != nil {
			return nil, fmt.Errorf("semver check (%s satisfies %s): %w", targetChildVer, childRange, err)
		}

		if alreadyOK {
			// Current ancestor version already admits the target child version.
			// No bump needed at this level; everything above can stay as-is.
			if len(result.Actions) == 0 {
				result.Verdict = VerdictNoBumpNeeded
			} else {
				result.Verdict = VerdictBump
			}
			return result, nil
		}

		// Must find a newer version of node that admits targetChildVer.
		sortedVers := sortedVersionKeys(meta.Versions)
		newVer, found := npmsemver.MinVersionAbove(sortedVers, node.Version, func(v string) bool {
			pv, ok := meta.Versions[v]
			if !ok {
				return false
			}
			r := getDeclaredRange(pv, child.Name)
			if r == "" {
				return true // newer version dropped the dependency entirely
			}
			ok2, _ := npmsemver.Satisfies(targetChildVer, r)
			return ok2
		})

		if !found {
			result.Verdict = VerdictDeadEnd
			result.BlockedBy = node.Name
			result.BlockReason = fmt.Sprintf(
				"%s@%s has no published version whose range for %s admits %s",
				node.Name, node.Version, child.Name, targetChildVer,
			)
			return result, nil
		}

		result.Actions = append(result.Actions, FixAction{
			Package: node.Name,
			FromVer: node.Version,
			ToVer:   newVer,
		})

		// Check whether the parent (chain[i-1]) is the importer root.
		parent := chain[i-1]
		if parent.IsRoot {
			// Look up the importer's declared specifier for this node.
			if de := importerDepEntry(lf, parent.DepPath, node.Name); de != nil {
				if de.IsLocal {
					// workspace: or link: dep — cannot upgrade via registry.
					result.Verdict = VerdictDeadEnd
					result.BlockedBy = node.Name
					result.BlockReason = fmt.Sprintf(
						"%s is a workspace/local package in %s; use pnpm.overrides instead",
						node.Name, parent.DepPath,
					)
					return result, nil
				}
				// For alias entries (npm:pkgname@range) extract the bare
				// semver range before checking.
				checkSpecifier := de.Specifier
				if de.IsAlias {
					rest := de.Specifier[4:] // strip "npm:"
					if idx := strings.LastIndex(rest, "@"); idx >= 0 {
						checkSpecifier = rest[idx+1:]
					}
				}
				admits, _ := npmsemver.Satisfies(newVer, checkSpecifier)
				if !admits {
					// Importer's specifier must also be widened.
					toVer := "^" + newVer
					if de.IsAlias {
						toVer = "npm:" + de.AliasOf + "@^" + newVer
					}
					result.Actions = append(result.Actions, FixAction{
						Package:     node.Name,
						ToVer:       toVer,
						IsSpecifier: true,
					})
				}
			}
			result.Verdict = VerdictBump
			return result, nil
		}

		// Propagate upward: the grandparent must now admit newVer for node.
		targetChildVer = newVer
	}

	// Unreachable: for all valid chains (len>=3), the loop hits parent.IsRoot==true
	// at i=1 and returns. This return is kept only to satisfy the compiler.
	return result, nil
}

// Analyze runs AnalyzeChain on every provided chain and aggregates the results.
func Analyze(chains [][]*graph.Node, lf *lockfile.Lockfile, vulnPkg, vulnVer, fixedVersion string, reg RegistryClient) (*Report, error) {
	report := &Report{
		VulnPkg:  vulnPkg,
		VulnVer:  vulnVer,
		FixedVer: fixedVersion,
	}

	for _, chain := range chains {
		cr, err := AnalyzeChain(chain, lf, vulnPkg, fixedVersion, reg)
		if err != nil {
			return nil, err
		}
		report.Chains = append(report.Chains, cr)
	}

	report.AllFixable = len(report.Chains) > 0
	for _, cr := range report.Chains {
		if cr.Verdict == VerdictDeadEnd {
			report.AllFixable = false
			report.NeedsOverride = true
		}
	}

	report.MinUnion = computeMinUnion(report.Chains)
	return report, nil
}

// getDeclaredRange returns node version v's declared range for childName,
// checking dependencies then optionalDependencies.
func getDeclaredRange(v *registry.PackageVersion, childName string) string {
	if v == nil {
		return ""
	}
	if r, ok := v.Dependencies[childName]; ok {
		return r
	}
	if r, ok := v.OptionalDependencies[childName]; ok {
		return r
	}
	return ""
}

// importerDepEntry returns the DepEntry the importer declares for depName,
// searching across all dependency groups. Also matches alias entries where
// AliasOf equals depName (e.g. "my-express: npm:express@^4" matches "express").
func importerDepEntry(lf *lockfile.Lockfile, importerPath, depName string) *lockfile.DepEntry {
	imp, ok := lf.Importers[importerPath]
	if !ok {
		return nil
	}
	for _, deps := range []map[string]*lockfile.DepEntry{
		imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies,
	} {
		if de, ok := deps[depName]; ok {
			return de
		}
		for _, de := range deps {
			if de.IsAlias && de.AliasOf == depName {
				return de
			}
		}
	}
	return nil
}

// sortedVersionKeys returns the version keys of m sorted by ascending semver.
// Versions that cannot be parsed are appended last.
func sortedVersionKeys(m map[string]*registry.PackageVersion) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		vi, ei := semver.NewVersion(keys[i])
		vj, ej := semver.NewVersion(keys[j])
		if ei != nil && ej != nil {
			return keys[i] < keys[j]
		}
		if ei != nil {
			return false
		}
		if ej != nil {
			return true
		}
		return vi.LessThan(vj)
	})
	return keys
}

// computeMinUnion builds the minimal union of package updates across all chains.
// For each package, we take the highest required version (greedy approach).
// Specifier updates (IsSpecifier=true) are collected separately and appended after
// version-bump entries so the FIX summary is self-sufficient.
func computeMinUnion(chains []*ChainResult) []FixAction {
	best := make(map[string]string)     // package → highest required version so far
	bestSpec := make(map[string]string) // package → ToVer of highest required specifier
	for _, cr := range chains {
		for _, fa := range cr.Actions {
			if fa.IsSpecifier {
				cur, exists := bestSpec[fa.Package]
				if !exists {
					bestSpec[fa.Package] = fa.ToVer
					continue
				}
				cv, _ := semver.NewVersion(semverFromSpecifier(cur))
				nv, _ := semver.NewVersion(semverFromSpecifier(fa.ToVer))
				if cv != nil && nv != nil && nv.GreaterThan(cv) {
					bestSpec[fa.Package] = fa.ToVer
				}
				continue
			}
			cur, exists := best[fa.Package]
			if !exists {
				best[fa.Package] = fa.ToVer
				continue
			}
			cv, err1 := semver.NewVersion(cur)
			nv, err2 := semver.NewVersion(fa.ToVer)
			if err1 == nil && err2 == nil && nv.GreaterThan(cv) {
				best[fa.Package] = fa.ToVer
			}
		}
	}

	result := make([]FixAction, 0, len(best)+len(bestSpec))
	for pkg, ver := range best {
		result = append(result, FixAction{Package: pkg, ToVer: ver})
	}
	for pkg, toVer := range bestSpec {
		result = append(result, FixAction{Package: pkg, ToVer: toVer, IsSpecifier: true})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Package != result[j].Package {
			return result[i].Package < result[j].Package
		}
		return !result[i].IsSpecifier // version bumps sort before specifier updates
	})
	return result
}

// semverFromSpecifier extracts the bare semver string from a specifier ToVer value.
// Handles "^4.17.1" → "4.17.1" and "npm:pkg@^4.17.1" → "4.17.1".
func semverFromSpecifier(s string) string {
	if idx := strings.LastIndex(s, "@"); idx >= 0 {
		s = s[idx+1:]
	}
	return strings.TrimLeft(s, "^~>=<")
}
