package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/user/pnpm-vuln-fixer/internal/analyzer"
	"github.com/user/pnpm-vuln-fixer/internal/graph"
)

// PrintHuman writes a human-readable vulnerability fix report to w.
func PrintHuman(w io.Writer, r *analyzer.Report) {
	fmt.Fprintf(w, "Vulnerable: %s@%s → fixed %s\n", r.VulnPkg, r.VulnVer, r.FixedVer)

	fixable := 0
	for i, cr := range r.Chains {
		fmt.Fprintf(w, "\nChain %d: %s\n", i+1, formatChain(cr.Chain))
		switch cr.Verdict {
		case analyzer.VerdictNoBumpNeeded:
			fmt.Fprintf(w, "  already satisfied — run `pnpm update %s` to re-resolve\n", r.VulnPkg)
			fixable++
		case analyzer.VerdictDirectDep:
			fmt.Fprintf(w, "  %s is a direct dependency — update specifier to %s\n", r.VulnPkg, r.FixedVer)
			fixable++
		case analyzer.VerdictBump:
			for _, a := range cr.Actions {
				if a.IsSpecifier {
					fmt.Fprintf(w, "  → update %s specifier in package.json to %s\n", a.Package, a.ToVer)
				} else if a.FromVer != "" {
					fmt.Fprintf(w, "  → bump %s from %s to %s\n", a.Package, a.FromVer, a.ToVer)
				} else {
					fmt.Fprintf(w, "  → bump %s to %s\n", a.Package, a.ToVer)
				}
			}
			fixable++
		case analyzer.VerdictDeadEnd:
			fmt.Fprintf(w, "  BLOCKED: %s\n", cr.BlockReason)
		}
	}

	total := len(r.Chains)
	fmt.Fprintln(w)
	if r.AllFixable {
		if len(r.MinUnion) > 0 {
			fmt.Fprintf(w, "FIX: update the following (resolves %d/%d chains):\n", fixable, total)
			for _, a := range r.MinUnion {
				printFixAction(w, a)
			}
		} else {
			fmt.Fprintf(w, "FIX: no package updates needed — run `pnpm update %s` (resolves %d/%d chains)\n", r.VulnPkg, fixable, total)
		}
	} else if fixable > 0 {
		fmt.Fprintf(w, "PARTIAL FIX (%d/%d chains fixable):\n", fixable, total)
		for _, a := range r.MinUnion {
			printFixAction(w, a)
		}
	} else {
		fmt.Fprintf(w, "NO FIX: no ancestor version admits the fixed version in any chain\n")
	}

	if r.NeedsOverride {
		fmt.Fprintf(w, "\nOVERRIDE (fallback — forced, not a natural upgrade):\n")
		fmt.Fprintf(w, "  Add to package.json:\n")
		fmt.Fprintf(w, "    \"pnpm\": { \"overrides\": { \"%s\": \"%s\" } }\n", r.VulnPkg, r.FixedVer)
	}
}

func printFixAction(w io.Writer, a analyzer.FixAction) {
	if a.IsSpecifier {
		fmt.Fprintf(w, "  - update %s specifier in package.json to %s\n", a.Package, a.ToVer)
	} else {
		fmt.Fprintf(w, "  - %s → %s\n", a.Package, a.ToVer)
	}
}

func formatChain(chain []*graph.Node) string {
	parts := make([]string, len(chain))
	for i, n := range chain {
		if n.IsRoot {
			parts[i] = n.DepPath
		} else {
			parts[i] = n.Name + "@" + n.Version
		}
	}
	return strings.Join(parts, " > ")
}
