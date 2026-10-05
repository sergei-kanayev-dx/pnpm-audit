// Command pnpm-audit-parents runs `pnpm audit --json` in a pnpm monorepo and, for every
// vulnerability, expands each reported usage path into the full chain from the
// workspace package down to the vulnerable one. Every hop shows the version actually
// installed alongside the range its parent declares for it, which is what tells you
// whether a patched version is already reachable within the declared ranges or whether
// an ancestor's constraint has to be widened first.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"unicode/utf8"
)

// pnpm 11 emits the npm audit v6 "advisories" format. Only the fields used here are
// declared; encoding/json ignores the rest (cwe, bundled, github_advisory_id, ...).
type auditReport struct {
	Advisories map[string]advisory `json:"advisories"`
	Metadata   metadata            `json:"metadata"`
	// pnpm reports failures such as a missing lockfile as a well-formed JSON object
	// with a zero exit status, so this has to be checked before trusting Advisories.
	Error *auditError `json:"error"`
}

type auditError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type advisory struct {
	ID                 int       `json:"id"`
	Title              string    `json:"title"`
	ModuleName         string    `json:"module_name"`
	Severity           string    `json:"severity"`
	VulnerableVersions string    `json:"vulnerable_versions"`
	PatchedVersions    string    `json:"patched_versions"`
	URL                string    `json:"url"`
	Findings           []finding `json:"findings"`
}

type finding struct {
	Version  string   `json:"version"`
	Paths    []string `json:"paths"`
	Dev      bool     `json:"dev"`
	Optional bool     `json:"optional"`
}

type metadata struct {
	Vulnerabilities   map[string]int `json:"vulnerabilities"`
	TotalDependencies int            `json:"totalDependencies"`
}

// severityRank orders advisories most severe first. Unknown severities sort last.
var severityRank = map[string]int{
	"critical": 0,
	"high":     1,
	"moderate": 2,
	"low":      3,
	"info":     4,
}

// registryPathCap is the number of usage paths the registry returns per advisory before
// truncating. A finding reporting exactly this many paths is almost certainly clipped.
const registryPathCap = 100

const usage = "usage: pnpm-audit-parents [dir] [-no-ranges] [-fix-deps-json]\n\n" +
	"  dir              workspace to audit (default \".\")\n" +
	"  -no-ranges       skip every registry lookup; print installed versions only\n" +
	"  -fix-deps-json   print a JSON report of the minimal change that resolves each\n" +
	"                   advisory, instead of the usage-path tree"

// block is one finding with its usage paths already expanded into chains, held aside
// so that every registry lookup in the whole report can be batched before rendering.
type block struct {
	advisory  advisory
	finding   finding
	chains    [][]hop
	pathCount int // before de-duplication
}

// runAudit executes `pnpm audit --json` in dir and returns its stdout.
//
// pnpm exits 1 whenever it finds vulnerabilities, which is the normal case here, so the
// exit status is deliberately ignored: success is judged by whether stdout is valid JSON.
func runAudit(dir string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("pnpm", "audit", "--json")
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// A non-ExitError (pnpm not on PATH, dir missing) is fatal on its own.
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return nil, fmt.Errorf("running pnpm audit in %s: %w", dir, runErr)
	}
	return stdout.Bytes(), nil
}

func run() error {
	dir := "."
	noRanges, fixDeps := false, false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-no-ranges", "--no-ranges":
			noRanges = true
		case "-fix-deps-json", "--fix-deps-json":
			fixDeps = true
		case "-h", "--help":
			fmt.Println(usage)
			return nil
		default:
			if strings.HasPrefix(arg, "-") {
				return fmt.Errorf("unknown flag %q\n\n%s", arg, usage)
			}
			dir = arg
		}
	}

	// The fix search is entirely range-driven, so it has nothing to work with when every
	// registry lookup is suppressed.
	if fixDeps && noRanges {
		return fmt.Errorf("-fix-deps-json needs registry lookups; drop -no-ranges\n\n%s", usage)
	}

	raw, err := runAudit(dir)
	if err != nil {
		return err
	}

	var report auditReport
	if err := json.Unmarshal(raw, &report); err != nil {
		// pnpm printed something that isn't the audit report — a missing lockfile, a
		// registry auth failure. Surface what it actually said.
		snippet := strings.TrimSpace(string(raw))
		if len(snippet) > 500 {
			snippet = snippet[:500] + "..."
		}
		if snippet == "" {
			snippet = "(no output)"
		}
		return fmt.Errorf("could not parse pnpm audit output: %w\npnpm said:\n%s", err, snippet)
	}

	if report.Error != nil {
		return fmt.Errorf("pnpm could not audit %s: %s (%s)", dir, report.Error.Message, report.Error.Code)
	}

	if len(report.Advisories) == 0 {
		if fixDeps {
			// Stdout stays a parseable document in this mode, even when there is nothing
			// to fix.
			return printFixReport(report, nil, newRangeLookup(dir, noRanges))
		}
		fmt.Println("No vulnerabilities found.")
		return nil
	}

	lock, err := loadLockfile(dir)
	if err != nil {
		return err
	}

	// Go randomizes map iteration, so sort for output that is stable across runs.
	advisories := make([]advisory, 0, len(report.Advisories))
	for _, a := range report.Advisories {
		advisories = append(advisories, a)
	}
	sort.Slice(advisories, func(i, j int) bool {
		ri, rj := severityRank[advisories[i].Severity], severityRank[advisories[j].Severity]
		if ri != rj {
			return ri < rj
		}
		if advisories[i].ModuleName != advisories[j].ModuleName {
			return advisories[i].ModuleName < advisories[j].ModuleName
		}
		return advisories[i].ID < advisories[j].ID
	})

	blocks, all := expand(lock, advisories)

	lookup := newRangeLookup(dir, noRanges)
	lookup.prefetch(all)

	if fixDeps {
		if err := printFixReport(report, blocks, lookup); err != nil {
			return err
		}
	} else {
		for _, b := range blocks {
			printFinding(b, lookup)
		}
		printSummary(report)
	}

	for _, p := range lookup.problems() {
		fmt.Fprintf(os.Stderr, "note: %s\n", p)
	}
	return nil
}

// expand turns every finding into a block of resolved chains, and also returns those
// chains flattened so the registry lookups can be prefetched in one pass.
func expand(lock *lockfile, advisories []advisory) ([]block, [][]hop) {
	var blocks []block
	var all [][]hop

	for _, a := range advisories {
		for _, f := range a.Findings {
			b := block{advisory: a, finding: f, pathCount: len(f.Paths)}

			// The same path can be reported more than once for a finding.
			seen := make(map[string]bool, len(f.Paths))
			for _, p := range f.Paths {
				if seen[p] {
					continue
				}
				seen[p] = true

				if c := buildChain(lock, p); len(c) > 0 {
					b.chains = append(b.chains, c)
					all = append(all, c)
				}
			}
			blocks = append(blocks, b)
		}
	}
	return blocks, all
}

func printFinding(b block, lookup *rangeLookup) {
	a, f := b.advisory, b.finding

	fmt.Printf("%s@%s  [%s]\n", a.ModuleName, f.Version, a.Severity)
	if a.Title != "" {
		fmt.Printf("  %s\n", a.Title)
	}
	if a.URL != "" {
		fmt.Printf("  %s\n", a.URL)
	}
	fmt.Printf("  vulnerable: %s   patched: %s\n", a.VulnerableVersions, a.PatchedVersions)
	fmt.Printf("  %d path(s):\n\n", b.pathCount)

	for _, c := range b.chains {
		printChain(c, lookup)
		fmt.Println()
	}

	if b.pathCount >= registryPathCap {
		fmt.Printf("  note: pnpm reports at most %d paths per advisory; this list is truncated upstream.\n\n", registryPathCap)
	}
}

// printChain renders one usage path as an indented tree, one line per hop, showing the
// range each parent declares next to the version actually installed.
//
// Column widths are computed per chain so a single path stays aligned without forcing
// every path in the report to the width of the deepest one.
func printChain(c []hop, lookup *rangeLookup) {
	labels := make([]string, len(c))
	ranges := make([]string, len(c))
	versions := make([]string, len(c))
	labelWidth, rangeWidth := 0, 0

	for i, h := range c {
		label := strings.Repeat("  ", i)
		if i > 0 {
			label += "└─ "
		}
		labels[i] = label + h.Name

		if i > 0 {
			// A workspace edge carries its range in the lockfile; anything deeper has
			// to come from the parent's published manifest.
			rng := h.Range
			if rng == "" {
				rng = lookup.get(h.parentName, h.parentVersion, h.Name)
			}
			ranges[i] = "wants " + orUnknown(rng)
		}

		if h.Workspace {
			versions[i] = "(workspace)"
		} else {
			versions[i] = "→  " + orUnknown(h.Version)
		}

		labelWidth = max(labelWidth, utf8.RuneCountInString(labels[i]))
		rangeWidth = max(rangeWidth, utf8.RuneCountInString(ranges[i]))
	}

	for i := range c {
		line := "    " + pad(labels[i], labelWidth) + "  " + pad(ranges[i], rangeWidth) + "  " + versions[i]
		if i == len(c)-1 {
			line += "   ** vulnerable **"
		}
		fmt.Println(strings.TrimRight(line, " "))
	}
}

func printSummary(report auditReport) {
	counts := report.Metadata.Vulnerabilities
	var parts []string
	for _, sev := range []string{"critical", "high", "moderate", "low", "info"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	summary := strings.Join(parts, ", ")
	if summary == "" {
		summary = "no severity counts reported"
	}
	fmt.Printf("%d advisories — %s (%d total dependencies)\n",
		len(report.Advisories), summary, report.Metadata.TotalDependencies)
}

func orUnknown(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// pad right-pads to a width counted in runes; the tree glyphs are multi-byte, so
// fmt's %-*s would align them wrongly.
func pad(s string, width int) string {
	if n := utf8.RuneCountInString(s); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pnpm-audit-parents: %v\n", err)
		os.Exit(1)
	}
}
