package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/user/pnpm-vuln-fixer/internal/analyzer"
	"github.com/user/pnpm-vuln-fixer/internal/graph"
	"github.com/user/pnpm-vuln-fixer/internal/lockfile"
	"github.com/user/pnpm-vuln-fixer/internal/registry"
	"github.com/user/pnpm-vuln-fixer/internal/report"
)

// ParsePackageArg splits a package identity like "lodash@4.17.10" or
// "@babel/traverse@7.22.0" into (name, version) by splitting on the LAST "@".
// Returns an error if the argument is not in "name@version" form.
func ParsePackageArg(arg string) (name, version string, err error) {
	// Find the last '@'. For scoped names the first '@' belongs to the scope.
	idx := strings.LastIndex(arg, "@")
	if idx <= 0 {
		return "", "", fmt.Errorf("invalid package argument %q: expected name@version", arg)
	}
	name = arg[:idx]
	version = arg[idx+1:]
	if name == "" || version == "" {
		return "", "", fmt.Errorf("invalid package argument %q: name and version must be non-empty", arg)
	}
	return name, version, nil
}

func main() {
	fs := flag.NewFlagSet("pnpm-vuln-fixer", flag.ContinueOnError)

	lockfilePath := fs.String("lockfile", "./pnpm-lock.yaml", "path to pnpm-lock.yaml")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	registryURL := fs.String("registry", "https://registry.npmjs.org", "npm registry URL")
	offline := fs.Bool("offline", false, "do not hit the network; use on-disk package.json files only")
	allChains := fs.Bool("all-chains", true, "analyze every path to root")
	maxDepth := fs.Int("max-depth", 50, "safety cap on upward traversal depth")
	verbose := fs.Bool("v", false, "verbose output")
	fs.BoolVar(verbose, "verbose", false, "verbose output")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	args := fs.Args()
	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: pnpm-vuln-fixer [flags] <pkg@version> <fixedVersion>\n")
		fs.PrintDefaults()
		os.Exit(2)
	}

	vulnArg := args[0]
	fixedVersion := args[1]

	vulnName, vulnVersion, err := ParsePackageArg(vulnArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "package: %s version: %s fixed: %s lockfile: %s registry: %s json: %v offline: %v allChains: %v maxDepth: %d\n",
			vulnName, vulnVersion, fixedVersion, *lockfilePath, *registryURL, *jsonOut, *offline, *allChains, *maxDepth)
	}

	// Detect lockfile version.
	ver, err := lockfile.DetectVersion(*lockfilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	if *verbose {
		fmt.Fprintf(os.Stderr, "lockfile version: %s\n", ver)
	}

	// Parse the lockfile.
	parser, err := lockfile.NewParser(ver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	f, err := os.Open(*lockfilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening lockfile: %v\n", err)
		os.Exit(2)
	}
	defer f.Close()

	lf, err := parser.Parse(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing lockfile: %v\n", err)
		os.Exit(2)
	}

	// Build dependency graph.
	g := graph.Build(lf, graph.BuildOpts{
		IncludeDev:      true,
		IncludeOptional: true,
	})

	// Locate the vulnerable package.
	vulnNodes, err := graph.FindVulnerable(g, vulnName, vulnVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(3)
	}

	// Enumerate paths to root for each vulnerable node.
	var chains [][]*graph.Node
	for _, node := range vulnNodes {
		paths := graph.PathsToRoot(g, node, *maxDepth)
		if !*allChains && len(paths) > 0 {
			chains = append(chains, paths[0])
			break
		}
		chains = append(chains, paths...)
	}

	if len(chains) == 0 {
		fmt.Fprintf(os.Stderr, "no paths to root found for %s@%s (package may be unreachable from importers)\n", vulnName, vulnVersion)
		os.Exit(3)
	}

	// Build registry client.
	reg := registry.NewClient(*registryURL)
	if *offline {
		reg.Offline = true
	}

	// Verify fixedVersion exists in registry before running analysis.
	vulnMeta, err := reg.FetchAbbrevMeta(vulnName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot fetch metadata for %s: %v\n", vulnName, err)
		os.Exit(1)
	}
	if _, exists := vulnMeta.Versions[fixedVersion]; !exists {
		fmt.Fprintf(os.Stderr, "error: %s@%s is not published in the registry\n", vulnName, fixedVersion)
		os.Exit(1)
	}

	// Run the bottom-up fix analysis.
	rpt, err := analyzer.Analyze(chains, lf, vulnName, vulnVersion, fixedVersion, reg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analysis error: %v\n", err)
		os.Exit(1)
	}

	// Write report.
	if *jsonOut {
		if err := report.PrintJSON(os.Stdout, rpt); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		report.PrintHuman(os.Stdout, rpt)
	}

	// Exit codes: 0 = all chains fixable, 1 = no complete fix.
	if rpt.AllFixable {
		os.Exit(0)
	}
	os.Exit(1)
}
