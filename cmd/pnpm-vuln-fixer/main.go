package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/user/pnpm-vuln-fixer/internal/lockfile"
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
	registry := fs.String("registry", "https://registry.npmjs.org", "npm registry URL")
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
			vulnName, vulnVersion, fixedVersion, *lockfilePath, *registry, *jsonOut, *offline, *allChains, *maxDepth)
	}

	ver, err := lockfile.DetectVersion(*lockfilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "lockfile version: %s\n", ver)
	}

	// Subsequent milestones will add graph building, analysis, and reporting here.
	_ = ver
	_ = *jsonOut
	_ = *registry
	_ = *offline
	_ = *allChains
	_ = *maxDepth
	fmt.Fprintf(os.Stderr, "analysis not yet implemented (lockfile v%s detected)\n", ver)
	os.Exit(1)
}
