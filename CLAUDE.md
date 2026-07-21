# pnpm-vuln-fixer — development notes

## Module

Module path: `github.com/user/pnpm-vuln-fixer`

## Package layout

```
cmd/pnpm-vuln-fixer/main.go      # flag parsing, wiring, exit codes
internal/lockfile/               # Parser interface + v9 implementation, type definitions
internal/graph/                  # forward+reverse graph, node identity, path-to-root
internal/registry/               # abbreviated-metadata HTTP client, in-memory cache, offline fallback
internal/npmsemver/              # thin Masterminds/semver wrapper exposing Satisfies + MinVersionAbove
internal/analyzer/               # bottom-up fix algorithm, Report/ChainResult types
internal/report/                 # PrintHuman + PrintJSON output functions
testdata/lockfiles/              # v9 YAML fixtures (simple, scoped, peers, monorepo, aliases)
testdata/registry/               # canned abbreviated metadata JSON for httptest servers
testdata/e2e/                    # golden end-to-end lockfile fixtures
```

## Key design decisions

### Parser interface
`lockfile.Parser` is an interface so future lockfile versions (v6, v5.4, multi-doc) can be added without touching the caller. Factory: `lockfile.NewParser(version string) (Parser, error)`. Currently only v9.0 is implemented.

### RegistryClient interface
`analyzer.RegistryClient` is defined in the analyzer package so tests can inject a mock without importing registry. The real `registry.Client` satisfies it.

### DepPath as node identity
Graph nodes use the full DepPath (including peer suffix) as their key. `Graph.ByBaseVersion` maps `"name@version"` (without peer suffix) to all matching nodes — this is what `FindVulnerable` uses so peer-suffixed snapshots are all matched.

### Error types
Graph errors use pointer-receiver typed errors (`*ErrPkgNotFound`, `*ErrPkgWrongVersion`) so callers can use `errors.As` to distinguish "package absent" from "package at wrong version".

### Chain orientation
`PathsToRoot` returns chains oriented `[importer, ..., directParent, vuln]` — root first, vulnerable package last. `AnalyzeChain` expects and enforces this orientation.

### Exit codes
- 0 — all chains fixable
- 1 — no complete fix (or analysis error)
- 2 — usage/parse error (bad args, unreadable or unsupported lockfile)
- 3 — vulnerable package not present at the specified version

### Alias handling
`npm:pkgname@range` specifiers: the importer DepEntry records `IsAlias=true`, `AliasOf="pkgname"`, `Version="pkgname@resolvedVer"`. Graph edges use `entry.Version` as the child DepPath (not `depName+"@"+entry.Version`).

### Local dependencies
`workspace:` and `link:` specifiers are marked `IsLocal=true` in DepEntry and skipped when building graph edges. A chain blocked by a local dep yields VerdictDeadEnd with a message suggesting `pnpm.overrides`.

### Registry URL encoding
Scoped package names are URL-encoded: `/` → `%2F` in the path segment after `@scope` so the registry receives `@scope%2Fname`.

## Testing conventions

- Table-driven tests with `t.Run` throughout.
- Registry tests use `net/http/httptest` serving canned JSON from `testdata/registry/` — no live network calls in any test.
- End-to-end tests in `cmd/pnpm-vuln-fixer/e2e_test.go` build the binary via `os/exec` and assert stdout + exit code against fixture lockfiles + an httptest mock registry.
- Lockfile fixtures live in `testdata/lockfiles/`; add a new fixture file rather than inline YAML strings when a test needs a non-trivial lockfile.
