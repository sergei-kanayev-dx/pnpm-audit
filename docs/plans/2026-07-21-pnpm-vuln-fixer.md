---
# pnpm-vuln-fixer: Go CLI for Transitive Vulnerability Resolution

## Overview

Build a Go CLI tool that, given a vulnerable transitive npm package and a fixed version, walks the pnpm dependency graph upward to find which direct (or intermediate) dependencies need to be bumped so the vulnerable package resolves to the fixed version. Follows the 8-milestone structure from plan.md.

## Context

- Files involved: `cmd/pnpm-vuln-fixer/main.go`, `internal/lockfile/`, `internal/graph/`, `internal/registry/`, `internal/npmsemver/`, `internal/analyzer/`, `internal/report/`, `testdata/`
- Related patterns: `plan.md` (prescriptive spec, read before each task)
- Dependencies: `gopkg.in/yaml.v3`, `github.com/Masterminds/semver/v3`

## Development Approach

- **Testing approach**: TDD — write fixtures and table-driven tests alongside each package
- Complete each task fully before moving to the next
- Each internal package is independently testable; build and test incrementally
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**

## Implementation Steps

### Task 1: Scaffold — module, CLI arg parsing, lockfile version detection

**Files:**
- Create: `go.mod`, `go.sum`
- Create: `cmd/pnpm-vuln-fixer/main.go`
- Create: `internal/lockfile/detect.go` (version detection only)
- Create: `internal/lockfile/detect_test.go`
- Create: `testdata/lockfiles/v9-simple.yaml`

- [x] run `go mod init` with module path `github.com/user/pnpm-vuln-fixer` (or project-appropriate path), add `gopkg.in/yaml.v3` and `github.com/Masterminds/semver/v3`
- [x] implement flag parsing in main.go: positional args `<pkg@version> <fixedVersion>`, flags `--lockfile`, `--json`, `--registry`, `--offline`, `--all-chains`, `--max-depth`, `-v`
- [x] implement scoped-name-aware arg parsing: split on last `@` to separate package name from version (handles `@scope/name@ver`)
- [x] implement `internal/lockfile.DetectVersion(path string) (string, error)` — reads lockfileVersion field, returns error for unsupported versions
- [x] write table-driven tests for version detection (v9.0, v6.x, v5.4, unknown version → error, missing file → error)
- [x] write tests for scoped arg parsing
- [x] wire version detection into main.go; exit with friendly message for unsupported lockfile versions
- [x] run `go test ./...` — must pass

### Task 2: v9 lockfile parser — in-memory model

**Files:**
- Create: `internal/lockfile/types.go` (data model structs)
- Create: `internal/lockfile/v9.go` (v9 parser)
- Create: `internal/lockfile/v9_test.go`
- Create: `testdata/lockfiles/v9-scoped.yaml`
- Create: `testdata/lockfiles/v9-peers.yaml`
- Create: `testdata/lockfiles/v9-monorepo.yaml`

- [x] define `Lockfile`, `Importer`, `Snapshot`, `Package` structs in types.go covering importers, packages, snapshots sections of v9.0 format
- [x] implement `ParseV9(r io.Reader) (*Lockfile, error)` using gopkg.in/yaml.v3 decoder
- [x] parse importers: dependency/devDependency/optionalDependency groups, each entry has `specifier` and `version`
- [x] parse snapshots: keyed by DepPath (name@version with optional peer suffix), each has `dependencies` and `optionalDependencies` maps
- [x] implement `Parser` interface with `Parse(r io.Reader) (*Lockfile, error)` and factory `NewParser(version string) (Parser, error)`
- [x] create v9-simple, v9-scoped (with `@scope/name`), v9-peers (with peer suffix DepPaths), v9-monorepo (multiple importers) fixture files
- [x] write table-driven tests parsing each fixture, asserting importer roots, snapshot edges, DepPath keys
- [x] run `go test ./...` — must pass

### Task 3: Forward + reverse graph and path-to-root enumeration

**Files:**
- Create: `internal/graph/graph.go`
- Create: `internal/graph/graph_test.go`

- [x] define `Node` (DepPath string, name+version fields, isRoot bool) and `Graph` structs
- [x] implement `Build(lf *lockfile.Lockfile, opts BuildOpts) *Graph` building forward edges (importer → snapshots → children) and reverse edges (child → parents)
- [x] index nodes by DepPath and by base `name@version` (for lookup ignoring peer suffix)
- [x] implement `FindVulnerable(g *Graph, pkg, version string) ([]*Node, error)` — returns all DepPath nodes matching `pkg@version`; returns typed error if pkg exists at other versions only
- [x] implement `PathsToRoot(g *Graph, start *Node, maxDepth int) [][]*Node` — reverse-BFS/DFS returning all simple paths from start node up to importers (cycle detection, maxDepth cap)
- [x] write tests: single parent, multi-parent, cycles, deeply nested (maxDepth truncation), no-path (isolated node), scoped name lookup
- [x] run `go test ./...` — must pass

### Task 4: Registry client + npmsemver wrapper

**Files:**
- Create: `internal/registry/client.go`
- Create: `internal/registry/client_test.go`
- Create: `internal/registry/offline.go`
- Create: `internal/npmsemver/semver.go`
- Create: `internal/npmsemver/semver_test.go`
- Create: `testdata/registry/` (canned JSON responses)

- [ ] implement `internal/npmsemver.Satisfies(version, rangeStr string) (bool, error)` wrapping Masterminds/semver constraint check
- [ ] implement `internal/npmsemver.MinVersionAbove(sorted []string, current string, predicate func(string) bool) (string, bool)` — smallest version > current where predicate holds
- [ ] write semver tests: caret (`^0.2.3`, `^0.0.3`), tilde, exact, hyphen range, `||`, prerelease exclusion — match npm behavior per plan.md §3.3
- [ ] implement `registry.Client` struct with `FetchAbbrevMeta(pkg string) (*AbbrevMeta, error)` using `net/http` and `Accept: application/vnd.npm.install-v1+json...` header
- [ ] URL-encode scoped package names (replace `/` with `%2F` in path segment after `@scope`)
- [ ] implement in-memory response cache keyed by package name
- [ ] implement offline fallback: read `node_modules/.pnpm/<name>@<version>/node_modules/<name>/package.json`
- [ ] write tests using `net/http/httptest` serving canned abbreviated metadata JSON from testdata/registry/; test scoped names, cache hit, 404 handling
- [ ] run `go test ./...` — must pass

### Task 5: Bottom-up fix algorithm

**Files:**
- Create: `internal/analyzer/analyzer.go`
- Create: `internal/analyzer/analyzer_test.go`

- [ ] define result types: `ChainResult`, `NodeVerdict` (fixable/dead-end/no-bump-needed), `FixAction` (which package to update, to what version)
- [ ] implement `AnalyzeChain(chain []*graph.Node, vuln, fixedVersion string, reg registry.Client, semver npmsemver package) ChainResult` bottom-up:
  - leaf edge: fetch parent's declared range for vuln; if satisfies(fixedVersion, range) → no-bump; else find minimal parent version P' where range admits fixedVersion
  - propagate upward: for each ancestor, check if its range admits P'; if not, find minimal ancestor version admitting P'
  - termination: reached importer → record FixAction; or dead end → record blocking package + reason
- [ ] implement direct-dep short-circuit: if vuln is a direct dep of importer, fix is updating that specifier
- [ ] implement `Analyze(g *graph.Graph, chains [][]*graph.Node, vuln, fixedVersion string, ...) *Report` combining per-chain results, computing minimal union of needed updates, flagging chains with no fix for overrides fallback
- [ ] write golden tests using fixture lockfile + mock registry for: already-satisfiable, single ancestor bump, cascade to root, dead end, direct-dep, multi-chain partial fix
- [ ] run `go test ./...` — must pass

### Task 6: Reporting — human-readable and JSON output

**Files:**
- Create: `internal/report/human.go`
- Create: `internal/report/json.go`
- Create: `internal/report/report_test.go`

- [ ] implement `PrintHuman(w io.Writer, r *analyzer.Report)` producing per-chain output matching plan.md §7 format (vulnerable line, chain, per-edge annotation, FIX/OVERRIDE line)
- [ ] implement `PrintJSON(w io.Writer, r *analyzer.Report) error` marshaling the report struct to JSON
- [ ] include pnpm.overrides fallback in output when any chain has no ancestor fix
- [ ] wire reporting into main.go (select human vs JSON via `--json` flag, write to stdout, set exit codes per plan.md §2)
- [ ] write tests asserting human output format for each verdict type and JSON round-trip validity
- [ ] run `go test ./...` — must pass

### Task 7: Edge cases — scoped, peer suffixes, workspaces, aliases, offline

**Files:**
- Modify: `internal/lockfile/v9.go`
- Modify: `internal/graph/graph.go`
- Modify: `internal/registry/client.go`
- Modify: `internal/analyzer/analyzer.go`
- Create: `testdata/lockfiles/v9-aliases.yaml`

- [ ] handle `workspace:` and `link:` specifiers in importer deps: skip registry lookup, treat as always-satisfiable local (not fixable via registry upgrade)
- [ ] handle aliased deps (`npm:other@range`): parse the `npm:` prefix, resolve registry lookups against the aliased package name
- [ ] handle dev/optional/peer edge inclusion: honor BuildOpts.IncludeDev, IncludeOptional, IncludePeer flags from graph.Build
- [ ] verify peer-suffixed DepPath multi-snapshot handling: graph builds correctly, path enumeration treats each DepPath as a distinct node, but `FindVulnerable` matches all of them
- [ ] handle `fixedVersion` not published: registry 404 on version → clear error message, exit code 1
- [ ] handle registry unreachable with `--offline` flag: fall through to offline reader gracefully; error if offline reader also fails
- [ ] add fixture testdata/lockfiles/v9-aliases.yaml; extend existing tests to cover the above cases
- [ ] run `go test ./...` — must pass

### Task 8: End-to-end golden tests, README, polish

**Files:**
- Create: `testdata/e2e/` (golden test fixtures)
- Create: `cmd/pnpm-vuln-fixer/main_test.go` (or `e2e_test.go`)
- Create: `README.md`

- [ ] write golden end-to-end tests in cmd/ that build the binary via `os/exec` (or use `testscript`) and run it against fixture lockfiles + mock registry, asserting stdout and exit code for: all-fixable, partial-fix, no-fix, exit-code-3 (pkg not present)
- [ ] verify exit codes 0/1/2/3 are set correctly in all code paths in main.go
- [ ] write README.md: installation, usage, flags, example output, output format description, limitations (v9 only, greedy algorithm, no re-verification)
- [ ] run `go test ./...` — must pass

### Task 9: Verify acceptance criteria

- [ ] run `go test ./...`
- [ ] run `go vet ./...`
- [ ] run `go build ./cmd/pnpm-vuln-fixer` and test binary against a real-world pnpm-lock.yaml v9 fixture
- [ ] verify all 8 exit-code paths work correctly

### Task 10: Update documentation

- [ ] update README.md if any behavior changed during testing
- [ ] update CLAUDE.md if internal patterns were established
- [ ] move this plan to `docs/plans/completed/`
