# Plan: `pnpm-vuln-fixer` a Go CLI that finds how to upgrade a transitive vulnerable package

> Hand this file to Claude Code as the spec. It is deliberately prescriptive about the algorithm and data formats, and leaves idiomatic implementation choices to you. Build it in phases (see **Milestones**); each phase should compile, be tested, and be committed before moving on.

## 1. Goal

A Go CLI, run from the root of a JavaScript project that uses **pnpm** (has a `pnpm-lock.yaml`). It answers one question:

> A vulnerable package `pkg@version` is installed. A fixed version `fixedVersion` exists. Which package(s) in the dependency tree can we update so that `pkg` resolves to `fixedVersion` (or higher)?

The core work is: locate the vulnerable package in the resolved dependency graph, walk **from the vulnerable package up toward the root importers**, and for each ancestor decide whether it already permits the fix or must itself be bumped — cascading upward until we reach a direct (root) dependency or hit a dead end.

## 2. CLI contract

```
pnpm-vuln-fixer <vulnerablePackage@version> <fixedVersion>
```

- **Arg 1** — vulnerable package identity, e.g. `lodash@4.17.10` or scoped `@babel/traverse@7.22.0`. Parse the version as the substring after the **last** `@` (so scoped names work).
- **Arg 2** — the fixed version, e.g. `4.17.21`. Treat as a concrete version; also accept a range and use its minimum.

Flags:
- `--lockfile <path>` (default `./pnpm-lock.yaml`)
- `--json` — machine-readable output
- `--registry <url>` (default `https://registry.npmjs.org`)
- `--offline` — do not hit the network; resolve ranges from on-disk `package.json` files under `node_modules/.pnpm/...` only
- `--all-chains` — analyze every path to root (default: yes; a false setting stops at first fixable chain)
- `--max-depth <n>` — safety cap on upward traversal
- `-v/--verbose`

Exit codes: `0` fix found for all chains, `1` no complete fix, `2` usage/parse error, `3` vulnerable package not present at that version.

## 3. Background the implementation depends on

### 3.1 pnpm lockfile format (verify at runtime!)
Read `lockfileVersion` first and branch. Support matrix:
- `5.4` → pnpm 7, `6.x` → pnpm 8, `9.0` → pnpm 9/10, and pnpm 11 introduced a **multi-document** YAML lockfile (an "env" document first, then the project document).
- **Primary target: v9.0.** Ship v9 first; make the parser an interface so v6/v5.4/multi-doc can be added later. If an unsupported version is seen, exit with a clear message.

**v9.0 structure** (this is what the graph is built from):
- `importers:` — one entry per workspace project (`.` is the root). Each dependency group (`dependencies`, `devDependencies`, `optionalDependencies`) maps `depName → { specifier, version }`, where `specifier` is the range from `package.json` and `version` is the resolved version key. These are the **roots** of the graph.
- `packages:` — immutable per-package metadata keyed by `name@version` (`resolution`/integrity, `engines`, `os`, etc.). Useful for validation, not for edges.
- `snapshots:` — the resolved dependency **edges**, keyed by *DepPath*. A DepPath is `name@version` optionally followed by a peer-dependency suffix, e.g. `react-dom@18.2.0(react@18.2.0)`. Each snapshot has a `dependencies` map (and optional `optionalDependencies`) of `name → resolvedRef`. **Because of peer suffixes, the same `name@version` can appear as several DepPaths.**

### 3.2 npm registry (needed to learn the *range* an ancestor declares, and to find newer versions)
The lockfile records *resolved* versions, not the semver *range* each parent declared for its child. To decide whether bumping an ancestor helps, fetch the ancestor's `package.json` dependency ranges:
- `GET {registry}/{pkg}` with header `Accept: application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*` returns **abbreviated metadata**: a `versions` map where each version object includes `dependencies`, `peerDependencies`, `optionalDependencies`, `os`, `engines`, `deprecated`. This is far smaller than the full doc — use it.
- Single version: `GET {registry}/{pkg}/{version}`.
- Cache responses in-memory per run (and optionally on disk). Handle scoped names by URL-encoding the `/` (`@scope%2Fname`) or use the path form the registry accepts.
- Offline fallback: read `node_modules/.pnpm/<name>@<version>/node_modules/<name>/package.json`.

### 3.3 Semver (npm-flavored) in Go
Use `github.com/Masterminds/semver/v3`. Its **constraint** checks follow npm/Cargo range rules (`^`, `~`, `x`-ranges, hyphen ranges, `||`, comparators). Known caveats to test explicitly:
- `0.x` caret behavior (`^0.2.3` → `>=0.2.3 <0.3.0`, `^0.0.3` → exact-ish) matches npm reasonably but verify with fixtures.
- Prerelease handling differs from npm's `semver` in edge cases; a range without a prerelease won't match prereleases. Add `-0` if you need to include them.
Wrap it behind a small internal `semver` package exposing exactly the two operations the algorithm needs (below), so the library can be swapped if npm-fidelity gaps appear.

## 4. Core algorithm

### 4.1 Build the graph
1. Parse the lockfile. Build:
   - **Forward edges**: `node → []childNode` from `snapshots` (plus importer roots from `importers`).
   - **Reverse edges** (dependents): invert the above. This is what lets us "walk from the vulnerable package to the root."
   - Node identity = DepPath (keep the peer suffix; also index by base `name@version` for lookup).
   - Roots = importers.
2. Decide which edge types to traverse: importer `dependencies` + `devDependencies` + `optionalDependencies`; snapshot `dependencies` + `optionalDependencies`. Make this configurable.

### 4.2 Locate the vulnerable node(s)
Find every DepPath whose base identity equals `pkg@version` (there may be several due to peer suffixes). If none, exit code 3. If `pkg` exists but only at other versions, say so.

### 4.3 Enumerate paths to root
For each vulnerable node, reverse-BFS/DFS up to importers, collecting all simple paths (detect and break cycles; respect `--max-depth`). Each path is a chain `importer → … → parent → vuln`.

### 4.4 Decide fixability, bottom-up, per chain
Two primitives from the `semver` wrapper:
- `satisfies(version, range) bool`
- `minVersionAbove(sortedVersions, current, predicate) *version` — smallest version `> current` for which `predicate(depRange(version)) == true`.

**Leaf edge (direct parent → vuln):**
1. Fetch the parent's declared range for `pkg` (registry abbreviated metadata for the parent's resolved version → `dependencies[pkg]`).
2. If `satisfies(fixedVersion, range)` → **fixable by re-resolution**: the parent already accepts the fix; no bump needed here (a `pnpm update pkg` re-resolves it). Record this and continue upward only to confirm nothing pins the parent itself.
3. Else the parent restricts `pkg` below the fix. Find the **minimal newer parent version** `P'` whose `dependencies[pkg]` range admits `fixedVersion` (fetch parent's `versions`, sort, `minVersionAbove`). If none exists → **dead end at parent** (record blocking package + reason).

**Propagate upward:** once a node must move to `P'`, its parent (grandparent) must permit `P'`:
- If grandparent's declared range for the parent `satisfies(P')` → stop; done for this chain (bumping the parent is enough, everything above re-resolves).
- Else find the grandparent's minimal newer version whose range for the child admits `P'`; recurse. Note: a newer ancestor version might drop the dependency entirely — that also resolves the chain; treat "no longer depends on child" as fixable.

**Termination:**
- Reached an **importer**: the actionable fix is *update a direct dependency* in that project's `package.json`. Report the dep name and the version/range to move to.
- **Dead end**: some ancestor has no available version admitting the needed child version. Report which package blocks it.

**Direct-dependency short-circuit:** if `pkg` is itself a direct dep of an importer, the fix is simply updating that dependency to `fixedVersion` (adjust specifier if it doesn't already admit it).

### 4.5 Combine chains
The vulnerable version is only fully removed if **every** chain is fixable. Emit:
- per-chain verdict + the concrete update it needs,
- overall verdict (all fixable / partially / not),
- the **minimal union** of root-level (and intermediate) updates,
- if some chain has no ancestor fix, recommend a pnpm `overrides` entry (`pnpm.overrides: { "pkg@version": "fixedVersion" }` / or `overrides` in `package.json`) as the fallback remediation, clearly flagged as a forced override rather than a natural upgrade.

## 5. Suggested Go layout
```
cmd/pnpm-vuln-fixer/main.go      # flag parsing, wiring, exit codes
internal/lockfile/               # parse pnpm-lock.yaml; version detection; interface + v9 impl
internal/graph/                  # forward+reverse graph, node identity, path-to-root
internal/registry/               # abbreviated-metadata client, cache, offline fallback
internal/npmsemver/              # thin wrapper over Masterminds/semver (the 2 primitives)
internal/analyzer/               # the bottom-up fix algorithm
internal/report/                 # human + JSON output
testdata/                        # lockfile fixtures + canned registry responses
```
Dependencies: `gopkg.in/yaml.v3` (YAML; use a decoder loop for multi-document lockfiles later), `github.com/Masterminds/semver/v3`. Prefer the stdlib `net/http` client; no heavy framework needed. `flag` or `spf13/cobra` for CLI (cobra only if you want subcommands later).

## 6. Edge cases to handle (and test)
- Scoped packages `@scope/name@version` (arg parsing + registry URL encoding).
- Peer-suffixed DepPaths → multiple snapshots for one `name@version`.
- `workspace:` / `link:` deps (local packages, not on the registry — skip registry lookups, treat as always-satisfiable local).
- Aliased deps (`npm:other@range`).
- `dev`/`optional`/`peer` dependency edges — configurable inclusion.
- Cyclic graphs and very deep trees (`--max-depth`).
- `fixedVersion` not published / doesn't exist → clear error.
- Registry unreachable → `--offline` path or graceful failure.
- Unsupported `lockfileVersion` → explicit, friendly message.
- `0.x` caret and prerelease semver quirks.

## 7. Output
Human-readable per chain, e.g.:
```
Vulnerable: lodash@4.17.10 → fixed 4.17.21
Chain: . > express@4.16.0 > lodash@4.17.10
  express@4.16.0 pins lodash "~4.17.4" (blocks 4.17.21)
  → bump express to 4.17.1 (requires lodash "^4.17.14", admits 4.17.21)
  express 4.17.1 is admitted by root specifier "^4.16.0" — update direct dependency.
FIX: update express to ^4.17.1 in package.json (resolves 1/1 chains)
```
Also provide `--json` with the graph paths, per-chain verdicts, and the recommended update set. When no ancestor fix exists, print the `pnpm.overrides` fallback.

## 8. Testing strategy
- Table-driven unit tests throughout.
- `internal/npmsemver`: caret/tilde/exact/hyphen/`0.x`/prerelease cases.
- `internal/lockfile`: v9 fixtures incl. scoped, peer suffixes, monorepo importers.
- `internal/graph`: reverse edges, multi-parent, cycles, path enumeration.
- `internal/registry`: `httptest` server serving canned abbreviated metadata — **no live network in tests**.
- `internal/analyzer`: golden end-to-end tests (fixture lockfile + mock registry → expected report), covering: already-satisfiable, single ancestor bump, cascade to root, dead end, direct-dependency, multi-chain partial fix.

## 9. Milestones (commit after each)
1. Scaffold: module, CLI, arg parsing (scoped-name aware), lockfile version detection.
2. v9 lockfile parser → in-memory model (+ fixtures/tests).
3. Forward+reverse graph and **path-from-vuln-to-root** enumeration. At this stage the tool can already list every chain and flag which direct parents' *lockfile-resolved* ranges look permissive — no registry yet.
4. Registry client (abbreviated metadata, cache, offline fallback) + `npmsemver` wrapper.
5. Bottom-up fix algorithm (minimal ancestor bumps, upward cascade, dead-end detection, direct-dep short-circuit).
6. Reporting (human + JSON) + `pnpm.overrides` fallback suggestion.
7. Edge cases (scoped, peer suffixes, workspaces, aliases, offline).
8. Docs (`README`), end-to-end golden tests, polish exit codes.

## 10. Notes / assumptions to confirm with the maintainer
- "Can be updated" is interpreted as **the minimal version bump that makes the ancestor's declared range admit `fixedVersion`** (greedy per chain). A full solver (choosing versions jointly across chains) is out of scope for v1 but the design leaves room for it.
- Bumping an ancestor changes its own subtree; v1 does *not* re-verify the whole resolution after a proposed bump (it trusts the range analysis). An optional "verify by simulated resolution" step is a good v2 addition.
- v1 targets `lockfileVersion 9.0` only; other versions are a follow-up.