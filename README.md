# pnpm-vuln-fixer

Walks a pnpm v9 lockfile upward from a vulnerable transitive dependency and finds which direct or intermediate packages need to be upgraded so the vulnerable package resolves to the patched version.

## Installation

```
go install github.com/user/pnpm-vuln-fixer/cmd/pnpm-vuln-fixer@latest
```

Or build from source:

```
git clone https://github.com/user/pnpm-vuln-fixer
cd pnpm-vuln-fixer
go build ./cmd/pnpm-vuln-fixer
```

## Usage

```
pnpm-vuln-fixer [flags] <pkg@vulnerableVersion> <fixedVersion>
```

Examples:

```
# Fix lodash 4.17.10 to 4.17.21 using the lockfile in the current directory
pnpm-vuln-fixer lodash@4.17.10 4.17.21

# Fix a scoped package, pointing at a specific lockfile
pnpm-vuln-fixer @babel/traverse@7.22.0 7.23.3 --lockfile ./packages/app/pnpm-lock.yaml

# Emit machine-readable output
pnpm-vuln-fixer lodash@4.17.10 4.17.21 --json
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--lockfile` | `./pnpm-lock.yaml` | Path to the pnpm-lock.yaml to analyze |
| `--registry` | `https://registry.npmjs.org` | npm registry URL for metadata lookups |
| `--json` | false | Emit JSON instead of human-readable text |
| `--offline` | false | Skip network requests; read from `node_modules/.pnpm` |
| `--all-chains` | true | Analyze every path from root to the vulnerable package |
| `--max-depth` | 50 | Maximum traversal depth (prevents runaway on cyclic-looking graphs) |
| `-v`, `--verbose` | false | Print debug info to stderr |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All dependency chains can be resolved by the suggested package updates |
| 1 | At least one chain has no available fix; use `pnpm.overrides` as a fallback |
| 2 | Usage error (bad arguments, unreadable or unsupported lockfile) |
| 3 | The vulnerable package is not present at the specified version in the lockfile |

## Example Output

### Human-readable (default)

```
Vulnerable: lodash@4.17.10 → fixed 4.17.21

Chain 1: . > express@4.16.0 > lodash@4.17.10
  → bump express from 4.16.0 to 4.18.2
  → update express specifier in package.json to ^4.18.2

FIX: update the following (resolves 1/1 chains):
  - express → 4.18.2
```

When a chain cannot be fixed via a registry upgrade:

```
Chain 2: packages/app > locked-dep@1.0.0 > lodash@4.17.10
  BLOCKED: locked-dep@1.0.0 has no published version whose range for lodash admits 4.17.21

PARTIAL FIX (1/2 chains fixable):
  - express → 4.18.2

OVERRIDE (fallback — forced, not a natural upgrade):
  Add to package.json:
    "pnpm": { "overrides": { "lodash": "4.17.21" } }
```

### JSON (--json)

```json
{
  "VulnPkg": "lodash",
  "VulnVer": "4.17.10",
  "FixedVer": "4.17.21",
  "Chains": [
    {
      "Chain": [...],
      "Verdict": 1,
      "Actions": [
        {"Package": "express", "FromVer": "4.16.0", "ToVer": "4.18.2", "IsSpecifier": false}
      ],
      "BlockedBy": "",
      "BlockReason": ""
    }
  ],
  "AllFixable": true,
  "MinUnion": [
    {"Package": "express", "FromVer": "", "ToVer": "4.18.2", "IsSpecifier": false}
  ],
  "NeedsOverride": false
}
```

### JSON fields

| Field | Type | Description |
|-------|------|-------------|
| `VulnPkg` | string | Vulnerable package name |
| `VulnVer` | string | Vulnerable version |
| `FixedVer` | string | Target patched version |
| `Chains` | array | Per-chain analysis (see below) |
| `AllFixable` | bool | True when every chain has a fix |
| `MinUnion` | array | Minimal set of `FixAction` objects to fix all fixable chains |
| `NeedsOverride` | bool | True when at least one chain requires `pnpm.overrides` |

Each chain object has:

| Field | Description |
|-------|-------------|
| `Chain` | Ordered nodes from root importer to the vulnerable package |
| `Verdict` | 0=NoBumpNeeded, 1=Bump, 2=DeadEnd, 3=DirectDep |
| `Actions` | Ordered list of `FixAction` from leaf toward root |
| `BlockedBy` | Package name that blocked the fix (dead-end only) |
| `BlockReason` | Human explanation for the blockage |

Each `FixAction`:

| Field | Description |
|-------|-------------|
| `Package` | Package to update |
| `FromVer` | Current resolved version (empty for specifier-only updates) |
| `ToVer` | Target version or specifier range |
| `IsSpecifier` | True when `ToVer` is a package.json specifier, not a resolved version |

## Limitations

- **v9 only**: supports pnpm lockfile version 9.0. Older formats (v6, v5) are detected but rejected with exit code 2.
- **Greedy algorithm**: selects the smallest ancestor version whose declared range admits the fixed package version. It does not simulate the full resolution or account for side effects of upgrading other transitive dependencies.
- **No re-verification**: after suggesting updates, the tool does not re-run pnpm resolution. Always validate with a fresh `pnpm install` after applying changes.
- **Local packages**: `workspace:` and `link:` dependencies cannot be fixed via a registry upgrade. Chains blocked by these will suggest `pnpm.overrides` instead.
