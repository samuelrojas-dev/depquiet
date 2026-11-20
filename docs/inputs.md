# Supported inputs

The scanners, lockfiles and SBOMs depquiet reads.

depquiet reads the dependency alerts of these scanners, natively or through SARIF:

| Scanner | Format | Input method |
|---|---|---|
| **None (standalone)** | **Lockfiles** | **`depquiet` (auto-detects lockfiles, queries OSV.dev)** |
| npm audit | JSON | `npm audit --json \| depquiet --stdin` |
| pnpm audit | JSON | `depquiet` in a project with `pnpm-lock.yaml`, or `pnpm audit --json \| depquiet --stdin` |
| pip-audit | JSON | `pip-audit --format json \| depquiet --stdin` |
| uv audit (uv 0.13+) | JSON | `depquiet --scanner uv`, or `uv audit --frozen --output-format json \| depquiet --stdin` |
| Trivy | JSON or SARIF | `trivy fs --format json . \| depquiet --stdin` |
| Grype | JSON | `grype dir:. -o json \| depquiet --stdin` |
| Snyk | JSON | `snyk test --json \| depquiet --stdin` |
| Dependabot | API JSON | `gh api /repos/O/R/dependabot/alerts --paginate \| depquiet --stdin` |
| **Any SARIF dependency scanner** | **SARIF v2.1.0** | `<scanner> --sarif \| depquiet --stdin` |
| **CycloneDX SBOM** | **JSON** | `depquiet --from-sbom vendor.cdx.json` |
| **SPDX SBOM** | **JSON** | `depquiet --from-sbom vendor.spdx.json` |

The SARIF parser reads dependency findings from Trivy, Grype, Snyk and other tools that emit
SARIF v2.1.0: CVE, package name, severity (CVSS or level-based) and fix version come from the
standard SARIF fields and common scanner-specific properties. A result that names no package
is a code finding (CodeQL, Semgrep and other static analysis): depquiet does not triage it and
says how many it left out, and a SARIF file with only code findings is reported as not scanned,
never as clean.

## npm component evidence

For npm audit input, JSON keeps the legacy `version` value and identifies it as
`version_kind: advisory_range`. Separate `components` record exact lockfile
versions, node locations, source hashes and stable instance IDs. Each candidate
has its own `range_match`; npm's package-level node list is not a per-advisory
affected-version list. Unknown or partial resolution remains explicit.

CycloneDX, SPDX and OpenVEX use those component identities instead of presenting
an advisory range as a component version. No lockfile resolution claims an
observed installation or product impact. See [npm component evidence](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/npm-component-evidence.md)
for the JSON contract, matching limits and export behavior. Explicitly scoped
reports support [instance baselines and diffs](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/instance-baselines.md);
unscoped legacy reports retain their existing identities.

## Standalone scanning with OSV.dev

When no scanner output is piped in and no native package manager is detected, depquiet falls back to **lockfile scanning via [OSV.dev](https://osv.dev)** — Google's open, free vulnerability database. Just run `depquiet` in any project with a lockfile:

| Lockfile | Ecosystem |
|---|---|
| `package-lock.json` / `yarn.lock` (Yarn 1 and Berry) / `pnpm-lock.yaml` (v5 to v9) | npm |
| `uv.lock` / `poetry.lock` / `requirements.txt` / `Pipfile.lock` | PyPI |
| `go.sum` | Go |
| `Cargo.lock` | crates.io |
| `pubspec.lock` | Pub (Dart/Flutter) |
| `Gemfile.lock` | RubyGems |
| `composer.lock` | Packagist (PHP) |
| `packages.lock.json` | NuGet (C#) |

Multiple lockfiles in the same project are merged and deduplicated. OSV.dev queries
are batched in groups of up to 1000 packages, then each distinct advisory is fetched
for its severity, CVE aliases and fixed versions. All pages and advisory lookups must
succeed before the scan is considered complete, and a lockfile that cannot be parsed stops
the scan instead of being left out of it. Use `--offline` to skip OSV.dev queries.

A project with `pnpm-lock.yaml` is audited with `pnpm audit` when pnpm is installed, and
through OSV.dev otherwise. A Yarn project is scanned from `yarn.lock` through OSV.dev:
`npm audit` cannot read that file.

A Python project without `uv.lock` or `poetry.lock` is audited from its requirement files:
`requirements*.txt` at the root and `requirements/*.txt`. Files named for tooling
(`requirements-dev.txt`, `requirements/test.txt`, `docs.txt`) are left out unless they are
the only ones. A compiled file (`pip-compile`, `uv pip compile`, hashes) is audited as
written, with no resolver run. Any other `requirements.txt` is resolved by pip, so the
packages it pulls in are audited too; when pip cannot resolve it, the exact versions it
lists are audited instead, and the report names the lines that have no exact version.
Every file left out, and every partial audit, is stated in the report.
