# depquiet

[![CI](https://github.com/samuelrojas-dev/depquiet/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelrojas-dev/depquiet/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/depquiet)](https://pypi.org/project/depquiet/)
[![Python versions](https://img.shields.io/pypi/pyversions/depquiet)](https://pypi.org/project/depquiet/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuelrojas-dev/depquiet/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/samuelrojas-dev/depquiet/graph/badge.svg)](https://codecov.io/gh/samuelrojas-dev/depquiet)

**Tells you which dependency alerts never reach production, and shows the proof.**

`pip-audit`, `uv audit`, `npm audit` and Dependabot report every advisory that matches a
version range. depquiet reads your lockfile and dependency groups, drops the alerts that
only your development tools install, and keeps everything else: an alert is only dismissed
when the lockfile proves it.

### On real projects

`pip-audit` on popular Python projects at their head, measured on 2026-11-11 and again on 2026-11-12 with depquiet 0.39.0, with the same results:

| Project | pip-audit alerts | Only reach dev tooling | Left to look at |
|:--|--:|--:|--:|
| [saleor](https://github.com/saleor/saleor) | 16 | 14 | 2 |
| [zulip](https://github.com/zulip/zulip) | 43 | 26 | 17 |
| [mlflow](https://github.com/mlflow/mlflow) | 17 | 10 | 7 |
| [langflow](https://github.com/langflow-ai/langflow) | 70 | 11 | 59 |
| [PostHog](https://github.com/PostHog/posthog) | 255 | 8 | 247 |

Every dismissed alert was checked against a separate walk of each `uv.lock`, with each
project's dependency groups read by hand: all are development-only, the one kind of alert
later versions still filter, which only filter less. Most are `virtualenv` and `filelock` pulled in
by `pre-commit`. Details and the other 12 projects: [benchmarks](#benchmarks).

Of the alerts left, many cannot be fixed by the upgrade the scanner names. Across 18 uv
projects, uv's resolver rejects the nearest fix for 502 of 991 kept alerts (51%), in 13 of
the 17 projects with alerts; in 81% of the blocked upgrades, the project's own pin is what
is in the way. See [`--check-fixes`](#can-the-fix-be-installed---check-fixes).

On npm, `npm audit --omit=dev` already does this: depquiet matches it row for row on the
projects measured, and adds which direct dependency brings each kept alert in.

### Quick start

```bash
pip install depquiet pip-audit
cd your-project
depquiet                                 # npm, pnpm and Python in one run
depquiet explain GHSA-3jp2-3mrg-2vxc     # why this alert got its verdict
depquiet --check-fixes                   # uv projects: can each fix actually be installed?
```

```yaml
# GitHub Actions
- uses: samuelrojas-dev/depquiet@v0
```

Reads `uv.lock`, `poetry.lock`, requirement files, `package-lock.json`, `pnpm-lock.yaml` and
`yarn.lock`, or the output of `uv audit`, Trivy, Grype, Snyk, Dependabot and SARIF tools.
Runs locally, no account, MIT.

### What it is not

depquiet works at the level of packages, not functions. It cannot tell you that an imported
package's vulnerable function is never called; Snyk, Endor Labs and, for Go,
`govulncheck` go further there. If your project is on uv, `uv audit --no-dev` gives you the
plain dev/production split natively; depquiet adds every group judged by name, the
dependency path, EPSS and mixed npm/Python repositories.

![depquiet on a small Express app: npm audit, then depquiet, then depquiet explain](https://raw.githubusercontent.com/samuelrojas-dev/depquiet/main/docs/demo/demo.gif)

The recording is a small Express app, where most of the noise is packages the app never
imports. Every line is real command output ([how it's made](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/demo/make_demo.py)).

## The problem

Dependency scanners report every advisory that matches a version range, whether or not
your application can reach the vulnerable code:

- **npm audit is "broken by design"** ([Dan Abramov](https://overreacted.io/npm-audit-broken-by-design/))
- **Dependabot is a "noise machine"**: Filippo Valsorda recommends [turning it off](https://words.filippo.io/dependabot) in favor of reachability-aware tools like `govulncheck`

The result is alert fatigue: teams either spend hours triaging noise or start ignoring
alerts, real ones included.

## How it works

depquiet filters one kind of alert on its own: what only development pulls in. Everything
else it keeps, and it sorts and explains it:

| Signal | Effect |
|---|---|
| **Dev dependencies** | **Filtered** when every known dependency path is for development, with no production parent. For npm, also when every locked copy inside the advisory's range is one the lockfile marks as development-only (unless `package.json` declares that top-level copy for production: then the lockfile is stale) |
| **Reachability** | Never filters. A production package that nothing imports, directly or through the production dependencies that bring it in, is shown for **review**: another library may load it at runtime |
| **Test-only use** | Never filters. A production package imported only from test files is shown for **review**: an ORM loads its database driver from a dialect name (Sequelize, TypeORM, Knex and `pg`), Next.js loads `sharp`, PyJWT loads `cryptography`, and no import names them |
| **EPSS scoring** | Off by default: EPSS only orders the report (known exploited first, then highest EPSS). With `--epss-threshold`, alerts scoring below it are filtered. The lookup uses the advisory's CVE alias, so it works for pip-audit, uv audit and npm audit |
| **Community templates** | A built-in template never dismisses on its own: when it matches, its note is added to the review. Custom templates without conditions, `.depquiet-ignore` and policy rules are your explicit dismissals |

**Bundled frontends:** like `npm audit --omit=dev`, depquiet treats `devDependencies` as
development-only. If your bundler (Vite, webpack, esbuild) ships a package listed there in
your production JavaScript, move it to `dependencies` or add it to `always_flag`, or depquiet
will filter its alerts.

See [benchmarks](#benchmarks) for measured results on a real project.

### Conservative by design

depquiet would rather let a false positive through than dismiss a real vulnerability:

- **Transitive dependencies are judged by their parents.** Your code never imports
  `path-to-regexp`; Express does. depquiet reads your manifests and lockfiles to find the
  direct dependencies that pull a package in, and keeps the alert if your code imports any
  of them. See [Direct vs. transitive](#direct-vs-transitive-dependencies).
- **Unknown means not filtered.** If no manifest or lockfile says whether a package is direct
  or transitive, or a file fails to parse, the alert is not filtered on reachability.
- **Declared but never imported is not proof.** Frameworks load packages your code never
  imports: Django its database driver, `transformers` the `accelerate` you declared,
  Sequelize the `pg` named by its dialect. No lockfile records those edges, so a production
  dependency your code does not import goes to review instead of being dismissed, and so
  does everything it brings in: `uvicorn` started from the command line is never imported,
  yet `h11` parses every request.
- **Production paths override development labels.** A package listed in `devDependencies`
  is still kept when a production dependency also pulls it in. A transitive package
  imported by the application is kept even when its declared parent is unused.
- **Import-level, not call-graph.** Reachability means "the package enters your app", not
  "the vulnerable function is called". It removes packages your app never loads; it does not
  prove an imported package's vulnerable function is unused. For Go, `govulncheck` does
  symbol-level analysis and is the better tool.

### Supported inputs

depquiet accepts output from any vulnerability scanner — natively or via SARIF:

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
| Dependabot | API JSON | `gh api /repos/O/R/dependabot/alerts \| depquiet --stdin` |
| **Any SARIF scanner** | **SARIF v2.1.0** | `<scanner> --sarif \| depquiet --stdin` |
| **CycloneDX SBOM** | **JSON** | `depquiet --from-sbom vendor.cdx.json` |
| **SPDX SBOM** | **JSON** | `depquiet --from-sbom vendor.spdx.json` |

The SARIF parser handles output from CodeQL, Semgrep, Trivy SARIF, Grype SARIF, Snyk SARIF, Checkmarx, Fortify, and any other tool that emits SARIF v2.1.0. CVE, package name, severity (CVSS or level-based), and fix version are extracted automatically from the standard SARIF fields and common scanner-specific properties.

### npm component evidence

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

### Standalone scanning with OSV.dev

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

### SBOM generation (CycloneDX + SPDX)

depquiet generates both major SBOM standards required by US Executive Order 14028:

```bash
# CycloneDX 1.5 (OWASP standard)
depquiet --sbom sbom.json              # CycloneDX JSON
depquiet --sbom sbom.xml               # CycloneDX XML (auto-detected)
depquiet --sbom out.cdx --sbom-format xml

# SPDX 2.3 (ISO/IEC 5962:2021)
depquiet --sbom sbom.spdx.json         # SPDX JSON (auto-detected)
depquiet --sbom out.spdx --sbom-format spdx
```

Both formats include full component inventory with Package URLs (purl), vulnerability references for known CVEs, depquiet triage verdicts, and tool creator metadata. CycloneDX additionally maps verdicts to analysis states; SPDX uses SECURITY external references with NVD links.

SBOM output works alongside all other flags — combine `--sbom` with `--sarif` to generate both in one pass.

### SBOM import — triage from third-party SBOMs

depquiet can consume CycloneDX and SPDX SBOMs as input, enabling triage on third-party SBOMs from vendors, container registries, or build systems — without needing the original lockfile:

```bash
# Explicit file input
depquiet --from-sbom vendor-sbom.cdx.json    # CycloneDX 1.4/1.5 JSON
depquiet --from-sbom vendor-sbom.spdx.json   # SPDX 2.3 JSON

# Piped via stdin (auto-detected)
cat container-sbom.json | depquiet --stdin
```

Two-mode operation:
- **Vulnerability mode** — if the SBOM contains vulnerability data (CycloneDX `vulnerabilities` array or SPDX SECURITY external refs), those are extracted and triaged directly
- **Package mode** — if no vulnerability data is present, the package inventory is extracted and queried against OSV.dev for known advisories

An inventory-only SBOM cannot be scanned with `--offline`. Missing packages or a failed
OSV.dev lookup produce "nothing scanned" and exit code `2`, rather than a clean report.

All standard depquiet flags work with SBOM input: `--epss-threshold`, `--kev`, `--sbom` (re-export), `--sarif`, `--html`, etc.

### Workspace and dynamic-import coverage

Declared npm `workspaces` and uv `[tool.uv.workspace]` members have independent
dependency graphs, command metadata and source scopes. Deep declared members are
discovered beyond the legacy depth limit. A package used by a production member
cannot be classified as dev-only solely from the root's declaration.

Scan JSON and saved `explain` output retain per-workspace usage, dependency roots
and coverage. Unreadable/malformed manifests, links that could hide a manifest or
recognized loaders with nonliteral targets block automatic absence-based
decisions. Several locked versions of one package, duplicate member names and
names shared between ecosystems do not: their edges are merged, which can only
add dependency paths. Positive imports remain visible alongside uncertainty.

A project with both JavaScript (npm or pnpm) and Python dependencies is scanned for both in
one run. Each ecosystem is audited by its own scanner and triaged against its own dependency
graph, and every finding records which one reported it (`"package_manager"` in the JSON).
If one scanner fails, the other's findings are still reported and the note says which
ecosystem was not scanned. `--scanner npm`, `--scanner pnpm` or `--scanner pip` limits a run
to one.

The analysis is bounded: initial workspace support covers npm and uv declarations,
and finding-to-workspace associations use conservative dependency names rather
than claiming an installed instance or verified call path. Other layouts retain
legacy discovery. See [workspace and dynamic-import coverage](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/workspace-coverage.md)
for patterns, limits, aggregation and compatibility.

### Reachability analysis in depth

Import detection works differently for each language:

**Python** — AST extraction via `ast.parse()` observes ordinary imports and
recognized `importlib.import_module` / `__import__` calls, including direct aliases.
Literal targets provide positive import evidence; nonliteral, conditional or
rebound loader bindings retain uncertainty. Comments and strings are not executed
as loader calls. Files that fail AST parsing retain the existing regex fallback;
this does not establish complete parse or dynamic-loader coverage.

**JavaScript / TypeScript** — Comment-stripping pipeline + pattern matching on actual import syntax. Handles all major import styles:
- ESM: `import X from 'pkg'`, `import {a, b} from 'pkg'`, `import 'pkg'` (side-effect)
- CommonJS: `require('pkg')`
- Dynamic: `import('pkg')`
- Re-exports: `export {a} from 'pkg'`, `export * from 'pkg'`
- Scoped packages: `@scope/name` resolved correctly
- Strips `//` and `/* */` comments so commented-out imports don't cause false positives
- Zero runtime dependencies — no external JS parser needed

A bounded lexer additionally observes `require(...)`, `import(...)` and
`module.require(...)` calls. Nonliteral targets retain explicit uncertainty with
file/line evidence. This is lexical analysis, not a full JavaScript/TypeScript
parser or arbitrary loader/dataflow resolution.

**Go** — Import statement parsing with comment stripping. Handles:
- Single imports: `import "pkg"`
- Grouped imports: `import ( "pkg1" ; "pkg2" )`
- Aliased, dot, and blank imports: `import m "pkg"`, `import _ "pkg"`
- Module path resolution: `github.com/user/repo/sub` → `github.com/user/repo`
- `golang.org/x/*` packages resolved correctly
- Skips `vendor/` directory

**Rust** — Import statement parsing with comment stripping. Handles:
- `use crate_name::...` and `use crate_name;`
- `extern crate crate_name;` and `extern crate crate_name as alias;`
- Nested use: `use crate_name::{a, b};`
- Hyphen-to-underscore normalization: `my-crate` in Cargo.toml → `my_crate` in source
- Skips Rust-internal path roots: `self`, `super`, `crate`, `std`, `core`, `alloc`
- Skips `target/` directory

**Java / Kotlin** — Import statement parsing with comment stripping. Handles:
- Standard imports: `import com.example.Foo;`
- Static imports: `import static org.junit.Assert.assertEquals;`
- Wildcard imports: `import com.example.*;`
- Kotlin imports (no semicolons): `import com.example.Foo`
- Maven coordinate splitting: `groupId:artifactId` → matches against `groupId` prefix
- Package-path heuristic: walks dot-separated segments until an uppercase class name or `*`
- Skips `build/` directory

**C#** — Using directive parsing with comment stripping. Handles:
- Standard usings: `using Newtonsoft.Json;`
- Static usings: `using static System.Math;`
- Alias usings: `using Json = Newtonsoft.Json.JsonConvert;`
- Global usings: `global using System.Linq;`
- NuGet namespace matching: package name matches the root namespace prefix
- Skips `build/` directory

**PHP** — Use statement parsing with comment stripping. Handles:
- Standard use: `use Monolog\Logger;`
- Function use: `use function GuzzleHttp\Promise\all;`
- Const use: `use const GuzzleHttp\Promise\FULFILLED;`
- Composer vendor/package convention: first two namespace segments lowercased and joined with `/`
- Case-insensitive matching (PHP namespaces are case-insensitive)
- Strips `//`, `#`, and `/* */` comments
- Skips `vendor/` directory

**Ruby** — Require statement parsing with comment stripping. Handles:
- `require 'gem_name'` (single and double quotes)
- `require 'gem_name/sub'` → extracts top-level `gem_name`
- `require_relative` skipped (project-internal files)
- Hyphenated gem convention: `aws-sdk-s3` matches both `require 'aws-sdk-s3'` and `require 'aws/sdk/s3'`
- Strips `#` and `=begin`/`=end` comments
- Skips `vendor/` directory

**Swift** — Import statement parsing with comment stripping. Handles:
- Standard imports: `import ModuleName`
- Kind imports: `import struct Module.Type`, `import class Module.Class`, `import func Module.func`
- Testable imports: `@testable import ModuleName`
- SwiftPM package-to-module mapping: hyphens become underscores (`swift-argument-parser` → `swift_argument_parser`)
- Top-level module name extraction from dotted imports
- Skips `.build/` directory

**Dart / Flutter** — Import statement parsing with comment stripping. Handles:
- Package imports: `import 'package:name/file.dart';`
- Subpath imports: `import 'package:name/src/sub.dart';` → extracts `name`
- `dart:` SDK imports skipped (SDK-internal)
- Relative imports skipped (project-internal)
- Hyphen-to-underscore normalization for scanners that report with hyphens
- Skips `.dart_tool/` directory

All ten analyzers map aliased package names (e.g., `my-package` → `my_package` for Python, `@scope/name/sub` → `@scope/name` for JS, `github.com/user/repo/sub` → `github.com/user/repo` for Go, `my-crate` → `my_crate` for Rust, `com.fasterxml.jackson.core:jackson-databind` → `com.fasterxml.jackson.core` for Java, `Newtonsoft.Json.Linq` → `Newtonsoft.Json` for C#, `Monolog\Logger\Handler` → `monolog/logger` for PHP, `aws-sdk-s3` → matches `require 'aws/sdk/s3'` for Ruby, `swift-argument-parser` → `swift_argument_parser` for Swift, `flutter-bloc` → `flutter_bloc` for Dart) and check all source files in the project, skipping `node_modules`, `.git`, `__pycache__`, `dist`, `build`, `.build`, `.dart_tool`, `vendor`, `target`, and other vendored directories.

### Direct vs. transitive dependencies

The import check only answers "does my code import this package?", which is the right
question for direct dependencies and the wrong one for transitive ones. Since v0.28.0
depquiet builds a dependency graph from the project before filtering:

| Ecosystem | Direct dependencies from | Dependency paths from |
|---|---|---|
| npm | `package.json`, `package-lock.json`, `pnpm-lock.yaml` importers | `package-lock.json` (v1-v3), `yarn.lock` (v1, berry), `pnpm-lock.yaml` (v5-v9) |
| Python | `uv.lock`, `pyproject.toml` (PEP 621, PEP 735, Poetry), `Pipfile`, `requirements.in`, hand-written `requirements.txt` | `uv.lock`, `poetry.lock`, pip-compile `# via` comments |
| Rust | `Cargo.lock` workspace crates | `Cargo.lock` |
| Ruby | `Gemfile.lock` | `Gemfile.lock` |
| PHP | `composer.json` | `composer.lock` |
| .NET | `packages.lock.json` | `packages.lock.json` |
| Dart | `pubspec.lock` | — |
| Go | `go.mod` (`// indirect`) | — |
| Java (Maven) | `pom.xml` | — |

Rules, in order:

1. **Direct** dependency that nothing uses (no import, never run as a command, not loaded by a
   used dependency): kept for **review**, not filtered. Frameworks load packages your code
   never imports, and no lockfile records that.
2. **Transitive** dependency: kept for **review** when none of the direct dependencies that
   pull it in are used, ACTION when one is. With no known path (Go, Dart, Maven) it is never
   filtered.
3. **Development only**: filtered when every known path to the package is a development
   one, with no production parent. This is the only rule that filters.

A direct dependency is **used** when any of these holds:

- a source file imports it. Python distribution names are mapped to module names
  (`PyYAML` → `yaml`, `llama-index-core` → `llama_index`). When the package is installed, in
  the project's virtualenv or in the environment depquiet runs in, its recorded modules are
  used. Otherwise depquiet tries a table of known mismatches and every name the distribution
  name allows, including a bare prefix: `django-auth-ldap` is matched by `import django`.
  Such a match keeps the alert, and the report says it rests on a name guess instead of
  listing those files as usage. Run depquiet where the dependencies are installed to get
  exact answers;
- the project runs one of its executables: `pm2 start` in a `package.json` script, a
  `Procfile` entry, or a Dockerfile command;
- it is named in the project's code, scripts or config (`INSTALLED_APPS = ["allauth"]`,
  `postgresql+psycopg2://`, `celery flower` in a service script). Docs, manifests and
  lockfiles don't count;
- a used dependency loads it itself (FastAPI loads `python-multipart`, SQLAlchemy loads
  database drivers).

A wrong match only moves an alert from REVIEW to ACTION; it never hides one.

**Unknown** dependency type: never filtered. This includes a `requirements.txt` where every line is pinned
   with `==` and there are no `# via` comments, since that is indistinguishable from
   `pip freeze` output.

`depquiet explain <CVE>` shows the dependency type and the packages that pull it in, and
`--json` output includes `dependency_type` and `introduced_by` for every alert.

## Install

```bash
pip install depquiet
```

## Usage

```bash
# Auto-detect lockfiles and scan (no scanner needed — uses OSV.dev)
depquiet

# Scan a specific directory
depquiet --path ./my-app

# Pipe in existing audit output
npm audit --json | depquiet --stdin
pip-audit --format json | depquiet --stdin
trivy fs --format json . | depquiet --stdin
grype dir:. -o json | depquiet --stdin
snyk test --json | depquiet --stdin
gh api /repos/OWNER/REPO/dependabot/alerts --paginate | depquiet --stdin

# SARIF input — any scanner that emits SARIF works
semgrep --sarif . | depquiet --stdin
codeql database analyze db --format=sarif-latest | depquiet --stdin
trivy fs --format sarif . | depquiet --stdin
checkmarx-cli scan --output-format sarif | depquiet --stdin

# Fully offline (skip EPSS API)
depquiet --offline

# A repo with both package-lock.json and uv.lock: both are scanned by default.
# To scan only one:
depquiet --scanner pip

# SARIF output for GitHub Code Scanning
depquiet --sarif results.sarif

# SBOM (EO 14028 compliance)
depquiet --sbom sbom.json                     # CycloneDX 1.5 JSON
depquiet --sbom sbom.xml --sbom-format xml    # CycloneDX 1.5 XML
depquiet --sbom sbom.spdx.json               # SPDX 2.3 JSON

# JSON output for scripting
depquiet --json

# Also filter alerts with EPSS below 5% (off by default)
depquiet --epss-threshold 0.05

# Use a custom config file
depquiet --config ./ci-config.yaml

# Auto-fix ACTION items that have a known fix version
depquiet --fix

# See what --fix would do without changing anything
depquiet --fix --dry-run

# License compliance scan
depquiet --license

# Use a suppression file (auto-detected from project root)
depquiet   # reads .depquiet-ignore if present

# Explicit ignore file
depquiet --ignore ./custom-ignore.yaml

# Write GitHub-flavored Markdown summary (for CI)
depquiet --summary report.md

# Self-contained HTML report (share via email/Slack/artifact)
depquiet --html report.html

# Configurable CI gate — fail only on critical findings
depquiet --fail-on critical

# Fail on high and above (skip moderate/low)
depquiet --fail-on high

# Never fail on findings (informational mode)
depquiet --fail-on none
```

### Can the fix be installed? (`--check-fixes`)

"Update to 1.45.1" is only advice until the rest of your pins allow it. For a project with a
`uv.lock`, `--check-fixes` asks uv's own resolver, with `uv lock --dry-run --upgrade-package`,
whether each alert still shown can be fixed, and prints what blocks it if not. Nothing is
written. On saleor, both alerts that survive triage turn out to be blocked:

```
$ uv audit --frozen --output-format json | depquiet --stdin --check-fixes

🔴 ACTION REQUIRED: 2 alerts
   • GHSA-3jp2-3mrg-2vxc  oauthlib  FIX: update to 4.0.1
     ✗ fix check: blocked: `oauthlib` was filtered by `exclude-newer-package` to only include
       packages uploaded before 2026-09-28T06:02:00Z. The requested version, v4.0.1, was
       published at 2026-10-31T09:52:56.206Z. ...
   • GHSA-xcq7-p3pf-p88h  opentelemetry-api  FIX: update to 1.45.1
     ✗ fix check: blocked: Because opentelemetry-semantic-conventions==0.58b0 depends on
       opentelemetry-api==1.37.0 and your project depends on opentelemetry-api==1.45.1, ...
```

The first is saleor's own supply-chain cooldown; the second needs
`opentelemetry-semantic-conventions` upgraded in the same step. A fix that resolves prints
`✓ fix check: resolves (uv lock --upgrade-package pkg==version)`. Each check is one
resolution against the package index, so it needs uv and network access; the JSON report
has a `fix_check` object per alert.

**Measured on 18 uv projects** (2026-11-12, at their head; script, raw output and every
resolver message in [`benchmarks/fixcheck_study`](https://github.com/samuelrojas-dev/depquiet/tree/main/benchmarks/fixcheck_study/)). Each kept
alert was checked against its own nearest fix; each package also against its highest fix,
the one upgrade that clears all of its alerts:

| | Kept alerts | Packages |
|:--|--:|--:|
| With a fix version | 991 | 175 |
| Fix resolves | 489 | 103 |
| **Fix blocked** | **502 (51%)** | **72 (41%)** |

What blocks the 72 package upgrades, read from uv's messages:

- 45: the project's own pin on that same package (`posthog requires aiohttp==3.13.5`).
- 13: another package's pin. depquiet retried each with that package upgraded in the same
  step; none resolved, because in all 13 the project pins that package too (`posthog
  requires lxml==6.0.2`, which holds `lxml-html-clean`).
- 9: a Python version newer than the oldest the project supports; 2: the project's own
  `exclude-newer` cooldown; 3: not told apart from uv's message.

So 58 of the 72 (81%) come down to a pin in the project's own `pyproject.toml`, directly or
one step away. None failed for network or build reasons. Blocked does not mean unfixable:
it means the scanner's "update to X" is not enough, and the pin to widen is the answer.

For each block, `--check-fixes` says what to do next: the requirement of yours to widen, or
the blocking package and the pin that holds it, or the Python floor or cooldown. When
upgrading the blocking package in the same step resolves, it prints the command
(`uv lock --upgrade-package a==1.2 --upgrade-package b`).
The study ran in a disposable VM, for the reason below.

`uv lock` can run code: when a package (your project included) computes its metadata with a
`setup.py` or another build hook, uv executes it to find its dependencies. `--check-fixes`
does nothing `uv lock` would not do in the same checkout, but run it only on code you
trust, and not in CI jobs that check out pull requests from outside contributors.

### One verified change for all the fixes (`--fix-plan`)

`--check-fixes` says, per package, whether the fix installs and what blocks it. `--fix-plan`
answers the next question: what do I change so the fixes install, together?

```bash
depquiet --fix-plan plan.diff     # or --fix-plan alone to print the diff
git apply plan.diff
uv lock --upgrade-package ...     # the command it prints
```

For a uv project it:

1. widens each requirement of yours that blocks a fix, just enough (`==2.31.0` → `==2.33.0`,
   `<3.7` → `<4`; other clauses, extras and markers stay as written);
2. when another package holds a fix back and you pin that package, lets uv pick a version of
   it that allows the fix, and pins that version in your style;
3. applies everything to a **temporary copy** of the project and runs `uv lock --dry-run` with
   all the upgrades at once. If they don't fit together, it keeps each fix that still
   resolves with the ones already kept and reports the rest with uv's reason.

Nothing in the project is changed. What is verified is resolution only: whether your code
works with the new versions, a major version change above all, is for your tests to say.
Like `--check-fixes`, it runs `uv lock`, so use it on trusted code.

Real run on a small project pinning `requests==2.31.0` and `botocore==1.29.0` (which caps
`urllib3` below 2):

```
🔧 Fix plan
   ✓ requests 2.31.0 → 2.33.0: widen your requirement
   ✓ urllib3 1.26.20 → 2.8.0: also move botocore → 1.44.2, which holds it back  (major version change)

   Verified with uv's resolver: all fixes resolve together.
   Then run: uv lock --upgrade-package requests==2.33.0 --upgrade-package urllib3==2.8.0 --upgrade-package botocore==1.44.2
```
```diff
-    "requests==2.31.0",
-    "botocore==1.29.0",
+    "requests==2.33.0",
+    "botocore==1.44.2",
```

After `git apply` and that command, pip-audit reports no known vulnerabilities in the
project's dependencies. Python-floor blocks are reported, not planned.

#### Fixes hidden by your cooldown (`exclude-newer`)

A cooldown (`exclude-newer = "7 days"`, or a date) protects you from a malicious release
by hiding releases newer than the cut-off. It hides security fixes too: the scanner flags
the vulnerable version, `uv lock` says "No solution found", and the usual way out is to
switch the cooldown off. `--fix-plan` writes the narrowest exemption uv supports instead:
an `exclude-newer-package` cut-off for that package only, one second after the fix was
published. The package can move to the fix and no further, even with `uv lock --upgrade`,
and every other package keeps the cooldown. Existing exemptions are kept, and the entry
goes where you set `exclude-newer` (`pyproject.toml` or `uv.toml`).

Real run on a project with `exclude-newer = "2025-06-01T00:00:00Z"` and requests 2.32.3,
whose fix for CVE-2024-47081 (2.32.4) was published on 2025-06-09:

```
🔧 Fix plan
   ✓ requests 2.32.3 → 2.32.4: exempt it from your exclude-newer cooldown, only up to this release (published 2025-06-09)

   Verified with uv's resolver: all fixes resolve together.
   Then run: uv lock --upgrade-package requests==2.32.4
```
```diff
 [tool.uv]
 exclude-newer = "2025-06-01T00:00:00Z"
+exclude-newer-package = { requests = "2025-06-09T16:43:06Z" }
```

After `git apply` and that command, requests is at 2.32.4, `uv lock --upgrade` keeps it
there, and urllib3 stays under the project's cut-off. An exemption admits a release younger
than your cooldown, so the plan says so: check that it is the advisory's fix and comes from
the project's usual publisher before you merge.

**Remove the entry once your cooldown catches up.** A per-package date overrides the
cooldown for that package for good. With `exclude-newer = "7 days"`, an entry left in place
holds the package at the fix release: in a real run, uv moved requests *back* from 2.34.2
to 2.32.4. With a rolling cooldown the plan prints the date after which to remove the
entry, and every depquiet scan warns about any `exclude-newer-package` date older than the
project's own cut-off, whoever wrote it:

```
⚠️  exclude-newer-package holds requests at releases before 2025-06-09T16:43:06Z, older than your cooldown's cut-off (2026-11-06T21:32:08Z): uv keeps requests on old releases. Remove the entry.
```

### Auto-remediation (`--fix`)

`depquiet --fix` upgrades packages that have ACTION verdicts **and** a known fix version:
`npm install <pkg>@<ver>` for npm, and for a Python project with a `uv.lock`,
`uv lock --upgrade-package <pkg>==<ver>` (then `uv sync` installs it). When uv's resolver
refuses, the report says what blocks the fix, as [`--check-fixes`](#can-the-fix-be-installed---check-fixes)
does. Other Python projects are not changed: `pip install` would only touch the environment
depquiet runs in and leave your requirement files as they are, so depquiet lists the
requirement to raise instead, and the alert still counts as open.

```
$ depquiet --fix

depquiet scan — npm (847 packages)
...

✅ Fixed 2 vulnerabilities:
   CVE-2024-4068  braces 3.0.2 → 3.0.3
   CVE-2024-33883  ejs 3.1.9 → 3.1.10

⚠️  1 ACTION items have no fix available:
   CVE-2024-21538  semver 7.5.4
```

Use `--dry-run` to preview changes without touching `node_modules` or `site-packages`:

```
$ depquiet --fix --dry-run

[dry-run] ✅ Fixed 2 vulnerabilities:
   CVE-2024-4068  braces 3.0.2 → 3.0.3   Would run: npm install braces@3.0.3
   CVE-2024-33883  ejs 3.1.9 → 3.1.10    Would run: npm install ejs@3.1.10
```

**Exit codes with `--fix`:** returns `0` when every ACTION item is resolved; returns `1` when any remain unfixed (no fix version, or the upgrade command failed).

### License compliance (`--license`)

`depquiet --license` scans every installed dependency for license risk — copyleft contamination, unknown licenses, and restrictive terms that could block enterprise adoption or open-source distribution.

```
$ depquiet --license

depquiet license scan — npm (847 packages)

LOW (permissive):  812 packages
   MIT, Apache-2.0, BSD-2-Clause, ISC, ...

MEDIUM (weak copyleft):  4 packages
   LGPL-2.1   libfoo 3.2.1
   MPL-2.0    bar-utils 1.0.0
   ...

🔴 HIGH (copyleft):  2 packages
   GPL-3.0    gpl-thing 1.0.0
   GPL-2.0    another-gpl 2.1.0

🔴 CRITICAL (network copyleft / non-OSS):  1 package
   AGPL-3.0   agpl-server 0.5.0

⚠️  UNKNOWN:  1 package
   ???        mystery-pkg 1.2.3

License scan: FAIL — 4 packages need review
```

Risk levels:

| Level | Licenses | Meaning |
|-------|----------|---------|
| **LOW** | MIT, BSD, Apache-2.0, ISC, Unlicense, ... | Permissive — safe for any use |
| **MEDIUM** | LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0 | Weak copyleft — check linking requirements |
| **HIGH** | GPL-2.0, GPL-3.0 | Strong copyleft — derivative works must be GPL |
| **CRITICAL** | AGPL-3.0, SSPL-1.0, BUSL-1.1 | Network copyleft or non-OSS — high legal risk |
| **UNKNOWN** | Unrecognized or missing | Needs manual review |

SPDX expressions are handled automatically: `MIT OR GPL-3.0` picks the most permissive (MIT → LOW), `MIT AND GPL-3.0` picks the most restrictive (GPL-3.0 → HIGH). Common non-SPDX strings like `"Apache License 2.0"` and `"GPLv3"` are normalized to their SPDX IDs.

**Exit codes with `--license`:** returns `0` when all dependencies are LOW or MEDIUM; returns `1` when any HIGH, CRITICAL, or UNKNOWN licenses are found.

Combine with JSON output for CI integration:

```bash
depquiet --license --json
```

With `--json`, the command emits one scan document. License results are included in its
`license` field; the vulnerability `summary` and `results` fields keep their existing shape.


**Python packages and their licenses.** The packages are the project's locked ones
(`uv.lock`, `poetry.lock`, `pdm.lock` or fully pinned requirement files), never the
environment depquiet runs in. Each license is read from the project's own virtualenv
(`.venv`, `venv`, `env`: METADATA files only, nothing is executed) when it holds that exact
version, else from PyPI for that version. With `--offline`, or when PyPI gives no license,
the package is UNKNOWN and the check fails: an unread license is not a permissive one.
Without a lockfile or pinned requirements, the report says the Python dependencies were
not checked.

### Suppression file (`.depquiet-ignore`)

Teams need a way to acknowledge accepted risk without disabling the tool. The `.depquiet-ignore` file provides per-CVE and per-package suppressions with accountability:

```yaml
ignores:
  # Suppress a specific CVE (any package)
  - cve: CVE-2024-1234
    reason: "Mitigated by WAF rule WR-123"
    expires: 2025-06-01
    author: alice

  # Suppress a CVE only for a specific package
  - cve: CVE-2024-5678
    package: lodash
    reason: "Only used in tests, no production exposure"

  # Suppress all CVEs for a package (migration planned)
  - package: deprecated-pkg
    reason: "Migration to replacement-pkg planned for Q2"
    expires: 2025-07-01
```

Place `.depquiet-ignore` in the project root (auto-detected) or pass `--ignore path/to/file.yaml`.

**Match priority:** CVE+package > CVE-only > package-only. Only ACTION and REVIEW items are suppressed — already-filtered items are left as-is.

**Expiry dates:** When an entry's `expires` date passes, it stops suppressing and depquiet prints a warning. This prevents suppressions from rotting forever — teams must re-evaluate periodically.

**Audit trail:** The `reason` field (recommended) explains why the risk was accepted. The `author` field records who made the decision.

### Scan comparison (`depquiet diff`)

Compare two saved depquiet reports to see new or absent finding contexts and
verdict changes. Reports with the same explicit `project_id` automatically use
instance contexts: npm candidates match on advisory, exact version, node location,
lockfile path and advisory range/status. A newly added version or location remains
visible even when the advisory was already present. Partial or unknown evidence
stays explicit. Other scanners retain literal reported-version contexts.

When both reports lack a project ID, matching retains the legacy exact advisory,
package and reported-version string. A scanner range stays a range; the diff does
not infer an installed version or advisory aliases. Use `--project-id team/service`
to bind missing scopes explicitly, `--instances` to require instance mode, or
`--legacy-identities` for an explicit compatibility comparison. Declared project
IDs must agree in every mode; a CLI option cannot override a conflicting ID.

The historical `fixed` field means a finding context is absent from the head
report. It does not establish remediation or product non-affectedness. A version
replacement can therefore appear as one absent context and one new context.
Compare the same declared project/input scope when interpreting these changes.

```bash
# Compare a base branch scan against a PR branch scan
depquiet diff base-scan.json pr-scan.json

# Machine-readable output
depquiet diff base-scan.json pr-scan.json --json

# Fail CI only when new ACTION items appear
depquiet diff base-scan.json pr-scan.json --fail-on-new

# Require scoped instance comparison (both reports must be complete)
depquiet diff base-scan.json pr-scan.json --instances --project-id team/service --fail-on-new
```

An explicit incomplete scan (`scanned: false`), malformed report, incompatible scope
or duplicate finding identity is rejected with exit code **2** and a diagnostic
on stderr, without a successful diff or overwriting an existing summary. Other
operational errors also return **2**. Exit **1** is used for new ACTION findings
with `--fail-on-new`; a missing input file retains its legacy exit code **1**.
Legacy comparisons accept structurally valid older reports without `scanned`,
but their completion cannot be verified from that missing flag. Instance mode
requires `scanned: true`; older npm-project reports without `version_kind` require
a rescan or explicit legacy comparison. See [identity and migration details](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/instance-baselines.md).

Typical CI workflow:

```yaml
- name: Scan base
  run: git stash && depquiet --json > /tmp/base.json && git stash pop

- name: Scan head
  run: depquiet --json > /tmp/head.json

- name: Diff
  run: depquiet diff /tmp/base.json /tmp/head.json --fail-on-new
```

Output shows new, fixed, and changed findings with severity, EPSS scores, and verdict transitions:

```
🆕 2 new | ✅ 1 fixed | 🔄 1 changed | — 12 unchanged

── New findings ──────────────────────────────────────
  [HIGH] CVE-2024-0001 in lodash@4.17.20 — Prototype Pollution → ACTION (EPSS: 42.0%)
```

### GitHub PR comments

Post scan diff results directly on pull requests as rich Markdown comments — severity badges, EPSS scores, fix versions, and verdict changes at a glance.

```bash
# Markdown output for piping to gh pr comment
depquiet diff base.json head.json --markdown

# Write markdown to a file (e.g. for $GITHUB_STEP_SUMMARY)
depquiet diff base.json head.json --summary diff-report.md
```

**GitHub Action** — automatic PR comments with the `diff-base` and `pr-comment` inputs:

```yaml
- uses: samuelrojas-dev/depquiet@v0
  with:
    diff-base: base-scan.json    # path to a base branch scan
    pr-comment: true             # post/update a PR comment with the diff
```

The action auto-updates the comment on re-runs (deletes previous depquiet comments first), writes a diff summary to `$GITHUB_STEP_SUMMARY`, and exposes `diff-new` / `diff-fixed` outputs for downstream steps.

### Config scaffolder (`depquiet init`)

Bootstrap a `.depquiet.yaml` for your project in seconds. `init` auto-detects the package manager, CI provider, and existing scanners, then generates a config with sensible defaults.

```bash
# Interactive — shows detection results, asks before writing
depquiet init

# Non-interactive — accept all defaults (great for scripts)
depquiet init --yes

# Overwrite an existing config
depquiet init --yes --force

# Write to a custom path
depquiet init -o configs/depquiet.yaml
```

Detection covers 11 package managers (npm, pip, Go, Cargo, Maven, Gradle, Gem, Composer, Pub, NuGet), 6 CI providers (GitHub Actions, GitLab CI, Jenkins, CircleCI, Bitbucket, Azure DevOps), and 6 scanner tools (Snyk, Trivy, Grype, OSV-Scanner, Dependabot, Renovate). GitHub Actions projects automatically get SARIF and summary outputs enabled.

### Verdict explainer (`depquiet explain`)

Understand exactly why a CVE received its verdict. Every contributing signal — EPSS score, reachability, dependency type, community template, KEV status, ignore rules — is laid out step-by-step so developers and security teams can audit triage decisions.

```bash
# Explain a CVE from a previous scan (saved with --json)
depquiet explain GHSA-9wv6-86v2-598j --from-json scan.json

# Machine-readable output
depquiet explain GHSA-9wv6-86v2-598j --from-json scan.json --json

# Live scan and explain
depquiet explain GHSA-9wv6-86v2-598j --path ./my-project
```

Each signal shows its effect on the final verdict:

```
🔴 GHSA-9wv6-86v2-598j — path-to-regexp outputs backtracking regular expressions
   Package: path-to-regexp@<0.1.10
   Severity: HIGH
   Verdict: ACTION (no automatic filter matched; product impact unverified)
   Fix: upgrade to express@4.22.3

   Signals:
  - EPSS score: unavailable — EPSS lookup was skipped or failed
  ↑ Reachability: reachable — Transitive, pulled in by express. Entry points: app.js
  · Dependency type: production — Included in production builds
  · CISA KEV: not listed
```

(The [real Express benchmark](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/RESULTS.md), scanned with `--offline`, so no EPSS.)

### Scan statistics (`depquiet stats`)

Get aggregate metrics for security dashboards and management reports. Works from `--json` output or a live scan.

```bash
# Stats from a saved scan
depquiet stats --from-json scan.json

# Machine-readable JSON
depquiet stats --from-json scan.json --json

# Top 5 affected packages
depquiet stats --from-json scan.json --top 5
```

Output includes verdict breakdown, severity distribution, filter reason analysis, top affected packages, EPSS distribution, and fix availability:

```
depquiet scan statistics
========================================

Total vulnerabilities: 29
Total dependencies:   14
Filter rate:          27.6%

Verdicts:
  🔴 ACTION       13 ( 44.8%) █████████░░░░░░░░░░░
  🟡 REVIEW        8 ( 27.6%) ██████░░░░░░░░░░░░░░
  🟢 FILTERED      8 ( 27.6%) ██████░░░░░░░░░░░░░░

Filter reasons:
  dev dependency               8 ( 50.0%)
  unreachable                  8 ( 50.0%)
...
```

### CISA KEV integration (`--kev`)

The [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog lists CVEs with confirmed active exploitation. Under [BOD 22-01](https://www.cisa.gov/binding-operational-directive-22-01), federal agencies must remediate KEV-listed CVEs within strict deadlines — and any organization should treat them as top priority.

```bash
# Check scan results against the KEV catalog
depquiet --kev

# Air-gapped environments: use a local copy of the catalog
depquiet --kev-file /path/to/known_exploited_vulnerabilities.json
```

How it works: KEV-listed CVEs are **auto-escalated to ACTION** regardless of other filters.
The match uses every identifier of the advisory: uv audit names advisories by GHSA id and
pip-audit by PYSEC or GHSA id, with the CVE as an alias, and KEV lists CVEs only.
`.depquiet-ignore` entries and policy `cves:` match aliases the same way. A low-EPSS, devDependency, or unreachable vulnerability that's on the KEV catalog gets promoted to ACTION because active exploitation trumps all other signals.

The KEV feed is cached locally for 24 hours. On network failure, depquiet falls back to the expired cache. In `--offline` mode, only the cache is used.

JSON output includes KEV enrichment:

```json
{
  "cve": "CVE-2021-44228",
  "verdict": "action",
  "kev": {
    "date_added": "2021-12-10",
    "due_date": "2021-12-24",
    "required_action": "Apply updates per vendor instructions.",
    "ransomware_use": true
  }
}
```

Combine with baseline and fail-on for maximum control:

```bash
# Accept known debt, but always flag KEV-listed CVEs
depquiet --baseline .depquiet-baseline.json --kev --fail-on high
```

### HTML report (`--html`)

Generate a self-contained interactive HTML report — zero external dependencies, all CSS and JS inline, ready to share via email, Slack, or upload as a CI artifact.

```bash
depquiet --html report.html
```

The report includes a severity donut chart, collapsible sections (review auto-collapses when >5 findings, filtered always starts collapsed), dark mode support, and client-side text search. All data is embedded as JSON for future extensibility. XSS-safe: user-controlled values are escaped in both HTML and embedded JSON contexts.

### PR annotations (`--annotations`)

Post vulnerability findings as inline annotations on PR diffs — like CodeQL or ESLint. Each ACTION or REVIEW finding becomes a GitHub Check Run annotation pointing at the package manifest or the file that imports the vulnerable package.

```bash
# Generate annotations JSON
depquiet --annotations annotations.json
```

In the GitHub Action, just add `annotations: true`:

```yaml
- uses: samuelrojas-dev/depquiet@v1
  with:
    annotations: true
```

Annotations are automatically posted via the Check Runs API. Critical/high findings appear as errors, moderate as warnings, and low/info as notices. Each annotation includes the CVE, severity, EPSS score, fix version, and a link to the NVD advisory.

### OpenVEX documents (`--vex`)

Generate [OpenVEX](https://openvex.dev) documents that communicate the exploitability status of every vulnerability in your project. VEX (Vulnerability Exploitability eXchange) is the CISA-recommended format for telling downstream consumers which CVEs actually affect your software — and which don't.

```bash
# Generate an OpenVEX document
depquiet --vex vex.json
```

Priority and product impact are separate. The current engine observes dependency
relationships and imports; it does not prove vulnerable-function execution or
product-specific mitigations. Automatic exports preserve this uncertainty:

| Output | Automatic impact state | Priority and context |
|---|---|---|
| OpenVEX | `under_investigation` | `status_notes` contains priority, observations and limits |
| CycloneDX JSON/XML | `in_triage` | `analysis.detail` and per-component `depquiet:triage` properties |
| Scan JSON | `assessment.status: under_investigation` | Existing `verdict`, plus `evidence` and `decision_trace` |

A low EPSS, dev-only metadata, baseline, ignore or policy match never becomes an
automatic `not_affected` claim. The existing remediation priorities and exit-code
policy remain available. See the [assessment contract](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/assessment-contract.md).

The output is consumable by policy engines like Sigstore's policy-controller and OPA/Gatekeeper to gate container deployments.

```yaml
# In the GitHub Action
- uses: samuelrojas-dev/depquiet@v1
  with:
    vex: depquiet-vex.json
```

### Accepted baselines (`--baseline`)

Baseline v2 records explicit project-scoped acceptance of exact npm component
contexts. Create a completed report, review its findings, then create the acceptance
document with your reason and author metadata:

```bash
depquiet --project-id team/service --json > current-scan.json
# A completed scan may exit 1 when ACTION findings exist; inspect the saved report.
depquiet baseline create current-scan.json -o .depquiet-baseline-v2.json \
  --reason "Reviewed dependency debt; tracked for remediation" --author "Security team"
depquiet --project-id team/service --baseline .depquiet-baseline-v2.json --fail-on high
```

Creation accepts only fully resolved npm findings whose associated candidates all
match the advisory range. Partial, unknown and other scanner contexts appear in
`unaccepted`; a valid document may contain zero acceptances. A finding is demoted
from ACTION/REVIEW to FILTERED only when every current context is eligible and
accepted. New versions, locations or advisory range/status contexts remain visible.
The project ID must match, and the decision trace retains reason, author and path.
Acceptance changes priority; product impact remains under investigation.

Existing scan JSON files used directly with `--baseline` keep their broad
`CVE:package` legacy semantics, including across versions and node locations.
They are not migrated automatically. A declared project ID is enforced even for
this legacy format. For v2 migration, rescan with an explicit scope and review the
new acceptance document. See [baseline format and compatibility](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/instance-baselines.md).

### Configurable CI gate (`--fail-on`)

By default, depquiet exits `1` whenever any ACTION item exists — just like Snyk's `--severity-threshold`. The `--fail-on` flag lets you control the minimum severity that fails the build:

| `--fail-on` value | Fails on |
|---|---|
| (default) | Any ACTION item, regardless of severity |
| `critical` | Critical only |
| `high` | High + Critical |
| `moderate` | Moderate + High + Critical |
| `low` | Low + Moderate + High + Critical |
| `none` | Never fails on findings (informational mode) |

This is useful for gradual adoption: start with `--fail-on critical` to block only the most dangerous vulnerabilities, then tighten the threshold as the team addresses lower-severity items.

```bash
# Block only critical and high vulnerabilities in CI
depquiet --fail-on high

# Informational mode — report everything, block nothing
depquiet --fail-on none --summary $GITHUB_STEP_SUMMARY
```

## CI Integration


**Alerts without a severity.** pip-audit and uv audit report no severity, so their
alerts show `unknown` (`"severity": "unknown", "severity_known": false` in `--json`;
`unknown` in SARIF properties, SBOM ratings, the summary and HTML report).
`--fail-on high` or `critical` counts those as meeting the threshold and says so on
stderr: a placeholder must never let a critical advisory through. For the same reason,
an ACTION alert without a severity is a SARIF `error` and a GitHub annotation `failure`. Use `--fail-on none`
to never fail, or a scanner that reports severity (npm audit, Grype, OSV.dev, an SBOM
with ratings) to gate on it.

### Exit codes

- `0` — No ACTION items at or above the `--fail-on` threshold (safe to pass)
- `1` — ACTION items found at or above the threshold (fail the build)
- `2` — Nothing was scanned: no supported manifest or lockfile, a lockfile that needs
  OSV.dev while `--offline` is set, or an input that cannot be read (`--stdin`,
  `--from-sbom`, `--kev-file`, `--baseline`). depquiet never reports an unscanned project
  as clean.

### GitHub Actions (Marketplace)

```yaml
- name: Triage vulnerabilities
  uses: samuelrojas-dev/depquiet@v0
  with:
    sarif: results.sarif
    policy: .depquiet-policy.yaml
    sbom: sbom.cdx.json
```

The action installs the depquiet version of the tag you reference, plus pip-audit for Python projects (`install-pip-audit: false` to skip), runs it, uploads SARIF to GitHub Code Scanning, uploads the SBOM as a build artifact, and fails the build if ACTION items are found. A repository with npm and Python dependencies is scanned for both; `scanner: uv` (or `npm`, `pnpm`, `pip`) limits it to one.

The action automatically writes a **Job Summary** to the PR checks page with severity badges, EPSS scores, fix versions, and a filtered breakdown.

For a uv project, `check-fixes: true` adds a "Can the fixes be installed?" table to the Job
Summary: each upgrade uv's resolver accepts, with the command, and each it rejects, with what
blocks it (your own pin, another package's pin, a Python floor or a cooldown). It installs uv
if the runner has none. It runs `uv lock`, which can execute build hooks, so enable it on
pushes and on pull requests from your own branches, not on `pull_request_target` or any job
that holds secrets while checking out outside contributions.

```yaml
- uses: samuelrojas-dev/depquiet@v0
  with:
    check-fixes: true
```

**Action inputs:** `path`, `scanner`, `epss-threshold`, `offline`, `sarif`, `templates`, `policy`, `sbom`, `sbom-format`, `from-sbom`, `ignore`, `license`, `baseline`, `kev`, `kev-file`, `html`, `annotations`, `vex`, `diff-base`, `pr-comment`, `check-fixes`, `fail-on-action`, `fail-on`, `python-version`, `install-pip-audit`.

**Action outputs:** `total`, `action`, `review`, `filtered` (alert counts), `sarif-file` and
`sbom-file` (paths, when generated), `diff-new` and `diff-fixed` (when `diff-base` is set).

```yaml
- uses: samuelrojas-dev/depquiet@v0
  id: depquiet
  with:
    fail-on-action: "false"
- env:
    ACTION_COUNT: ${{ steps.depquiet.outputs.action }}
  run: echo "$ACTION_COUNT alerts need action"
```

> **Note:** `fail-on` (severity-based) supersedes `fail-on-action` (boolean). When `fail-on` is set, `fail-on-action` is ignored.

`fail-on-action: false` only permits vulnerability findings. Scanner failures still fail
the step. Diff summaries and PR comments use the saved scan, including when findings
cause the scanning step to fail; they do not run another scan.

### GitHub Actions (manual)

```yaml
- name: Triage vulnerabilities
  run: |
    pip install depquiet
    depquiet --sarif results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Community templates

depquiet ships with **20 built-in templates** in [nuclei-style](https://github.com/projectdiscovery/nuclei-templates) YAML.

A built-in template matches only when depquiet can read the project source and finds no
import of the package, or of any direct dependency that brings it in. Since 0.43 a match no
longer dismisses the alert: that is exactly the case where another library may load the
package (requests loads `certifi` on every HTTPS call), so the template's note is added to
the review instead. Custom templates without conditions are explicit unconditional
dismissal rules, so add `not-imported` conditions when that is not your intention.

Earlier versions gave each template a technical justification ("mitigated by Express 4.x
defaults", "timing attack") that depquiet never verified, and some were wrong. Since 0.40.5
the reason states only what was checked.

| Template | Package | CVE |
|---|---|---|
| lodash prototype pollution | lodash | CVE-2020-8203, CVE-2019-10744, CVE-2018-16487 |
| semver ReDoS | semver | CVE-2022-25883 |
| express open redirect | express | CVE-2024-29041 |
| axios SSRF | axios | CVE-2023-45857 |
| json5 prototype pollution | json5 | CVE-2022-46175 |
| webpack-dev-middleware path traversal | webpack-dev-middleware | CVE-2024-29180 |
| ip SSRF | ip | CVE-2023-42282 |
| requests proxy-auth leak | requests | CVE-2023-32681 |
| cryptography null dereference | cryptography | CVE-2024-0727 |
| minimist prototype pollution | minimist | CVE-2021-44906, CVE-2020-7598 |
| nth-check ReDoS | nth-check | CVE-2021-3803 |
| postcss ReDoS | postcss | CVE-2023-44270, CVE-2021-23382, CVE-2021-23368 |
| glob-parent ReDoS | glob-parent | CVE-2020-28469 |
| node-forge signature verification | node-forge | CVE-2022-24771, CVE-2022-24772, CVE-2022-24773 |
| shell-quote injection | shell-quote | CVE-2021-42740 |
| qs prototype pollution | qs | CVE-2022-24999 |
| word-wrap ReDoS | word-wrap | CVE-2023-26115 |
| tough-cookie prototype pollution | tough-cookie | CVE-2023-26136 |
| js-yaml code execution | js-yaml | CVE-2013-4660 |
| certifi root CA removal | certifi | CVE-2023-37920, CVE-2024-39689 |

```yaml
id: qs-prototype-pollution
reason: "No import of qs, or of a direct dependency that brings it in, was found in the project source. ..."
author: "@depquiet"
cves:
  - CVE-2022-24999
package: qs
not-imported: ["qs"]
```

### Contributing a template

1. Create a YAML file in `templates/dismiss/`
2. Add the CVE, affected package, and dismiss conditions
3. Open a PR — the community reviews and merges

A template's reason must state only what depquiet checks. Technical arguments about how a
library is used belong in the PR discussion, with a source, not in the dismissal text.

## Configuration

Create `.depquiet.yaml` in your project root (or pass `--config path/to/config.yaml`).
Every key is optional — add only what you need:

```yaml
# Triage tuning
project_id: team/service     # stable explicit scope for instance baselines/diffs
epss_threshold: 0.05          # filter EPSS below this (default: off, EPSS only orders)
offline: false                # skip EPSS API (default: false)
always_flag:                  # packages that must never be filtered
  - lodash
  - express
template_dirs:                # extra template directories
  - ./my-templates

# CI gate
fail_on: high                 # severity threshold: critical | high | moderate | low | none

# Integrations
kev: true                     # check CISA KEV catalog
kev_file: data/kev.json       # local KEV catalog (air-gapped)
license: true                 # run license compliance analysis

# Input paths (relative to project root)
policy: .depquiet-policy.yaml
ignore: .depquiet-ignore
baseline: reports/baseline.json

# Output files (relative to project root)
sarif: reports/depquiet.sarif
html: reports/depquiet.html
summary: reports/summary.md
sbom: reports/sbom.cdx.json
sbom_format: json             # json | xml | spdx
vex: reports/vex.json
annotations: reports/annotations.json
```

CLI flags always override config values when explicitly passed. `template_dirs` from both sources are merged. This enables zero-flag CI — just run `depquiet` and the config drives everything.

## Policy engine

Commit security policies alongside your code. Rules match on vulnerability attributes and override
the default triage verdict — first matching rule wins.

Create `.depquiet-policy.yaml` in your project root (or pass `--policy path/to/policy.yaml`):

```yaml
rules:
  # Always block critical CVEs, even if filters would dismiss them
  - id: block-critical
    action: action
    severity: critical

  # Dismiss low-EPSS noise in dev dependencies
  - id: dismiss-low-epss-dev
    action: filter
    is_dev: true
    epss_below: 0.01

  # Always flag these core packages
  - id: block-core-packages
    action: action
    packages: [express, lodash]

  # Specific CVE override
  - id: accept-cve-1234
    action: filter
    cves: [CVE-2024-1234]
```

### Match conditions

All conditions on a rule must match (AND logic):

| Condition | Type | Description |
|-----------|------|-------------|
| `severity` | string or list | `critical`, `high`, `medium` (or `moderate`), `low`, `info` |
| `packages` | string or list | Package names to match |
| `epss_below` | float | EPSS score below this threshold |
| `epss_above` | float | EPSS score above this threshold |
| `is_dev` | bool | Match dev dependencies only |
| `has_fix` | bool | Match vulnerabilities with a known fix |
| `cves` | string or list | Specific CVE IDs |

A rule with an unknown key (`severty:`), an unknown severity or an EPSS bound that is not a
number between 0 and 1 is skipped with a warning: dropping just that condition would widen the
rule to every finding. A trailing `# comment` on a line is ignored.

### Actions

| Action | Aliases | Effect |
|--------|---------|--------|
| `action` | `block` | Escalate to ACTION REQUIRED |
| `review` | | Mark for review |
| `filter` | `filtered`, `dismiss`, `ignore` | Filter out |

## Benchmarks

Six real projects: five popular open-source apps pinned to a commit, plus a small Express
app pinned to 2022 versions. npm projects are audited with `npm audit`, Python projects with
`pip-audit` on every version in their `uv.lock` / `poetry.lock`. Every verdict is listed in
[benchmarks/RESULTS.md](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/RESULTS.md).

| Project | Scanner | Alerts | Filtered by 0.27 | Filtered now | Filtered by 0.27, kept now |
|---|---|---:|---:|---:|---:|
| [mealie-recipes/mealie](https://github.com/mealie-recipes/mealie) | pip-audit | 229 | 200 | 31 | 170 |
| [hagopj13/node-express-boilerplate](https://github.com/hagopj13/node-express-boilerplate) | npm audit | 163 | 115 | 29 | 86 |
| [gothinkster/node-express-realworld-example-app](https://github.com/gothinkster/node-express-realworld-example-app) | npm audit | 95 | 59 | 41 | 18 |
| Express app, 2022 versions | npm audit | 29 | 26 | 8 | 18 |
| [paperless-ngx/paperless-ngx](https://github.com/paperless-ngx/paperless-ngx) | pip-audit | 17 | 17 | 0 | 17 |
| [sahat/hackathon-starter](https://github.com/sahat/hackathon-starter) | npm audit | 2 | 2 | 2 | 0 |
| **Total** | | **535** | **419 (78%)** | **111 (21%)** | **309** |

0.27 dismissed 309 alerts without evidence. It counted any package the app didn't import
itself as unreachable, which is true of nearly every transitive package, and it compared
Python distribution names literally, so `Django`, `PyYAML` or `llama-index-core` never matched
`import django`, `import yaml` or `import llama_index`.

What depquiet filters now is packages that only development tooling pulls in (jest,
eslint, nx, nodemon, pre-commit, mkdocs). On the npm projects those are the alerts
`npm audit --omit=dev` also removes. The realworld app declares `axios` under `dependencies`
but imports it only from its end-to-end tests; until 0.43 its 33 axios and form-data alerts
were filtered as test-only. They are now kept for review, because depquiet cannot tell that
case from a database driver a library loads at runtime. On these projects nearly every
other production dependency is in use, so the useful output is less the filtering than the trace: each kept
alert names the direct dependency it comes through and where the app uses it.

The same comparison on five larger projects at their head on 2026-11-10 (Kong/insomnia
`8891ce2`, open-webui `b0e6098`, saleor `ea4a69f`, uptime-kuma `fb8ef0f`, wekan `77239ee`;
188 npm alerts) gives the same picture: depquiet
filters the 85 alerts `npm audit --omit=dev` drops, row for row, and nothing else. On npm,
expect depquiet to match `--omit=dev` and explain the rest, not to beat it. Python is
different, because `pip-audit` has no equivalent switch. On 17 projects with a `uv.lock`,
at their head on 2026-11-11, `pip-audit` reported 1,004 alerts and depquiet filtered 72 as
development-only:

| Project | pip-audit alerts | Development-only, filtered |
|---|---:|---:|
| zulip | 43 | 26 |
| saleor | 16 | 14 |
| langflow | 70 | 11 |
| mlflow | 17 | 10 |
| PostHog | 255 | 8 |
| llama_index, open-webui, pydantic-ai | 188 | 3 |
| nine others (Chainlit, crewAI, litellm, ...) | 415 | 0 |

Each verdict was checked against a separate walk of the project's `uv.lock`, with the
dependency groups of every project read by hand to decide which are tooling: none of the 72
packages is reachable from a production dependency, an extra or a non-tooling group. The
same walk finds 21 more development-only alerts that depquiet keeps, most of them in
llama_index, whose integration packages each declare their own dependencies.

That hand reading matters. A dependency group is only a named list: zulip keeps everything
its servers run in a group called `prod`, and PostHog keeps optional features in groups
such as `sentiment`. depquiet treats a group as development-only when its name says so
(`dev`, `test`, `docs`, `lint`...) and as production otherwise; up to 0.33.1 it treated
every group as development-only and filtered all 43 zulip alerts, 17 of them wrongly.

Nothing else was filtered: every one of these projects has a dynamic import somewhere,
which keeps the unused-dependency filter off.

If your project is on uv, uv 0.13 ships `uv audit` (still experimental), and
`uv audit --no-dev` excludes the development group natively. depquiet reads `uv audit`
output too: `depquiet --scanner uv`, or automatically when uv is installed and pip-audit is
not. What it adds on top is the rest of the triage: every group judged by its name rather
than only `dev`, the direct dependency that brings each alert in, EPSS, and npm or pnpm
dependencies in the same run.

Run them yourself: `python -I benchmarks/run_benchmark.py`. The first run clones the pinned
commits into `benchmarks/.cache/`; `benchmarks/capture_real.py` re-captures the audits. The
synthetic fixtures in the same report are parser regression tests, not evidence.

## Compared to

depquiet ingests reports from npm audit, pip-audit, Trivy, Grype, Dependabot,
Snyk and SARIF-producing tools. It adds dependency/import context, configurable
priorities and decision history, and can query OSV directly from lockfiles.

The alert-reduction figures above describe captured scans; they do not establish
false-positive rates or superiority over another scanner. The new
[reference evaluator](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/reference/README.md) checks labelled cases,
including missing findings and unsafe dismissals. Two explicitly synthetic
contract examples exercise its mechanics:

```bash
python benchmarks/reference/run.py --output synthetic-scan.json
python benchmarks/evaluate.py --labels benchmarks/reference/synthetic.labels.json --scan synthetic-scan.json --snapshot benchmarks/reference/synthetic.snapshot.json --json
```

The separate [upstream reference set](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/reference/real/README.md) contains
10 selected advisory contexts from four pinned npm/Python projects, with frozen
audits, source hashes and review evidence. CI checks that five `retain` and five
`unknown` cases remain visible. Labels are agent-reviewed; human review is pending.

A separate [configuration extension](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/reference/extensions/README.md)
adds two identities from the same pinned RealWorld project, preserving the original
inputs. The combined deliberate sample has 12 contexts: six `retain`, six
`unknown`, no `filter` labels and no human adjudications. It does not measure safe
noise reduction.

The [review workflow](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/reference-reviews.md) prepares pending records, binds
them to exact label/snapshot/case identities and reports caller-declared human,
external and agent coverage separately. Disagreements remain uncertain; a human
`filter` record cannot weaken a proposed `retain` or `unknown`. Optional coverage
gates require explicit records without treating metadata as authenticated review.
There are no real `filter` labels, so this set does not measure safe dismissal,
full-project coverage or real-world accuracy. Replay requires no upstream code
execution or package installation.

## License

MIT

## Contributing

depquiet is designed to grow through community templates. Every template you contribute adds context that helps developers decide on an alert faster.

See [CONTRIBUTING.md](https://github.com/samuelrojas-dev/depquiet/blob/main/CONTRIBUTING.md) for guidelines.
