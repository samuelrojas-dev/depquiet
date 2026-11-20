# How triage works

How depquiet decides between ACTION, REVIEW and FILTERED. The short version, and the rules it never breaks, are in the README's [Conservative by design](https://github.com/samuelrojas-dev/depquiet/blob/main/README.md#conservative-by-design).

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
| **EPSS scoring** | Off by default: EPSS only orders the report (known exploited first, then highest EPSS). With `--epss-threshold`, alerts scoring below it are filtered. EPSS is keyed by CVE id: pip-audit and uv audit give it as an alias, and for `npm audit`, which reports only GitHub advisory ids, depquiet looks the CVE up on OSV.dev (cached) |
| **Community templates** | A built-in template never dismisses on its own: when it matches, its note is added to the review. Custom templates without conditions, `.depquiet-ignore` and policy rules are your explicit dismissals |

**Bundled frontends:** like `npm audit --omit=dev`, depquiet treats `devDependencies` as
development-only. If your bundler (Vite, webpack, esbuild) ships a package listed there in
your production JavaScript, move it to `dependencies` or add it to `always_flag`, or depquiet
will filter its alerts.

See [benchmarks](benchmarks.md#triage-on-six-real-projects) for measured results on a real project.

## Workspace and dynamic-import coverage

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

## Reachability analysis in depth

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

## Direct vs. transitive dependencies

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
