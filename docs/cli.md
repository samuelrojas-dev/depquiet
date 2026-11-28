# Command-line reference

Every command and flag outside the fix plan, which has its own page: [Fix plans](fix-plans.md).

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

# SARIF input from a dependency scanner
trivy fs --format sarif . | depquiet --stdin
grype dir:. -o sarif | depquiet --stdin

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

# Fix the ACTION alerts: in uv, Poetry and npm projects this applies the
# verified fix plan (the same as --fix-plan --apply)
depquiet --fix

# See the plan --fix would apply, without changing anything
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

## License compliance (`--license`)

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

## Suppression file (`.depquiet-ignore`)

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

## Scan comparison (`depquiet diff`)

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

## GitHub PR comments

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

## Config scaffolder (`depquiet init`)

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

## Verdict explainer (`depquiet explain`)

Understand exactly why a CVE received its verdict. Every contributing signal — EPSS score, reachability, dependency type, community template, KEV status, ignore rules — is laid out step-by-step so developers and security teams can audit triage decisions.

```bash
# Explain a CVE from a previous scan (saved with --json)
depquiet explain GHSA-9wv6-86v2-598j --from-json scan.json

# Machine-readable output
depquiet explain GHSA-9wv6-86v2-598j --from-json scan.json --json

# Live scan and explain
depquiet explain GHSA-9wv6-86v2-598j --path ./my-project
```

Look an alert up by its own id or by any alias: `depquiet explain CVE-2024-35195` finds
the alert pip-audit reports as `PYSEC-2026-1873`. KEV reads "not listed" only when the
scan checked KEV (`--kev`, `--kev-file` or the config); otherwise it reads "not checked".

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
  · CISA KEV: not checked — The scan ran without --kev
```

(The [real Express benchmark](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/RESULTS.md), scanned with `--offline`, so no EPSS.)

## Scan statistics (`depquiet stats`)

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

## CISA KEV integration (`--kev`)

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
`npm audit` gives no CVE at all, so depquiet looks it up on OSV.dev; an advisory whose CVE
cannot be found is reported as not checked, never as clean.
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

## HTML report (`--html`)

Generate a self-contained interactive HTML report — zero external dependencies, all CSS and JS inline, ready to share via email, Slack, or upload as a CI artifact.

```bash
depquiet --html report.html
```

The report includes a severity donut chart, collapsible sections (review auto-collapses when >5 findings, filtered always starts collapsed), dark mode support, and client-side text search. All data is embedded as JSON for future extensibility. XSS-safe: user-controlled values are escaped in both HTML and embedded JSON contexts.

## PR annotations (`--annotations`)

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

## Accepted baselines (`--baseline`)

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

## Configurable CI gate (`--fail-on`)

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
