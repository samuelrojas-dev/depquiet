# CI integration

The GitHub Action, exit codes and manual CI setup.

**Alerts without a severity.** pip-audit and uv audit report no severity, so their
alerts show `unknown` (`"severity": "unknown", "severity_known": false` in `--json`;
`unknown` in SARIF properties, SBOM ratings, the summary and HTML report).
`--fail-on high` or `critical` counts those as meeting the threshold and says so on
stderr: a placeholder must never let a critical advisory through. For the same reason,
an ACTION alert without a severity is a SARIF `error` and a GitHub annotation `failure`. Use `--fail-on none`
to never fail, or a scanner that reports severity (npm audit, Grype, OSV.dev, an SBOM
with ratings) to gate on it.

## Exit codes

- `0` — No ACTION items at or above the `--fail-on` threshold (safe to pass)
- `1` — ACTION items found at or above the threshold (fail the build)
- `2` — Nothing was scanned: no supported manifest or lockfile, a lockfile that needs
  OSV.dev while `--offline` is set, or an input that cannot be read (`--stdin`,
  `--from-sbom`, `--kev-file`, `--baseline`). depquiet never reports an unscanned project
  as clean.

## GitHub Actions (Marketplace)

```yaml
- name: Triage vulnerabilities
  uses: samuelrojas-dev/depquiet@v0
  with:
    sarif: results.sarif
    policy: .depquiet-policy.yaml
    sbom: sbom.cdx.json
```

The action installs the depquiet version of the tag you reference, plus pip-audit for Python projects (`install-pip-audit: false` to skip; uv and Poetry when `check-fixes` or `fix-pr` need them, all three at pinned versions: pip-audit 2.10.1, uv 0.13.8, Poetry 2.5.1, unless the runner already has uv or Poetry), runs it, uploads SARIF to GitHub Code Scanning, uploads the SBOM as a build artifact, and fails the build if ACTION items are found. A repository with npm and Python dependencies is scanned for both; `scanner: uv` (or `npm`, `pnpm`, `pip`) limits it to one.

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

**Action inputs:** `path`, `scanner`, `epss-threshold`, `offline`, `sarif`, `templates`, `policy`, `sbom`, `sbom-format`, `from-sbom`, `ignore`, `license`, `baseline`, `kev`, `kev-file`, `html`, `annotations`, `vex`, `diff-base`, `pr-comment`, `check-fixes`, `fail-on-action`, `fail-on`, `python-version`, `install-pip-audit`, `fix-pr`, `fix-pr-branch`, `fix-pr-token`.

**Action outputs:** `total`, `action`, `review`, `filtered` (alert counts), `sarif-file` and
`sbom-file` (paths, when generated), `diff-new` and `diff-fixed` (when `diff-base` is set),
`fix-pr-url` (when `fix-pr` opened or updated a pull request).

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

## GitHub Actions (manual)

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
