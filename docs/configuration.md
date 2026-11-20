# Configuration and policy engine

`.depquiet.yaml` and the policy engine.

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

An alert whose scanner states no severity (pip-audit, uv audit, or `"Severity": "UNKNOWN"`
from Trivy or Grype) never matches a `severity` condition: depquiet does not guess one, so a
rule that dismisses `moderate` alerts cannot dismiss alerts of unknown severity.

A rule with an unknown key (`severty:`), an unknown severity or an EPSS bound that is not a
number between 0 and 1 is skipped with a warning: dropping just that condition would widen the
rule to every finding. A trailing `# comment` on a line is ignored.

### Actions

| Action | Aliases | Effect |
|--------|---------|--------|
| `action` | `block` | Escalate to ACTION REQUIRED |
| `review` | | Mark for review |
| `filter` | `filtered`, `dismiss`, `ignore` | Filter out |
