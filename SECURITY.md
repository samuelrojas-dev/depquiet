# Security Policy

## Supported versions

depquiet is pre-1.0. Security fixes go into the latest 0.x release only, so upgrade to the
newest version before reporting.

## Reporting a vulnerability

Please report it privately. **Do not open a public issue.**

Email **sarojas123@icloud.com** with:

1. a description of the vulnerability
2. steps to reproduce
3. the potential impact
4. a suggested fix, if you have one

You will receive an acknowledgment within 48 hours and a detailed response within
5 business days.

A missed vulnerability (an alert depquiet filters that it should have kept) is a security
bug too. Those can be reported in a public issue with a minimal reproduction.

## What depquiet runs

Reading the project is text only: manifests, lockfiles and source files are parsed, never
imported or executed. Some modes do start other programs, and some of those can run code
from the project or its dependencies:

| Mode | Runs | Can run project or dependency code? |
|---|---|---|
| Scan of a uv/poetry lockfile or pinned requirements | `pip-audit --no-deps --disable-pip` on the pins | No |
| Scan of unpinned requirements | `pip-audit -r`, which resolves them in a temporary environment | Yes: building an sdist runs its build code |
| Scan of a `pyproject.toml` with no lockfile | `pip-audit <project>`, which builds and installs the project | Yes: the project's build backend |
| npm scan | `npm audit --json` | No |
| `--check-fixes`, `--fix-plan` | `uv lock --dry-run` (on a temporary copy for `--fix-plan`) | Yes: uv can run build hooks |
| `--fix` | `uv lock --upgrade-package`, or `npm install pkg@version` | Yes: npm runs install scripts |

Run those modes on code you trust, as you would `pip install` or `npm install`. In CI,
treat a pull request from a fork accordingly. `--stdin` and `--from-sbom` read a report you
produced and start no scanner.

## What depquiet sends over the network

Only package names, versions and advisory or CVE ids, never source code. `--offline` turns
off every request depquiet makes itself:

| Endpoint | When | What is sent |
|---|---|---|
| `api.first.org` (EPSS) | by default | CVE ids |
| `www.cisa.gov` (KEV catalog) | `--kev` | nothing (the catalog is downloaded) |
| `api.osv.dev` | lockfiles that depquiet looks up itself | package names and versions |
| `pypi.org` | `--license` | package names and versions |

The scanners depquiet starts (pip-audit, npm, uv, Trivy) reach their own registries and
advisory databases.

## Trusted inputs

depquiet obeys the files in the project it scans: `.depquiet.yaml`, `.depquiet-ignore`,
`.depquiet-policy.yaml`, and any template directory they name. A custom template without
conditions, an ignore entry or a policy rule can dismiss any alert. That is their purpose.
A change to those files can therefore hide an alert from CI, so review it like code (a
`CODEOWNERS` entry for them is a good idea). An unreadable rule is skipped with a warning,
never widened, and an expired or unreadable ignore date counts as expired.

The built-in templates never dismiss on their own: they add a note to an alert kept for
review. Audit JSON is parsed with the standard library `json` module, with no `eval` or
dynamic execution.

## Dependencies

depquiet has **no runtime dependencies** beyond the Python standard library. Its release
workflow publishes to PyPI with Trusted Publishing (no stored token). The Action
(`action.yml`) and the release workflow pin third-party actions to commit SHAs, kept up to
date by Dependabot.
