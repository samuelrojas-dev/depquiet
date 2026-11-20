# Alerts no upgrade can close: the Python floor in popular uv projects

Snapshot of **20 November 2026**. Question: in popular Python projects, how many open
vulnerability alerts cannot be closed by any upgrade, because every fixed release needs a
newer Python than the project still supports?

## Results

| | |
|---|---|
| Popular active Python repos checked | 300 |
| With a `uv.lock` at the root | 94 |
| Analysed (lock audited, lowest supported Python known) | 92 |
| With at least one alert depquiet marks *action* | 70 |
| **With a vulnerable package no fixed release reaches on their lowest Python** | **40 of 70 (57%)** |
| Vulnerable locked copies (repo, package, version) | 831 |
| Of those, blocked by the Python floor | 100 (12%) |
| *Action* alerts | 6,221 |
| Of those, blocked by the Python floor | 1,258 (20%) |

Blocked copies by package: soupsieve 32, filelock 25, pillow 22, dnspython 9, tornado 8,
unstructured 3, vllm 1. For these advisories every fixed release of pillow, filelock,
dnspython and tornado needs Python 3.11, and every fixed soupsieve release (3.0.2 and up)
needs **3.11.5**.

**The 3.11.5 trap.** 30 projects lock a vulnerable soupsieve that no fix reaches on their
lowest Python. **13 of them already require Python 3.11** and are still blocked, because
3.11.0 to 3.11.4 stay supported: manim, prefect, skyvern, airflow, graphrag, mlflow,
serena, pydantic, python-telegram-bot, spotify-downloader, hindsight, wagtail, private-gpt.
For those, `requires-python >=3.11` is not enough; `>=3.11.5` is.

Per-copy data: [`blocked_copies.csv`](blocked_copies.csv).

## Method

1. The 300 most-starred Python repos with more than 1,000 stars, pushed since 1 November
   2026 and not archived (GitHub search), and those with a `uv.lock` on the default branch.
2. `depquiet --offline --json` on each lock. It audits the locked versions with pip-audit
   (OSV/PyPI advisories) without resolving or installing anything, and sorts alerts into
   action, review and filtered (dev-only and similar). Only *action* alerts count above.
3. For each alert with a fix version, PyPI's `requires_python` for every stable release at or
   above it. An alert is **blocked by the Python floor** when none of those releases
   installs on the project's lowest supported Python (the `>=` bound of the lock's
   `requires-python`, or the pinned version for `==3.12.*`-style projects).

Reproduce: `collect.sh`, then `analyze.py` and `summarize.py` (all read-only).

## Limits

- Advisories come from pip-audit, not from GitHub's Dependabot; the two databases mostly
  agree but are not identical.
- "Blocked" is read from PyPI metadata, not from a resolver run: a project can still close
  such an alert with an environment marker, by vendoring, or by dropping the dependency.
  For the project's other Pythons the fix may already be locked (a forked lock); the alert
  stays open because the old copy still serves the oldest Pythons.
- Counting alerts weighs heavily toward packages with many advisories (pillow); the
  per-copy figures are the fairer measure.
- One snapshot of default branches on one day.
- This is a measurement, not a criticism of any project: supporting older Pythons is a
  legitimate choice. The point is that no upgrade tool can close these alerts without
  someone deciding to drop those Pythons.

## Why it matters for depquiet

This is the case `depquiet --fix-plan --raise-python-floor` (uv and Poetry) and the MCP
`plan_fixes` tool are built for: they find the exact floor, check it with the project's own
resolver, and say which Pythons it drops.
