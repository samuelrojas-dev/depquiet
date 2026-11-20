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

## Larger samples (same day, later)

The same measurement on two bigger samples, now with Poetry projects too (`poetry.lock`,
Python range from its metadata or `pyproject.toml`). The first sample above is contained in
the top 1,000.

| | Top 1,000 (>500 stars) | 200 to 500 stars |
|---|--:|--:|
| Repos checked (pushed since 20 Oct 2026) | 1,000 | 1,000 |
| With a lock (uv / Poetry) | 266 (244 / 22) | 257 (220 / 37) |
| Analysed | 261 | 255 |
| With at least one *action* alert | 196 | 176 |
| **With a vulnerable package no fixed release reaches on their lowest Python** | **98 (50%)** | **76 (43%)** |
| Vulnerable copies blocked by the Python floor | 256 of 2,272 (11%) | 191 of 1,394 (14%) |
| *Action* alerts blocked by the Python floor | 2,910 of 16,082 (18%) | 2,066 of 10,131 (20%) |
| soupsieve 3.11.5 trap: repos / already requiring 3.11 | 65 / 32 | 31 / 15 |

The share holds as the sample grows: about half of the projects with alerts have at least
one that no upgrade can close without dropping a Python version. In the top 1,000, 10 of the
16 Poetry projects with action alerts are in that group. The second column is reported
apart on purpose: smaller projects include more that are simply less maintained, where an
open alert says less about the Python floor.

Data: [`blocked_copies_top1000.csv`](blocked_copies_top1000.csv),
[`blocked_copies_200_500_stars.csv`](blocked_copies_200_500_stars.csv), and the repo lists
`repos_top1000.txt` and `repos_200_500_stars.txt`.

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

Reproduce: `collect.sh` (its header has the commands for each sample), which runs
`analyze.py` and `summarize.py`. All read-only.

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
