# Fixes that fit without changing requires-python

The [Python floor study](../2026-11-python-floor/) found 98 projects among the top 1000 uv
projects that lock at least one vulnerable package whose fix needs a newer Python than the
project supports. This study reruns all 98 with depquiet 0.58.0, which asks uv for such a fix
by name (`uv lock --upgrade-package soupsieve`) and keeps the result when uv locks one release
per Python range: the fixed release on the Pythons that can install it, the newest release that
installs on the older ones, `requires-python` unchanged, and no other package moved back.

That is the change the FinanceDatabase maintainer asked for in review instead of a higher floor,
and merged ([JerBouma/FinanceDatabase#269](https://github.com/JerBouma/FinanceDatabase/pull/269)).

## Results

Run on 23 November 2026 (02:03–04:54 UTC), at each project's default branch HEAD (the commit
is in `forked_fixes.csv` and in each `out/*.json`).

| Outcome | Projects |
|---|---|
| At least one fix by Python range | 24 |
| Other fixes only (none by Python range) | 25 |
| No fix fits: every fix needs a newer Python | 8 |
| Not checked: uv could not build the project from the files fetched | 19 |
| depquiet printed no fix plan (the reason was not recorded) | 12 |
| No `uv.lock` at HEAD any more, or the fetch failed | 10 |
| **Total** | **98** |

In the 24 projects, depquiet found **32 fixes by Python range**: soupsieve 17, filelock 9,
pillow 5, tornado 1. Together they close **460 alerts on the newer Pythons** of those projects.
On the older Pythons, the copy that stays behind moves forward too and closes **159** of those
alerts there (in 31 of the 32 fixes; in pwndbg's filelock it closes none).

Typical rows (all in `forked_fixes.csv`):

| Project | Package | Newer Pythons get | Older Pythons keep | Alerts closed (newer / older) |
|---|---|---|---|---|
| datalab-to/marker | pillow | 13.0.0 (Python 3.11+) | 12.3.0 | 53 / 17 |
| zylon-ai/private-gpt | soupsieve | 4.1.3 (Python 3.11.5+) | 2.10 | 8 / 5 |
| camel-ai/camel | tornado | 6.6.1 (Python 3.11+) | 6.5.10 | 10 / 6 |
| tirth8205/code-review-graph | filelock | 4.3.0 (Python 3.11+) | 4.1.0 | 12 / 1 |

## What this does and does not show

- **Verified with uv's resolver only.** depquiet runs `uv lock --dry-run` on a copy of the
  project. Nobody ran these projects' tests. A major version change (pillow 13, soupsieve 4)
  can break code.
- **Scanners still see the older copy.** The lock keeps a vulnerable release for the oldest
  Pythons, and a scanner that reads the lock, like pip-audit, still reports the alerts that
  copy has. The fix protects whoever runs the project on a newer Python.
- **19 projects were not really checked.** The run fetches only `uv.lock`, `uv.toml` and the
  `pyproject.toml` files, to fit in a small VM. When a project's build needs more than that
  (a README, its sources, a version from git), uv cannot lock it and depquiet reports the fixes
  as "could not be checked". A full clone would be needed for those 19.
- **"Every fix needs a newer Python" is not "nothing can be done".** In 8 projects no release
  with a fix moves the oldest Pythons forward. uv could still lock the fix for the newer Pythons
  and leave the older copy as it is. depquiet 0.58.0 does not propose that, because the lock
  would close no alert for a scanner; raising `requires-python` (`--raise-python-floor`) is the
  other way.
- **Only the projects of the floor study.** These 98 projects were chosen because they had a
  fix blocked by Python. This says nothing about uv projects in general.

## Files

- `repos.txt`: the 98 projects, from `../2026-11-python-floor/blocked_copies_top1000.csv`.
- `run.sh`, `wrap.py`: the run. Each project is fetched with only `uv.lock`, `uv.toml` and its
  `pyproject.toml` files, then `depquiet --path . --fix-plan --json`. Run it in a disposable
  VM: `uv lock` can run a project's build hooks.
- `out/*.json`: the fix plan of each project, as depquiet printed it, with the commit.
- `log.txt`: the run log (times in UTC).
- `summarize.py`: rebuilds the counts above and `forked_fixes.csv` from `out/`.
