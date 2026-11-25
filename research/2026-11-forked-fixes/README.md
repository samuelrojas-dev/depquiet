# Fixes that fit without changing requires-python

The [Python floor study](../2026-11-python-floor/) found 98 projects among the top 1000 uv
projects that lock at least one vulnerable package whose fix needs a newer Python than the
project supports. This study reruns all 98 with depquiet 0.58.0, which asks uv for such a fix
by name (`uv lock --upgrade-package soupsieve`) and keeps the result when uv locks one release
per Python range: the fixed release on the Pythons that can install it, the newest release that
installs on the older ones, `requires-python` unchanged, and no other package moved back.

That is the change the FinanceDatabase maintainer asked for in review instead of a higher floor,
and merged ([JerBouma/FinanceDatabase#269](https://github.com/JerBouma/FinanceDatabase/pull/269)).

> **Correction (23 November 2026).** The first version of this page said the 32 fixes close
> 460 alerts on newer Pythons and 159 on older ones. 14 of those 32 move the older Pythons to a
> release with advisories of its own that the locked release did not have (filelock 4.1.0,
> pillow 12.3.0 over pillow 10.4 or 11.3), so they trade old alerts for new ones there. depquiet
> 0.58.0 counted only the alerts a release closes, not the ones it brings. Without those 14:
> **18 fixes in 17 projects, closing 116 alerts on newer Pythons and 61 on older ones.** depquiet
> 0.58.1 checks each new release with pip-audit and no longer proposes the other 14
> (`advisory_check.csv`).

## Results

Run on 23 November 2026 (02:03–04:54 UTC), at each project's default branch HEAD (the commit
is in `forked_fixes.csv` and in each `out/*.json`).

| Outcome | Projects |
|---|---|
| At least one fix by Python range (17 with a clean one, see the correction) | 24 |
| Other fixes only (none by Python range) | 25 |
| No fix fits: every fix needs a newer Python | 8 |
| Not checked: uv could not build the project from the files fetched | 19 |
| depquiet printed no fix plan (the reason was not recorded) | 12 |
| No `uv.lock` at HEAD any more, or the fetch failed | 10 |
| **Total** | **98** |

In the 24 projects, depquiet 0.58.0 found 32 fixes by Python range: soupsieve 17, filelock 9,
pillow 5, tornado 1. The 18 soupsieve and tornado fixes are clean: in 17 projects they close
**116 alerts on the newer Pythons** and **61 on the older ones**, and neither copy has an
advisory the locked release did not have. The 9 filelock and 5 pillow fixes close alerts on
newer Pythons too, but the copy they leave for older Pythons has new advisories (up to 15, for
filelock 4.1.0 over 3.19.1 or 3.20); 0.58.1 does not propose them.

Typical rows (all in `forked_fixes.csv`):

| Project | Package | Newer Pythons get | Older Pythons keep | Alerts closed (newer / older) |
|---|---|---|---|---|
| zylon-ai/private-gpt | soupsieve | 4.1.3 (Python 3.11.5+) | 2.10 | 8 / 5 |
| camel-ai/camel | tornado | 6.6.1 (Python 3.11+) | 6.5.10 | 10 / 6 |
| datalab-to/marker | pillow | 13.0.0 (Python 3.11+) | 12.3.0, with 6 advisories 10.4.0 did not have | not clean |
| tirth8205/code-review-graph | filelock | 4.3.0 (Python 3.11+) | 4.1.0, with 6 advisories 3.32.2 did not have | not clean |

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

## Second pass: the 19 projects that were not checked

Rerun on 25 November 2026 (00:08–00:46 UTC) with depquiet 0.58.1, a full shallow clone of each
project, and `SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0` so builds that take their version from git
tags work without the tags (`run_full.sh`, `repos19.txt`, `out_full/`, `log_full.txt`).

- **3 more fixes by Python range, all clean** (pip-audit finds no advisory on either copy that
  the locked release did not have): soupsieve in kornia/kornia and pydantic/pydantic (4.1.3 on
  newer Pythons, 2.10 on older), tornado in spotify/luigi (6.6.1 on Python 3.11+, 6.5.10 on
  older). Together they close 27 alerts on newer Pythons and 17 on older ones.
- **3 plans pin soupsieve 4.0.0 and give older Pythons beautifulsoup4 4.6.3 (2018)**: prefect,
  streamlink, infinigen. depquiet flags the older beautifulsoup4 and says that raising
  `requires-python` to 3.11.5 avoids it. Why: their locks already fork soupsieve (2.10 below
  Python 3.11.5; above it, 4.1.3 in prefect, 4.1 in streamlink, 3.0.4 in infinigen), and the
  plan pinned 4.0.0 because of the alerts on the 2.10 copy. In prefect and streamlink that moves
  the newer copy back; `uv lock --dry-run` on prefect confirmed it (`soupsieve v2.10, v4.1.3 ->
  v4.0`). That was a bug, fixed after this run: the plan now leaves such a fix out. infinigen's
  newer copy (3.0.4) is below 4.0.0, so the fix does not apply there; it was not rerun.
- 2 runs did not finish because the VM ran out of disk (crewAI, OpenViking), 1 still could not be
  built (data-juicer), and the rest found other fixes or none.

With both passes: **21 clean fixes by Python range in 20 projects, closing 143 alerts on newer
Pythons and 78 on older ones**, `requires-python` unchanged.

## Files

- `repos.txt`: the 98 projects, from `../2026-11-python-floor/blocked_copies_top1000.csv`.
- `run.sh`, `wrap.py`: the run. Each project is fetched with only `uv.lock`, `uv.toml` and its
  `pyproject.toml` files, then `depquiet --path . --fix-plan --json`. Run it in a disposable
  VM: `uv lock` can run a project's build hooks.
- `out/*.json`: the fix plan of each project, as depquiet printed it, with the commit.
- `log.txt`: the run log (times in UTC).
- `check_advisories.py`: asks pip-audit for the advisories of each fix's locked, older and newer
  release, and writes `advisory_check.csv` (run on 23 November 2026; needs network).
- `run_full.sh`, `repos19.txt`, `out_full/`, `log_full.txt`: the second pass.
- `summarize.py`: rebuilds the counts above and `forked_fixes.csv` from `out/` and
  `advisory_check.csv`.
