# What holds back security fixes in popular Python projects (November 2026)

We went looking for the packages that block security fixes across popular uv projects: a
"Blocker Index". The biggest blocker turned out not to be a package at all. It was each
project's own `requires-python`.

## Results

Sample: the 120 most-starred GitHub repositories with a `uv.lock` (from the 2026-11-20 top-1000
snapshot in [`../2026-11-python-floor`](../2026-11-python-floor)). depquiet scanned each lock,
then built and verified a fix plan with uv. 115 were scanned: 4 have a `uv.lock` with no
packages in it, and 1 could not be cloned. 94 have alerts that need action, **8,007 advisories**
in all (each advisory counted once per package per repository; deprioritized alerts left out).

| Where each advisory ends up | Advisories | Share | Repos |
|---|---:|---:|---:|
| Fixed by the verified plan | 4,623 | 57.7% | 70 |
| Needs a newer Python than `requires-python` allows | 991 | 12.4% | 26 |
| Held back by another package that no release of lets the fix in | 275 | 3.4% | 15 |
| Only an older release of a direct dependency allows it | 137 | 1.7% | 6 |
| Left out for other reasons (fixes that conflict, resolutions that fail on one platform, builds that need a GPU toolchain) | 918 | 11.5% | 42 |
| uv cannot lock the project as it is, so no plan | 768 | 9.6% | 3 |
| JavaScript side of a mixed repository (pnpm), not planned | 237 | 3.0% | 4 |
| No fixed version reported | 58 | 0.7% | 28 |

**The Python floor holds back 2.4 times more advisories (991) than every other package combined
(412).** It is also the easiest one to see past: depquiet verifies whether raising
`requires-python`, or for a library `[tool.uv] environments`, lets each fix in.

### The packages that hold fixes back

29 packages hold back at least one fix. Most of them do it in a single project. The ones that do
it in more than one:

| Holds back | Repos | Fixes held | Advisories | Kind |
|---|---:|---|---:|---|
| crawl4ai | 2 | pillow, lxml | 107 | no release allows it |
| tensordict | 2 | virtualenv | 32 | only an older release allows it |
| vllm | 2 | setuptools | 4 | no release allows it |
| daphne | 2 | autobahn | 2 | no release allows it |

The full list is in [`blocker_index.csv`](blocker_index.csv), and every held fix with uv's own
explanation in [`blocked_fixes.csv`](blocked_fixes.csv).

The packages whose fixes are held back most often, by different blockers in different projects:
**pillow** (4 repositories: airflow, camel, owl, private-gpt), then **setuptools**,
**opentelemetry-api**, **wcmatch** and **virtualenv** (3 each).

### What this means

- A security fix in a popular Python project is far more often stuck on the project's own Python
  floor than on a dependency. Dependabot does not say so: it reports "cannot update to a
  non-vulnerable version" and leaves the alert open.
- When a dependency is the blocker, it is usually one package in one project, not a single
  package blocking the ecosystem. The useful thing is to name it in that project: depquiet's
  dashboard issue does ("semgrep holds back mcp, opentelemetry-api, wcmatch: no release of
  semgrep lets these fixes in yet").
- 58% of what needs action is fixable today with a change uv verifies, without raising
  `requires-python` and without moving a direct dependency back.

## Method

1. `depquiet --path <clone> --fix-plan - --json` on a shallow clone of the default branch
   (2026-11-27). depquiet scans `uv.lock` with pip-audit (OSV.dev as fallback), checks each fix
   with uv, and verifies the fixes together on a copy of the project.
2. [`breakdown.py`](breakdown.py) puts every advisory that needs action in one outcome, by its
   package's place in the plan, in this order: fixed, needs a newer Python, only an older direct
   dependency allows it, held back by another package, no fixed version, other.
3. [`aggregate.py`](aggregate.py) counts the blockers. A fix that a higher `requires-python`
   lets in is not credited to a package, even when a first attempt named one.

Versions: 91 repositories ran on depquiet `main` at the 0.60.1 changes; the 29 below ran on
depquiet 0.60.2 from PyPI. 0.60.2 only adds the rule `aggregate.py` already applies.

### Two runs, and why

The first run's machine could not reach package indexes outside PyPI (download.pytorch.org,
Microsoft's feed, mirrors) or OSV.dev, so 29 repositories, mostly machine-learning projects, came
back incomplete. Publishing those numbers would have overcounted "could not be checked". All 29
ran again on GitHub Actions runners, which have no such limit
([`rerun.txt`](rerun.txt); the workflows are in
[depquiet-floor-test](https://github.com/samuelrojas-dev/depquiet-floor-test/tree/main/.github/workflows)).
After the rerun, no advisory is left as "could not be checked" over a fetch error.

## Limits

- One snapshot of one branch per project. Locks change every day.
- Alerts are depquiet's scan of the lockfile (pip-audit, OSV.dev), not GitHub's Security tab.
  Counts can differ a little.
- "No release allows it" means uv found no release of the blocker that lets the fix in, at the
  time of the run.
- The 3 projects uv could not lock: DB-GPT (`tool.uv.default-groups` names a group that does not
  exist: 604 advisories), deepwiki-open (no `pyproject.toml` next to the lock) and openpilot (a
  path dependency lives in a git submodule, which the shallow clone did not fetch: a limit of this
  study, not of the project).
- textual, claude-seo, hermes-webui and DeepCode have a `uv.lock` with no packages: not counted.
  On textual, depquiet's OSV.dev fallback over `poetry.lock` also stopped at one advisory whose
  severity it could not read; that should skip the advisory, not end the scan, and is being fixed.

## Files

| File | What |
|---|---|
| `repos.txt` | The 120 repositories and branches |
| `rerun.txt` | The 29 re-run on GitHub Actions |
| `results.tar.gz` | Every repository's result, trimmed to what the scripts read (130 KB) |
| `breakdown.py`, `breakdown.txt` | Where each advisory ends up |
| `aggregate.py`, `blocker_index.csv`, `blocked_fixes.csv`, `summary.json` | The blockers |
| `vm_rerun.sh` | The same rerun as a script, for any Linux machine |

To reproduce from the results: `tar xzf results.tar.gz && python3 breakdown.py slim && python3
aggregate.py slim .`
