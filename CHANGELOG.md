# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- A first scan groups ACTION alerts by package, with the highest fix: on depquiet-floor-test,
  71 alerts took 170 lines, pillow's 40 of them with two different fix versions. Alerts are
  listed one by one only when `--check-fixes` reports on each fix.
- After a scan with fixable alerts in a uv, Poetry or npm project, the report ends with the next
  step: `depquiet --fix-plan`, which checks one change for all of them and changes nothing
  (`depquiet --fix` applies it).
- `--help` matches what works: `--fix-plan` and `--apply` cover uv, Poetry and npm, and
  `--raise-python-floor` uv and Poetry. The note for other projects no longer says that npm uses
  `--fix`: npm has a verified `--fix-plan`.

### Fixed
- `--fix` applies the verified fix plan in uv, Poetry and npm projects (the same as
  `--fix-plan --apply`). It used to run one upgrade per alert: on depquiet-floor-test it moved
  semgrep, a direct dependency, from 1.187.0 back to 1.136.0 to fix mcp (which brought in a new
  protobuf alert), and moved soupsieve to 4.0.0 and then back to 3.0.2 while reporting the alert
  fixed in 4.0.0 as fixed. Now it is one version per package, checked together, never a direct
  dependency moved back; it says which alerts the plan leaves open, and its exit code counts
  only those. `--fix --dry-run` shows the plan.
- In other projects, `--fix` runs one upgrade per package, to the highest fix its alerts name,
  and reports what it upgraded instead of "Fixed N alerts".
- With `--apply` the plan says "Running:" instead of "Then run:", and the confirmation names
  only what changed ("uv.lock is updated" when no requirement file was edited).
- A `pyproject.toml` (or `uv.toml`) that is a link to a file outside the project no longer
  crashes `--fix-plan` with a traceback. depquiet verifies on a copy of the project, which cannot
  follow that link, so the plan says so and plans nothing. A link inside the project still works.
- An unexpected error prints one plain message, says it is a bug in depquiet and where to report
  it, and exits with code `3` (never `0`). `DEPQUIET_DEBUG=1` shows the traceback.

## [0.60.5] - 2026-11-27

### Fixed
- The plan no longer proposes a fix that carries advisories of its own. An advisory names the
  first release that fixes it, and that release can have advisories published later: on
  LightRAG, the plan moved virtualenv to 21.14.10 and langgraph-sdk to 0.4.4, and a scan of the
  new lock flagged both again (fixed in 21.14.13 and 0.4.6). Each fixed release's advisories are
  now read from PyPI, and the plan moves on to the release that fixes those too, verified with
  the rest. If that later release does not resolve, the advisory's own fix is kept. The plan says
  so: "21.14.10, the advisory's fix, has advisories of its own, fixed in 21.14.13".

## [0.60.4] - 2026-11-27

### Fixed
- A fix is reported as held back by another package, with no release of it allowing the fix,
  only when that package's newest release on PyPI still leaves the fix out. uv failing with the
  blocker loosened only says that no version of it fits with the rest of the project: in camel,
  depquiet said no version of crawl4ai allowed pillow 13.0.0, yet crawl4ai 0.9.6 requires only
  pillow>=10.4, and camel's own `psutil<6` and its `agentops<0.4` were what kept uv on crawl4ai
  0.6.3. Such a fix now says the newest release allows it and gives uv's explanation; when PyPI
  cannot be asked, nothing is claimed. A confirmed blocker names the requirement that caps the
  fix (`semgrep 1.187.0 requires mcp==1.29.0`).

## [0.60.3] - 2026-11-27

### Fixed
- OSV.dev fallback: an advisory whose only severity is a vector depquiet cannot score (CVSS v4)
  is kept with an unknown severity instead of ending the whole scan. Found by the Blocker Index
  study: textual's `poetry.lock` stopped at PYSEC-2026-4320, and every other alert went unreported.

## [0.60.2] - 2026-11-27

### Fixed
- A fix that a higher `requires-python` lets in no longer keeps the package a first attempt
  named as its blocker (`blocked_by`), so the dashboard does not say another package holds it
  back. Real case: crewAI, where filelock was reported as blocked by litellm and wcmatch by e2b,
  while raising `requires-python` to 3.11 lets both in.

## [0.60.1] - 2026-11-27

### Changed
- uv plans leave out a fix that only fits by moving one of the project's own dependencies
  back, and report it as held back by that dependency with the older release that would allow
  it, instead of putting it in the plan with a warning. Real case: on the depquiet-floor-test
  demo, fixing mcp moved semgrep, a direct dependency, from 1.187.0 back to 1.136.0 (and 16
  other packages); now pillow and soupsieve are fixed and mcp is reported as "fits only by
  moving semgrep back from 1.187.0 to 1.136.0". Moving transitive packages back, or giving
  only older Pythons an older copy in a forked lock, still only warns. JSON: `needs_older`.
- Dashboard: a package held back by another one says whether an older release of it allows
  the fix (your call) or none does (only a change upstream unblocks it).

## [0.60.0] - 2026-11-27

### Added
- Dashboard issue (`--dashboard FILE`, Action input `dashboard: "true"`): one issue,
  "depquiet: dependency alerts", that gives every vulnerable package a state and what to do
  about it: fixed in the fix pull request (with its link), held back by another package that
  no release of lets the fix in (grouped by that package: on wagtail, semgrep held back mcp,
  opentelemetry-api and wcmatch, 8 advisories, that nothing in wagtail can fix), needs a change
  in the project (with the verified `requires-python` or `[tool.uv] environments` option), no
  fixed version reported, or deprioritized, which it never dismisses. Updated on every run.
  Built from depquiet's own scan: a workflow's `GITHUB_TOKEN` gets 403 on the Dependabot alerts
  API, with or without `security-events`.
- Fix plans record the packages that hold a fix back when no release of them allows it
  (`blocked_by` in the JSON).
- npm: `fixAvailable: true` (npm audit fix fixes it within the declared ranges) is kept as
  `fix_in_range`, so it is not reported as "no fix". A fix through a parent that would move the
  parent back (npm audit offered wagtail draftail 1.1.0 with 2.0.1 installed) is shown as that,
  not offered.
- uv plans say which fixes Dependabot cannot open, and why: the release needs a newer Python
  than the oldest one `requires-python` allows, which is the Python Dependabot resolves for
  (it ignores `[tool.uv] environments`). The fix pull request gets a "Why Dependabot did not
  open this" section, the terminal a line, the JSON `dependabot_cannot`. Real run on the
  state depquiet-floor-test was in before its fix: "pillow 13.0.0 needs Python >=3.11,
  soupsieve 4.0.0 needs Python >=3.11.5". The Python each release needs comes from PyPI.

## [0.59.2] - 2026-11-27

### Changed
- README: a section near the top shows the pull request Dependabot would not open, on
  depquiet-floor-test (`requires-python = ">=3.10"` with `[tool.uv] environments`): Dependabot
  moved pillow to 12.3.0, still vulnerable, and opened nothing for soupsieve; the `fix-pr`
  Action moved both to fixed releases in `uv.lock` only, and the 64 open alerts went to 0.
  PyPI shows the same README.
- The Action's description, which the GitHub Marketplace shows, now says what it does when
  Dependabot cannot update.

## [0.59.1] - 2026-11-27

### Fixed
- The `[tool.uv] environments` suggestion now says that Dependabot does not read it: Dependabot
  still picks its Python from `requires-python`, so it will not open those updates itself and
  each later fix of that kind needs a manual `uv lock`. A stac-auth-proxy contributor showed it
  with the Dependabot CLI; docs/fix-plans.md has the table.
- When the plan is empty and a higher `requires-python` would help, the terminal no longer says
  "--raise-python-floor" twice: the Python floor section already says it.

### Changed
- The `[tool.uv] environments` suggestion adds that the `fix-pr` Action can do the relock
  Dependabot will not. Real run on depquiet-floor-test: 64 open Dependabot alerts, one pull
  request from the Action changing only `uv.lock`, all 64 marked fixed after the merge.

## [0.59.0] - 2026-11-25

### Added
- uv plans: when a higher `requires-python` would unblock fixes, the plan also tries
  `[tool.uv] environments = ["python_full_version >= 'X'"]` on the copy, with `requires-python`
  unchanged. If uv resolves the fixes that way and nothing moves back, the Python floor section
  shows the line to add: the lock (CI, development) gets the fixes and the library's users keep
  installing on older Pythons. That is how wagtail undid the downstream breakage a higher floor
  caused (`python_floor.lock_environment` in the JSON).

### Added
- Python floor: when a fix it would unblock reaches the project only through development
  dependencies, the plan says so, and that for a library a higher floor costs users on older
  Pythons an install to clear alerts in tools they never install. The nmdc-schema maintainer kept
  `requires-python` for exactly that reason (soupsieve came only through the dev group).

### Changed
- uv plans: when a fix is left out because the lock already holds the fixed release for newer
  Pythons, the reason now names the exact `requires-python` that would fix the older copy, read
  from the lock's resolution markers ("Only raising requires-python to >=3.11.5 fixes the older
  copy").

## [0.58.2] - 2026-11-25

### Fixed
- uv plans: when the lock already holds a fixed release for newer Pythons and an older copy
  below (prefect: soupsieve 4.1.3 on 3.11.5+, 2.10 below), the alerts on the older copy made the
  plan pin `soupsieve==4.0.0`. That moved the newer Pythons from 4.1.3 back to 4.0 and gave the
  older ones beautifulsoup4 4.6.3. The plan now leaves such a fix out and says that only a higher
  `requires-python` fixes the older copy.

## [0.58.1] - 2026-11-23

### Fixed
- uv plans: a partial fix, or a fix by Python range, could move the older Pythons to a release
  with advisories the locked release did not have, and the plan counted only the alerts it
  closes. On whisperX, filelock 3.19.1 (4 alerts) became 4.1.0 for Python 3.10, which has 17
  others. The plan now asks pip-audit for each new release's advisories and drops a fix that
  brings any new one. The forked-fixes study is corrected: 18 clean fixes in 17 projects, 116
  alerts closed on newer Pythons, not 32 fixes and 460.

## [0.58.0] - 2026-11-22

### Added
- uv plans: when a fix needs a newer Python than the project's floor, the plan first asks uv
  for the package by name (`uv lock --upgrade-package soupsieve`) and keeps the result when uv
  locks one release per Python range: the full fix on the Pythons that can install it, the
  newest release that installs on the older ones, `requires-python` unchanged. Before, the
  partial fix pinned the older release for every Python. The FinanceDatabase maintainer
  asked for exactly this split in review and merged it (JerBouma/FinanceDatabase#269).
- uv plans: when a pinned fix resolves only by moving another package back (on FinanceDatabase,
  `soupsieve==4.0.0` gave Python 3.11.0–3.11.4 yfinance 0.1.96 from 2022), the plan asks for
  the fix by name and keeps that instead when nothing moves back.

## [0.57.1] - 2026-11-21

### Added
- npm pull request descriptions (`--fix-plan-report`, the Action's `fix-pr`) say what npm
  audit offered instead ("npm audit fix --force would move @tailwindcss/typography back from
  0.5.19 to 0.5.4") and which parent held each package back. The first real fix pull request
  on an npm project (depquiet-npm-fixpr-test #1) showed only the override.

## [0.57.0] - 2026-11-21

### Added
- The Action's `fix-pr` works on npm projects: one pull request with the verified
  `package.json` change (requirements and scoped overrides) and `package-lock.json`. npm
  runs with `--package-lock-only --ignore-scripts`, so no install script runs in the job
  that holds the push token.

## [0.56.3] - 2026-11-21

### Changed
- npm plans no longer include a major upgrade of the project's own dependency. When every
  fixed release is on a newer major line, that copy is left, with the jump named
  ("electron 33.2.1, your own dependency (devDependencies: ^33.2.1): every fixed release is
  on a newer major line (42.11.16 and up)…"). 0.56.2 widened upscayl's electron from
  ^33.2.1 to ^42.11.16. The package's other copies are still fixed.

## [0.56.2] - 2026-11-21

### Fixed
- npm plans: advisories bounded by prereleases (`>=15.0.0-canary.0 <15.5.30`, seen for next,
  electron and semver) made every release look vulnerable, so the plan said "no published
  release … is outside the advisories" and flagged versions no advisory covers (semver
  6.3.2). Prerelease bounds are now read exactly for stable versions.
- npm plans: an existing override of the same package under the same parent is named
  ("your package.json already overrides qs under typed-rest-client to 6.15.3; 6.16.1 is the
  lowest fixed release: raise it there") instead of being rewritten or reported as "npm
  still locks".

## [0.56.1] - 2026-11-21

### Fixed
- npm plans, from the first runs on real projects (OpenHands, nodemon, mathjs, upscayl; npm
  9.2, 2026-11-21):
  - Copies bundled inside another package (`inBundle`, like the minimatch npm 11.10.1 ships)
    are named instead of reported as "npm still locks", and do not block the fix.
  - A copy that `npm update` left vulnerable although its parent's range admits the fix now
    gets an override inside that range.
  - No override across a major version: such a copy is left, with the parent to upgrade
    named, and the package's other copies are still fixed (shown as "it leaves …").
  - The version shown is what the vulnerable copies became: upscayl's yaml 1.10.2 read
    "→ 2.9.1" because an unrelated 2.x copy was in the lock.

## [0.56.0] - 2026-11-21

### Added
- **`--fix-plan` and `--apply` for npm projects** (`package.json` with a `package-lock.json`
  v2 or v3), verified with npm on a temporary copy (`npm update --package-lock-only
  --ignore-scripts`). Round 1 takes what npm can do within semver, including npm audit's own
  fix when it is a plain upgrade of a parent. Round 2 adds an `overrides` entry, scoped to
  the parent that pins a vulnerable copy, for what is still vulnerable, on the fixed
  package's own major line. The plan says when npm audit's only fix is semver-major, and
  when that fix is a downgrade (`npm audit fix --force` would move
  @tailwindcss/typography back from 0.5.19 to 0.5.4). On an own fixture, npm audit went from
  9 vulnerable packages to 0.

### Fixed
- The report grouped by package named the wrong package when npm audit's fix is a version of
  the parent: "postcss-selector-parser … FIX: update to 0.5.4" now reads "FIX: update
  @tailwindcss/typography to 0.5.4".

## [0.55.0] - 2026-11-21

### Fixed
- When no fix resolves, `--check-fixes` and `--fix-plan` check whether the project locks at
  all without upgrades. If it does not, they say so once ("uv cannot lock this project as it
  is, even without upgrades") instead of listing uv's error under every fix as if it were
  about that fix. Found on python-telegram-bot, whose own `all` extra does not resolve on
  its declared Pythons.

## [0.54.0] - 2026-11-21

### Added
- **The fix plan says when a fix fits only by splitting the lock.** uv can fit soupsieve 4.0 on
  `requires-python >=3.11` by giving Python 3.11.0-3.11.4 beautifulsoup4 4.6.3 (2018). The plan
  now finds the split point, checks that raising `requires-python` to it (`>=3.11.5`) keeps one
  beautifulsoup4, and says so; `--raise-python-floor` puts that edit in the plan. Found by
  checking the Python floor study with the resolver.

### Fixed
- A build failure names the package and its last error. uv's hint ("Build failures usually
  indicate a problem with the package or the build environment") named neither, and every fix
  in the plan repeated it. When the package is the project itself or a local path
  dependency, the message says uv needs it to read the project's metadata.

## [0.53.0] - 2026-11-20

### Added
- **Partial fixes on Poetry projects too.** Asked to update a held-back package, Poetry moves
  it to the newest release that installs on the current Python (soupsieve 2.8.3 → 2.10 on
  `>=3.10`); the plan keeps that as a partial fix when it closes at least one alert.

### Fixed
- Versions compare without trailing zeros (`2.10` equals `2.10.0`): Poetry locks soupsieve
  "2.10" while the advisory says "2.10.0", and the partial fix counted one alert too few.

## [0.52.0] - 2026-11-20

### Added
- **Partial fixes on the current Python.** When the full fix needs a newer Python and the
  floor is not raised, the uv plan adds the newest release that installs on the current
  `requires-python`, verified with uv alongside the rest, and says how many of the package's
  alerts it closes (`closes 5 of 8 alerts; the other 3 need Python >=3.11.5`). The pull
  request description lists only the advisories it closes. Found on a test repository where
  Dependabot reported "cannot update" for soupsieve while 2.10 installs on Python 3.10.

## [0.51.1] - 2026-11-20

### Changed
- **The README leads with the fix plan.** It opens with the problem (Dependabot cannot update
  to a non-vulnerable version) and a real before/after of `--fix-plan`, and is 264 lines
  instead of 1,779. Reference material moved verbatim to `docs/` (fix plans, triage, inputs,
  CLI, CI, SBOM and OpenVEX, configuration, templates, benchmarks).
- `depquiet init` links the generated config to `docs/configuration.md`.

## [0.51.0] - 2026-11-19

### Added
- **`--raise-python-floor` works on Poetry projects.** A fix that needs a newer Python was
  left out with "held below by another requirement", which hid the cause: `poetry update`
  on a transitive package resolves and keeps the old version. depquiet now requires the fix
  directly on a copy, reads the Python each release needs from Poetry's error
  (`soupsieve (4.1.1) requires Python >=3.11.5`), and verifies the raised `requires-python`
  with Poetry, as the uv plan does. Without the flag the plan reports the option; with it,
  the diff raises `requires-python`. A `python` constraint in `[tool.poetry.dependencies]`
  is reported, not rewritten.

### Changed
- **The README shows the MCP server in a real agent run**: a 20-second GIF of Claude Code
  planning the fixes for a public uv project, ending at the plan that raises
  `requires-python` to 3.11.5.

## [0.50.2] - 2026-11-19

### Fixed
- **The Python floor plan read uv's hint wrongly in two cases.** uv writes
  `soupsieve==4.0 only supports >=3.11.5` for soupsieve 4.0.0, and the check only matched
  the exact version string, so the 3.11.5 floor was lost: with another fix needing 3.11,
  `--raise-python-floor` raised `requires-python` to 3.11, which leaves soupsieve's alerts
  open. Versions now compare without trailing zeros, and a floor hint that names the
  package limiting a transitive fix counts as the floor that fix needs. Found while an
  agent ran `plan_fixes` on a real project.

### Changed
- **The MCP tools describe every parameter and result field.** Parameters carry
  descriptions in the input schema, results have an output schema (`structuredContent`),
  and the tool descriptions say when to use each tool, what it needs (network; the plan
  runs the resolver) and that neither edits the project.

## [0.50.1] - 2026-11-18

### Added
- **depquiet on the MCP Registry.** `server.json` describes the server for
  registry.modelcontextprotocol.io, run as `uvx --with 'mcp>=2.3,<3' --with pip-audit depquiet
  mcp`; the README carries the `mcp-name:` marker the registry checks, and the release
  workflow publishes the entry after PyPI (GitHub OIDC, `mcp-publisher` pinned by version and
  checksum). New `depquiet mcp` subcommand, the same server as `depquiet-mcp`.

## [0.50.0] - 2026-11-18

### Added
- **An MCP server for coding agents** (`depquiet-mcp`, `pip install 'depquiet[mcp]'`), with two
  read-only tools: `triage_alerts` (the scan, trimmed per alert) and `plan_fixes` (the
  verified fix plan with its diff, lock command and Python floor option). Neither edits the
  project; the agent applies the plan when the user agrees. Checked end to end with the
  official MCP client over stdio on a real uv project with pip-audit.

## [0.49.0] - 2026-11-18

### Added
- An alert whose vulnerable copy uv.lock holds only for older Pythons says so: "only
  installed on Python below 3.11.5; requires-python >=3.11.5 would drop this copy" (`--json`:
  `python_scope`). With `requires-python = ">=3.11"`, uv locks soupsieve 2.10 for
  3.11.0–3.11.4 because every patched soupsieve needs 3.11.5; seen in four public projects
  in November 2026. The verdict does not change: those installs are still exposed.

### Changed
- With `--fix-plan`, the text report groups the alerts by package (the shape of the plan),
  with one summary line for the fix checks instead of three or four lines per alert. A
  known-exploited (KEV) alert is named on its package's line. On a fresh 0.48.0 run with 21
  alerts, 20 of them tornado, the output went from 107 lines to 50, and the plan from line
  79 to line 22. Without `--fix-plan`, every alert is listed as before.
- The Action's name (its GitHub Marketplace title) is now "depquiet — Verified Dependency
  Fix Plans", in line with the README. The `uses: samuelrojas-dev/depquiet@v0` reference
  does not change.

### Fixed
- SARIF paths are relative to the repository root, as GitHub code scanning reads them.
  With `--path` (Action: `path:`) set to a subfolder, alerts pointed at `app.js` instead of
  `sub/folder/app.js`, so GitHub could not link them to the file. The manifest fallback now
  names the manifest the project has (`pyproject.toml` when there is no
  `requirements.txt`). Found on depquiet's own repository, where the Action's smoke test
  opened alerts on `app.js:1` for its test fixture.
- A plan with nothing in it now says that the files asked for were not written
  (`Nothing in the plan yet, so plan.diff and plan.md were not written.`) and, when raising
  requires-python would let fixes in, to run again with `--raise-python-floor`. Found
  following the README on a fresh install of 0.48.0: neither file appeared, and nothing said
  why.

## [0.48.0] - 2026-11-18

### Changed
- The README, the PyPI summary and the Action description now lead with the verified fix
  plan, with the triage second. "What it is not" and "Compared to" say that Dependabot's
  reachability analysis (October 2026 preview, JavaScript/TypeScript, GitHub Enterprise
  Cloud) checks call paths, a deeper verdict than depquiet's package-level one for those
  projects.

### Added
- **The fix plan checks whether raising `requires-python` unblocks the fixes that need a
  newer Python** (uv projects). It raises the floor on the temporary copy, asks uv again,
  and reports how many fixes and alerts that lets through and which Python versions it
  drops. `--raise-python-floor` (Action: `fix-pr-raise-python-floor`) puts the
  `requires-python` edit in the diff, `--apply` and the fix pull request; without it the
  plan only reports the option, because dropping a Python version is the maintainer's
  call. In `--json` as `fix_plan.python_floor`. When the floor the fixes ask for still
  leaves uv splitting the lock just above it, with older packages below the split, the plan
  moves to the exact floor: on a public uv SDK, `>=3.11` gave Python 3.11.0–3.11.4
  beautifulsoup4 4.6.3 (2018), and the plan proposes `>=3.11.5`, which keeps one
  beautifulsoup4 (confirmed on that project in a disposable VM). The split points come from
  the lock uv writes on a temporary copy; up to three are tried, lowest first. Seen on real
  projects where Dependabot fails repeatedly on pytest because the project still declares
  `>=3.9`.
- **`--fix-filtered`** (Action: `fix-pr-include-filtered`): `--check-fixes` and `--fix-plan`
  also cover filtered alerts (development-only, test-only, ...), which Dependabot keeps open
  until the package moves. Off by default. Works for uv and Poetry plans.
- **The fix plan names everything the verified lock moves**, not only the fixes: a parent
  that moves without a requirement change, added packages, and packages nothing requires any
  more. In the text output ("It also changes uv.lock"), the pull request description (`--fix-
  plan-report`, the Action's `fix-pr`) and `--json` (`lock_changes`), for uv and Poetry.
  Found on microbiomedata/nmdc-lakehouse: the plan said "setuptools 81.0.0 → 84.1.0" while
  the lock also moved oaklib 0.7.4 → 0.7.5 and dropped six packages.

### Fixed
- **The fix plan warns when the lock moves a package to an older version.** On a
  public uv SDK, the plan that keeps Python 3.9 showed `jupyterlab 4.5.7 → 2.3.2,`:
  uv's line was `v4.5.7 -> v2.3.2, v4.x` (one copy per Python version), depquiet kept only
  the first version, and nothing said 2.3.2 is a downgrade. Every final version is now
  shown, downgrades are marked ⚠ and listed first, and the text output and pull request
  description say to check them (and that raising requires-python may avoid them).
- A fix the plan could not ask for is counted when the verified lock moves its package past
  the fix anyway. On a public uv SDK the plan listed `jupyterlab → 4.5.11` as not
  included while the same lock moved jupyterlab 4.5.7 → 4.6.6. It now shows "moves past the
  fix with the rest of the plan", and the command stays the one that was verified. A fix
  retried with a raised Python floor that still fails gives that reason, not the old one.
- Found on the first real run of the Python floor plan, on a public uv SDK:
  - a fix that uv says "only supports >3.9.0" (cryptography, which excludes 3.9.0 itself)
    was not read as a Python floor and was left out, although the plan already raised the
    floor past it;
  - fixes left out for a reason that names `requires-python` (a fix that needs a newer
    version of another package, say) are now tried again once the floor is raised;
  - the pull request header said "requirements" when only `requires-python` changed, the
    text said "1 more fix" for the only fix and "Python 3.9 and 3.10 is".
- With `--fix-plan` and output saved to one file (`> out.txt 2>&1`), the plan printed above
  the scan report.
- In a lock forked by Python version (a package locked twice, such as pytest 8.4.2 for 3.9
  and 9.2.0 for 3.10+), the plan reported the newer copy as the installed version and missed
  uv's `Update x v1, v2 -> v2` lines in its list of lock changes. It now reads the lower copy
  (the one the alert is about) and those lines.
- `--fix-plan FILE` says so when it writes no file: a plan that only moves the lockfile has
  no requirement diff, and the file silently did not appear.
- A scanner error that ends in a Python traceback is reported by its last line
  (`requests.exceptions.ReadTimeout: ...`) instead of a slice of the traceback.
- `depquiet baseline create` says why when it accepts nothing: baseline v2 accepts npm
  component evidence only, so on a Python scan it suppressed no alert while reporting
  success. It now names the alternative (`depquiet --baseline <scan.json>`).
- The baseline note agrees in number ("1 known finding suppressed").

## [0.47.6] - 2026-11-17

### Fixed
- **Five built-in template names described the wrong vulnerability.** They show in
  `depquiet explain` and in `--json` (`template_id`). Checked against each advisory:
  `axios-ssrf-server-only` is now `axios-xsrf-token-leak` (CVE-2023-45857 leaks the XSRF
  token; it is not SSRF), `node-forge-timing-attack` is `node-forge-signature-verification`,
  `postcss-redos` is `postcss-redos-and-parsing` (CVE-2023-44270 is a parsing error, not
  ReDoS), `express-open-redirect-static` is `express-open-redirect`, and
  `webpack-dev-middleware-dev-only` is `webpack-dev-middleware-path-traversal` (the template
  never checks that the package is development-only). The other 15 match their advisories.
- The lodash template also requires `zipObjectDeep` to be absent: CVE-2020-8203 is in that
  function, which the template did not check. It is now `lodash-prototype-pollution`.
- The report header says what produced the alerts ("Python, via pip-audit" instead of "pip",
  which read as if the project used pip); one blank line before the KEV note; "nothing
  scanned" names the full path instead of ending in "..".

## [0.47.5] - 2026-11-17

### Fixed
- **A dependency group uv installs in production could be filtered as development-only.**
  Groups were classified by name alone. But `uv sync --frozen --no-dev`, the usual
  production install, leaves out only the group named `dev`: every other group in
  `tool.uv.default-groups` is installed. With `default-groups = "all"`, a `docs` group's
  packages shipped and depquiet filtered their alerts. A group in `default-groups` is now
  production, whatever its name, except `dev`.

### Documentation
- The README states the rule above, and that for Poetry depquiet assumes production installs
  with `poetry install --only main` (`--without dev` would still install a non-optional
  `docs` or `test` group).

## [0.47.4] - 2026-11-17

### Security
- **A crafted report could put a `javascript:` link in the HTML report.** A SARIF rule's
  `helpUri` (or any advisory URL from a report piped to `--stdin`) was written into the
  HTML report as a link: `javascript:alert(document.domain)` ran on click. A URL is now kept
  only when it is an `http(s)` address, so HTML, Markdown, SARIF and annotations never get
  another scheme. Markdown links escape parentheses so a URL cannot close the link early.

### Fixed
- **`--fix --dry-run` said "✅ Fixed 8 vulnerabilities" and exited 0.** On the demo project 5
  of those 8 upgrades cannot install (botocore 1.29.0 holds urllib3 below 1.27), and 10
  ACTION alerts were still open. A dry run now lists the upgrades it would try, says they
  were neither run nor checked against the resolver (`--check-fixes` checks them), and
  exits as the scan does.
- **`--license` read a License field that names no license as UNKNOWN.** python-dateutil
  publishes "Dual License" with Apache and BSD classifiers, and failed the license check.
  The OSI classifiers are used when the field names no license. When a package has several,
  they are combined with AND, so the most restrictive sets the risk: the first one used to
  win, and MIT listed before GPL-3.0 read as MIT.
- The HTML report's first column is "Advisory" (it held PYSEC and GHSA ids under "CVE") and
  shows the CVE when the scanner's id is another. "Fixed 1 vulnerabilities" reads "Fixed 1
  alert".

## [0.47.3] - 2026-11-17

### Fixed
- **`--sbom` listed only the packages with an alert.** The SBOM was documented as a full
  component inventory, but the lockfile's packages never reached it: the demo project's
  CycloneDX file had 2 of its 9 packages. It now lists every package in the project's
  lockfiles (or in the SBOM read with `--from-sbom`), and warns when it can only list the
  packages with an alert. CycloneDX JSON and XML validate against the official 1.5 schemas,
  and SPDX passes spdx-tools' full validation.
- **The README's Dependabot command failed with more than one page of alerts.**
  `gh api .../dependabot/alerts --paginate` prints each page as its own JSON array, and
  depquiet answered "invalid JSON on stdin". Back-to-back arrays and `--slurp` output are
  now read as one list.
- **`snyk test --all-projects --json` was read as Dependabot alerts**, because it is an
  array: the real alerts were lost and one empty alert was reported. Arrays are now read by
  what they contain, and an array that is neither is refused.
- **A SARIF file with only code findings was reported clean.** A result that names no
  package (CodeQL, Semgrep) is not a dependency alert, and depquiet dropped it silently:
  Semgrep's output gave "No vulnerabilities found", exit 0. depquiet now says how many it
  left out, and a file with only code findings is "nothing scanned" (exit 2). The README no
  longer lists CodeQL and Semgrep as supported inputs.
- Dependabot keeps the GHSA id, and Snyk every other CVE and its own id, as aliases, so
  EPSS, KEV, ignores and `explain` find them.

## [0.47.2] - 2026-11-17

### Fixed
- **A policy rule on severity could hide every alert of unknown severity.** pip-audit and
  uv audit report no severity; depquiet stores such an alert as `moderate` and marks the
  severity unknown. Policy rules ignored that mark, so `severity: moderate` with
  `action: filter` dismissed every pip-audit alert of a project, and the scan passed with
  exit 0. A `severity` condition now never matches an unknown severity.
- **Trivy, Grype, npm, pnpm, Snyk, Dependabot and SARIF reports with no severity** (absent,
  empty, or `UNKNOWN`) were read as a measured `moderate`. They are now unknown, as for
  pip-audit, so reports, `--fail-on`, SARIF levels and policies treat them as unknown. Grype's
  `Negligible` reads as info; a SARIF `security-severity` CVSS score in a result's properties
  reads as its score's level instead of `moderate`.
- `depquiet stats --from-json` counted unknown severities as moderate.
- Results within a verdict were sorted by the severity's name (critical, high, info, low,
  moderate), so `--json` listed low before moderate. They are sorted by level.
- `depquiet --help` lists `stats` and `init`; two warnings said "alert(s)" and
  "suppression(s)".

## [0.47.1] - 2026-11-17

### Fixed
- **`depquiet explain` says only what the scan established.** Found in an end-to-end check
  of 0.47.0 installed from PyPI:
  - An alert can be looked up by its CVE alias: `explain CVE-2024-35195` reported "CVE not
    found" for the alert pip-audit names `PYSEC-2026-1873`, although the help asks for a
    CVE id.
  - From a saved scan, an alert with no severity (pip-audit, uv audit) showed
    "Severity: MODERATE", the placeholder it is stored with. It shows "UNKNOWN".
  - From a saved scan, the alert's aliases were dropped, so explain said it had "no CVE id
    or alias" and found no EPSS score although the scan had both.
  - "CISA KEV: not listed" appeared for scans that never checked KEV. It now reads "not
    checked" and says why. `--json` records `kev_checked`; a live `explain` checks KEV
    when the project's config asks for it.

### Documentation
- The README's headline table is remeasured with 0.47.0 (2026-11-15, same commits, in a
  disposable VM). Given the same pip-audit report, 0.39.0 and 0.47.0 agree on every verdict
  in all 18 projects; the alert counts grew because advisories were published.

## [0.47.0] - 2026-11-15

### Fixed
- **Cut lists say what they leave out.** The fix pull request listed at most 6 advisories
  per package without saying so: on the demo project it showed 9 of the 10 alerts it fixes.
  It now adds "and N more". The same holds for the parents (`via`) and import sites in the
  text report and in `depquiet explain`, and text cut to fit ends with "…".
- **A failed EPSS lookup is reported.** When api.first.org could not be reached, or answered
  with something unreadable, the report silently had no EPSS scores. depquiet now warns how
  many CVEs went without one, like it already did for KEV and CVE lookups. An unreadable
  answer no longer stops the scan.
- **Escape sequences from scanner reports never reach the terminal.** A title with control
  characters (from any report piped to `--stdin`) could clear the screen or rewrite earlier
  lines. They are removed when an advisory is read.
- `is_direct` in `--json` comes from the dependency graph. pip-audit, uv audit, OSV, Grype
  and Dependabot cannot tell direct from transitive, so the field was a placeholder `true`,
  even next to `"dependency_type": "unknown"`. It is now `null` when no file says.
- `--apply` and `--fix-plan-report` without `--fix-plan`, and a `--path` that does not
  exist, are refused before the scan runs, with an error that says what is wrong.
- `--fix-plan` on a project with nothing to fix says so instead of "No fix could be
  planned", and on a project without `uv.lock` it names Poetry and, for npm, `--fix`.
- Notes about the scan (KEV, baseline, failed lookups) print after the report's header,
  not before it.
- Counts agree in number ("1 alert", "1 vulnerable package"), and a scanner error no
  longer runs into the next sentence.
- `--fix-plan --apply` says that its exit code reports the alerts found before the plan
  was applied. It stays 1 on purpose: the Action applies the plan on a separate branch,
  so the scanned branch still has those alerts.

### Changed
- The Action installs pip-audit 2.10.1, uv 0.13.8 and Poetry 2.5.1, pinned, instead of
  the latest release of each: its fix-pr job holds a token that can push. `--fix-plan
  --apply` was verified end to end with uv 0.13.8 and with Poetry 2.5.1.
- Python 3.14 is tested in CI and declared.

### Documentation
- The README described Dependabot's result as `update_not_possible`, an internal
  dependabot-core name that GitHub's documentation does not use. It now quotes the message
  GitHub documents: it "cannot update" the dependency "to a non-vulnerable version". The
  0.45.0 entry below used the same name.

## [0.46.0] - 2026-11-14

### Added
- **`--fix-plan`, `--apply` and `fix-pr` for Poetry projects**, verified with Poetry's
  resolver, for `[tool.poetry.dependencies]` and `[project]` requirements. Because
  `poetry update --lock` never fails when another package holds a fix back, depquiet reads
  the holders from `poetry.lock`, lets Poetry move them, and checks the resulting lock.
  Exact pins stay exact; `^`, `~` and ranges keep their style. Verified with Poetry 2.5.1
  and pip-audit on two projects where botocore holds urllib3 below its fix: 10 alerts
  → 0 (legacy table, exact pins) and 16 → 1 (PEP 621 ranges; the one left is a filtered
  dev-only alert). Dependabot cannot make this change in Python projects
  (dependabot-core#16337), and Renovate's maintainers say security fixes for transitive
  packages in `poetry.lock` are not supported (renovate discussion #28776).

## [0.45.2] - 2026-11-14

### Changed
- Releasing is one step: merging the release pull request. The release workflow tags the
  merged commit when `pyproject.toml` carries a version that has no tag yet (and
  `__init__.py` and the changelog agree), then runs the usual verification and publishes.
  A tag pushed by hand still works. CI now validates the workflow files with actionlint.

### Fixed
Found by running depquiet on a new npm project with a real `npm audit`: none of its 72
alerts carried a CVE id.
- **EPSS and KEV never applied to `npm audit` scans.** npm reports only GitHub advisory
  (GHSA) ids, and both are keyed by CVE id. depquiet now looks up each advisory's CVE on
  OSV.dev (in parallel, cached under `~/.cache/depquiet`; never with `--offline`). The
  README claimed EPSS worked for npm audit; it does now.
- **`--kev` reported "0 of 72 CVEs on the CISA KEV catalog" when it could check none of
  them.** Advisories with no CVE id are no longer counted as checked, and a warning says
  how many could not be checked. A failed CVE lookup is reported too.

## [0.45.1] - 2026-11-14

### Fixed
Found by using `fix-pr` as a new user, on a real repository and real uv:
- On a project without `uv.lock`, the Action's fix pull request step said "no fix that
  uv's resolver confirms", which reads as "nothing to fix". It now warns that `fix-pr`
  works on uv projects.
- The README's opening never mentioned `--fix-plan` or `fix-pr`; it does now. The
  `fix-pr` section says to set `fail-on-action: "false"` (otherwise the job fails after
  opening the pull request) and that a closed pull request is opened again on the next
  run. `depquiet --help` lists `--fix-plan --apply`.

## [0.45.0] - 2026-11-14

### Added
- **`fix-pr`: one pull request with every fix that installs.** `--fix-plan --apply`
  applies the verified plan to the project (requirement edits, then `uv lock`; if the lock
  fails, every file is put back). `--fix-plan-report FILE` writes the plan as a pull
  request description. The Action's `fix-pr` input does both on a schedule and opens or
  updates one pull request (`fix-pr-branch`, `fix-pr-token`, output `fix-pr-url`). It
  covers what Dependabot leaves as `update_not_possible` in Python projects: a parent
  that must move to fix a vulnerable transitive dependency (dependabot-core#16337).
  Verified with uv 0.11.32 on a project where botocore held urllib3 back: 10 alerts
  before, 0 after. uv projects only; never runs on pull request events.

### Fixed
- The README's headline table said it was measured with depquiet 0.40.0; the study that
  produced it records 0.39.0 (0.40.0 was only the version bumped in the same commit).

### Added
- `benchmarks/fixcheck_study/remeasure.sh`: re-measures the headline table with the latest
  release in a disposable VM. One pip-audit run per project, given to both 0.39.0 and the
  latest release, so differences come from depquiet and not from new advisories.

## [0.44.1] - 2026-11-13

### Fixed
Found by using depquiet as a first-time user: PyPI page, quick start in a clean
environment, the Action docs.
- README "Direct vs. transitive" still said an unused direct dependency, and a
  transitive one whose parents are unused, are **filtered**. Both have gone to review
  since 0.41; the section now says development-only paths are the only rule that filters.
- `depquiet explain` said an advisory's EPSS score was "not looked up" because it is
  reported by a PYSEC or GHSA id. Since 0.42 the lookup uses the CVE alias, so a missing
  score means the lookup was skipped or failed, and that is what it says now.
- `--check-fixes` on a project without `uv.lock` said "needs uv on PATH" when uv was
  missing too; it now says first that it works on projects with a `uv.lock`.
- The PyPI summary ("Tells you which CVEs actually matter") promised more than depquiet
  checks; it now matches the repository description.
- Nine README links to `docs/` and `benchmarks/` were relative and broken on PyPI; they
  point to GitHub now. The Action's outputs are documented, with an example.

### Fixed
- `SECURITY.md` said depquiet "never runs code from scanned projects", that its only
  network call was EPSS, and that 0.1.x was the supported version. None of that was true:
  some modes start pip-audit, uv or npm, which can run build code or install scripts, and
  KEV, OSV.dev and PyPI are also reached. It now lists, per mode, what runs and whether it
  can execute project code, what is sent where, which project files can dismiss alerts,
  and that only the latest release gets fixes.

## [0.44.0] - 2026-11-13

### Added
- **`--fix-plan` plans fixes hidden by your `exclude-newer` cooldown.** Instead of
  switching the cooldown off, it writes an `exclude-newer-package` cut-off for that
  package only, one second after the fix was published, verified with uv's resolver:
  the package moves to the fix and no further, and the rest of the project keeps the
  cooldown. Existing exemptions are kept; the entry goes to `pyproject.toml` or `uv.toml`,
  wherever `exclude-newer` is set. This is the narrow exemption uv's maintainers suggest
  instead of a blanket bypass (astral-sh/uv#18995). Verified end to end with uv 0.11.32.
- **Every scan warns about stale `exclude-newer-package` entries**: a per-package date
  older than the project's own cut-off holds that package on old releases (with a
  rolling `"7 days"` cooldown, uv moved requests back from 2.34.2 to 2.32.4 in a real
  run). With a rolling cooldown, `--fix-plan` prints the date after which to remove the
  entry it writes (`remove_after` in JSON). Package names with a dot are quoted and
  Windows line endings are kept when the entry is written.

## [0.43.0] - 2026-11-13

### Changed
Found by a black-box audit: dozens of small projects where the vulnerable package runs
in production, each checked for whether depquiet hides it. depquiet now filters on its
own only what development alone pulls in; everything else is kept and explained.
- **Test-only use no longer filters.** A production dependency imported only from tests
  was dismissed, though libraries load packages without any import naming them:
  Sequelize, TypeORM and Knex load `pg` from a dialect name, Next.js loads `sharp`,
  PyJWT loads `cryptography`. Adding a test made the alert disappear. It is now kept for
  review, with a note. On the benchmark, the realworld app's 33 axios and form-data
  alerts, imported only from its end-to-end tests, move from filtered to review.
- **Built-in community templates no longer dismiss on their own.** They match only when
  nothing imports the package, the case depquiet keeps for review because another
  library may load it: the `certifi` template hid CVE-2024-39689 in projects where
  `requests` uses certifi on every HTTPS call. A match now adds the template's note to
  the review. Custom templates without conditions still dismiss.

### Fixed
- A stale `package-lock.json` that still marked a package `"dev": true` filtered it even
  after `package.json` moved it to `dependencies` and the app imported it. The manifest
  now wins for the top-level copy; a nested copy under a dev tool keeps its own scope.
- Templates match an advisory's aliases, not only its id.
- `depquiet explain` showed a package imported only from tests as "reachable".
- README: the filter table said reachability filters transitive packages of unused
  dependencies; those have been kept for review since 0.41. The benchmark row for the
  2022 Express app showed its ACTION count (13) as filtered; it filters 8. Totals:
  111 of 535 alerts filtered (21%), not 149 (28%). The `depquiet stats` example is
  regenerated from that run. Added a note on devDependencies that a bundler ships.

### Security
- `action.yml` and the release workflow pin third-party actions to commit SHAs (the
  same commits their tags pointed to); Dependabot keeps them updated.

## [0.42.2] - 2026-11-12

### Fixed
Found by running 0.42.1 from PyPI on a real pip-audit project with live EPSS
scores (EPSS ordering and alias lookup worked as intended):
- Advisory titles were cut to 120 characters before Markdown was stripped, so
  a long link left titles like "urllib3's streaming API is". Titles are now
  cleaned first, then cut at a word, in every parser.
- EPSS scores below 0.5% showed as `EPSS 0%`, which reads as "no chance". They
  now show as `0.4%` or `<0.1%` in the terminal, Job Summary, HTML report and
  `depquiet explain`.
- `depquiet explain` called an EPSS score of 50%+ "escalated" and any other
  score "Above threshold", though EPSS no longer changes the verdict and no
  threshold is set by default. It now says the score orders the report.

## [0.42.1] - 2026-11-12

### Fixed
Found by reviewing 0.42.0 end to end, every command and input file:
- `depquiet init` wrote `epss_threshold: 0.1` into new configs, turning EPSS
  filtering back on. It now leaves it as a commented-out example.
- A missing, empty or wrong `--kev-file` crashed with a traceback and exit 1,
  the "findings" code; a CI step that tolerates findings passed without a KEV
  check. It is now an error with exit 2. A `{}` file no longer reads as "no
  exploited CVEs". When the KEV catalog cannot be downloaded, the warning goes
  to stderr, so `--json` users see it too.
- `--from-sbom` and `--stdin` input that cannot be read is exit 2 (was 1), and a
  JSON array given as an SBOM no longer crashes.
- A `--policy`, `--ignore` or `--config` file that yields nothing (wrong shape)
  was ignored silently; a lost policy can drop `flag` rules. It now warns.
- A fix that exists only as a pre-release (`26.10.0rc1`) is labeled
  `(pre-release)` in the terminal and in `depquiet explain`.
- `depquiet init --path` with a mistyped directory created that directory. It
  now stops with exit 2.

## [0.42.0] - 2026-11-12

### Changed
- **EPSS no longer filters or downgrades alerts by default.** EPSS is a
  probability over the whole internet, not a statement about your project, so
  a low score is no reason to hide an alert. It now orders the report: known
  exploited (KEV) first, then highest EPSS, then severity. To filter, pass
  `--epss-threshold`, set `epss_threshold` in `.depquiet.yaml`, or the Action's
  `epss-threshold` input (now empty by default). The old rule that turned an
  alert with EPSS below 30% into REVIEW is gone.
- EPSS lookups use the advisory's CVE alias. Before, pip-audit, uv audit and
  npm audit findings (named by PYSEC or GHSA ids) never got a score.

### Fixed
Found by installing 0.41.0 from PyPI in a clean environment and using it on uv,
requirements.txt and npm projects:
- `--check-fixes` showed only the last line of uv's error ("we can conclude that
  your project's requirements are unsatisfiable") with uv 0.11, which draws the
  cause tree with `╰─▶` instead of `cause:`. Both formats are read now.
- `depquiet explain` said "EPSS lookup was skipped or failed" for pip-audit and
  uv audit findings, whose ids are not CVEs. It now says EPSS scores CVE ids and
  names the advisory's CVE alias.
- Advisory titles in the terminal showed raw Markdown (`### Impact`, links) cut
  mid-word; they are one clean line now.
- `--fix` on a project without a uv.lock listed one line per advisory; it lists
  one line per package with the version that clears all of them.
- `--fix-plan` on a project without a uv.lock reported "--check-fixes works on
  projects with a uv.lock"; it names `--fix-plan`.
- The report footer said "product impact remains under investigation"; it now
  says what verdicts are based on. `depquiet --help` lists common runs and the
  `explain`, `diff` and `baseline` commands.

## [0.41.0] - 2026-11-12

### Added
- `--fix-plan [FILE]` (uv projects): the `pyproject.toml` changes that let the
  suggested fixes install together, verified with `uv lock --dry-run` on a
  temporary copy of the project, as a diff for `git apply` plus the `uv lock`
  command to run. It widens the project's own blocking requirements just enough,
  moves a pinned package that holds a fix back to a version uv picks (pinned in
  the project's style), and when not everything fits, keeps the largest set
  that resolves as a whole and reports the rest with uv's reason. Major version
  changes are flagged. Nothing in the project is changed. `--json` adds
  `fix_plan`.

## [0.40.6] - 2026-11-12

### Fixed
- A transitive package reached only through production dependencies the project
  declares but never imports was filtered as unreachable, while those direct
  dependencies themselves were (rightly) kept for review. Example: `uvicorn` in
  an extra, started from the command line, went to review, and `h11`, which
  parses every request it serves, was filtered. Such packages now go to review
  too, with a note. Dev-only packages are still filtered. The README benchmark
  and real-project numbers are unchanged by this.

## [0.40.5] - 2026-11-12

### Fixed
- Built-in template reasons made technical claims depquiet never verified, shown
  as the reason an alert was dismissed, and some were wrong: qs CVE-2022-24999
  "mitigated by default in Express 4.x" (Express 4.x was affected up to 4.17.2),
  the node-forge CVEs called a "timing attack" (they are signature verification
  flaws), lodash "only defaultsDeep and merge" (CVE-2020-8203 is zipObjectDeep).
  Each reason now states only what is checked: no import of the package, or of
  a direct dependency that brings it in. The matching was already conservative.
  A duplicate semver template was removed (20 built-in templates).
- Import detection for Rust, Ruby, Go, PHP, Java, C#, Swift and Dart treated
  comment markers inside strings as comments: `"assets/*"` opened a block
  comment that swallowed every later `use`/`require` up to the next `*/`, and
  `"issue #42"` cut the rest of a Ruby or PHP line. A missed import makes a
  used package look unreachable, so its alerts could be filtered. Comments are
  now removed by a scanner that keeps strings (and Rust raw strings and char
  literals); an unterminated string hides at most its own line. Rust (`use`
  inside functions) and Ruby (`require` anywhere) were the realistic cases.
- `always_flag` compared names exactly: `Django` or `PyYAML` in the config did
  not protect `django` or `pyyaml` from the scanner. Names now compare the way
  package managers do.

## [0.40.4] - 2026-11-12

### Fixed
- `--license` on a Python project listed the packages installed where depquiet
  runs, not the project's dependencies: on pallets/flask it reported 187
  packages (playwright, pytest, depquiet itself...), and a GPL dependency of the
  project that was not installed there was never seen, so the check could PASS.
  It now lists the project's locked packages (`uv.lock`, `poetry.lock`,
  `pdm.lock`, pinned requirements) and reads each license from the project's own
  virtualenv or PyPI for that exact version (78 packages on flask, matching its
  `uv.lock`). Unread licenses are UNKNOWN and fail; no lockfile is reported as
  not checked. PEP 639 `License-Expression` is read; `MIT-0` is known.
- The Action's PR comment step deleted any comment starting with
  "## 🔍 depquiet", whoever wrote it; it now deletes only the bot's own.

- An alert without a severity (pip-audit, uv audit) was shown and exported as
  `moderate`, a value no scanner reported: in the terminal, the Job Summary, the
  HTML report, `--json`, GitHub annotations, SARIF and the SBOM's CycloneDX
  ratings. It is now `unknown` everywhere. An ACTION alert without a severity is
  a SARIF `error` and an annotation `failure`, so code scanning merge protection
  set to errors no longer lets it through as a warning.

## [0.40.3] - 2026-11-12

### Fixed
- `.depquiet.yaml` slips weakened the scan in silence: a trailing comment turned
  `kev: true  # exploited` into KEV off and `always_flag: [lodash]  # core` into
  an unprotected lodash; `epss_threshold: 5` (meant as 5%) was accepted and
  filtered every alert with an EPSS score as low. Comments are now stripped, an
  EPSS threshold outside 0-1 is rejected (config: warning and 0.1; CLI: error),
  and unknown keys (`fail-on`) and unreadable booleans are reported.
- `--kev` never matched uv audit findings and rarely pip-audit ones: those name
  an advisory by its GHSA or PYSEC id and give the CVE as an alias, which was
  dropped, while the CISA KEV catalog lists CVE ids only. Aliases are now kept,
  KEV matches any of them, and `.depquiet-ignore` entries and policy `cves:`
  match them too. `--json` rows list `aliases`.

## [0.40.2] - 2026-11-12

### Fixed
- Policy rules could widen to every finding: a trailing `# comment`
  (`severity: [low, info]  # noise`), a misspelled key (`severty:`), an unknown
  severity, the documented `medium`, or an unreadable `epss_below` dropped that
  condition, so a filter rule meant for low-severity noise filtered critical
  alerts too. Comments are now stripped, `medium` means `moderate`, and a rule
  with an unknown key, severity or EPSS bound is skipped with a warning.
- `.depquiet-ignore`: an `expires` date with a trailing comment, slashes or a
  typo was read as no expiry, making a temporary suppression permanent. Comments
  are stripped, and an unreadable date now counts as expired, with a warning.
- `--fail-on high` (or `critical`) passed every pip-audit and uv audit alert:
  those scanners report no severity, and the placeholder `moderate` was compared
  as if measured. Alerts without a severity now count as meeting the threshold,
  with a note on stderr, and `--json` marks them `"severity_known": false`. The
  same placeholder from OSV.dev, SARIF and SBOM input is marked unknown too.

## [0.40.1] - 2026-11-12

### Fixed
- `--fix` on a Python project with a `uv.lock` updated nothing: a pip-audit alert
  ran `pip install` into the environment depquiet runs in, left `uv.lock` as it
  was, and was reported as fixed. It now runs `uv lock --upgrade-package`, and a
  refusal names what blocks the fix. Python projects without a `uv.lock` are
  never pip-installed: the requirement to raise is listed and the alert stays open.

## [0.40.0] - 2026-11-12

### Added
- Fix-check study rerun with per-alert checks: uv's resolver rejects the nearest
  fix for 502 of 991 kept alerts (51%); 58 of the 72 blocked package upgrades come
  down to the project's own pin. The study table counts fixes that resolve only
  with another package upgraded.
- GitHub Action input `check-fixes`: runs `--check-fixes` (installing uv if
  needed) and the Job Summary gains a "Can the fixes be installed?" table with the
  command for each upgrade that resolves and the next step for each that is blocked.

## [0.39.0] - 2026-11-11

### Added
- `--check-fixes` explains each blocked fix and what to do next: a pin in your own
  pyproject (named, with the requirement to widen), another package's pin (retried
  with that package upgraded in the same step, up to two rounds, printing the
  command that resolves), a Python floor, or an `exclude-newer` cooldown. The JSON
  `fix_check` gains `reason`, `next_step`, `also_upgrade` and `updates`.
- An alert whose package upgrade is blocked is checked against its own nearest fix,
  so an older backport that installs is reported as resolving.

### Fixed
- pip-audit and uv audit fixes: the fix version is the nearest one above the
  installed version, not the first listed (which could be an older release line).

### Documentation
- Fix-check study on 18 uv projects: uv's resolver rejects the upgrade that clears
  a package's alerts for 73 of 175 packages (42%), carrying up to 543 of 1,011 kept
  alerts with a fix. Script, raw results and VM runner in
  `benchmarks/fixcheck_study/`; numbers in the README.
- `--check-fixes` runs `uv lock`, which may execute build hooks (`setup.py`):
  documented in the README and the `--help` text, with the advice to use it only
  on trusted checkouts and not on pull requests from outside contributors.

## [0.38.0] - 2026-11-11

### Added
- `--check-fixes`: for a project with a `uv.lock`, asks uv's resolver
  (`uv lock --dry-run --upgrade-package pkg==version`) whether the fix of each
  alert still shown can be installed, and reports what blocks it if not. On
  saleor both surviving alerts are blocked: `oauthlib 4.0.1` is newer than the
  project's `exclude-newer-package` cut-off, and `opentelemetry-api 1.45.1`
  conflicts with the pinned `opentelemetry-semantic-conventions`. One
  resolution per package (the highest fix among its alerts); nothing is
  written. The result is shown under each alert and as `fix_check` in the
  JSON report.

## [0.37.0] - 2026-11-11

### Changed
- **A production dependency that the project declares but never imports is
  shown for review instead of being filtered as unreachable.** Measuring the
  filter on Python projects found it dismissing packages that are in use:
  pretix declares `oauthlib` and uses it through `oauth2_provider`, which
  imports it; open-webui declares `accelerate`, which `transformers` loads at
  runtime. A lockfile does not record either edge, and without one (pretix has
  none) no edge is known at all. The same applies to npm (an ORM loading its
  database driver by dialect name). Development dependencies and transitive
  packages are filtered as before. On the demo Express app 5 `lodash` alerts
  move from filtered to review; the five real projects in the benchmark are
  unchanged.

### Fixed
- Module names for `django-oauth-toolkit` (`oauth2_provider`), `django-allauth`,
  `django-storages`, `django-debug-toolbar`, `django-extensions`,
  `django-celery-beat`, `social-auth-app-django`, `social-auth-core` and
  `opentelemetry-api`, so their imports are recognised when the package is not
  installed where depquiet runs.

## [0.36.1] - 2026-11-11

### Fixed
- **GitHub Action:** it installed only depquiet, so a Python project had no
  pip-audit and fell back to OSV.dev, or failed with `offline: true`. It now
  installs pip-audit too (`install-pip-audit: false` to skip). It also
  installed the latest depquiet from PyPI whatever tag was used; it now
  installs the action's own code, so `@v0.36.1` runs 0.36.1 and a new tag
  works before PyPI's index lists it. CI now runs the Action on an npm and a
  Python project.
- **GitHub Action:** new `scanner` input, matching `--scanner`.
- The scan header read "(4 packages)" when 231 were audited: it counts packages
  with alerts, and now says "vulnerable packages".

## [0.36.0] - 2026-11-11

### Added
- `uv audit` (uv 0.13+) as an input and a scanner. Its JSON is accepted on
  `--stdin`, `--scanner uv` runs `uv audit --frozen`, and a uv project with uv
  installed and no pip-audit is audited with it instead of failing. pip-audit
  stays first when installed, so existing reports and finding ids do not
  change. Packages uv flags with an adverse status (archived, deprecated...)
  are named in the note. `fix` uses `uv lock --upgrade-package`.

## [0.35.0] - 2026-11-11

### Added
- A project with JavaScript (npm or pnpm) and Python dependencies is scanned for
  both in one run, each with its own scanner and triaged against its own graph.
  Until now a default run scanned the first ecosystem found and only named the
  other in a note. Each finding carries the package manager that reported it, in
  the JSON report and in `fix`, SARIF locations and annotations; finding
  identities match a single-ecosystem scan, so existing baselines keep working.
  If one scanner fails, the other's findings are kept and the note names the
  ecosystem that was not scanned. `--scanner` still limits a run to one.
- The license report covers every ecosystem of a merged scan.

## [0.34.0] - 2026-11-11

### Added
- Python projects that keep requirement files instead of a lockfile.
  `requirements*.txt` and the `requirements/*.txt` layout are audited (ansible/awx
  and apache/superset have nothing at the root and could not be scanned). Files
  named for tooling are left out unless they are the only ones. Compiled files
  are audited as written, with `--no-deps`, so no resolver runs and nothing can
  fail to install. The report names every file left out.
- When pip cannot resolve `requirements.txt` (home-assistant/core in a clean
  environment), the exact versions it lists are audited instead of the scan
  failing, and the report names the lines without an exact version.

### Fixed
- A dependency group named `pre-commit` was counted as production.

## [0.33.2] - 2026-11-11

### Fixed
- **False dismissal: every dependency group was treated as development-only.**
  PEP 735 and Poetry groups are named lists with no fixed meaning. zulip keeps
  its production dependencies in a group called `prod`, and all 43 of its
  `pip-audit` alerts were filtered, 17 of them for packages its servers run
  (`social-auth-core`, `pyasn1`, `tornado`...). On PostHog, 23 alerts for
  `transformers` and `torch` in a feature group were filtered the same way. A
  group is now development-only when its name says so (`dev`, `test`, `docs`,
  `lint`, `typing`, `ci`, `benchmark`...) and production otherwise, in
  `pyproject.toml`, in `uv.lock` and in Poetry groups. This affects every
  release that reads dependency groups, not only 0.33.

## [0.33.1] - 2026-11-11

### Fixed
- **False dismissal in uv workspaces (introduced in 0.33.0).** A member whose
  `pyproject.toml` declares `dynamic = ["dependencies"]` had an empty dependency
  list, so a package the root lists in a development group and a member ships as
  an extra was filtered as development-only (seen on pydantic-ai with `fastmcp`).
  Member dependencies are now read from `uv.lock`, the hatch
  `uv-dynamic-versioning` table or setuptools requirement files; without any of
  them the graph is incomplete and nothing is filtered.
- **Python scans were slow to unusable on large repositories (regression in
  0.33.0).** Every file was parsed again for every package and alert: more than
  eight minutes of triage on PrefectHQ/prefect for two alerts, now under ten
  seconds. Imports are indexed once per scan, for Python and for JavaScript,
  where a bounded cache had the same effect past 8,192 files.
- The scanned project's own `SyntaxWarning`s (invalid escape sequences) were
  printed on depquiet's stderr.
- Development groups were followed as dependencies of the project, so a plugin
  depending on the project appeared to pull in its linters and test tools, and
  those alerts were kept (12 of 17 on mlflow).
- `members = ["."]` and `./`-prefixed patterns in a workspace declaration marked
  the graph incomplete (langflow).

## [0.33.0] - 2026-11-10

### Added
- pnpm projects. `pnpm-lock.yaml` (lockfile v5 to v9, including the two-document
  layout of pnpm 10+) is read for the package list and the dependency graph, with
  each importer's `dependencies` and `devDependencies`. A project with that
  lockfile is audited with `pnpm audit` when pnpm is installed and through OSV.dev
  otherwise, and `pnpm audit --json | depquiet --stdin` is accepted. pnpm's
  per-finding `dev` flag filters an alert as development-only when every affected
  installed version carries it. `--scanner pnpm` selects it explicitly.
- Python usage evidence no longer lists files that only import a module sharing a
  name prefix with the package (`import django` for `django-auth-ldap`). The alert
  is still kept, and the report says the match is a name guess.
- npm alerts are filtered as development-only when every locked copy inside the
  advisory's range is marked `dev` in the lockfile, even if another copy of the
  same package is a production dependency at an unaffected version. Components
  carry the new `lock_scope` field.
- `--scanner npm|pip` chooses the scanner in a project with both ecosystems. The
  report now says which ecosystem a run did not scan instead of staying silent.

### Changed
- A report from `npm audit` or `pip-audit` is traced through that ecosystem's
  manifests and lockfiles only. A crate or Python package with the same name as
  an npm package no longer adds dependency paths to it.
- In workspaces, a member that uses a package without declaring it no longer
  blocks a development-only classification made by the members that declare it.

### Fixed
- Yarn Berry lockfiles (`version: 1.2.3`) yielded no packages, so a Yarn 2+
  project could not be scanned at all. Aliased entries are reported under the
  package they install, and workspace placeholders are skipped.
- A Yarn-only project no longer runs `npm audit` first just to fail on the
  missing `package-lock.json`.
- A lockfile that could not be parsed was skipped silently while the others were
  scanned. The scan now stops and names the file.
- A Python project that refers to itself in an extra (`all = ["myproject[a,b]"]`)
  was treated as one of its own dependencies. Every file imports the project, so
  every transitive package looked in use, and the project was shown as the path.
- When a Python package is installed where depquiet runs, its recorded module
  names are used on their own, without the name-based guesses.
- The dependency graph was marked incomplete, disabling every graph-based filter,
  by layouts that cannot hide a dependency path: several locked versions of one
  package in a shared lock, edges to uninstalled optional packages, two workspace
  members with the same name, a package name present in two ecosystems, and
  symbolic links to files that are not manifests or lockfiles. On Kong/insomnia,
  saleor and open-webui this kept every alert, including the ones
  `npm audit --omit=dev` drops. Links that stand in for a manifest, a lockfile or
  a directory still leave the graph incomplete.
- npm aliases (`"x-cjs": "npm:x@^4"`) are linked to the package they install, so
  an advisory for the real package is traced through dependents that list the alias.

## [0.32.0] - 2026-11-10

### Added
- Test-only usage filter (`test_only`): an alert is filtered when the package, and
  every used production dependency that pulls it in, is imported only from test
  code or test-runner configuration, is not run as a project command and is not
  named in any non-test file. Catches dependencies declared as production but used
  only by tests, which `npm audit --omit=dev` keeps. Requires complete graph and
  source coverage; otherwise the alert is retained.

### Fixed
- PEP 735 `{include-group = "..."}` entries in `[dependency-groups]` no longer mark
  the dependency graph incomplete. An include of a group that does not exist still
  does.

## [0.31.0] - 2026-11-10

### Added
- Offline reference-review workflow with pending forms, strict case/label/snapshot
  bindings, separate declared human/agent coverage, disagreement tracking and
  opt-in review-coverage gates. Human filter votes cannot weaken proposed labels;
  human retain/unknown constraints can make the safety gate stricter.
- Two additional pinned configuration contexts in a separate corpus extension,
  preserving the original ten labels/snapshots and frozen audits. Twelve pending
  forms and CI replay retain explicit zero-human-review provenance.
- Explicit npm/uv workspace discovery and independent dependency/source contexts,
  including deep declared members, per-workspace evidence and saved explanations.
- Bounded Python/JavaScript dynamic-loader observations with literal targets or
  explicit unresolved file/line evidence. Added graph and analysis coverage fields;
  legacy saved reports preserve unknown coverage when those fields are absent.
- Project-scoped baseline v2 creation (`depquiet baseline create`) with exact npm
  component contexts, reason/author metadata and a source-report SHA-256. Partial
  or unknown evidence remains unaccepted; every current context must be eligible
  and accepted before the finding's priority can be demoted.
- Instance-aware saved-scan diffs for matching explicit project IDs, including
  concrete versions/locations, unresolved context counts and a new-ACTION gate.
  Added `--project-id`, `--instances` and `--legacy-identities` for explicit scope
  binding and compatibility. Existing unscoped report identities remain supported.
- Auditable npm component candidates, separate from the advisory range: exact
  lockfile versions, node locations, SHA-256 provenance, stable instance IDs and
  per-advisory matched/not_matched/unknown associations. One lockfile snapshot is
  shared across an audit report; no package installation or Node runtime is needed.
- Explicit partial-resolution metadata and saved-scan explanations that preserve
  component evidence. Unsupported version/range semantics remain unknown.
- Structured dependency evidence and an ordered priority-decision history in scan
  JSON and saved-scan explanations. Preserve observations through policy, baseline,
  ignore and KEV decisions.
- A snapshot-bound reference evaluator with explicit coverage denominators and
  regression gates for unsafe or uncertain dismissals. Its initial two examples
  are labelled synthetic contract cases, not real-world accuracy measurements.
- Ten selected upstream advisory contexts across four pinned npm/Python projects,
  with frozen audit hashes, source evidence and explicit review provenance. Five
  require retention and five remain uncertain; human review is pending and no
  safe-dismissal or full-project accuracy claims are made.
- An offline upstream replay harness and CI matrix that check exact Git blobs and
  artifact hashes, keep missing selected findings visible to the evaluator and
  upload scan/evaluation evidence without running upstream code or installing it.

### Changed
- Automatic VEX assessments now remain `under_investigation`; CycloneDX analyses
  remain `in_triage`. Priority, EPSS and suppression rules no longer manufacture
  product-impact or mitigation claims. Existing triage gates are unchanged.
- VEX includes document version and assessment notes. CycloneDX retains all
  package/version references and priorities when one advisory affects multiple
  components. Incomplete scans cannot generate clean export artifacts.
- Reports distinguish no action-priority findings from a completed empty scan.
- CI evaluates controlled reference cases on every supported platform and runs
  for pull requests targeting development branches as well as main.

### Fixed
- Root development metadata no longer hides a production dependency in a deep
  declared workspace. Member sources/commands and shared-lock direct roots no
  longer bleed into sibling contexts; exported member edges exclude dev tools.
- Unreadable, malformed, missing or ambiguous graph/workspace inputs prevent
  dev-only and absence-based filtering. Recognized unresolved dynamic loaders
  block unreachable and conditional source-absence template decisions while
  preserving positive usage evidence. Cross-ecosystem name collisions and linked
  source boundaries retain explicit uncertainty.
- Legacy baselines with a declared project ID cannot suppress a different or
  unscoped project. Conflicting project IDs also fail in explicit legacy diffs.
- New npm versions or node locations no longer inherit an instance baseline's
  acceptance solely because their advisory/package is already known. Invalid
  instance inputs fail before priority changes or successful output artifacts.
- npm CycloneDX/SPDX/OpenVEX exports correlate advisories with concrete component
  instances, keeping versions outside the range in inventory without associating
  that advisory. Missing/partial resolution uses an explicitly unknown unversioned
  identity instead of manufacturing a component version from an advisory range.
- Exported PURL versions encode build metadata while preserving the standard's
  literal-colon rule. SPDX SECURITY references use the advisory reference type.
- Reachability and source-absence template conditions no longer dismiss findings
  based on included-source read/metadata errors or failed source-directory enumeration.
  Evidence retains observed imports and records coverage errors; unresolved usage
  stays unknown. Source content and read failures are shared within each scan.
- Saved-scan diffs preserve distinct advisory/package/version contexts instead
  of silently overwriting findings for another version. Adding a new affected
  version can trigger the new-ACTION gate even if that advisory was already present.
- Diffs reject explicit incomplete scans, malformed inputs and duplicate finding
  identities. Invalid-input errors return exit code 2 without a successful report
  or overwriting an existing summary; legacy reports without `scanned` remain supported.
- SBOM inventories now report an incomplete scan with exit code 2 when offline,
  empty, or unable to complete an OSV lookup, instead of claiming no vulnerabilities.
- OSV scans retrieve complete advisory records, including severity, CVE aliases and
  fixed versions, and handle paginated results without accepting partial reports.
- Keep explicitly imported transitive dependencies and packages shared between
  development and production dependency paths.
- Evaluate built-in template dismissal conditions conservatively and include all
  21 templates in installed wheels as package resources.
- Resolve scanner executables on Windows and audit every locked Python version,
  including multiple platform variants of the same package.
- Detect piped scanner JSON by its contents rather than the local project's ecosystem.
- Emit one JSON document with combined vulnerability and license results.
- Preserve operational failures in the GitHub Action, quote paths containing spaces,
  and generate diff summaries and comments from the original scan even after findings.
- Normalize SARIF paths on Windows and make unit tests independent of platform-specific
  permission APIs, default text encodings and installed vulnerability scanners.

### Changed
- CI tests Python 3.13 on Windows as well as the existing Linux matrix.

## [0.30.1] - 2026-11-04

### Fixed
- **A scanner that couldn't run looked like a clean project.** With pip-audit not
  installed, `depquiet` in a Python project printed "No vulnerabilities found"; so did a
  failed `npm audit` (no lockfile, network error), an OSV.dev network failure, and an
  empty or wrong directory. depquiet now falls back to OSV.dev lockfile scanning when the
  native scanner fails and says so, and otherwise reports "nothing scanned" with the reason
  and exits with code 2. It never reports an unscanned project as clean.
- pip-audit audited the environment depquiet ran in, not the project. It now audits the
  project's `uv.lock` / `poetry.lock` pins (without resolving or installing),
  `requirements.txt`, or `pyproject.toml`.
- Output crashed with `UnicodeEncodeError` on Windows when redirected
  (`depquiet > report.txt`, CI logs). Non-UTF-8 streams are switched to UTF-8.
- The README's GitHub Action example used `@v0`, a tag that didn't exist. Releases now
  move the `v0` tag to the latest version.

### Added
- OSV.dev lockfile scanning reads `uv.lock` and `poetry.lock`.
- Exit code `2`: nothing was scanned.
- Quick start section at the top of the README.

## [0.30.0] - 2026-11-04

### Fixed
- **Python dependencies were compared to imports by literal name.** `Django`, `PyYAML`,
  `Pillow` or `llama-index-core` never matched `import django`, `yaml`, `PIL` or
  `llama_index`, so real dependencies looked unused and their alerts were filtered. On
  mealie 0.27 filtered 200 of 229 alerts. Names are now mapped through the project's
  virtualenv metadata (`top_level.txt`/`RECORD`), a table of known mismatches, and rules
  (case, `python-` prefix, namespace prefixes, `django-` app labels).
- Dependencies used without an import were treated as unused: apps listed in
  `INSTALLED_APPS`, database drivers named in connection URLs, services started from
  scripts (`celery flower`), and plugins a library loads itself (FastAPI ->
  `python-multipart`, SQLAlchemy -> drivers). A dependency named in the project's code,
  scripts or config (not docs, manifests or lockfiles) now counts as used.
- pip-audit output that lists one advisory several times (same id, or a PYSEC id and its
  GHSA/CVE alias) produced duplicate alerts.
- Scans re-read and re-parsed every source file for every package checked. mealie (560
  Python files, 229 alerts) took 259 s; it now takes under 2 s.
- README links and the demo GIF are absolute, so they render on PyPI.

### Added
- `uv.lock` (direct, dev and transitive dependencies) and `poetry.lock` (transitive) in
  the dependency graph.
- Python benchmark scenarios: paperless-ngx (uv.lock) and mealie (poetry.lock) at pinned
  commits, audited with pip-audit. Across all six real projects: 535 alerts; 0.27 filtered
  419, depquiet now filters 102.

## [0.29.0] - 2026-11-04

### Fixed
- Dependencies the project runs instead of imports (`pm2 start` in `npm start`,
  `cross-env`, Procfile and Dockerfile commands) were treated as unused, so they and
  everything they pull in were filtered as unreachable. On
  hagopj13/node-express-boilerplate that was `pm2` and 45 alerts beneath it. A direct
  dependency now counts as used when one of its executables (lockfile `bin`, or the package
  name) appears in `package.json` scripts, a `Procfile` or a `Dockerfile`.

### Added
- Benchmark on three public Express projects pinned to a commit (hackathon-starter,
  node-express-realworld-example-app, node-express-boilerplate). Across them and the
  existing real scenario, `npm audit` reports 289 alerts; 0.27 filtered 202 and depquiet
  now filters 74, all with a traceable reason. Their source is cloned at the pinned commit
  at run time, not redistributed.

### Removed
- "You just saved ~N minutes of triage time" from the scan output. The number was
  filtered alerts × 2 minutes, an assumption presented as a measurement.

## [0.28.0] - 2026-11-04

### Fixed
- **Reachability no longer dismisses transitive dependencies.** Before, a package was
  "unreachable" whenever the app didn't import it directly, which is true of almost every
  transitive package. On a real Express app, 0.27 filtered 13 alerts in `body-parser`,
  `path-to-regexp`, `qs`, `cookie`, `send` and `serve-static`, all of which Express calls
  on every request. A transitive package is now filtered only when none of the direct
  dependencies that pull it in are imported, and a direct dependency also pulled in by an
  imported one stays reachable. Alerts whose dependency type can't be determined are no
  longer filtered on reachability.
- `depquiet fix` upgraded the wrong package for npm transitive advisories: it ran
  `npm install body-parser@4.22.3` when npm audit's fix was express 4.22.3. Fixes now target
  the package npm audit names (`fix_package`), and every output shows e.g.
  `express@4.22.3`.
- Filtered-reason breakdown printed `└─` before `├─` and didn't say that an alert can
  match several reasons.

### Added
- `depquiet.depgraph`: direct dependencies and dependency paths from `package.json`,
  `package-lock.json` (v1-v3), `yarn.lock` (v1, berry), `pyproject.toml` (PEP 621, PEP 735,
  Poetry), `Pipfile`, `requirements.in`, pip-compile `requirements.txt`, `Cargo.lock`,
  `Gemfile.lock`, `composer.json`/`composer.lock`, NuGet `packages.lock.json`,
  `pubspec.lock`, `go.mod` and `pom.xml`.
- Transitive packages pulled in only by devDependencies are filtered as dev-only.
- `dependency_type`, `introduced_by` and `fix_package` in `--json` output; `explain` shows
  which dependencies pull a package in; human output shows `via <parent>`.
- Real benchmark scenario (`benchmarks/fixtures/real-npm-express`) captured with npm itself
  by `benchmarks/capture_real.py`, with a per-alert verdict table in `RESULTS.md`.

### Changed
- README numbers now come only from the real benchmark. Removed the unsourced figures
  (89% noise reduction from synthetic fixtures, "3.5 hours per week", "60-80% unreachable",
  per-filter impact percentages, Snyk pricing) and the "zero false negatives" claim.

## [0.27.1] - 2026-11-04

### Fixed
- Release workflow now runs lint, format, mypy and the test suite, and checks that the
  tag matches `depquiet.__version__`, before publishing to PyPI. Previously any tag
  published without checks, including a tag pointing at an older commit.

### Note
- 0.19.0 through 0.27.0 were never tagged, so they were not published to PyPI. 0.27.1
  is the first PyPI release since 0.18.0 and includes every change listed below it.
- Release permissions (`contents: write`, `id-token: write`) are scoped to the publish
  job instead of the whole workflow.
- License scan no longer uses the deprecated `metadata["License"]` lookup, which will
  raise `KeyError` for packages without a License field on future Python versions.
- Formatting and mypy errors that kept CI red since v0.24.0.

### Added
- `.pre-commit-config.yaml` running ruff, ruff-format and mypy locally.
- `DeprecationWarning` is now an error in the test suite.

## [0.27.0] - 2026-11-04

### Added

- **`depquiet stats` aggregate statistics** — produces summary metrics from a scan or saved `--json` output for security dashboards and management reports
- Verdict breakdown with visual bar charts (ACTION / REVIEW / FILTERED)
- Severity distribution (critical / high / moderate / low / info)
- Filter reason breakdown (unreachable, dev dependency, low EPSS, template, ignored)
- Top affected packages ranking (`--top N` to control count)
- EPSS score distribution across severity buckets
- Fix availability summary (fixable vs. no fix)
- Human-readable and `--json` output formats
- 30 tests covering computation, formatting, JSON roundtrip, and CLI dispatch

## [0.26.0] - 2026-11-04

### Added

- **`depquiet explain` verdict explainer** — shows exactly why a CVE received its verdict, with every contributing signal laid out step-by-step
- Six signal types: EPSS score, reachability, dependency type, community template, CISA KEV, ignore rule
- Each signal shows its effect on the verdict: escalated (↑), filtered (↓), neutral (·), or not applicable (-)
- Two modes: live scan or from saved `--json` output (`--from-json FILE`)
- Human-readable output with verdict icons (🔴 ACTION / 🟡 REVIEW / 🟢 FILTERED)
- Machine-readable `--json` output for CI integration
- Fix availability and upgrade path shown when available
- 33 tests covering signal extraction, formatting, JSON output, lookup, and CLI dispatch

## [0.25.0] - 2026-11-04

### Added

- **`depquiet init` config scaffolder** — interactive subcommand that detects the project environment and generates a `.depquiet.yaml` with sensible defaults
- Auto-detects 11 package managers: npm, pip, Go, Cargo, Maven, Gradle, Gem, Composer, Pub, NuGet, and multi-manager monorepos
- Auto-detects 6 CI providers: GitHub Actions, GitLab CI, Jenkins, CircleCI, Bitbucket Pipelines, Azure DevOps
- Auto-detects existing scanners: Snyk, Trivy, Grype, OSV-Scanner, Dependabot, Renovate
- GitHub Actions projects get SARIF and summary outputs enabled by default
- `--yes` flag for non-interactive mode (CI/scripted setups)
- `--force` flag to overwrite existing config
- `-o` / `--output` flag for custom output path
- Generated config is loadable by depquiet's own config parser (round-trip tested)
- 48 tests covering detection, generation, overwrite protection, and CLI dispatch

## [0.24.0] - 2026-11-04

### Added

- **Expanded project configuration (`.depquiet.yaml`)** — every major CLI flag now has a config-file equivalent, enabling zero-flag CI runs from a single committed config file
- New config keys: `fail_on`, `kev`, `kev_file`, `license`, `policy`, `ignore`, `baseline`, `sarif`, `html`, `summary`, `sbom`, `sbom_format`, `vex`, `annotations`
- CLI flags always override config values when explicitly passed; config values serve as project defaults
- Output paths in config are resolved relative to the project root
- Enum validation for `fail_on` (critical/high/moderate/low/none) and `sbom_format` (json/xml/spdx) with warnings on invalid values
- Case-insensitive parsing for enum values and boolean yes/no/true/false
- 46 tests covering config defaults, key parsing, CLI-config merge semantics, validation, and edge cases

### Changed

- `Config.merge_cli()` now accepts all new keys with consistent override semantics: `None`/`False` means "not set on CLI, fall through to config"; explicit values win
- CLI internals refactored to detect which flags were explicitly passed (vs argparse defaults) so config values aren't silently overridden

## [0.23.0] - 2026-11-04

### Added

- **SBOM import — triage from third-party SBOMs** (`--from-sbom FILE` or `--stdin` auto-detection) — read CycloneDX 1.4/1.5 JSON or SPDX 2.3 JSON as input, extract vulnerabilities or package inventories, and feed them through the full triage engine
- New `parsers/sbom.py` module with `SbomParser`, `is_cyclonedx()`, `is_spdx()` detection, CycloneDX vulnerability + package extraction, SPDX SECURITY ref + package extraction, and purl parsing with ecosystem resolution
- **Two-mode operation**: if the SBOM contains vulnerability data (CycloneDX `vulnerabilities` array or SPDX SECURITY external refs), those are triaged directly; if not, the package inventory is extracted and queried against OSV.dev for known advisories
- Auto-detection in the engine dispatch chain — CycloneDX and SPDX SBOMs piped via `--stdin` are detected before scanner-specific formats
- New `--from-sbom` CLI flag for explicit SBOM file input (alternative to piping via `--stdin`)
- Purl parsing with support for scoped npm packages (`%40` → `@`), Go modules, Cargo, Maven, NuGet, Packagist, RubyGems, and Pub ecosystems
- CycloneDX severity mapping from both string labels and CVSS scores, fix version extraction from `affects.versions`, and component resolution via `bom-ref` lookup
- 53 tests covering purl parsing, format detection, CycloneDX/SPDX package and vulnerability extraction, severity mapping, engine integration, and the unified SbomParser API

## [0.22.0] - 2026-11-04

### Added

- **SPDX 2.3 SBOM generation (`--sbom-format spdx`)** — produce ISO/IEC 5962:2021-compliant Software Package Data Exchange documents, required alongside CycloneDX by US Executive Order 14028
- New `spdx.py` module with `generate_spdx_json()` and `write_spdx()` functions
- Auto-detection of `.spdx.json` and `.spdx` file extensions for format inference
- SPDX document includes: spdxVersion 2.3, CC0-1.0 data license, Package URLs (purl), SECURITY external references for known CVEs with depquiet verdict annotations, DESCRIBES relationships, and tool creator metadata
- Package inventory from lockfile parsing or fallback from triage results (same dual-source as CycloneDX)
- Deduplication of packages by purl (lockfile mode) or by name@version (scan-results mode)
- Integration with existing `write_sbom()` via `fmt="spdx"` — all three formats (json, xml, spdx) use the same CLI flag
- 22 tests covering SPDX ID generation, verdict annotations, document structure, lockfile/scan-result sources, deduplication, SECURITY refs, relationships, edge cases, file output, and integration with `write_sbom`

## [0.21.0] - 2026-11-03

### Added

- **OpenVEX document generation (`--vex FILE`)** — generate standards-compliant VEX (Vulnerability Exploitability eXchange) documents following the OpenVEX v0.2.0 specification
- Automatic verdict-to-VEX-status mapping: ACTION → affected, REVIEW → under_investigation, FILTERED → not_affected
- Machine-readable justifications for not_affected findings: `vulnerable_code_not_in_execute_path` (unreachable/dev), `inline_mitigations_already_exist` (low EPSS), `component_not_present` (community template), `vulnerability_not_exploitable` (ignored)
- Human-readable impact statements with EPSS scores and filter reason details
- Action statements for affected findings include fix versions, EPSS scores, and CISA KEV status
- Product and subcomponent identification using Package URL (purl) format
- `vex` input for the GitHub Action — generates and uploads the VEX document as a workflow artifact
- 57 tests for the VEX module covering status mapping, justifications, impact/action statements, JSON serialization, file output, and edge cases

## [0.20.0] - 2026-11-03

### Added

- **GitHub Check Run annotations (`annotations: true`)** — post inline vulnerability findings directly on PR diffs, like CodeQL or ESLint. Each ACTION or REVIEW finding becomes an annotation on the package manifest or reachable import file
- `--annotations FILE` CLI flag to write GitHub Check Run annotations JSON
- Severity-to-annotation-level mapping: critical/high → failure, moderate → warning, low/info → notice
- Automatic batching of annotations in groups of 50 (GitHub API limit)
- Annotations include CVE, severity, EPSS score, fix version, KEV status, and NVD link
- Support for 9 package manager manifest files (npm, pip, Go, Cargo, Maven, NuGet, Composer, Gem, Pub)
- `annotations` input for the GitHub Action — posts annotations via the Check Runs API using `GITHUB_TOKEN`
- 40 tests for the annotations module covering generation, content, paths, severity mapping, batching, serialization, file output, and KEV integration

## [0.19.0] - 2026-11-03

### Added

- **Standalone HTML report (`--html FILE`)** — generate a self-contained interactive HTML report with zero external dependencies. All CSS and JavaScript are inline for easy sharing via email, Slack, or artifact storage
- Severity donut chart using CSS `conic-gradient` — visual breakdown of critical, high, moderate, low, and info findings
- Collapsible sections: review auto-collapses when >5 findings, filtered always starts collapsed
- Dark mode support via `prefers-color-scheme` media query
- Client-side text search filtering across all findings tables
- Embedded JSON data blob for future client-side filtering extensibility
- XSS prevention: `html.escape()` for table content, Unicode escaping (`<`/`>`) for JSON in `<script>` tags
- `html` input for the GitHub Action
- 33 tests for the HTML report module covering structure, content, chart, collapsible sections, file output, CLI integration, JSON embedding, XSS prevention, and footer

## [0.18.0] - 2026-11-03

### Added

- **GitHub PR comment integration** — post scan diff results directly on pull requests with rich Markdown tables
- `depquiet diff --markdown` for GitHub-flavored Markdown output with severity badges, EPSS scores, and fix versions
- `depquiet diff --summary FILE` to write Markdown diff to a file (for `$GITHUB_STEP_SUMMARY`)
- `diff-base` input for the GitHub Action — provide a base scan JSON to enable automatic diff comparison
- `pr-comment` input for the GitHub Action — post scan diff as a PR comment (auto-updates on re-runs)
- `diff-new` and `diff-fixed` outputs from the GitHub Action for downstream workflow steps
- Severity badge mapping: 🔴 critical, 🟠 high, 🟡 moderate, 🔵 low, ⚪ info
- 10 new tests for Markdown formatting and CLI markdown/summary flags (44 total diff tests)

## [0.17.0] - 2026-11-03

### Added

- **Scan comparison (`depquiet diff`)** — compare two `depquiet --json` outputs to show new, fixed, and changed findings. Answers the PR-level question: "did this change introduce new vulnerabilities?"
- `depquiet diff base.json head.json` with human-readable output (emoji indicators, severity badges, EPSS scores)
- `depquiet diff --json` for machine-readable diff output
- `--fail-on-new` flag — exit 1 only when new ACTION findings appear (ideal for CI gates)
- `DiffFinding` and `ScanDiff` dataclasses for programmatic diff access
- 34 tests for the diff module covering dataclasses, scan comparison, formatting, JSON output, and CLI integration

## [0.16.0] - 2026-11-03

### Added

- **CISA KEV integration (`--kev`)** — check vulnerabilities against the CISA Known Exploited Vulnerabilities catalog. KEV-listed CVEs are auto-escalated to ACTION, reflecting BOD 22-01 requirements for federal agencies
- `--kev-file` flag for air-gapped environments — load a local KEV catalog JSON instead of fetching from CISA
- KEV data enrichment in JSON output (`kev.date_added`, `kev.due_date`, `kev.required_action`, `kev.ransomware_use`)
- KEV properties in SARIF output (`kev`, `kev_date_added`, `kev_due_date`, `kev_ransomware_use`)
- `kev` and `kev-file` inputs for the GitHub Action
- 24-hour local cache for the KEV feed with automatic fallback to expired cache on network failure
- Ransomware campaign usage tracking from KEV entries
- 27 tests for the KEV module covering parsing, catalog lookup, apply/escalation, file loading, caching, and CLI integration

## [0.15.0] - 2026-11-03

### Added

- **Baseline diffing (`--baseline`)** — only fail on NEW vulnerabilities not in a previous scan. Enables gradual adoption on existing codebases with tech debt
- `baseline` input for the GitHub Action
- Baseline identifies findings by `cve:package` key; known findings are demoted to FILTERED
- Works with `--fail-on` for layered control: baseline suppresses known, threshold gates new
- 16 tests for the baseline module covering load, apply, edge cases, and CLI integration

## [0.14.0] - 2026-11-03

### Added

- **Configurable CI gate (`--fail-on`)** — exit 1 only when ACTION items at or above a severity threshold exist. Options: `critical`, `high`, `moderate`, `low`, `none`
- `fail-on` input for the GitHub Action — overrides the boolean `fail-on-action` with severity-based control
- 15 tests for the fail-on module covering threshold logic, mixed severities, edge cases, and CLI integration

## [0.13.0] - 2026-11-03

### Added

- **GitHub Actions Job Summary** — rich Markdown report rendered directly in PR checks via `$GITHUB_STEP_SUMMARY`. Shows action items table with severity badges, EPSS scores, and fix versions; review items (auto-collapsed when >5); and filtered breakdown by reason
- `--summary` CLI flag to write GitHub-flavored Markdown summary to any file
- `ignore` input for the GitHub Action — pass a custom `.depquiet-ignore` path
- `license` input for the GitHub Action — run license compliance in CI
- `review` output from the GitHub Action — number of review-level items
- 18 tests for the summary module covering all verdict combinations, table rendering, severity badges, collapsing, and file output

## [0.12.0] - 2026-11-03

### Added

- **Suppression file (`.depquiet-ignore`)** — per-CVE and per-package suppressions with required reason, optional expiry dates, and author tracking for audit trails
- Match priority: CVE+package > CVE-only > package-only
- Expired entries print warnings instead of silently suppressing
- `--ignore` CLI flag for custom ignore file path
- Auto-detection of `.depquiet-ignore`, `.depquiet-ignore.yaml`, `.depquiet-ignore.yml` in the project root
- New `FilterReason.IGNORED` for suppressed items
- 45 tests for the ignore module covering parsing, matching, expiry, apply_ignores, and edge cases

## [0.11.0] - 2026-11-03

### Added

- **License compliance analysis (`--license`)** — scan all dependencies for license risk. Classifies ~60 SPDX license IDs into LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN risk levels.
- Copyleft detection: flags GPL, AGPL, SSPL, BUSL and other restrictive licenses that may contaminate proprietary code
- SPDX expression support: `OR` picks the most permissive option, `AND` picks the most restrictive
- Common alias normalization: `"Apache License 2.0"` → `Apache-2.0`, `"GPLv3"` → `GPL-3.0`, etc.
- npm scanner: reads `license` / `licenses` fields from every `node_modules/*/package.json` (including scoped packages)
- pip scanner: uses `pip list` + `importlib.metadata` classifiers to resolve license IDs
- `--license --json` for machine-readable license output
- 33 tests for the license module covering classification, npm/pip scanning, report output, and edge cases

## [0.10.0] - 2026-11-03

### Added

- **Auto-remediation (`--fix`)** — automatically upgrade vulnerable packages with known fix versions. Runs `npm install pkg@ver` or `pip install pkg==ver` for ACTION items that have a `fix_version`.
- `--dry-run` flag — preview what `--fix` would do without changing `node_modules` or `site-packages`
- `FixResult` and `FixReport` dataclasses for programmatic fix tracking
- 17 tests for the fix module covering dry-run, success, failure, timeout, and edge cases

## [0.9.0] - 2026-11-03

### Added

- **Policy engine** — commit security policies alongside code (`.depquiet-policy.yaml`). Rules match on severity, EPSS, package, dev status, CVE IDs; first matching rule wins.
- `--policy` CLI flag and `policy` input for the GitHub Action
- Action aliases: `block` → ACTION, `dismiss`/`ignore`/`filtered` → FILTERED
- Custom lightweight YAML parser — no PyYAML dependency required

## [0.8.0] - 2026-11-03

### Added

- **CycloneDX 1.5 SBOM generation** — JSON and XML output formats compliant with OWASP CycloneDX 1.5 (EO 14028 ready)
- `--sbom` and `--sbom-format` CLI flags; format auto-detected from file extension
- `sbom`, `sbom-format` inputs for the GitHub Action; SBOM auto-uploaded as build artifact
- Package URL (purl) generation for 9 ecosystems: npm, PyPI, Go, crates.io, Maven, NuGet, Packagist, RubyGems, Pub

## [0.7.0] - 2026-11-03

### Added

- **SARIF v2.1.0 input parser** — pipe SARIF output from any scanner into depquiet via `--stdin`
- **Standalone lockfile scanning** via the OSV.dev API — no external scanner required; auto-detects lockfiles when no native scanner is found

## [0.6.0] - 2026-11-02

### Added

- **Reachability analysis for 10 languages**: Python (AST), JavaScript/TypeScript (AST), Go, Rust, Java/Kotlin, C#, PHP, Ruby, Swift, Dart/Flutter
- Each analyzer detects ecosystem-specific import patterns and build directory exclusions

## [0.5.0] - 2026-11-02

### Added

- **JavaScript/TypeScript AST-based reachability** — detects `require()`, `import` statements, and dynamic imports using `acorn`-style parsing
- **Go reachability analysis** — scans `.go` files for `import` blocks

## [0.4.0] - 2026-11-01

### Added

- **Snyk parser**: triage Snyk CLI output via `snyk test --json | depquiet --stdin` — auto-detects `vulnerabilities` array + `packageManager` key, extracts CVEs from `identifiers`, maps dependency chain depth from `from[]`, deduplicates CVE+package
- **AST-based Python reachability** (v2): upgraded from regex to `ast.parse()` — immune to false positives from comments, docstrings, strings, and variable names that tripped up the old regex. Falls back to regex for unparseable files (Python 2, encoding issues)
- **12 new community templates** (21 total): minimist prototype pollution, nth-check ReDoS, postcss ReDoS, glob-parent ReDoS, node-forge timing attack, shell-quote injection, qs prototype pollution, semver ReDoS, word-wrap ReDoS, tough-cookie prototype pollution, js-yaml code execution, certifi root CA removal

### Changed

- Test suite expanded from 234 to 292 tests
- Coverage maintained at **100%** across all 20 source files (948/948 statements)
- 6 parsers now supported: npm, pip, trivy, dependabot, grype, snyk

## [0.3.0] - 2026-11-01

### Added

- **Grype parser**: triage Anchore Grype output via `grype dir:. -o json | depquiet --stdin` — auto-detects `matches` array, deduplicates CVE+package, maps artifact types to depquiet ecosystems, handles both modern and legacy fix formats
- **Dependabot parser**: triage GitHub Dependabot alerts via `gh api /repos/OWNER/REPO/dependabot/alerts --paginate | depquiet --stdin` — auto-detects JSON arrays, processes only open alerts, deduplicates CVE+package, handles GHSA-only advisories
- **Dependabot example** in `examples/dependabot-alerts/` with sample alerts and expected verdicts
- **Benchmark suite**: reproducible filter-rate measurement across 4 scenarios — **89% noise reduction** proven across npm, pip, trivy, and grype

### Changed

- **Python reachability analysis**: upgraded from bare string matching to proper `import X` / `from X import Y` / `__import__('X')` detection — prevents false positives from package names appearing in comments or prose
- **Mixed-project reachability**: `check()` now searches both JS and Python files instead of picking one ecosystem, so mixed-language projects triage correctly
- trivy.py test coverage raised from 84% to 100%
- Test suite expanded from 156 to 234 tests
- Coverage maintained at **100%** across all 19 source files (869/869 statements)

## [0.2.0] - 2026-11-01

### Added

- **Trivy parser**: auto-detects `trivy fs --format json` output via `--stdin`, processes `lang-pkgs` results (skips OS packages)
- **`.depquiet.yaml` config file**: commit triage preferences alongside code — `epss_threshold`, `template_dirs`, `always_flag`, `offline`
- **`--config` CLI flag**: specify a custom config file path instead of the default `.depquiet.yaml` in the project root
- **`always_flag`**: packages that must never be filtered — forced to ACTION verdict regardless of filters
- **7 new community templates**: express open redirect, axios SSRF, webpack-dev-middleware, json5 prototype pollution, ip SSRF, requests proxy-auth leak, cryptography null dereference (9 total)
- **Trivy container example** in `examples/trivy-container/`
- **Node.js API example** with `.depquiet.yaml` config in `examples/node-api/`
- **Python web app example** in `examples/python-web/`
- PEP 561 `py.typed` marker for typed package compliance

### Changed

- Full `mypy --strict` compliance across all source files
- All bare `dict` annotations replaced with `dict[str, Any]`
- Parser list uses `Protocol` for structural typing
- Test suite expanded from 29 to 156 tests
- Coverage raised from 84% to 99%

### Fixed

- SARIF output bug: `_build_locations` crashed on missing imports field
- `_parse_yaml_simple` return type narrowed from `dict` to `dict[str, object]` for mypy strict

## [0.1.0] - 2026-10-31

### Added

- Core triage engine with four filters: devDependency, reachability, EPSS, and community templates
- npm audit JSON parser with full advisory support
- pip-audit JSON parser (stub, expandable)
- EPSS score integration via FIRST.org API (`--offline` to skip)
- Import reachability analysis for JavaScript/TypeScript projects
- Community template system with YAML-based dismiss rules
- Bundled templates: lodash prototype pollution, semver ReDoS
- SARIF v2.1.0 output for GitHub Code Scanning integration
- JSON output mode for programmatic consumption
- Colored terminal output with before/after noise reduction display
- CLI with `--sarif`, `--json`, `--offline`, `--stdin`, `--epss-threshold`, `--templates`
- CI exit code: 1 if ACTION items found, 0 otherwise
- Full test suite with 29 tests
- CI workflow with lint, typecheck, test matrix (3.11/3.12/3.13), and build
- Automated release workflow with trusted PyPI publishing

[Unreleased]: https://github.com/samuelrojas-dev/depquiet/compare/v0.60.5...HEAD
[0.60.5]: https://github.com/samuelrojas-dev/depquiet/compare/v0.60.4...v0.60.5
[0.60.4]: https://github.com/samuelrojas-dev/depquiet/compare/v0.60.3...v0.60.4
[0.60.3]: https://github.com/samuelrojas-dev/depquiet/compare/v0.60.2...v0.60.3
[0.60.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.60.1...v0.60.2
[0.60.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.60.0...v0.60.1
[0.60.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.59.2...v0.60.0
[0.59.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.59.1...v0.59.2
[0.59.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.59.0...v0.59.1
[0.59.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.58.2...v0.59.0
[0.58.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.58.1...v0.58.2
[0.58.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.58.0...v0.58.1
[0.58.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.57.1...v0.58.0
[0.57.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.57.0...v0.57.1
[0.57.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.56.3...v0.57.0
[0.56.3]: https://github.com/samuelrojas-dev/depquiet/compare/v0.56.2...v0.56.3
[0.56.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.56.1...v0.56.2
[0.56.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.56.0...v0.56.1
[0.56.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.55.0...v0.56.0
[0.55.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.54.0...v0.55.0
[0.54.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.53.0...v0.54.0
[0.53.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.52.0...v0.53.0
[0.52.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.51.1...v0.52.0
[0.51.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.51.0...v0.51.1
[0.51.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.50.2...v0.51.0
[0.50.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.50.1...v0.50.2
[0.50.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.50.0...v0.50.1
[0.50.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.49.0...v0.50.0
[0.49.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.48.0...v0.49.0
[0.48.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.47.6...v0.48.0
[0.47.6]: https://github.com/samuelrojas-dev/depquiet/compare/v0.47.5...v0.47.6
[0.47.5]: https://github.com/samuelrojas-dev/depquiet/compare/v0.47.4...v0.47.5
[0.47.4]: https://github.com/samuelrojas-dev/depquiet/compare/v0.47.3...v0.47.4
[0.47.3]: https://github.com/samuelrojas-dev/depquiet/compare/v0.47.2...v0.47.3
[0.47.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.47.1...v0.47.2
[0.47.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.47.0...v0.47.1
[0.47.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.46.0...v0.47.0
[0.46.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.45.2...v0.46.0
[0.45.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.45.1...v0.45.2
[0.45.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.45.0...v0.45.1
[0.45.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.44.1...v0.45.0
[0.44.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.44.0...v0.44.1
[0.44.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.43.0...v0.44.0
[0.43.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.42.2...v0.43.0
[0.42.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.42.1...v0.42.2
[0.42.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.42.0...v0.42.1
[0.42.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.41.0...v0.42.0
[0.41.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.40.6...v0.41.0
[0.40.6]: https://github.com/samuelrojas-dev/depquiet/compare/v0.40.5...v0.40.6
[0.40.5]: https://github.com/samuelrojas-dev/depquiet/compare/v0.40.4...v0.40.5
[0.40.4]: https://github.com/samuelrojas-dev/depquiet/compare/v0.40.3...v0.40.4
[0.40.3]: https://github.com/samuelrojas-dev/depquiet/compare/v0.40.2...v0.40.3
[0.40.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.40.1...v0.40.2
[0.40.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.40.0...v0.40.1
[0.40.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.39.0...v0.40.0
[0.39.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.38.0...v0.39.0
[0.38.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.37.0...v0.38.0
[0.37.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.36.1...v0.37.0
[0.36.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.36.0...v0.36.1
[0.36.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.35.0...v0.36.0
[0.35.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.34.0...v0.35.0
[0.34.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.33.2...v0.34.0
[0.33.2]: https://github.com/samuelrojas-dev/depquiet/compare/v0.33.1...v0.33.2
[0.33.1]: https://github.com/samuelrojas-dev/depquiet/compare/v0.33.0...v0.33.1
[0.33.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.32.0...v0.33.0
[0.31.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.30.1...v0.31.0
[0.21.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.20.0...v0.21.0
[0.32.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.31.0...v0.32.0
[0.20.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/samuelrojas-dev/depquiet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/samuelrojas-dev/depquiet/releases/tag/v0.1.0
