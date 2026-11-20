# Fix plans

`--check-fixes`, `--fix-plan` and the Action's `fix-pr`: what to change so the fixes install, verified with the project's own resolver.

## Can the fix be installed? (`--check-fixes`)

"Update to 1.45.1" is only advice until the rest of your pins allow it. For a project with a
`uv.lock`, `--check-fixes` asks uv's own resolver, with `uv lock --dry-run --upgrade-package`,
whether each alert still shown can be fixed, and prints what blocks it if not. Nothing is
written. On saleor, both alerts that survive triage turn out to be blocked:

```
$ uv audit --frozen --output-format json | depquiet --stdin --check-fixes

🔴 ACTION REQUIRED: 2 alerts
   • GHSA-3jp2-3mrg-2vxc  oauthlib  FIX: update to 4.0.1
     ✗ fix check: blocked: `oauthlib` was filtered by `exclude-newer-package` to only include
       packages uploaded before 2026-09-28T06:02:00Z. The requested version, v4.0.1, was
       published at 2026-10-31T09:52:56.206Z. ...
   • GHSA-xcq7-p3pf-p88h  opentelemetry-api  FIX: update to 1.45.1
     ✗ fix check: blocked: Because opentelemetry-semantic-conventions==0.58b0 depends on
       opentelemetry-api==1.37.0 and your project depends on opentelemetry-api==1.45.1, ...
```

The first is saleor's own supply-chain cooldown; the second needs
`opentelemetry-semantic-conventions` upgraded in the same step. A fix that resolves prints
`✓ fix check: resolves (uv lock --upgrade-package pkg==version)`. Each check is one
resolution against the package index, so it needs uv and network access; the JSON report
has a `fix_check` object per alert.

**Measured on 18 uv projects** (2026-11-12, at their head; script, raw output and every
resolver message in [`benchmarks/fixcheck_study`](https://github.com/samuelrojas-dev/depquiet/tree/main/benchmarks/fixcheck_study/)). Each kept
alert was checked against its own nearest fix; each package also against its highest fix,
the one upgrade that clears all of its alerts:

| | Kept alerts | Packages |
|:--|--:|--:|
| With a fix version | 991 | 175 |
| Fix resolves | 489 | 103 |
| **Fix blocked** | **502 (51%)** | **72 (41%)** |

What blocks the 72 package upgrades, read from uv's messages:

- 45: the project's own pin on that same package (`posthog requires aiohttp==3.13.5`).
- 13: another package's pin. depquiet retried each with that package upgraded in the same
  step; none resolved, because in all 13 the project pins that package too (`posthog
  requires lxml==6.0.2`, which holds `lxml-html-clean`).
- 9: a Python version newer than the oldest the project supports; 2: the project's own
  `exclude-newer` cooldown; 3: not told apart from uv's message.

So 58 of the 72 (81%) come down to a pin in the project's own `pyproject.toml`, directly or
one step away. None failed for network or build reasons. Blocked does not mean unfixable:
it means the scanner's "update to X" is not enough, and the pin to widen is the answer.

For each block, `--check-fixes` says what to do next: the requirement of yours to widen, or
the blocking package and the pin that holds it, or the Python floor or cooldown. When
upgrading the blocking package in the same step resolves, it prints the command
(`uv lock --upgrade-package a==1.2 --upgrade-package b`).
The study ran in a disposable VM, for the reason below.

`uv lock` can run code: when a package (your project included) computes its metadata with a
`setup.py` or another build hook, uv executes it to find its dependencies. `--check-fixes`
does nothing `uv lock` would not do in the same checkout, but run it only on code you
trust, and not in CI jobs that check out pull requests from outside contributors.

## One verified change for all the fixes (`--fix-plan`)

`--check-fixes` says, per package, whether the fix installs and what blocks it. `--fix-plan`
answers the next question: what do I change so the fixes install, together?

```bash
depquiet --fix-plan plan.diff     # or --fix-plan alone to print the diff
git apply plan.diff
uv lock --upgrade-package ...     # the command it prints
```

For a uv project it:

1. widens each requirement of yours that blocks a fix, just enough (`==2.31.0` → `==2.33.0`,
   `<3.7` → `<4`; other clauses, extras and markers stay as written);
2. when another package holds a fix back and you pin that package, lets uv pick a version of
   it that allows the fix, and pins that version in your style;
3. applies everything to a **temporary copy** of the project and runs `uv lock --dry-run` with
   all the upgrades at once. If they don't fit together, it keeps each fix that still
   resolves with the ones already kept and reports the rest with uv's reason.

Nothing in the project is changed. What is verified is resolution only: whether your code
works with the new versions, a major version change above all, is for your tests to say.
Like `--check-fixes`, it runs `uv lock`, so use it on trusted code.

Real run on a small project pinning `requests==2.31.0` and `botocore==1.29.0` (which caps
`urllib3` below 2):

```
🔧 Fix plan
   ✓ requests 2.31.0 → 2.33.0: widen your requirement
   ✓ urllib3 1.26.20 → 2.8.0: also move botocore → 1.44.2, which holds it back  (major version change)

   Verified with uv's resolver: all fixes resolve together.
   Then run: uv lock --upgrade-package requests==2.33.0 --upgrade-package urllib3==2.8.0 --upgrade-package botocore==1.44.2
```
```diff
-    "requests==2.31.0",
-    "botocore==1.29.0",
+    "requests==2.33.0",
+    "botocore==1.44.2",
```

After `git apply` and that command, pip-audit reports no known vulnerabilities in the
project's dependencies.

The plan also names everything else the verified lock moves, because a reviewer sees it in
the lockfile diff: a parent that has to move with a fix without any requirement change, and
packages that nothing requires any more. On a project locked at oaklib 0.7.4, which caps
setuptools below 82:

```
🔧 Fix plan
   ✓ setuptools 81.0.0 → 83.0.0: upgrade  (major version change)

   It also changes uv.lock:
     · oaklib 0.7.4 → 0.7.5
     · appdirs 1.4.4 (removed: nothing requires it any more)
     · eutils 0.6.1 (removed: nothing requires it any more)
     ...
```

When only the lockfile moves, there is no diff to write, and depquiet says so.

### Fixes that need a newer Python (`--raise-python-floor`)

A project that still declares `requires-python = ">=3.9"` cannot take a fix that supports
only 3.10 and up, even if it runs on 3.12: uv has to find versions for every Python the
project claims. Dependabot then fails on that update again and again. depquiet raises the
floor to what the fixes need **on the temporary copy**, asks uv again, and says what that
unblocks. Dropping a Python version is your decision (harmless for an application, a
breaking change for the users of a published library), so the edit goes into the plan only
with `--raise-python-floor`. Real run with uv 0.11 on a small project with
`requires-python = ">=3.9"`, pytest locked twice (8.4.2 for 3.9, 9.2.0 for 3.10+) and an
alert fixed in pytest 9.0.0:

```
🔧 Fix plan
   ✓ tornado 6.4.1 → 6.5: upgrade
   ✗ pytest → 9.2.0: needs a newer Python: see Python floor below

   Python floor:
     Raising requires-python to >=3.10 would let 1 more fix install (pytest; 1 alert), verified with uv's resolver.
     It drops Python 3.9: fine for an application, a breaking change for users of a published library.
     Add --raise-python-floor to put that change in the plan.
```

With `--raise-python-floor`, the diff changes `requires-python = ">=3.9"` to `">=3.10"`
(upper bounds such as `<4` are kept; `~=` and `==3.9.*` are left for you to rewrite), and
`--apply` leaves pytest 9.2.0 as the only copy in `uv.lock`. The target is 9.2.0, not the
fix's 9.0.0, because the lock already had 9.2.0 for newer Pythons: the plan does not move
it back down. Workspace members whose own floor is lower are raised too. The Action's input
is `fix-pr-raise-python-floor`.

Poetry projects get the same option. `poetry update` on a transitive package resolves and
quietly keeps the old version, so depquiet requires the fix directly on a copy, reads the
Python each release needs from Poetry's error (`soupsieve (4.1.1) requires Python
>=3.11.5`), and verifies the raised `requires-python` with Poetry. A project that also sets
`python` in `[tool.poetry.dependencies]` gets the floor reported, but not edited: raise both
by hand.

### Fixing filtered alerts too (`--fix-filtered`)

The plan covers the alerts depquiet shows. A filtered alert (pytest in a `dev` group, say)
needs no action by depquiet's reading, but Dependabot keeps it open until the package moves.
`--fix-filtered` (Action: `fix-pr-include-filtered`) checks and plans those fixes as well,
so one pull request can close them. That is the usual case for the Python floor above:
pytest and other test tools are often what a project's `>=3.9` holds back.

### Poetry projects

`--fix-plan`, `--apply` and `fix-pr` work on Poetry projects too (a `poetry.lock` and no
`uv.lock`), verified with Poetry's own resolver, for both `[tool.poetry.dependencies]` and
`[project]` requirements. Real run with Poetry 2.5.1 on the same case, `requests = "2.31.0"`
and `botocore = "1.29.0"`:

```
🔧 Fix plan
   ✓ requests 2.31.0 → 2.33.0: widen your requirement
   ✓ urllib3 1.26.20 → 2.8.0: also move botocore → 1.44.3, which holds it back  (major version change)

   Verified with Poetry's resolver: all fixes resolve together.
   Then run: poetry update --lock requests urllib3 botocore
```
```diff
 [tool.poetry.dependencies]
 python = "^3.11"
-requests = "2.31.0"
-botocore = "1.29.0"
+requests = "2.33.0"
+botocore = "1.44.3"
```

10 alerts before, 0 after. What differs from uv:

- `poetry update --lock urllib3` does not fail when botocore holds urllib3 back: it
  resolves and leaves urllib3 where it was. depquiet reads the holders from `poetry.lock`,
  lets Poetry move them, and checks the new lock.
- Poetry has no "upgrade to exactly this version": `poetry update` moves a package to the
  newest version your constraints allow, so a range such as `^2.31` can land above the
  fix. An exact pin stays exact, at the fix version. The plan shows where each package ends.
- `--check-fixes` on its own is for uv projects. For Poetry the plan is the check.
- Constraints with `||` and git or path dependencies are not rewritten: that fix is listed
  as left out, with the reason.
- No `exclude-newer` handling: that is a uv setting.

### One pull request with every fix that installs (`fix-pr`)

`--fix-plan --apply` applies the verified plan to the project: it edits the requirements
and runs `uv lock`. If `uv lock` fails, every file is put back as it was. The Action's
`fix-pr` input does that on a schedule and opens **one pull request** with the result, so
the work left for you is to read it and let your tests run:

```yaml
name: depquiet fixes
on:
  schedule:
    - cron: "17 6 * * 1"   # Mondays
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: samuelrojas-dev/depquiet@v0
        with:
          fix-pr: "true"
          fail-on-action: "false"
          # fix-pr-token: ${{ secrets.DEPQUIET_PR_TOKEN }}
```

Real run on a project with `requests==2.31.0` and `botocore==1.29.0`, where botocore holds
urllib3 below 1.27: 10 alerts before, 0 after, and this description on the pull request.
The project and both pull requests are public:
[depquiet-fixpr-test](https://github.com/samuelrojas-dev/depquiet-fixpr-test), with
[the uv pull request](https://github.com/samuelrojas-dev/depquiet-fixpr-test/pull/1) and
[the Poetry one](https://github.com/samuelrojas-dev/depquiet-fixpr-test/pull/2).

| Package | From | To | Advisories | How |
|---|---|---|---|---|
| `requests` | 2.31.0 | 2.33.0 | PYSEC-2026-1873, PYSEC-2026-1872, PYSEC-2026-2275 | widens the project's own requirement |
| `urllib3` | 1.26.20 | 2.8.0 **(major version change)** | PYSEC-2026-1999, PYSEC-2026-1998, … | also moves `botocore` → 1.44.3, which held it back |

That second row is the case other tools leave open today. Dependabot cannot raise a parent
to fix a vulnerable transitive dependency in Python projects
([dependabot-core#16337](https://github.com/dependabot/dependabot-core/issues/16337),
open as of November 2026): Dependabot reports that it cannot update the dependency to a
non-vulnerable version ([its error reference](https://docs.github.com/en/code-security/reference/supply-chain-security/troubleshoot-dependabot/dependabot-errors)).

What to know before you turn it on:

- **uv and Poetry projects**, like `--fix-plan`. The Action installs Poetry when it finds
  a `poetry.lock` and Poetry is not already on the runner.
- The branch (`depquiet/security-fixes`, or `fix-pr-branch`) is **force-pushed on every
  run**: it is always your branch plus one commit. Do not commit to it by hand.
- The commit holds only `pyproject.toml`, `uv.toml`, `uv.lock` and `poetry.lock` changes.
- **Your CI does not start on a pull request opened with the default `GITHUB_TOKEN`**:
  that is how GitHub works. Pass a personal access token or GitHub App token as
  `fix-pr-token` to have your tests run on it.
- The repository must allow it: Settings → Actions → General → "Allow GitHub Actions to
  create and approve pull requests".
- It never runs on `pull_request` events: `uv lock` can execute build hooks, and this step
  holds a token with write access.
- depquiet checks that the versions resolve, not that your code works with them. Fixes it
  cannot verify are listed in the pull request as not included, with the reason.
- Set `fail-on-action: "false"` in this workflow, as above: otherwise the job shows as
  failed even after it opens the pull request, because the alerts are still on your
  branch until you merge it.
- Each run updates the open pull request. If you close it without merging, the next run
  opens it again while the fixes remain available; unlike Dependabot, depquiet does not
  remember a closed one. Add the advisories to `.depquiet-ignore`, or turn `fix-pr` off.

### Fixes hidden by your cooldown (`exclude-newer`)

A cooldown (`exclude-newer = "7 days"`, or a date) protects you from a malicious release
by hiding releases newer than the cut-off. It hides security fixes too: the scanner flags
the vulnerable version, `uv lock` says "No solution found", and the usual way out is to
switch the cooldown off. `--fix-plan` writes the narrowest exemption uv supports instead:
an `exclude-newer-package` cut-off for that package only, one second after the fix was
published. The package can move to the fix and no further, even with `uv lock --upgrade`,
and every other package keeps the cooldown. Existing exemptions are kept, and the entry
goes where you set `exclude-newer` (`pyproject.toml` or `uv.toml`).

Real run on a project with `exclude-newer = "2025-06-01T00:00:00Z"` and requests 2.32.3,
whose fix for CVE-2024-47081 (2.32.4) was published on 2025-06-09:

```
🔧 Fix plan
   ✓ requests 2.32.3 → 2.32.4: exempt it from your exclude-newer cooldown, only up to this release (published 2025-06-09)

   Verified with uv's resolver: all fixes resolve together.
   Then run: uv lock --upgrade-package requests==2.32.4
```
```diff
 [tool.uv]
 exclude-newer = "2025-06-01T00:00:00Z"
+exclude-newer-package = { requests = "2025-06-09T16:43:06Z" }
```

After `git apply` and that command, requests is at 2.32.4, `uv lock --upgrade` keeps it
there, and urllib3 stays under the project's cut-off. An exemption admits a release younger
than your cooldown, so the plan says so: check that it is the advisory's fix and comes from
the project's usual publisher before you merge.

**Remove the entry once your cooldown catches up.** A per-package date overrides the
cooldown for that package for good. With `exclude-newer = "7 days"`, an entry left in place
holds the package at the fix release: in a real run, uv moved requests *back* from 2.34.2
to 2.32.4. With a rolling cooldown the plan prints the date after which to remove the
entry, and every depquiet scan warns about any `exclude-newer-package` date older than the
project's own cut-off, whoever wrote it:

```
⚠️  exclude-newer-package holds requests at releases before 2025-06-09T16:43:06Z, older than your cooldown's cut-off (2026-11-06T21:32:08Z): uv keeps requests on old releases. Remove the entry.
```

## Auto-remediation (`--fix`)

`depquiet --fix` upgrades packages that have ACTION verdicts **and** a known fix version:
`npm install <pkg>@<ver>` for npm, and for a Python project with a `uv.lock`,
`uv lock --upgrade-package <pkg>==<ver>` (then `uv sync` installs it). When uv's resolver
refuses, the report says what blocks the fix, as [`--check-fixes`](#can-the-fix-be-installed---check-fixes)
does. Other Python projects are not changed: `pip install` would only touch the environment
depquiet runs in and leave your requirement files as they are, so depquiet lists the
requirement to raise instead, and the alert still counts as open.

```
$ depquiet --fix

depquiet scan — npm (847 packages)
...

✅ Fixed 2 vulnerabilities:
   CVE-2024-4068  braces 3.0.2 → 3.0.3
   CVE-2024-33883  ejs 3.1.9 → 3.1.10

⚠️  1 ACTION items have no fix available:
   CVE-2024-21538  semver 7.5.4
```

Use `--dry-run` to preview changes without touching `node_modules` or `site-packages`:

```
$ depquiet --fix --dry-run

[dry-run] ✅ Fixed 2 vulnerabilities:
   CVE-2024-4068  braces 3.0.2 → 3.0.3   Would run: npm install braces@3.0.3
   CVE-2024-33883  ejs 3.1.9 → 3.1.10    Would run: npm install ejs@3.1.10
```

**Exit codes with `--fix`:** returns `0` when every ACTION item is resolved; returns `1` when any remain unfixed (no fix version, or the upgrade command failed).
