# When npm audit's only fix is a downgrade: a pilot

Snapshot of **21 November 2026**. A pilot, to decide whether depquiet's fix plan should
cover npm. Question: when npm's own tooling cannot fix a vulnerable package within semver,
what does it offer instead, and is there a smaller fix it misses?

## Results

| | |
|---|--:|
| Popular JS/TS repos checked (200 TypeScript + 200 JavaScript, >5,000 stars, pushed since 1 Nov 2026) | 400 |
| With a `package-lock.json` at the root | 155 |
| Audited (`npm audit --package-lock-only`) | 153 |
| With at least one vulnerable package | 126 |
| Vulnerable packages: fix within semver / semver-major fix only / no fix | 2,554 / 1,516 / 134 |
| **Repos where some package has only a semver-major fix** | **101 of 126** |
| Repos where some package has no fix at all | 32 |

**The semver-major fix is often a downgrade.** npm audit proposes 408 distinct semver-major
fixes (per repo); 399 could be compared with the lock, and **221 of them move a package to
an older version** than the lock has. They come up in **80 of the 100** repos with such a fix. For example,
in OpenHands, `@tailwindcss/typography` 0.5.20 → 0.5.4, and in showdown, `@eslint/js`
10.0.1 → 9.39.5. This is what `npm audit fix --force` applies.

**A smaller fix often exists.** In 42 repos, at least one of these packages (semver-major or
no fix) has a fixed release on the same compatible line as the installed one, for example
postcss-selector-parser 6.0.10 → 6.1.5. @tailwindcss/typography 0.5.19 pins exactly
`6.0.10`, so no upgrade within ranges reaches the fix, and npm audit proposes the
downgrade above instead. An `overrides` entry scoped to that parent would keep the parent
and move only the vulnerable package, within its own major line. Per package, among the
semver-major cases: 71 have a same-line fix, 375 only a fix on a newer line, 41 no fixed
release; the other 1,022 are vulnerable only through a dependency (npm audit lists the
parent too).

## Checked on real projects

After `--fix-plan` for npm shipped, it was run on four of the projects above, in a
disposable VM on 21 November 2026 (depquiet 0.56.3, npm 9.2, `--fix-filtered` so that
development-only alerts count too). Each project was cloned shallow; the plan was applied
to that clone with `--apply`, and npm audit run before and after.

| Project | npm audit vulnerable packages, before → after | Fixed / left out |
|---|--:|--:|
| upscayl | 49 → 20 | 25 / 8 |
| nodemon | 64 → 48 | 19 / 12 |
| OpenHands | 25 → 15 | 10 / 1 |
| mathjs | 16 → 14 | 3 / 5 |
| **Total** | **154 → 97** | **57 / 26** |

No package moved to an older version, no override crossed a major version, and no
dependency the project declares was moved to a new major version. What was left out, by
reason:

- **Bundled inside another package's tarball** (`inBundle`): nodemon's dependency on npm
  11.10.1 ships glob, tar, sigstore, pacote and others; only a new npm release changes them.
- **Every fixed release is on a newer major line, below a parent's pin**: for example
  diff 1.4.0 under mocha 2.5.3 (2016), tough-cookie 2.4.3 under request, and glob
  10.3.10 under @next/eslint-plugin-next. The plan names the parent to upgrade.
- **Every fixed release is on a newer major line of the project's own dependency**:
  upscayl's electron (`^33.2.1`, fixed only in 42.x) and exiftool-vendored (`^29.3.0`).
  The plan names the jump and leaves it to the project.
- **No fixed release published**: request 2.88.0 and extract-zip 2.0.1.
- **The project's own override pins a vulnerable version**: OpenHands overrides qs under
  typed-rest-client to 6.15.3, which is inside an advisory; the plan names 6.16.1.

Earlier runs the same day (0.56.0 to 0.56.2) found problems that are fixed in 0.56.3:
copies bundled in npm reported as "npm still locks"; advisories bounded by prereleases
(next, electron, semver) read as covering every release; and, in 0.56.2, upscayl's own
electron widened from `^33.2.1` to `^42.11.16` and exiftool-vendored to a new major as if
they were lockfile fixes. The CHANGELOG has each one.

## Method

1. GitHub search: the 200 most-starred TypeScript and 200 most-starred JavaScript repos with
   more than 5,000 stars, pushed since 1 November 2026, not archived
   ([`repos_candidates.txt`](repos_candidates.txt)).
2. `fetch.sh`: `package.json` and `package-lock.json` from the root of the default branch,
   when the lock exists ([`repos_with_lock.txt`](repos_with_lock.txt)).
3. `audit.sh`: `npm audit --json --package-lock-only --ignore-scripts` (npm 10.9). It reads the
   lock and asks the registry; nothing is installed or run.
4. `tally.py` counts `fixAvailable`; `downgrades.py` compares each semver-major target with
   the version at `node_modules/<name>` in the lock; `analyze.py` reads every stable release
   from the registry and checks, with depquiet's npm range matcher, whether one outside all
   the package's advisory ranges sits on the installed version's caret line
   (`python analyze.py ../../src`, run from this folder after the two steps above).

## Limits

- A pilot: one day, one sample, root lockfiles only (pnpm and yarn projects, and lockfiles in
  subfolders, are not counted).
- Advisories are npm audit's (the GitHub Advisory Database).
- "Downgrade" compares with the copy at `node_modules/<name>`, the hoisted one; a nested copy
  can differ.
- "A same-line fix exists" is read from registry metadata, not from an install: an override
  can still break the parent, which was not tested with that version. Nothing here was
  resolved with npm.
- This is a measurement, not a criticism of npm or of any project.

## What it means for depquiet

The npm counterpart of the Python floor finding: the tool reports a fix, but the fix it
can apply is either impossible within ranges or worse than the problem. A depquiet npm fix
plan would say which parent's range holds the package back, flag downgrades, and propose a
scoped override on the same line, verified with npm on a temporary copy.
