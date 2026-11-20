# Benchmarks

Measured results behind the numbers in the README. Every figure here comes from a run whose script and output are in `benchmarks/`.

## On real projects

`pip-audit` on popular Python projects, at the commits that were their head on 2026-11-11,
audited again on 2026-11-15 with depquiet 0.47.0:

| Project | pip-audit alerts | Only reach dev tooling | Left to look at |
|:--|--:|--:|--:|
| [saleor](https://github.com/saleor/saleor) | 21 | 14 | 7 |
| [zulip](https://github.com/zulip/zulip) | 49 | 26 | 23 |
| [mlflow](https://github.com/mlflow/mlflow) | 21 | 14 | 7 |
| [langflow](https://github.com/langflow-ai/langflow) | 80 | 13 | 67 |
| [PostHog](https://github.com/PostHog/posthog) | 269 | 8 | 261 |

Every filtered alert has one reason: development-only paths in the lockfile, the only kind
of alert depquiet still filters. The same pip-audit report given to depquiet 0.39.0, which
first measured this table on 2026-11-11, gets the same verdict for every alert on all 18
projects measured: the counts grew because advisories were published in between, not
because depquiet changed. The 2026-11-11 dismissals were also checked by hand against a
separate walk of each `uv.lock`; most were `virtualenv` and `filelock` pulled in by
`pre-commit`. Details and the other projects: [benchmarks](#triage-on-six-real-projects).

Of the alerts left, many cannot be fixed by the upgrade the scanner names. Across 18 uv
projects on 2026-11-12, uv's resolver rejects the nearest fix for 502 of 991 kept alerts (51%), in 13 of
the 17 projects with alerts; in 81% of the blocked upgrades, the project's own pin is what
is in the way. See [`--check-fixes`](fix-plans.md#can-the-fix-be-installed---check-fixes).

For uv and Poetry projects depquiet goes one step further: [`--fix-plan`](fix-plans.md#one-verified-change-for-all-the-fixes---fix-plan)
computes the requirement changes that let the fixes install together and verifies them
with the project's own resolver, and the GitHub Action's
[`fix-pr`](fix-plans.md#one-pull-request-with-every-fix-that-installs-fix-pr) opens one pull request
with them. That includes the case where Dependabot reports that it "cannot update" the
dependency "to a non-vulnerable version": a parent package that must move before a
vulnerable dependency can.

On npm, `npm audit --omit=dev` already does this: depquiet matches it row for row on the
projects measured, and adds which direct dependency brings each kept alert in.

## Triage on six real projects

Six real projects: five popular open-source apps pinned to a commit, plus a small Express
app pinned to 2022 versions. npm projects are audited with `npm audit`, Python projects with
`pip-audit` on every version in their `uv.lock` / `poetry.lock`. Every verdict is listed in
[benchmarks/RESULTS.md](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/RESULTS.md).

| Project | Scanner | Alerts | Filtered by 0.27 | Filtered now | Filtered by 0.27, kept now |
|---|---|---:|---:|---:|---:|
| [mealie-recipes/mealie](https://github.com/mealie-recipes/mealie) | pip-audit | 229 | 200 | 31 | 170 |
| [hagopj13/node-express-boilerplate](https://github.com/hagopj13/node-express-boilerplate) | npm audit | 163 | 115 | 29 | 86 |
| [gothinkster/node-express-realworld-example-app](https://github.com/gothinkster/node-express-realworld-example-app) | npm audit | 95 | 59 | 41 | 18 |
| Express app, 2022 versions | npm audit | 29 | 26 | 8 | 18 |
| [paperless-ngx/paperless-ngx](https://github.com/paperless-ngx/paperless-ngx) | pip-audit | 17 | 17 | 0 | 17 |
| [sahat/hackathon-starter](https://github.com/sahat/hackathon-starter) | npm audit | 2 | 2 | 2 | 0 |
| **Total** | | **535** | **419 (78%)** | **111 (21%)** | **309** |

0.27 dismissed 309 alerts without evidence. It counted any package the app didn't import
itself as unreachable, which is true of nearly every transitive package, and it compared
Python distribution names literally, so `Django`, `PyYAML` or `llama-index-core` never matched
`import django`, `import yaml` or `import llama_index`.

What depquiet filters now is packages that only development tooling pulls in (jest,
eslint, nx, nodemon, pre-commit, mkdocs). On the npm projects those are the alerts
`npm audit --omit=dev` also removes. The realworld app declares `axios` under `dependencies`
but imports it only from its end-to-end tests; until 0.43 its 33 axios and form-data alerts
were filtered as test-only. They are now kept for review, because depquiet cannot tell that
case from a database driver a library loads at runtime. On these projects nearly every
other production dependency is in use, so the useful output is less the filtering than the trace: each kept
alert names the direct dependency it comes through and where the app uses it.

The same comparison on five larger projects at their head on 2026-11-10 (Kong/insomnia
`8891ce2`, open-webui `b0e6098`, saleor `ea4a69f`, uptime-kuma `fb8ef0f`, wekan `77239ee`;
188 npm alerts) gives the same picture: depquiet
filters the 85 alerts `npm audit --omit=dev` drops, row for row, and nothing else. On npm,
expect depquiet to match `--omit=dev` and explain the rest, not to beat it. Python is
different, because `pip-audit` has no equivalent switch. On 17 projects with a `uv.lock`,
at their head on 2026-11-11, `pip-audit` reported 1,004 alerts and depquiet filtered 72 as
development-only:

| Project | pip-audit alerts | Development-only, filtered |
|---|---:|---:|
| zulip | 43 | 26 |
| saleor | 16 | 14 |
| langflow | 70 | 11 |
| mlflow | 17 | 10 |
| PostHog | 255 | 8 |
| llama_index, open-webui, pydantic-ai | 188 | 3 |
| nine others (Chainlit, crewAI, litellm, ...) | 415 | 0 |

Each verdict was checked against a separate walk of the project's `uv.lock`, with the
dependency groups of every project read by hand to decide which are tooling: none of the 72
packages is reachable from a production dependency, an extra or a non-tooling group. The
same walk finds 21 more development-only alerts that depquiet keeps, most of them in
llama_index, whose integration packages each declare their own dependencies.

That hand reading matters. A dependency group is only a named list: zulip keeps everything
its servers run in a group called `prod`, and PostHog keeps optional features in groups
such as `sentiment`. depquiet treats a group as development-only when its name says so
(`dev`, `test`, `docs`, `lint`...) and as production otherwise; up to 0.33.1 it treated
every group as development-only and filtered all 43 zulip alerts, 17 of them wrongly.
A group listed in uv's `tool.uv.default-groups` (or every group, with `"all"`) is
production whatever its name, except `dev`: `uv sync --no-dev`, the usual production
install, still installs the other default groups. For Poetry, depquiet assumes production installs
with `poetry install --only main`: `--without dev` would still install a non-optional `docs`
or `test` group, which depquiet then filters.

Nothing else was filtered: every one of these projects has a dynamic import somewhere,
which keeps the unused-dependency filter off.

**Remeasured on 2026-11-15** with depquiet 0.47.0, at the same commits, in a disposable VM
([`remeasure.sh`](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/fixcheck_study/remeasure.sh)),
on the 18 projects of the [fix-check study](fix-plans.md#can-the-fix-be-installed---check-fixes): one
pip-audit report per project, given to both 0.39.0 and 0.47.0. No verdict differs on any of
them. Since that study's run on 2026-11-12, alerts went from 1,127 to 1,228 as advisories
were published, and filtered alerts from 104 to 114, every one of them for development-only
paths:

| Project | pip-audit alerts | Development-only, filtered |
|---|---:|---:|
| flask | 34 | 32 |
| zulip | 49 | 26 |
| saleor | 21 | 14 |
| mlflow | 21 | 14 |
| langflow | 80 | 13 |
| PostHog | 269 | 8 |
| litellm | 57 | 4 |
| redash, open-webui, llama_index | 237 | 3 |
| eight others (Chainlit, crewAI, mitmproxy, ...) | 460 | 0 |

The 10 newly filtered alerts (mlflow 4, litellm 4, langflow 2) were not checked by hand
like the 72 above.

If your project is on uv, uv 0.13 ships `uv audit` (still experimental), and
`uv audit --no-dev` excludes the development group natively. depquiet reads `uv audit`
output too: `depquiet --scanner uv`, or automatically when uv is installed and pip-audit is
not. What it adds on top is the rest of the triage: every group judged by its name rather
than only `dev`, the direct dependency that brings each alert in, EPSS, and npm or pnpm
dependencies in the same run.

Run them yourself: `python -I benchmarks/run_benchmark.py`. The first run clones the pinned
commits into `benchmarks/.cache/`; `benchmarks/capture_real.py` re-captures the audits. The
synthetic fixtures in the same report are parser regression tests, not evidence.

## Reference evaluator

depquiet ingests reports from npm audit, pip-audit, Trivy, Grype, Dependabot,
Snyk and SARIF-producing tools. It adds dependency/import context, configurable
priorities and decision history, and can query OSV directly from lockfiles.

The alert-reduction figures above describe captured scans; they do not establish
false-positive rates or superiority over another scanner. The new
[reference evaluator](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/reference/README.md) checks labelled cases,
including missing findings and unsafe dismissals. Two explicitly synthetic
contract examples exercise its mechanics:

```bash
python benchmarks/reference/run.py --output synthetic-scan.json
python benchmarks/evaluate.py --labels benchmarks/reference/synthetic.labels.json --scan synthetic-scan.json --snapshot benchmarks/reference/synthetic.snapshot.json --json
```

The separate [upstream reference set](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/reference/real/README.md) contains
10 selected advisory contexts from four pinned npm/Python projects, with frozen
audits, source hashes and review evidence. CI checks that five `retain` and five
`unknown` cases remain visible. Labels are agent-reviewed; human review is pending.

A separate [configuration extension](https://github.com/samuelrojas-dev/depquiet/blob/main/benchmarks/reference/extensions/README.md)
adds two identities from the same pinned RealWorld project, preserving the original
inputs. The combined deliberate sample has 12 contexts: six `retain`, six
`unknown`, no `filter` labels and no human adjudications. It does not measure safe
noise reduction.

The [review workflow](https://github.com/samuelrojas-dev/depquiet/blob/main/docs/reference-reviews.md) prepares pending records, binds
them to exact label/snapshot/case identities and reports caller-declared human,
external and agent coverage separately. Disagreements remain uncertain; a human
`filter` record cannot weaken a proposed `retain` or `unknown`. Optional coverage
gates require explicit records without treating metadata as authenticated review.
There are no real `filter` labels, so this set does not measure safe dismissal,
full-project coverage or real-world accuracy. Replay requires no upstream code
execution or package installation.
