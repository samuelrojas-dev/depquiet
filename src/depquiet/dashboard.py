"""One answer for every open alert: the dashboard issue.

A Dependabot alert that Dependabot cannot fix stays open with "cannot update
to a non-vulnerable version", and someone has to find out why, alert by
alert. The dashboard puts every vulnerable package of the scan in one of a few
states, each with what to do:

- fixed in the fix pull request (the verified plan);
- held back by another package that no release of lets the fix in, so only
  that package can unblock it (wagtail, 2026-11-27: semgrep held back mcp,
  opentelemetry-api and wcmatch);
- needs a change in the project (a newer Python, a requirement depquiet could
  not edit), with the verified option when there is one;
- no fixed version reported by the scan;
- deprioritized (development-only, test-only, unreachable, ...), never
  dismissed: the reader decides.

It is built from depquiet's own scan, not from GitHub's alerts: a workflow's
GITHUB_TOKEN gets 403 on the Dependabot alerts API, with or without
security-events (tested on depquiet-floor-test, 2026-11-27). So the counts can
differ a little from the Security tab, which uses GitHub's advisory database.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from depquiet.fixcheck import _pep503
from depquiet.fixplan import FixPlan, PlanItem
from depquiet.models import FilterReason, ScanResult, Verdict, first_items, version_key

TITLE = "depquiet: dependency alerts"
# The Action replaces it with the fix pull request's URL once it exists.
PR_PLACEHOLDER = "{{DEPQUIET_FIX_PR_URL}}"

_FILTER_TEXT = {
    FilterReason.DEV_DEPENDENCY: "reaches the project only through development dependencies",
    FilterReason.TEST_ONLY: "imported only from tests",
    FilterReason.UNREACHABLE: "not imported by your code",
    FilterReason.LOW_EPSS: "low exploit probability (EPSS)",
    FilterReason.COMMUNITY_TEMPLATE: "matched a community template",
    FilterReason.IGNORED: "ignored in your depquiet configuration",
}


@dataclass
class _Package:
    name: str
    advisories: list[str] = field(default_factory=list)
    fix_version: str = ""
    # npm audit: the fix is often a new version of the parent that pulls the
    # package in, not of the package itself (wagtail: immutable's fix is a parent).
    fix_package: str = ""
    fix_in_range: bool = False  # npm: ``npm audit fix`` fixes it, no version named
    filtered: list[str] = field(default_factory=list)  # why, when every result was filtered
    open: bool = False  # at least one ACTION or REVIEW result


def _packages(result: ScanResult) -> dict[str, _Package]:
    found: dict[str, _Package] = {}
    for r in result.results:
        key = _pep503(r.vuln.package)
        pkg = found.setdefault(key, _Package(r.vuln.package))
        if r.vuln.cve not in pkg.advisories:
            pkg.advisories.append(r.vuln.cve)
        pkg.fix_in_range = pkg.fix_in_range or r.vuln.fix_in_range
        if r.vuln.fix_version and not pkg.fix_version:
            pkg.fix_version = r.vuln.fix_version
            pkg.fix_package = r.vuln.fix_package
        if r.verdict is Verdict.FILTERED:
            for reason in r.reasons:
                text = (
                    r.template_reason
                    if reason is FilterReason.COMMUNITY_TEMPLATE and r.template_reason
                    else _FILTER_TEXT.get(reason, reason.value)
                )
                if text not in pkg.filtered:
                    pkg.filtered.append(text)
        else:
            pkg.open = True
    return found


def _count(n: int, word: str, plural: str = "") -> str:
    return f"{n} {word if n == 1 else plural or word + 's'}"


def _advisories(n: int) -> str:
    return _count(n, "advisory", "advisories")


def _row(pkg: _Package) -> str:
    return _advisories(len(pkg.advisories))


def dashboard_markdown(
    result: ScanResult,
    plan: FixPlan | None,
    version: str = "",
    date: str = "",
    pr_line: str | None = None,
    installed: dict[str, str] | None = None,
) -> str:
    """The dashboard issue body.

    ``pr_line`` replaces the line that links the fix pull request; None leaves
    the placeholder for the Action to fill once the pull request exists.
    ``installed`` (top-level npm package -> locked version) lets a fix through a
    parent that would move the parent back be shown as what it is: npm audit
    offered wagtail draftail 1.1.0 while 2.0.1 was installed (2026-11-27).
    """
    installed = installed or {}
    packages = _packages(result)
    items: dict[str, PlanItem] = {_pep503(i.package): i for i in (plan.items if plan else [])}
    floor = plan.python_floor if plan else None

    fixed: list[tuple[_Package, PlanItem]] = []
    # (blocker, "semgrep 1.187.0 → 1.136.0" when an older release of it allows the fix)
    held: dict[tuple[str, str], list[_Package]] = {}
    change: list[tuple[_Package, str]] = []
    no_fix: list[_Package] = []
    has_fix: list[_Package] = []
    filtered: list[_Package] = []
    for key, pkg in sorted(packages.items()):
        if not pkg.open:
            filtered.append(pkg)
            continue
        item = items.get(key)
        if item is not None and item.included:
            fixed.append((pkg, item))
        elif item is not None and item.blocked_by:
            for blocker in item.blocked_by:
                older = next((n for n in item.needs_older if n.startswith(f"{blocker} ")), "")
                held.setdefault((blocker, older), []).append(pkg)
        elif item is not None and floor is not None and item.package in floor.unblocked:
            option = f"raising requires-python to >={floor.floor} lets it install (verified)"
            if floor.lock_environment:
                option += (
                    f"; for a library, `[tool.uv] environments = "
                    f'["{floor.lock_environment}"]` instead (verified; Dependabot does not '
                    "read it, the fix-pr Action does)"
                )
            change.append((pkg, f"needs a newer Python: {option}"))
        elif item is not None and item.why:
            change.append((pkg, item.why))
        elif not pkg.fix_version and not pkg.fix_in_range:
            no_fix.append(pkg)
        elif (
            pkg.fix_package
            and (now := installed.get(_pep503(pkg.fix_package)))
            and version_key(pkg.fix_version) < version_key(now)
        ):
            change.append(
                (
                    pkg,
                    f"npm audit's only fix moves `{pkg.fix_package}` back from {now} to "
                    f"{pkg.fix_version}; not offered. `depquiet --fix-plan` looks for an "
                    "override that keeps it.",
                )
            )
        else:
            has_fix.append(pkg)

    def advisories(group: list[_Package]) -> int:
        return sum(len(p.advisories) for p in group)

    held_pkgs = list({p.name: p for ps in held.values() for p in ps}.values())
    rows = [
        ("✅ Fixed in the fix pull request", [p for p, _ in fixed]),
        ("⛓ Held back by another package", held_pkgs),
        ("🔧 Needs a change in your project", [p for p, _ in change]),
        ("🆙 Fixed release available", has_fix),
        ("⏳ No fixed version reported", no_fix),
        ("💤 Deprioritized (not dismissed)", filtered),
    ]
    total = advisories(list(packages.values()))
    stamp = ", ".join(x for x in (date, f"depquiet {version}" if version else "") if x)
    lines = [
        "## Every open alert, and what to do about it",
        "",
        f"{_advisories(total)} in "
        f"{_count(len(packages), 'package')}" + (f" ({stamp})." if stamp else "."),
        "",
        "| | Packages | Advisories |",
        "|---|---|---|",
    ]
    lines += [f"| {label} | {len(group)} | {advisories(group)} |" for label, group in rows if group]
    if not packages:
        lines = ["## Every open alert, and what to do about it", "", "No open advisories."]

    if fixed:
        link = PR_PLACEHOLDER if pr_line is None else pr_line
        lines += ["", "### ✅ Fixed in the fix pull request", "", link, ""]
        # A fix that only fits by moving other packages back is not free: on
        # depquiet-floor-test, fixing mcp moved semgrep 1.187.0 back to 1.136.0.
        warning = plan.downgrade_warning() if plan else ""
        if warning:
            lines += [f"⚠ {warning}", ""]
        needs = plan.needs_newer_python if plan else {}
        for pkg, item in fixed:
            note = (
                f" Dependabot cannot open this one: it needs Python >={needs[item.package]}."
                if item.package in needs
                else ""
            )
            lines.append(
                f"- `{pkg.name}` {item.installed or '?'} → {item.version} ({_row(pkg)}).{note}"
            )
    if held:
        lines += ["", "### ⛓ Held back by another package", ""]
        for (blocker, older), pkgs in sorted(held.items(), key=lambda kv: -advisories(kv[1])):
            names = first_items([f"`{p.name}`" for p in pkgs], 6)
            count = _advisories(advisories(pkgs))
            if older:
                lines.append(
                    f"- **`{blocker}`** holds back {names} ({count}). Only an older `{blocker}` "
                    f"allows the fix ({older}): moving your own dependency back is your call, so "
                    "the fix pull request leaves it out."
                )
            else:
                lines.append(
                    f"- **`{blocker}`** holds back {names} ({count}). No release of `{blocker}` "
                    f"lets these fixes in yet, so only a change in `{blocker}` unblocks them: "
                    "nothing in this project can."
                )
    if change:
        lines += ["", "### 🔧 Needs a change in your project", ""]
        lines += [f"- `{p.name}` ({_row(p)}): {why}" for p, why in change]
    if has_fix:
        lines += ["", "### 🆙 Fixed release available", ""]
        lines += [
            f"- `{p.name}` ({_row(p)}): upgrade `{p.fix_package}` to {p.fix_version}, "
            "which pulls in the fix."
            if p.fix_package and _pep503(p.fix_package) != _pep503(p.name)
            else f"- `{p.name}` ({_row(p)}): `npm audit fix` updates it within your declared "
            "ranges."
            if not p.fix_version
            else f"- `{p.name}` → {p.fix_version} ({_row(p)})"
            for p in has_fix
        ]
    if no_fix:
        lines += ["", "### ⏳ No fixed version reported", ""]
        lines += [f"- `{p.name}` ({_row(p)}): the scan reported no fixed version." for p in no_fix]
    if filtered:
        lines += [
            "",
            "### 💤 Deprioritized (not dismissed)",
            "",
            "depquiet lowers these, it does not dismiss them: review before ignoring.",
            "",
        ]
        lines += [f"- `{p.name}` ({_row(p)}): {'; '.join(p.filtered)}." for p in filtered]
    lines += [
        "",
        "---",
        "Updated by the [depquiet](https://github.com/samuelrojas-dev/depquiet) Action on every "
        "run: edits to this issue are overwritten. Counts come from depquiet's own scan of the "
        "lockfile, so they can differ a little from the Security tab.",
    ]
    return "\n".join(lines) + "\n"
