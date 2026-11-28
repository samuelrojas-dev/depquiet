"""Auto-remediation — upgrade vulnerable packages to their fix versions.

Examines ACTION triage results that have a known ``fix_version`` and runs
the appropriate package manager command to upgrade them. Only touches
packages where the verdict is ACTION (not REVIEW or FILTERED) and a fix
is available, so the blast radius is minimal.

Projects with a uv.lock, poetry.lock or package-lock.json never get here: the
CLI applies the verified fix plan for them (``--fix-plan --apply``), one
version per package, checked together, and never a direct dependency moved
back. This module is what is left for other projects. Python projects without
a lock are not fixed: ``pip install`` would change whatever environment
depquiet runs in and leave the requirement files as they are, so the alert
would come back. They are listed with the requirement to change.

One upgrade per package, to the highest fix its alerts name: running one per
fix version moved soupsieve to 4.0.0 and then back to 3.0.2 (depquiet-floor-test,
2026-11-27), and reported both as fixed.

Usage::

    depquiet --fix              # scan + auto-fix ACTION items
    depquiet --fix --dry-run    # show what would be fixed without changing anything
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from depquiet.fixcheck import FixCheck, _classify, _explain
from depquiet.models import ScanResult, TriageResult, Verdict, clip, first_items, version_key


@dataclass
class FixResult:
    """Outcome of a single package fix attempt."""

    package: str
    from_version: str
    to_version: str
    cve: str
    success: bool
    message: str = ""
    alerts: int = 1  # the package's alerts this one upgrade covers


@dataclass
class FixReport:
    """Summary of all fix attempts."""

    fixed: list[FixResult] = field(default_factory=list)
    skipped: list[FixResult] = field(default_factory=list)
    failed: list[FixResult] = field(default_factory=list)
    # Fixes depquiet cannot apply itself: the change to make by hand.
    manual: list[FixResult] = field(default_factory=list)

    @property
    def total_fixable(self) -> int:
        return len(self.fixed) + len(self.failed)


def find_fixable(scan_result: ScanResult) -> list[TriageResult]:
    """One ACTION result per package to upgrade: the one naming its highest fix."""
    return [
        max(group, key=lambda t: version_key(t.vuln.fix_version)) for group in _groups(scan_result)
    ]


def _groups(scan_result: ScanResult) -> list[list[TriageResult]]:
    """ACTION results with a fix, grouped by the package that carries the fix."""
    groups: dict[str, list[TriageResult]] = {}
    for tr in scan_result.results:
        if tr.verdict == Verdict.ACTION and tr.vuln.fix_version:
            groups.setdefault(tr.vuln.fix_package or tr.vuln.package, []).append(tr)
    return list(groups.values())


def apply_fixes(
    scan_result: ScanResult,
    project: Path,
    *,
    dry_run: bool = False,
) -> FixReport:
    """Apply fixes for ACTION items with known fix versions.

    Args:
        scan_result: Result of a depquiet scan.
        project: Path to the project root.
        dry_run: If True, report what would be fixed without running commands.

    Returns:
        FixReport with results of each fix attempt.
    """
    report = FixReport()
    pm = scan_result.package_manager

    for group in _groups(scan_result):
        tr = max(group, key=lambda t: version_key(t.vuln.fix_version))
        # Upgrade the package that carries the fix (for npm, often the direct
        # parent), never pin a transitive package as a new direct dependency.
        pkg = tr.vuln.fix_package or tr.vuln.package
        fix_ver = tr.vuln.fix_version
        from_ver = tr.vuln.version
        cve = first_items([t.vuln.cve for t in group], 3)

        manager = _manager(tr.vuln.package_manager or pm, project)
        if manager == "pip":
            report.manual.extend(
                FixResult(
                    package=pkg,
                    from_version=t.vuln.version,
                    to_version=t.vuln.fix_version,
                    cve=t.vuln.cve,
                    success=False,
                    message=(
                        f"require {pkg}>={fix_ver} where the project pins {pkg}, then reinstall"
                    ),
                )
                for t in group
            )
            continue
        if dry_run:
            cmd_str = _build_command_str(manager, pkg, fix_ver)
            report.fixed.append(
                FixResult(
                    package=pkg,
                    from_version=from_ver,
                    to_version=fix_ver,
                    cve=cve,
                    success=True,
                    message=f"Would run: {cmd_str}",
                    alerts=len(group),
                )
            )
            continue

        result = _run_fix(manager, pkg, fix_ver, project)
        if result.success:
            report.fixed.append(
                FixResult(
                    package=pkg,
                    from_version=from_ver,
                    to_version=fix_ver,
                    cve=cve,
                    success=True,
                    message=result.message,
                    alerts=len(group),
                )
            )
        else:
            report.failed.append(
                FixResult(
                    package=pkg,
                    from_version=from_ver,
                    to_version=fix_ver,
                    cve=cve,
                    success=False,
                    message=result.message,
                    alerts=len(group),
                )
            )

    # Report ACTION items without a fix version
    for tr in scan_result.action:
        if not tr.vuln.fix_version:
            report.skipped.append(
                FixResult(
                    package=tr.vuln.package,
                    from_version=tr.vuln.version,
                    to_version="",
                    cve=tr.vuln.cve,
                    success=False,
                    message="No fix version available",
                )
            )

    return report


def _manager(manager: str, project: Path) -> str:
    """A Python alert in a project with a uv.lock is fixed in the lockfile."""
    if manager in ("pip", "uv") and (project / "uv.lock").is_file():
        return "uv"
    return manager


def _build_command_str(pm: str, package: str, fix_version: str) -> str:
    """Build the shell command string for display."""
    if pm == "uv":
        return f"uv lock --upgrade-package {package}=={fix_version}"
    # Default to npm-style
    return f"npm install {package}@{fix_version}"


@dataclass
class _CmdResult:
    success: bool
    message: str


def _run_fix(pm: str, package: str, fix_version: str, project: Path) -> _CmdResult:
    """Run the package manager command to fix a vulnerability."""
    if pm == "uv":
        # Raise the locked version; pyproject.toml ranges stay as written.
        cmd = ["uv", "lock", "--upgrade-package", f"{package}=={fix_version}"]
    else:
        cmd = ["npm", "install", f"{package}@{fix_version}"]

    try:
        result = subprocess.run(
            cmd,
            cwd=project,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            done = "uv.lock updated; run uv sync" if pm == "uv" else "updated"
            return _CmdResult(success=True, message=f"{package} {fix_version}: {done}")
        if pm == "uv" and "No solution found" in f"{result.stdout}{result.stderr}":
            check = FixCheck("blocked", package, fix_version, _explain(result.stderr))
            _classify(check, result.stderr)
            return _CmdResult(
                success=False,
                message=f"blocked: {check.next_step or clip(check.detail, 200)}",
            )
        return _CmdResult(
            success=False,
            message=(
                f"Command failed (exit {result.returncode}): {clip(result.stderr.strip(), 200)}"
            ),
        )
    except FileNotFoundError:
        return _CmdResult(success=False, message=f"Command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return _CmdResult(success=False, message="Command timed out after 120s")


def print_fix_report(report: FixReport, *, dry_run: bool = False) -> None:
    """Print a human-readable fix report to stderr."""
    prefix = "[dry-run] " if dry_run else ""

    if report.fixed and dry_run:
        # Nothing ran, and nothing was resolved: these are attempts, not fixes.
        print(
            f"\n{prefix}Would try {_n(len(report.fixed), 'upgrade')}. Not run and not checked "
            "against the resolver: --check-fixes shows which of them can install.",
            file=sys.stderr,
        )
        for r in report.fixed:
            print(
                f"   {r.cve}  {r.package} {r.from_version} → {r.to_version}: {r.message}",
                file=sys.stderr,
            )
    elif report.fixed:
        alerts = sum(r.alerts for r in report.fixed)
        print(
            f"\n{prefix}✅ Upgraded {_n(len(report.fixed), 'package')} "
            f"({_n(alerts, 'alert')}); scan again to confirm what is closed:",
            file=sys.stderr,
        )
        for r in report.fixed:
            print(
                f"   {r.package} {r.from_version} → {r.to_version}  ({r.cve})",
                file=sys.stderr,
            )

    if report.failed:
        print(f"\n{prefix}❌ Failed to fix {len(report.failed)}:", file=sys.stderr)
        for r in report.failed:
            print(f"   {r.cve}  {r.package}: {r.message}", file=sys.stderr)

    if report.manual:
        print(
            f"\n{prefix}✋ {len(report.manual)} advisories in "
            f"{len({m.package for m in report.manual})} packages to fix by hand "
            "(depquiet edits no requirement files):",
            file=sys.stderr,
        )
        for line in _manual_lines(report.manual):
            print(f"   {line}", file=sys.stderr)

    if report.skipped:
        print(
            f"\n{prefix}⚠️  {len(report.skipped)} ACTION items have no fix available:",
            file=sys.stderr,
        )
        for r in report.skipped:
            print(f"   {r.cve}  {r.package} {r.from_version}", file=sys.stderr)


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _manual_lines(items: list[FixResult]) -> list[str]:
    """One line per package: the version that clears all of its listed advisories."""
    by_package: dict[str, list[FixResult]] = {}
    for item in items:
        by_package.setdefault(item.package, []).append(item)
    lines = []
    for package, group in by_package.items():
        target = max((g.to_version for g in group), key=version_key)
        ids = ", ".join(g.cve for g in group)
        count = f"{len(group)} advisories" if len(group) > 1 else "1 advisory"
        lines.append(
            f"{package} {group[0].from_version}: require {package}>={target} where the project "
            f"pins {package}, then reinstall ({count}: {ids})"
        )
    return lines
