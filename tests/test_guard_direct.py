"""A fix that only fits by moving one of the project's own dependencies back is left out.

Real case (depquiet-floor-test demo branch, 2026-11-27): the plan fixed mcp by
moving semgrep, a direct dependency, from 1.187.0 back to 1.136.0, and 16 other
packages with it. The pull request warned, but merging it would have quietly cost
51 semgrep releases. Now the other fixes go in and mcp is reported as held back.
"""

from __future__ import annotations

from pathlib import Path

import depquiet.fixplan as fp
from depquiet.dashboard import dashboard_markdown
from depquiet.fixcheck import FixCheck
from depquiet.fixplan import build_fix_plan
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
        'dependencies = ["pillow>=12", "semgrep>=1.100"]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.11"\n\n'
        '[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n'
        '[[package]]\nname = "pillow"\nversion = "12.2.0"\n\n'
        '[[package]]\nname = "semgrep"\nversion = "1.187.0"\n\n'
        '[[package]]\nname = "mcp"\nversion = "1.29.0"\n',
        encoding="utf-8",
    )
    return tmp_path


def _result() -> ScanResult:
    def r(package: str, version: str, fix: str) -> TriageResult:
        return TriageResult(
            Vulnerability(f"GHSA-{package}", package, version, Severity.HIGH, fix_version=fix),
            Verdict.ACTION,
        )

    return ScanResult(
        ".", "pip", 4, [r("mcp", "1.29.0", "1.30.0"), r("pillow", "12.2.0", "13.0.0")]
    )


def _checks() -> dict[str, FixCheck]:
    return {
        "mcp": FixCheck("resolves", "mcp", "1.30.0"),
        "pillow": FixCheck("resolves", "pillow", "13.0.0"),
    }


def _uv(monkeypatch, *, transitive: bool = False) -> None:
    moved = "click" if transitive else "semgrep"
    old, new = ("8.4.2", "8.1.8") if transitive else ("1.187.0", "1.136.0")

    def run(root: Path, executable: str, specs: list[str], timeout: int):
        lines = []
        if any(s.startswith("pillow") for s in specs):
            lines.append("Update pillow v12.2.0 -> v13.0.0")
        if any(s.startswith("mcp") for s in specs):
            lines.append("Update mcp v1.29.0 -> v1.30.0")
            lines.append(f"Update {moved} v{old} -> v{new}")
        return 0, "", "\n".join(lines) + "\n"

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)


def test_the_fix_that_moves_a_direct_dependency_back_is_left_out(tmp_path, monkeypatch) -> None:
    _uv(monkeypatch)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    assert [i.package for i in plan.included] == ["pillow"]
    mcp = next(i for i in plan.items if i.package == "mcp")
    assert not mcp.included
    assert mcp.needs_older == ["semgrep 1.187.0 → 1.136.0"]
    assert mcp.blocked_by == ["semgrep"]
    assert "fits only by moving semgrep back from 1.187.0 to 1.136.0" in mcp.why
    assert plan.downgrades == []
    assert plan.status == "partial"
    assert plan.to_dict()["left_out"][0]["needs_older"] == ["semgrep 1.187.0 → 1.136.0"]


def test_the_dashboard_says_an_older_release_allows_it(tmp_path, monkeypatch) -> None:
    _uv(monkeypatch)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    body = dashboard_markdown(_result(), plan, pr_line="")
    assert "**`semgrep`** holds back `mcp` (1 advisory)." in body
    assert "Only an older `semgrep` allows the fix (semgrep 1.187.0 → 1.136.0)" in body
    assert "No release of `semgrep`" not in body


def test_moving_a_transitive_package_back_still_only_warns(tmp_path, monkeypatch) -> None:
    _uv(monkeypatch, transitive=True)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    assert sorted(i.package for i in plan.included) == ["mcp", "pillow"]
    assert [c.package for c in plan.downgrades] == ["click"]


def test_both_kinds_of_holding_back_are_told_apart() -> None:
    scan = ScanResult(
        ".",
        "pip",
        3,
        [
            TriageResult(
                Vulnerability("A", "mcp", "1", Severity.HIGH, fix_version="2"), Verdict.ACTION
            ),
            TriageResult(
                Vulnerability("B", "wcmatch", "1", Severity.HIGH, fix_version="2"), Verdict.ACTION
            ),
        ],
    )
    plan = fp.FixPlan(
        "none",
        items=[
            fp.PlanItem(
                "mcp",
                "2",
                "1",
                blocked_by=["semgrep"],
                needs_older=["semgrep 1.187.0 → 1.136.0"],
                why="fits only by moving semgrep back",
            ),
            fp.PlanItem(
                "wcmatch",
                "2",
                "1",
                blocked_by=["semgrep"],
                why="blocked by semgrep, and no version of it allows the fix",
            ),
        ],
    )
    body = dashboard_markdown(scan, plan, pr_line="")
    assert (
        "**`semgrep`** holds back `mcp` (1 advisory). Only an older `semgrep` allows the fix"
        in body
    )
    assert "**`semgrep`** holds back `wcmatch` (1 advisory). No release of `semgrep`" in body
