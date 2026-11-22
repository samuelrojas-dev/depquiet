"""Partial fixes: the newest fix that installs on the current Python, when the full one needs more.

Real case (depquiet-floor-test, 2026-11-20): requires-python >=3.10, soupsieve 2.8.3
with 8 advisories. 5 are fixed by releases that install on 3.10 (2.8.4 to 2.10), 3
only by releases that need 3.11.5. Dependabot reported "cannot update" for all of
them; uv resolves soupsieve 2.10 on 3.10, which closes the 5.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck, _classify
from depquiet.fixplan import build_fix_plan, fix_plan_markdown, print_fix_plan
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

UV_FLOOR_ERROR = """hint: The `requires-python` value (>=3.10) includes Python versions that \
are not supported by your dependencies (e.g., soupsieve==4.0 only supports >=3.11.5). \
Consider using a more restrictive `requires-python` value (like >=3.11.5).
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.10"\n'
        'dependencies = ["beautifulsoup4>=4.13"]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.10"\n\n'
        '[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n'
        '[[package]]\nname = "beautifulsoup4"\nversion = "4.15.0"\n\n'
        '[[package]]\nname = "soupsieve"\nversion = "2.8.3"\n',
        encoding="utf-8",
    )
    return tmp_path


def _result() -> ScanResult:
    fixes = [("A", "2.8.4"), ("B", "2.9.0"), ("C", "2.10.0"), ("D", "3.0.2"), ("E", "4.0.0")]
    return ScanResult(
        project_path=".",
        package_manager="pip",
        total_dependencies=2,
        results=[
            TriageResult(
                vuln=Vulnerability(f"GHSA-{i}", "soupsieve", "2.8.3", Severity.HIGH, fix_version=f),
                verdict=Verdict.ACTION,
            )
            for i, f in fixes
        ],
    )


def _checks() -> dict[str, FixCheck]:
    check = FixCheck("blocked", "soupsieve", "4.0.0")
    _classify(check, UV_FLOOR_ERROR)
    return {"soupsieve": check}


def _uv(monkeypatch, installs_on_310: tuple[str, ...] = ("2.8.4", "2.9.0", "2.10.0")):
    """Like uv: soupsieve releases up to 2.10 install on 3.10, 3.0.2 and up need 3.11.5."""
    calls: list[list[str]] = []

    def run(root: Path, executable: str, specs: list[str], timeout: int):
        calls.append(list(specs))
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        wanted = [s.split("==")[1] for s in specs if s.startswith("soupsieve==")]
        if '">=3.10"' in text and any(v not in installs_on_310 for v in wanted):
            return 1, "", UV_FLOOR_ERROR
        target = wanted[0] if wanted else "2.8.3"
        return 0, f"Update soupsieve v2.8.3 -> v{target}\n", ""

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)
    return calls


def test_the_newest_fix_on_the_current_python_goes_in_the_plan(tmp_path, monkeypatch) -> None:
    _uv(monkeypatch)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    [partial] = plan.included
    assert (partial.package, partial.installed, partial.version) == ("soupsieve", "2.8.3", "2.10.0")
    assert partial.partial == "closes 3 of 5 alerts; the other 2 need Python >=3.11.5"
    [blocked] = plan.left_out
    assert blocked.version == "4.0.0" and "3.11.5" in blocked.why
    assert plan.status == "partial"
    assert plan.command == "uv lock --upgrade-package soupsieve==2.10.0"
    assert plan.python_floor is not None and plan.python_floor.unblocked == ["soupsieve"]
    assert plan.to_dict()["included"][0]["partial"] == partial.partial


def test_the_pr_description_lists_only_the_advisories_the_partial_fix_closes(
    tmp_path, monkeypatch
) -> None:
    _uv(monkeypatch)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    row = next(line for line in fix_plan_markdown(plan, _result()).splitlines() if "2.10.0" in line)
    assert "GHSA-A, GHSA-B, GHSA-C" in row
    assert "GHSA-D" not in row and "GHSA-E" not in row
    assert "closes 3 of 5 alerts" in row


def test_terminal_output_says_partial(tmp_path, monkeypatch, capsys) -> None:
    import sys

    _uv(monkeypatch)
    print_fix_plan(build_fix_plan(_result(), _project(tmp_path), _checks()), sys.stdout)
    out = capsys.readouterr().out
    assert "✓ soupsieve 2.8.3 → 2.10.0: the newest fix your Python range allows" in out
    assert "✗ soupsieve → 4.0.0" in out
    assert "1 partial fix on your current Python range resolves" in out


def test_a_partial_fix_that_does_not_resolve_falls_back_to_the_next(tmp_path, monkeypatch) -> None:
    calls = _uv(monkeypatch, installs_on_310=("2.8.4", "2.9.0"))
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    [partial] = plan.included
    assert partial.version == "2.9.0"
    assert partial.partial == "closes 2 of 5 alerts; the other 3 need Python >=3.11.5"
    assert ["soupsieve==2.10.0"] in calls


def test_no_partial_fix_when_the_floor_is_raised(tmp_path, monkeypatch) -> None:
    _uv(monkeypatch)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    assert all(not i.partial for i in plan.items)


@pytest.mark.parametrize("installed", ["2.10.0", "4.0.0"])
def test_no_partial_fix_below_what_is_installed(tmp_path, monkeypatch, installed) -> None:
    project = _project(tmp_path)
    lock = project / "uv.lock"
    lock.write_text(lock.read_text().replace('"2.8.3"', f'"{installed}"'), encoding="utf-8")
    _uv(monkeypatch)
    plan = build_fix_plan(_result(), project, _checks())
    assert all(not i.partial for i in plan.items)


def test_trailing_zeros_do_not_make_a_release_newer() -> None:
    """Poetry locks soupsieve "2.10"; the advisory's fix says "2.10.0"."""
    from depquiet.models import version_key

    assert version_key("2.10.0") == version_key("2.10")
    assert version_key("2.10") < version_key("2.10.1") < version_key("3")
    assert version_key("4.0.0") > version_key("3.0.4")


def _forking_uv(monkeypatch, report: str = "Update soupsieve v2.8.3 -> v2.10.0, v4.0.0\n"):
    """Like uv on FinanceDatabase: asked for soupsieve by name, it forks the lock at 3.11.5."""
    calls = _uv(monkeypatch)
    pinned = fp._run_lock

    def run(root: Path, executable: str, specs: list[str], timeout: int):
        if "soupsieve" in specs:
            calls.append(list(specs))
            return 0, report, ""
        return pinned(root, executable, specs, timeout)

    monkeypatch.setattr(fp, "_run_lock", run)
    return calls


def test_a_forked_lock_gives_newer_pythons_the_full_fix(tmp_path, monkeypatch) -> None:
    """FinanceDatabase PR 269: requires-python kept, 4.1.3 on 3.11.5+, 2.10 below."""
    _forking_uv(monkeypatch)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    [fix] = plan.included
    assert (fix.version, fix.forked_below) == ("4.0.0", "2.10.0")
    assert fix.partial == (
        "Python >=3.11.5 gets 4.0.0, which closes all 5 alerts; older Pythons keep 2.10.0, "
        "which closes 3"
    )
    assert plan.command == "uv lock --upgrade-package soupsieve"
    assert plan.diff == ""  # pyproject.toml is not touched
    assert plan.to_dict()["included"][0]["forked_below"] == "2.10.0"
    row = next(line for line in fix_plan_markdown(plan, _result()).splitlines() if "4.0.0" in line)
    assert "GHSA-E" in row and "uv locks one release per Python range" in row


def test_terminal_output_names_both_copies(tmp_path, monkeypatch, capsys) -> None:
    import sys

    _forking_uv(monkeypatch)
    print_fix_plan(build_fix_plan(_result(), _project(tmp_path), _checks()), sys.stdout)
    out = capsys.readouterr().out
    assert "✓ soupsieve 2.8.3 → 4.0.0: requires-python unchanged" in out
    assert "older Pythons keep 2.10.0" in out


@pytest.mark.parametrize(
    "report",
    [
        "Update soupsieve v2.8.3 -> v4.0.0\n",  # no fork
        "Update soupsieve v2.8.3 -> v2.8.3, v3.0.2\n",  # bottom copy does not move
        "Update soupsieve v2.8.3 -> v2.10.0, v3.0.2\n",  # top copy short of the full fix
        "Update soupsieve v2.8.3 -> v2.10.0, v4.0.0\nUpdate beautifulsoup4 v4.15.0 -> v4.6.3\n",
    ],
)
def test_a_fork_that_falls_short_falls_back_to_the_pinned_partial_fix(
    tmp_path, monkeypatch, report
) -> None:
    _forking_uv(monkeypatch, report)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    [partial] = plan.included
    assert (partial.version, partial.forked_below) == ("2.10.0", "")
    assert plan.command == "uv lock --upgrade-package soupsieve==2.10.0"
