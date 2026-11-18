"""A fix held back by the project's Python floor gets a verified plan, not just a report.

Seen on real projects: Dependabot fails again and again to update pytest on a
project that declares ``requires-python >=3.9`` while running on 3.12, and
maintainers open hand-written "raise the Python floor and relock" pull requests
to clear their alerts. Before this, ``--fix-plan`` said "raise requires-python"
and stopped.

Now it raises the floor on a copy, asks uv's resolver again, and says how many
fixes that lets install. Dropping a Python version is the maintainer's call, so
the edit goes into the diff only with ``--raise-python-floor``.

The resolver answers below are the ones uv 0.11 gave on a real project with
``requires-python = ">=3.9"`` and pytest locked twice (8.4.2 for 3.9, 9.2.0
for 3.10+).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck, _classify, _updates
from depquiet.fixplan import (
    _set_requires_python,
    _uv_lock_changes,
    build_fix_plan,
    dropped_pythons,
    raise_floor,
)
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

UV_FLOOR_ERROR = """  \u00d7 No solution found when resolving dependencies for split (markers:
  │ python_full_version == '3.9.*'):
  ╰─▶ Because the requested Python version (>=3.9) does not satisfy
      Python>=3.10 and pytest==9.0.0 depends on Python>=3.10, we can conclude
      that pytest==9.0.0 cannot be used.

hint: The `requires-python` value (>=3.9) includes Python versions that are not supported by \
your dependencies (e.g., pytest==9.0.0 only supports >=3.10). Consider using a more restrictive \
`requires-python` value (like >=3.10).
"""

UV_RAISED_REPORT = """Resolved 11 packages in 103ms
Update iniconfig v2.1.0, v2.3.1 -> v2.3.1
Update pluggy v1.6.0, v1.7.0 -> v1.7.0
Update pytest v8.4.2, v9.2.0 -> v9.2.0
Update tornado v6.4.1 -> v6.5
"""

# --- reading uv's answer -------------------------------------------------------


def test_the_check_records_the_floor_the_fix_needs() -> None:
    check = FixCheck("blocked", "pytest", "9.0.0")
    _classify(check, UV_FLOOR_ERROR)
    assert check.reason == "python" and check.python_floor == "3.10"
    assert "--fix-plan checks" in check.next_step
    assert check.to_dict()["python_floor"] == "3.10"


def test_an_upper_python_bound_is_not_a_floor() -> None:
    check = FixCheck("blocked", "x", "2.0")
    _classify(check, "hint: (e.g., x==2.0 only supports <3.13)")
    assert check.reason == "python" and check.python_floor == ""
    assert "--fix-plan" not in check.next_step


def test_forked_lock_updates_are_read() -> None:
    assert "pytest v8.4.2, v9.2.0 -> v9.2.0" in _updates(UV_RAISED_REPORT)
    changes = _uv_lock_changes(UV_RAISED_REPORT, [fp.PlanItem("pytest", "9.2.0")])
    assert [c.describe() for c in changes][:2] == [
        "iniconfig 2.1.0, 2.3.1 → 2.3.1",
        "pluggy 1.6.0, 1.7.0 → 1.7.0",
    ]


# --- the requires-python edit --------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "floor", "expected"),
    [
        (">=3.9", "3.10", ">=3.10"),
        (">=3.9,<4", "3.10", ">=3.10,<4"),
        (">=3.8, <4.0", "3.11", ">=3.11, <4.0"),
        (">=3.12", "3.10", ">=3.12"),  # already high enough
        ("<4", "3.10", ">=3.10,<4"),
        (">=3.9,<3.10", "3.10", None),  # the upper bound excludes the new floor
        ("~=3.9", "3.10", None),  # for a person to rewrite
        ("==3.9.*", "3.10", None),
    ],
)
def test_raise_floor(spec, floor, expected) -> None:
    assert raise_floor(spec, floor) == expected


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [("3.9", "3.10", "3.9"), ("3.8", "3.11", "3.8, 3.9 and 3.10"), ("3.10", "3.10", "")],
)
def test_dropped_pythons(old, new, expected) -> None:
    assert dropped_pythons(old, new) == expected


def test_only_the_project_table_is_edited() -> None:
    text = (
        '[project]\nname = "x"\nrequires-python = ">=3.9"\n\n'
        '[tool.other]\nrequires-python = ">=3.9"\n'
    )
    after = _set_requires_python(text, ">=3.9", ">=3.10")
    assert after.count('">=3.10"') == 1 and after.endswith('requires-python = ">=3.9"\n')


# --- the plan --------------------------------------------------------------------


def _project(tmp_path: Path, requires: str = ">=3.9") -> Path:
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = "{requires}"\n'
        'dependencies = ["tornado>=6.0", "pytest>=8"]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.9"\n\n'
        '[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n'
        '[[package]]\nname = "pytest"\nversion = "8.4.2"\n\n'
        '[[package]]\nname = "pytest"\nversion = "9.2.0"\n\n'
        '[[package]]\nname = "tornado"\nversion = "6.4.1"\n',
        encoding="utf-8",
    )
    return tmp_path


def _result() -> ScanResult:
    rows = [("pytest", "8.4.2", "9.0.0"), ("tornado", "6.4.1", "6.5")]
    return ScanResult(
        project_path=".",
        package_manager="pip",
        total_dependencies=2,
        results=[
            TriageResult(
                vuln=Vulnerability(f"PYSEC-{p}", p, v, Severity.HIGH, fix_version=f),
                verdict=Verdict.ACTION,
            )
            for p, v, f in rows
        ],
    )


def _checks() -> dict[str, FixCheck]:
    pytest_check = FixCheck("blocked", "pytest", "9.0.0")
    _classify(pytest_check, UV_FLOOR_ERROR)
    return {"pytest": pytest_check, "tornado": FixCheck("resolves", "tornado", "6.5")}


@pytest.fixture
def uv(monkeypatch):
    """A resolver that, like uv, accepts pytest 9 only once the floor is >=3.10."""
    calls: list[tuple[str, list[str]]] = []

    def run(root: Path, executable: str, specs: list[str], timeout: int):
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        calls.append((text, list(specs)))
        if any(s.startswith("pytest==") for s in specs) and '">=3.9"' in text:
            return 1, "", UV_FLOOR_ERROR
        return 0, UV_RAISED_REPORT, ""

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)
    return calls


def test_the_floor_is_verified_and_reported_but_not_planned(tmp_path, uv) -> None:
    project = _project(tmp_path)
    plan = build_fix_plan(_result(), project, _checks())
    assert plan.status == "partial" and [i.package for i in plan.included] == ["tornado"]
    assert plan.diff == "" and plan.command == "uv lock --upgrade-package tornado==6.5"
    option = plan.python_floor
    assert option is not None and not option.adopted
    assert option.floor == "3.10" and option.unblocked == ["pytest"] and option.alerts == 1
    assert option.dropped == "3.9"
    [left] = plan.left_out
    assert "--raise-python-floor" in left.why
    # The check ran on a copy with the floor raised; the project is untouched.
    assert any('">=3.10"' in text for text, _ in uv)
    assert '">=3.9"' in (project / "pyproject.toml").read_text(encoding="utf-8")


def test_raise_python_floor_puts_the_edit_in_the_plan(tmp_path, uv) -> None:
    project = _project(tmp_path)
    plan = build_fix_plan(_result(), project, _checks(), raise_python_floor=True)
    assert plan.status == "verified" and plan.python_floor and plan.python_floor.adopted
    assert '-requires-python = ">=3.9"' in plan.diff
    assert '+requires-python = ">=3.10"' in plan.diff
    # The newer fork already has pytest 9.2.0: aim there, never back down to 9.0.0.
    pytest_item = next(i for i in plan.items if i.package == "pytest")
    assert pytest_item.version == "9.2.0" and pytest_item.fixed_in == "9.0.0"
    assert "pytest==9.2.0" in plan.command and "pytest==9.0.0" not in plan.command
    assert "requires-python to >=3.10" in plan.note
    assert [c.package for c in plan.lock_changes] == ["iniconfig", "pluggy"]
    data = plan.to_dict()
    assert data["python_floor"]["floor"] == ">=3.10" and data["python_floor"]["adopted"]
    assert data["included"][0]["fixed_in"] == "9.0.0"


def test_markdown_says_the_floor_is_raised(tmp_path, uv) -> None:
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    text = fp.fix_plan_markdown(plan, _result())
    assert "### Python floor" in text and "Python 3.9 is no longer supported" in text
    assert "raises `requires-python` to `>=3.10`" in text


def test_terminal_output(tmp_path, uv) -> None:
    out = io.StringIO()
    fp.print_fix_plan(build_fix_plan(_result(), _project(tmp_path), _checks()), out)
    text = out.getvalue()
    assert "would let 1 more fix install (pytest; 1 alert)" in text
    assert "It drops Python 3.9" in text and "Add --raise-python-floor" in text
    assert "   \n" not in text  # no trailing blanks


def test_a_floor_that_still_does_not_resolve_stays_out(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")

    def run(root, executable, specs, timeout):
        if any(s.startswith("pytest==") for s in specs):
            return 1, "", "No solution found\n  cause: something else blocks pytest"
        return 0, "Update tornado v6.4.1 -> v6.5\n", ""

    monkeypatch.setattr(fp, "_run_lock", run)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    assert plan.diff == "" and [i.package for i in plan.included] == ["tornado"]
    assert plan.python_floor and plan.python_floor.still_blocked == ["pytest"]
    assert not plan.python_floor.adopted
    assert "still does not resolve" in plan.left_out[0].why


def test_a_floor_depquiet_will_not_rewrite_runs_no_check(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, requires="~=3.9")
    calls: list[list[str]] = []
    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(
        fp, "_run_lock", lambda root, exe, specs, timeout: calls.append(specs) or (0, "", "")
    )
    plan = build_fix_plan(_result(), project, _checks(), raise_python_floor=True)
    assert plan.python_floor and "will not rewrite" in plan.python_floor.problem
    assert all(not any(s.startswith("pytest") for s in c) for c in calls)


def test_apply_writes_the_raised_floor(tmp_path, uv, monkeypatch) -> None:
    project = _project(tmp_path)
    plan = build_fix_plan(_result(), project, _checks(), raise_python_floor=True)
    seen: list[list[str]] = []

    class Done:
        returncode, stdout, stderr = 0, "", ""

    monkeypatch.setattr(fp.subprocess, "run", lambda cmd, **k: seen.append(cmd) or Done())
    assert fp.apply_fix_plan(plan, project) == ""
    assert 'requires-python = ">=3.10"' in (project / "pyproject.toml").read_text("utf-8")
    assert "pytest==9.2.0" in seen[0]


def test_cli_flag_needs_fix_plan(tmp_path, capsys) -> None:
    from depquiet.cli import main

    assert main(["--path", str(tmp_path), "--raise-python-floor"]) == 2
    assert "--raise-python-floor needs --fix-plan" in capsys.readouterr().err


def test_cli_passes_the_flag(tmp_path, monkeypatch) -> None:
    from depquiet import cli

    seen: dict[str, object] = {}
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"dependencies": []})))
    monkeypatch.setattr(cli, "check_fixes", lambda result, path, **k: ({}, ""))
    monkeypatch.setattr(
        cli,
        "build_fix_plan",
        lambda *a, **k: seen.update(k) or fp.FixPlan("none", note="n"),
    )
    cli.main(["--path", str(tmp_path), "--stdin", "--fix-plan", "--raise-python-floor"])
    assert seen.get("raise_python_floor") is True


def test_workspace_members_with_a_lower_floor_are_raised_too(tmp_path) -> None:
    project = _project(tmp_path)
    member = tmp_path / "packages" / "lib"
    member.mkdir(parents=True)
    (member / "pyproject.toml").write_text(
        '[project]\nname = "lib"\nversion = "1"\nrequires-python = ">=3.8,<4"\n', encoding="utf-8"
    )
    lock = (project / "uv.lock").read_text(encoding="utf-8")
    lock += '\n[[package]]\nname = "lib"\nversion = "1"\nsource = { editable = "packages/lib" }\n'
    (project / "uv.lock").write_text(lock, encoding="utf-8")
    edits, dropped, problem = fp._floor_edits(project, "3.10")
    assert problem == "" and dropped == "3.8 and 3.9"
    assert sorted((e.file, e.new) for e in edits) == [
        ("packages/lib/pyproject.toml", ">=3.10,<4"),
        ("pyproject.toml", ">=3.10"),
    ]


# --- filtered alerts (--fix-filtered) -------------------------------------------
#
# On both real projects that motivated the Python floor plan, pytest is a
# development dependency: depquiet filters its alert, so without --fix-filtered
# the plan never sees it, while Dependabot keeps it open.


def _filtered_result() -> ScanResult:
    result = _result()
    result.results[0].verdict = Verdict.FILTERED  # pytest: development only
    return result


def test_filtered_alerts_are_left_out_of_the_plan_by_default(tmp_path, uv) -> None:
    plan = build_fix_plan(_filtered_result(), _project(tmp_path), _checks())
    assert [i.package for i in plan.items] == ["tornado"] and plan.python_floor is None


def test_fix_filtered_plans_them_too(tmp_path, uv) -> None:
    result = _filtered_result()
    plan = build_fix_plan(
        result,
        _project(tmp_path),
        _checks(),
        raise_python_floor=True,
        include_filtered=True,
    )
    assert plan.status == "verified" and plan.python_floor and plan.python_floor.alerts == 1
    assert "PYSEC-pytest" in fp.fix_plan_markdown(plan, result)


def test_fix_targets_with_filtered() -> None:
    from depquiet.fixcheck import fix_targets

    assert fix_targets(_filtered_result()) == {"tornado": "6.5"}
    assert fix_targets(_filtered_result(), include_filtered=True) == {
        "pytest": "9.0.0",
        "tornado": "6.5",
    }


def test_cli_fix_filtered_needs_a_fix_flag(tmp_path, capsys) -> None:
    from depquiet.cli import main

    assert main(["--path", str(tmp_path), "--fix-filtered"]) == 2
    assert "--fix-filtered needs --check-fixes or --fix-plan" in capsys.readouterr().err
