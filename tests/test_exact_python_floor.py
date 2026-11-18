"""The exact Python floor, when the one the fixes ask for still splits the lock.

On a public uv SDK, ``requires-python >=3.11`` let all 21 fixes in, but
uv split the lock at 3.11.5: Python 3.11.0-3.11.4 got beautifulsoup4 4.6.3
(2018). By hand, ``>=3.11.5`` left one beautifulsoup4, 4.14.3. The plan now
finds that floor itself, from the split points in the lock uv writes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck
from depquiet.fixplan import build_fix_plan, dropped_pythons
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

LOCK_WITH_SPLITS = """version = 1
requires-python = ">=3.11"
resolution-markers = [
    "python_full_version >= '3.13'",
    "python_full_version >= '3.11.5' and python_full_version < '3.13'",
    "python_full_version < '3.11.5'",
]
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "sdk"\nversion = "1"\nrequires-python = ">=3.9"\n'
        'dependencies = ["pytest", "beautifulsoup4"]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "sdk"\nversion = "1"\nsource = { virtual = "." }\n'
        '\n[[package]]\nname = "pytest"\nversion = "8.4.2"\n'
        '\n[[package]]\nname = "beautifulsoup4"\nversion = "4.14.3"\n',
        encoding="utf-8",
    )
    return tmp_path


def _result() -> ScanResult:
    return ScanResult(
        project_path=".",
        package_manager="pip",
        total_dependencies=1,
        results=[
            TriageResult(
                vuln=Vulnerability(
                    "PYSEC-1", "pytest", "8.4.2", Severity.HIGH, fix_version="9.0.3"
                ),
                verdict=Verdict.ACTION,
            )
        ],
    )


def _checks() -> dict[str, FixCheck]:
    return {"pytest": FixCheck("blocked", "pytest", "9.0.3", reason="python", python_floor="3.11")}


def _install(monkeypatch, *, exact_fixes: bool = True):
    written: list[Path] = []

    def run(root, executable, specs, timeout):
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        if '">=3.9"' in text:
            return 1, "", "No solution found"
        if '">=3.11"' in text or not exact_fixes:
            return (
                0,
                "Update pytest v8.4.2 -> v9.0.3\n"
                "Update beautifulsoup4 v4.14.3 -> v4.6.3, v4.14.3\n",
                "",
            )
        return 0, "Update pytest v8.4.2 -> v9.0.3\n", ""

    def write(root, executable, specs, timeout):
        written.append(root)
        (root / "uv.lock").write_text(LOCK_WITH_SPLITS, encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)
    monkeypatch.setattr(fp, "_write_lock", write)
    return written


def test_the_plan_moves_to_the_split_that_removes_the_downgrade(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path)
    written = _install(monkeypatch)
    plan = build_fix_plan(_result(), project, _checks(), raise_python_floor=True)
    option = plan.python_floor
    assert option and option.floor == "3.11.5" and option.refined_from == "3.11"
    assert option.avoids == ["beautifulsoup4"]
    assert '+requires-python = ">=3.11.5"' in plan.diff
    assert plan.downgrades == []
    assert plan.items[0].python_floor == "3.11.5"
    # The lock was written on a temporary copy only.
    assert written and all(project not in p.parents and p != project for p in written)
    assert "version = 1\n\n[[package]]" in (project / "uv.lock").read_text(encoding="utf-8")


def test_the_report_says_why(tmp_path, monkeypatch) -> None:
    _install(monkeypatch)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    lines = "\n".join(fp.python_floor_lines(plan.python_floor))
    assert ">=3.11.5, not >=3.11: with >=3.11, uv splits the lock at 3.11.5" in lines
    text = fp.fix_plan_markdown(plan, _result())
    assert "`>=3.11.5` rather than `>=3.11`" in text
    assert plan.to_dict()["python_floor"]["refined_from"] == ">=3.11"


def test_no_downgrade_means_no_extra_lock(tmp_path, monkeypatch) -> None:
    written = _install(monkeypatch)

    def clean(root, executable, specs, timeout):
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        if '">=3.9"' in text:
            return 1, "", "No solution found"
        return 0, "Update pytest v8.4.2 -> v9.0.3\n", ""

    monkeypatch.setattr(fp, "_run_lock", clean)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    assert plan.python_floor and plan.python_floor.floor == "3.11"
    assert written == []


def test_a_split_that_does_not_help_keeps_the_floor_and_the_warning(tmp_path, monkeypatch) -> None:
    _install(monkeypatch, exact_fixes=False)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    assert plan.python_floor and plan.python_floor.floor == "3.11"
    assert not plan.python_floor.refined_from
    assert [c.package for c in plan.downgrades] == ["beautifulsoup4"]


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [("3.9", "3.11.5", "3.9, 3.10 and 3.11 below 3.11.5"), ("3.9", "3.10.0", "3.9")],
)
def test_dropped_pythons_with_a_patch_floor(old, new, expected) -> None:
    assert dropped_pythons(old, new) == expected
