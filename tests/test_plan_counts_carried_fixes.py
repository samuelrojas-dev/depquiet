"""A fix the plan could not ask for, but that the verified lock reaches anyway.

On sparkgeo/prescient-sdk, the plan listed ``jupyterlab → 4.5.11`` under "Not
included" while the same verified lock moved jupyterlab 4.5.7 → 4.6.6, past the
fix. The alert closes with that pull request; the report said it would not.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck
from depquiet.fixplan import _final_versions, build_fix_plan
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

REPORT = """Resolved 300 packages in 9s
Update jupyterlab v4.5.7 -> v4.6.6
Update tornado v6.5.5 -> v6.6.1
Update numpy v2.0.2, v2.2.6 -> v2.4.4
"""


def test_final_versions() -> None:
    final = _final_versions(REPORT)
    assert final["jupyterlab"] == ["4.6.6"] and final["numpy"] == ["2.4.4"]


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "sdk"\nversion = "1"\ndependencies = ["tornado", "jupyterlab"]\n',
        encoding="utf-8",
    )
    lock = 'version = 1\n\n[[package]]\nname = "sdk"\nversion = "1"\nsource = { virtual = "." }\n'
    lock += '\n[[package]]\nname = "tornado"\nversion = "6.5.5"\n'
    lock += '\n[[package]]\nname = "jupyterlab"\nversion = "4.5.7"\n'
    (tmp_path / "uv.lock").write_text(lock, encoding="utf-8")
    return tmp_path


def _result() -> ScanResult:
    rows = [("tornado", "6.5.5", "6.6.1"), ("jupyterlab", "4.5.7", "4.5.11")]
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
    return {
        "tornado": FixCheck("resolves", "tornado", "6.6.1"),
        "jupyterlab": FixCheck("resolves", "jupyterlab", "4.5.11"),
    }


@pytest.fixture
def uv(monkeypatch):
    """Exactly jupyterlab 4.5.11 conflicts with the rest; without it, the lock reaches 4.6.6."""
    calls: list[list[str]] = []

    def run(root, executable, specs, timeout):
        calls.append(list(specs))
        if "jupyterlab==4.5.11" in specs:
            return 1, "", "No solution found\n  cause: jupyterlab==4.5.11 conflicts"
        return 0, REPORT, ""

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)
    return calls


def test_a_fix_the_lock_reaches_is_counted(tmp_path, uv) -> None:
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    assert plan.status == "verified" and plan.left_out == []
    item = next(i for i in plan.items if i.package == "jupyterlab")
    assert item.carried and item.version == "4.6.6" and item.fixed_in == "4.5.11"
    # The verified command is the one shown: the carried fix adds no flag.
    assert plan.command == "uv lock --upgrade-package tornado==6.6.1"
    assert [c.package for c in plan.lock_changes] == ["numpy"]
    assert plan.to_dict()["included"][0]["carried"] is True


def test_the_report_says_how_it_lands(tmp_path, uv) -> None:
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    text = fp.fix_plan_markdown(plan, _result())
    assert "| `jupyterlab` | 4.5.7 | 4.6.6 |" in text
    assert "moves past the fix with the rest of the plan" in text
    assert "Not included" not in text
    out = io.StringIO()
    fp.print_fix_plan(plan, out)
    assert "the verified lock takes it to 4.6.6, past the fix" in out.getvalue()


def test_a_lock_that_stops_short_of_the_fix_stays_out(tmp_path, monkeypatch) -> None:
    def run(root, executable, specs, timeout):
        if "jupyterlab==4.5.11" in specs:
            return 1, "", "No solution found"
        return 0, "Update jupyterlab v4.5.7 -> v4.5.9\n", ""

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    assert [i.package for i in plan.left_out] == ["jupyterlab"]
