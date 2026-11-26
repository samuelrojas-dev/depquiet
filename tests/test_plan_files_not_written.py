"""A plan with nothing in it says that the files asked for were not written.

Found following the README on a fresh install of 0.48.0: on a project whose
every fix needs a newer Python, ``--fix-plan plan.diff --fix-plan-report plan.md``
wrote neither file and said nothing about it.
"""

from __future__ import annotations

import io
import json

import depquiet.fixplan as fp
from depquiet import cli


def _run(tmp_path, monkeypatch, capsys, plan: fp.FixPlan, *extra: str) -> str:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"dependencies": []})))
    monkeypatch.setattr(cli, "check_fixes", lambda *a, **k: ({}, ""))
    monkeypatch.setattr(cli, "build_fix_plan", lambda *a, **k: plan)
    cli.main(["--stdin", "--scanner", "pip", "--path", str(tmp_path), *extra])
    return capsys.readouterr().err


def _waiting_plan() -> fp.FixPlan:
    return fp.FixPlan(
        "none",
        items=[fp.PlanItem("pytest", "9.0.3", why="needs a newer Python")],
        note="n",
        python_floor=fp.PythonFloor("3.10", unblocked=["pytest"], alerts=1),
    )


def test_both_files_are_named(tmp_path, monkeypatch, capsys) -> None:
    diff, report = tmp_path / "plan.diff", tmp_path / "plan.md"
    err = _run(
        tmp_path,
        monkeypatch,
        capsys,
        _waiting_plan(),
        "--fix-plan",
        str(diff),
        "--fix-plan-report",
        str(report),
    )
    assert f"Nothing in the plan yet, so {diff} and {report} were not written." in err
    # The Python floor section already says it; once is enough (seen on stac-auth-proxy).
    assert err.count("--raise-python-floor") == 1
    assert not diff.exists() and not report.exists()


def test_no_file_asked_no_file_line(tmp_path, monkeypatch, capsys) -> None:
    plan = fp.FixPlan("none", note="n")
    err = _run(tmp_path, monkeypatch, capsys, plan, "--fix-plan")
    assert "not written" not in err and "--raise-python-floor" not in err
