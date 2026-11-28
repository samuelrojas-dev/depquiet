"""--fix applies the verified plan wherever the project has one.

Real case (depquiet-floor-test, 2026-11-27): --fix ran one ``uv lock
--upgrade-package`` per alert. It moved semgrep, a direct dependency, from
1.187.0 back to 1.136.0 to fix mcp (which brought in a new protobuf alert), and
moved soupsieve to 4.0.0 and then back to 3.0.2, while reporting the alert
fixed in 4.0.0 as fixed. The verified plan does neither.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import depquiet.cli as cli
import depquiet.fixplan as fp
from depquiet.cli import main

AUDIT = {
    "dependencies": [
        {
            "name": "soupsieve",
            "version": "2.8.3",
            "vulns": [
                {"id": "CVE-2026-1", "fix_versions": ["2.10.0"], "aliases": []},
                {"id": "CVE-2026-2", "fix_versions": ["4.0.0"], "aliases": []},
            ],
        },
        {
            "name": "wcmatch",
            "version": "8.5.2",
            "vulns": [{"id": "CVE-2026-3", "fix_versions": ["11.2"], "aliases": []}],
        },
    ]
}


def _project(tmp_path: Path, lock: str = "uv.lock") -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["soupsieve", "wcmatch"]\n',
        encoding="utf-8",
    )
    (tmp_path / lock).write_text("version = 1\n", encoding="utf-8")
    return tmp_path


def _plan(*packages: str) -> fp.FixPlan:
    items = [
        fp.PlanItem("soupsieve", "4.0.0", "2.8.3", included="soupsieve" in packages),
        fp.PlanItem("wcmatch", "11.2", "8.5.2", included="wcmatch" in packages),
    ]
    for item in items:
        if not item.included:
            item.why = "blocked by semgrep, and no release of it allows the fix"
    status = "verified" if len(packages) == 2 else "partial"
    return fp.FixPlan(status, items=items, note="Verified with uv's resolver only.")


@pytest.fixture
def run(monkeypatch, capsys):
    applied: list[fp.FixPlan] = []

    def go(project: Path, *flags: str, plan: fp.FixPlan, problem: str = ""):
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
        monkeypatch.setattr(cli, "check_fixes", lambda *a, **k: ({}, ""))
        monkeypatch.setattr(cli, "build_fix_plan", lambda *a, **k: plan)

        def apply(p, path):
            applied.append(p)
            return problem

        monkeypatch.setattr(cli, "apply_fix_plan", apply)

        def old(*a, **k):
            raise AssertionError("--fix must not run one upgrade per alert here")

        monkeypatch.setattr(cli, "apply_fixes", old)
        code = main(["--path", str(project), "--stdin", "--scanner", "pip", *flags])
        out = capsys.readouterr()
        return code, out.out, out.err

    return go, applied


def test_fix_applies_the_verified_plan(tmp_path, run) -> None:
    go, applied = run
    code, out, err = go(_project(tmp_path), "--fix", plan=_plan("soupsieve", "wcmatch"))
    assert len(applied) == 1
    assert (
        "Running: uv lock --upgrade-package soupsieve==4.0.0 --upgrade-package wcmatch==11.2" in err
    )
    assert "Then run:" not in err
    assert "Applied: uv.lock is updated. Run your tests before you commit." in err
    assert "Every ACTION alert is in the applied plan. Scan again to confirm." in err
    assert "--- a/" not in out  # no diff on stdout for --fix
    assert code == 0


def test_what_the_plan_leaves_out_keeps_the_exit_code(tmp_path, run) -> None:
    go, applied = run
    code, _, err = go(_project(tmp_path), "--fix", plan=_plan("soupsieve"))
    assert len(applied) == 1
    assert "Still open: 1 alert the plan does not fix (left out above)." in err
    assert "✗ wcmatch → 11.2: blocked by semgrep" in err
    assert code == 1


def test_dry_run_shows_the_plan_and_changes_nothing(tmp_path, run) -> None:
    go, applied = run
    code, _, err = go(_project(tmp_path), "--fix", "--dry-run", plan=_plan("soupsieve", "wcmatch"))
    assert applied == []
    assert "Then run: uv lock" in err
    assert code == 1


def test_a_failed_apply_is_an_error(tmp_path, run) -> None:
    go, _ = run
    code, _, err = go(
        _project(tmp_path), "--fix", plan=_plan("soupsieve"), problem="uv lock failed"
    )
    assert "Error: --fix: uv lock failed" in err
    assert code == 2


@pytest.mark.parametrize("lock", ["poetry.lock", "package-lock.json"])
def test_poetry_and_npm_projects_use_the_plan_too(lock) -> None:
    assert cli._has_planned_lock(_project(Path(__import__("tempfile").mkdtemp()), lock))


def test_a_project_without_a_lock_gets_the_manual_list(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "requirements.txt").write_text("soupsieve==2.8.3\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    code = main(["--path", str(tmp_path), "--stdin", "--scanner", "pip", "--fix"])
    err = capsys.readouterr().err
    assert "soupsieve 2.8.3: require soupsieve>=4.0.0 where the project pins soupsieve" in err
    assert code == 1
