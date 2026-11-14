"""--fix-plan --apply: the plan on the project itself, all or nothing."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.fixplan import FixPlan, PlanEdit, PlanItem, apply_fix_plan, fix_plan_markdown
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

PYPROJECT = '[project]\nname = "d"\nversion = "1"\ndependencies = ["requests==2.31.0"]\n'
LOCK = 'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.31.0"\n'


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(LOCK, encoding="utf-8")
    return tmp_path


def _plan() -> FixPlan:
    item = PlanItem(
        package="requests",
        version="2.33.0",
        installed="2.31.0",
        edits=[PlanEdit("pyproject.toml", "requests", "requests==2.31.0", "requests==2.33.0")],
        included=True,
    )
    left = PlanItem(package="idna", version="3.15", why="needs Python 3.12 | or newer")
    return FixPlan("partial", items=[item, left], note="Verified with uv's resolver only.")


def _uv(monkeypatch, returncode: int, relock: bool = True) -> list[list[str]]:
    seen: list[list[str]] = []

    def run(cmd, cwd, **kwargs):
        seen.append(cmd)
        if relock:
            (Path(cwd) / "uv.lock").write_text(LOCK.replace("2.31.0", "2.33.0"))
        return subprocess.CompletedProcess(cmd, returncode, "", "error: no solution")

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp.subprocess, "run", run)
    return seen


def test_apply_edits_the_project_and_relocks(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path)
    seen = _uv(monkeypatch, 0)
    assert apply_fix_plan(_plan(), project) == ""
    assert "requests==2.33.0" in (project / "pyproject.toml").read_text()
    assert seen == [["/usr/bin/uv", "lock", "--upgrade-package", "requests==2.33.0"]]


def test_failed_lock_puts_every_file_back(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path)
    _uv(monkeypatch, 1)  # uv rewrote the lock and then failed
    problem = apply_fix_plan(_plan(), project)
    assert "nothing was changed" in problem
    assert (project / "pyproject.toml").read_text() == PYPROJECT
    assert (project / "uv.lock").read_text() == LOCK


def test_timeout_puts_every_file_back(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path)

    def run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp.subprocess, "run", run)
    assert "timed out" in apply_fix_plan(_plan(), project)
    assert (project / "pyproject.toml").read_text() == PYPROJECT


def test_apply_without_uv_or_fixes_changes_nothing(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path)
    monkeypatch.setattr(fp.shutil, "which", lambda name: None)
    assert "uv is not on PATH" in apply_fix_plan(_plan(), project)
    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    assert "no fix to apply" in apply_fix_plan(FixPlan("none"), project)
    assert (project / "pyproject.toml").read_text() == PYPROJECT


def test_markdown_lists_fixes_advisories_and_what_was_left_out() -> None:
    vuln = Vulnerability(
        cve="PYSEC-2026-1873", package="Requests", version="2.31.0", severity=Severity.HIGH
    )
    result = ScanResult(
        project_path=".",
        package_manager="pip",
        total_dependencies=1,
        results=[TriageResult(vuln=vuln, verdict=Verdict.ACTION)],
    )
    text = fix_plan_markdown(_plan(), result, "0.45.0")
    assert "| `requests` | 2.31.0 | 2.33.0 | PYSEC-2026-1873 |" in text
    assert "widens the project's own requirement" in text
    assert "- `idna` → 3.15: needs Python 3.12 \\| or newer" in text  # pipes cannot break it
    assert "let your tests decide" in text and "depquiet) 0.45.0." in text


def test_cli_apply_needs_fix_plan(tmp_path, monkeypatch, capsys) -> None:
    import io

    from depquiet.cli import main

    (tmp_path / "requirements.txt").write_text("x==1\n")
    monkeypatch.setattr("sys.stdin", io.StringIO('{"dependencies": []}'))
    assert main(["--path", str(tmp_path), "--stdin", "--offline", "--apply"]) == 2
    assert "--apply needs --fix-plan" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--apply", "--fix-plan-report"])
def test_help_documents_the_flags(flag, capsys) -> None:
    from depquiet.cli import main

    with pytest.raises(SystemExit):
        main(["--help"])
    assert flag in capsys.readouterr().out
