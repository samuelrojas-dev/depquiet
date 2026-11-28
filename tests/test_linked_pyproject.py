"""A pyproject.toml that links outside the project, and errors that are bugs.

Real case (end-to-end review, 2026-11-27): with pyproject.toml a link to
../shared/pyproject.toml, --fix-plan crashed with a raw ValueError traceback.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import depquiet.cli as cli
import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

PYPROJECT = (
    '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
    'dependencies = ["requests==2.31.0"]\n'
)


def _link(target: Path, link: Path) -> None:
    try:
        os.symlink(os.path.relpath(target, link.parent), link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")


def _result() -> ScanResult:
    vuln = Vulnerability("PYSEC-1", "requests", "2.31.0", Severity.HIGH, fix_version="2.33.0")
    return ScanResult(".", "pip", 1, [TriageResult(vuln, Verdict.ACTION)])


def test_a_pyproject_linked_outside_the_project_is_explained(tmp_path, monkeypatch) -> None:
    (tmp_path / "shared").mkdir()
    (tmp_path / "shared" / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    project = tmp_path / "proj"
    project.mkdir()
    _link(tmp_path / "shared" / "pyproject.toml", project / "pyproject.toml")
    (project / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    checks = {"requests": FixCheck("blocked", "requests", "2.33.0", reason="own-pin")}
    plan = fp.build_fix_plan(_result(), project, checks)
    assert plan.status == "unsupported"
    assert plan.note.startswith("pyproject.toml → ")
    assert "a link to a file outside the project" in plan.note
    # The lower-level helpers skip the linked file instead of raising ValueError.
    assert fp._edits_for(project, "requests", "2.33.0") == []
    assert fp._edits_matching(project, "requests") == []
    assert fp._floor_edits(project, "3.12")[0] == []


def test_a_link_inside_the_project_still_plans(tmp_path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    _link(tmp_path / "config" / "pyproject.toml", tmp_path / "pyproject.toml")
    assert fp._linked_outside(tmp_path) == []
    edits = fp._edits_for(tmp_path, "requests", "2.33.0")
    assert [(e.file, e.new) for e in edits] == [("config/pyproject.toml", "requests==2.33.0")]


def test_an_unexpected_error_is_one_plain_message(monkeypatch, capsys) -> None:
    def boom(argv):
        raise ValueError("'/x/pyproject.toml' is not in the subpath of '/y'")

    monkeypatch.setattr(cli, "_main", boom)
    monkeypatch.delenv("DEPQUIET_DEBUG", raising=False)
    assert cli.main([]) == 3
    err = capsys.readouterr().err
    assert "unexpected error: ValueError:" in err
    assert "This is a bug in depquiet, not in your project." in err
    assert cli.ISSUES_URL in err and "Traceback" not in err


def test_debug_shows_the_traceback(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_main", lambda argv: (_ for _ in ()).throw(ValueError("boom")))
    monkeypatch.setenv("DEPQUIET_DEBUG", "1")
    with pytest.raises(ValueError, match="boom"):
        cli.main([])


def test_ctrl_c_is_not_a_bug(monkeypatch, capsys) -> None:
    def stop(argv):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_main", stop)
    assert cli.main([]) == 130
    assert "interrupted" in capsys.readouterr().err
