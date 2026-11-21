"""When no fix resolves, check whether the project locks at all.

Real case (python-telegram-bot, 2026-11-20): uv reported the project's own
``all`` extra as unsatisfiable on its declared Pythons ("sphinx 9.2.0 needs
Python >=3.13"), so every fix came back blocked for a reason no upgrade can
change, and the plan listed that message under soupsieve as if it were about
soupsieve.
"""

from __future__ import annotations

from pathlib import Path

import depquiet.fixcheck as fc
from depquiet.fixcheck import check_fixes
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

UNSATISFIABLE = """  \u00d7 No solution found when resolving dependencies for split
  (markers: python_full_version >= '3.12'):
  ╰─▶ Because the requested Python version (>=3.11) does not satisfy Python>=3.13 and
      demo:all depends on sphinx{python_full_version >= '3.12'}==9.2.0, we can conclude that
      demo:all's requirements are unsatisfiable.
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text('version = 1\nrequires-python = ">=3.11"\n', encoding="utf-8")
    return tmp_path


def _result() -> ScanResult:
    return ScanResult(
        project_path=".",
        package_manager="pip",
        total_dependencies=2,
        results=[
            TriageResult(
                vuln=Vulnerability(f"GHSA-{p}", p, "1.0", Severity.HIGH, fix_version="2.0"),
                verdict=Verdict.ACTION,
            )
            for p in ("soupsieve", "idna")
        ],
    )


def _uv(monkeypatch, *, base_ok: bool, resolves: tuple[str, ...] = ()) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(root: Path, executable: str, specs: list[str], timeout: int):
        calls.append(list(specs))
        if not specs:
            return (0, "", "") if base_ok else (1, "", UNSATISFIABLE)
        if any(s.split("==")[0] in resolves for s in specs):
            return 0, "Update idna v1.0 -> v2.0\n", ""
        return 1, "", UNSATISFIABLE

    monkeypatch.setattr(fc.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fc, "_run_lock", run)
    return calls


def test_a_project_that_does_not_lock_says_so_once(tmp_path, monkeypatch) -> None:
    calls = _uv(monkeypatch, base_ok=False)
    result = _result()
    checks, note = check_fixes(result, _project(tmp_path))
    assert note.startswith("uv cannot lock this project as it is, even without upgrades")
    assert "demo:all's requirements are unsatisfiable" in note
    assert [] in calls
    for check in checks.values():
        assert check.status == "error"
        assert check.detail.startswith("the project does not lock as it is")
    assert all(f.fix_check is not None and f.fix_check.status == "error" for f in result.results)


def test_a_project_that_locks_keeps_its_answers(tmp_path, monkeypatch) -> None:
    calls = _uv(monkeypatch, base_ok=True)
    checks, note = check_fixes(_result(), _project(tmp_path))
    assert note == "" and [] in calls
    assert {c.status for c in checks.values()} == {"blocked"}


def test_no_baseline_when_a_fix_resolves(tmp_path, monkeypatch) -> None:
    calls = _uv(monkeypatch, base_ok=False, resolves=("idna",))
    checks, note = check_fixes(_result(), _project(tmp_path))
    assert note == "" and [] not in calls
    assert checks["idna"].status == "resolves"
