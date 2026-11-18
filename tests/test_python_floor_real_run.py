"""What the first real run of the Python floor plan (a public uv SDK) showed.

- uv wrote ``cryptography==50.0.0 only supports >3.9.0`` (cryptography excludes
  3.9.0 itself): depquiet did not read ``>`` as a floor, so cryptography was left
  out although the plan already raised the floor to 3.11.
- jupyterlab and urllib3 were left out for reasons that named requires-python
  ("does not resolve together with the rest", "blocked by requests"), and were
  never tried again once the floor was raised.
- Wording: "lets 1 more fix" for the only fix, "Python 3.9 and 3.10 is", and a
  header that said "requirements" when only requires-python changed.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck, _classify, _lowest_python
from depquiet.fixplan import build_fix_plan
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability


@pytest.mark.parametrize(
    ("spec", "expected"),
    [(">=3.10", "3.10"), (">3.9.0", "3.9.1"), (">3.9", "3.10"), ("<3.13", ""), ("", "")],
)
def test_lowest_python(spec, expected) -> None:
    assert _lowest_python(spec) == expected


def test_a_strict_floor_from_uv_is_read() -> None:
    check = FixCheck("blocked", "cryptography", "50.0.0")
    _classify(
        check,
        "hint: The `requires-python` value (>=3.9) includes Python versions that are not "
        "supported by your dependencies (e.g., cryptography==50.0.0 only supports >3.9.0).",
    )
    assert check.reason == "python" and check.python_floor == "3.9.1"


REQUIRES_PYTHON_HINT = (
    "While the active Python version is 3.12, the resolution failed for other Python "
    "versions supported by your project. Consider limiting your project's supported Python "
    "versions using `requires-python`."
)


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "sdk"\nversion = "1"\nrequires-python = ">=3.9"\n'
        'dependencies = ["requests>=2.32", "urllib3", "pytest"]\n',
        encoding="utf-8",
    )
    lock = 'version = 1\n\n[[package]]\nname = "sdk"\nversion = "1"\nsource = { virtual = "." }\n'
    for name, version in (("requests", "2.32.3"), ("urllib3", "1.26.20"), ("pytest", "8.4.2")):
        lock += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
    (tmp_path / "uv.lock").write_text(lock, encoding="utf-8")
    return tmp_path


def _result() -> ScanResult:
    rows = [("pytest", "8.4.2", "9.0.3"), ("urllib3", "1.26.20", "2.8.0")]
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


@pytest.fixture
def uv(monkeypatch):
    """urllib3 2.8 needs a newer requests, which needs Python >=3.11: both wait on the floor."""

    def run(root, executable, specs, timeout):
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        if '">=3.9"' in text and any(s.startswith(("pytest==", "urllib3==")) for s in specs):
            return 1, "", f"No solution found\nhint: {REQUIRES_PYTHON_HINT}"
        return 0, "Update urllib3 v1.26.20 -> v2.8.0\nUpdate pytest v8.4.2 -> v9.0.3\n", ""

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)


def _checks() -> dict[str, FixCheck]:
    floor = FixCheck("blocked", "pytest", "9.0.3", reason="python", python_floor="3.11")
    chained = FixCheck(
        "blocked",
        "urllib3",
        "2.8.0",
        reason="",
        next_step=f"blocked by requests: {REQUIRES_PYTHON_HINT}",
    )
    return {"pytest": floor, "urllib3": chained}


def test_fixes_left_out_over_requires_python_are_tried_again(tmp_path, uv) -> None:
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    assert plan.status == "verified"
    assert sorted(i.package for i in plan.included) == ["pytest", "urllib3"]
    assert plan.python_floor and sorted(plan.python_floor.unblocked) == ["pytest", "urllib3"]


def test_without_the_flag_they_say_the_floor_would_let_them_in(tmp_path, uv) -> None:
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    why = {i.package: i.why for i in plan.left_out}
    assert "raising requires-python to >=3.11 lets it install" in why["urllib3"]
    assert why["urllib3"].startswith("does not fit with the project's current requires-python")


def test_wording(tmp_path, uv) -> None:
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    text = fp.fix_plan_markdown(plan, _result())
    assert "changes only `requires-python` in `pyproject.toml`, and `uv.lock`" in text
    assert "Python 3.9 and 3.10 are no longer supported" in text
    lines = "\n".join(fp.python_floor_lines(plan.python_floor))
    assert "lets 2 fixes install" in lines and "more" not in lines


class _FileLikeStdout(io.StringIO):
    """stdout redirected to a file: held in a buffer until flushed into the shared file."""

    def __init__(self, shared: io.StringIO) -> None:
        super().__init__()
        self.shared = shared

    def isatty(self) -> bool:
        return False

    def flush(self) -> None:
        self.shared.write(self.getvalue())
        self.seek(0)
        self.truncate()


def test_report_comes_before_the_plan_when_saved_to_one_file(tmp_path, monkeypatch) -> None:
    """The plan (stderr, unbuffered) printed above the report (stdout) under ``> f 2>&1``."""
    from depquiet import cli

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    shared = io.StringIO()
    stdout = _FileLikeStdout(shared)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"dependencies": []}'))
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", shared)
    monkeypatch.setattr(cli, "check_fixes", lambda *a, **k: ({}, ""))
    monkeypatch.setattr(cli, "build_fix_plan", lambda *a, **k: fp.FixPlan("none", note="n"))
    cli.main(["--stdin", "--scanner", "pip", "--path", str(tmp_path), "--fix-plan"])
    stdout.flush()
    out = shared.getvalue()
    assert "No vulnerabilities found" in out and "Fix plan" in out
    assert out.index("No vulnerabilities found") < out.index("Fix plan")
