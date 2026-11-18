"""--fix-plan: the pyproject.toml edits that let the fixes install together.

The resolver is faked here; the scenarios mirror two real runs against uv:
requests==2.31.0 / idna<3.7 (both own pins), and botocore==1.29.0 holding
urllib3 below 2 (a chain).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck
from depquiet.fixplan import build_fix_plan, widen
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability


@pytest.mark.parametrize(
    ("requirement", "fix", "expected"),
    [
        ("requests==2.31.0", "2.33.0", "requests==2.33.0"),
        ("idna>=3.4,<3.7", "3.15", "idna>=3.4,<4"),
        ("tornado>=6.5.0,<=6.5.10", "6.6", "tornado>=6.5.0,<7"),
        ("pkg~=1.2", "2.0", "pkg>=2.0,<3"),
        ("pkg!=1.5,>=1.0", "1.5", "pkg>=1.0"),
        (
            "pillow==12.3.0; python_version < '3.11'",
            "13.0.0",
            "pillow==13.0.0; python_version < '3.11'",
        ),
        ("uvicorn[standard]==0.20.0", "0.30.0", "uvicorn[standard]==0.30.0"),
        ("langchain>=0.3.30,<0.4.dev0", "1.3.9", "langchain>=0.3.30,<2"),
        ("requests>=2.0", "2.33.0", None),  # already allows it
        ("requests", "2.33.0", None),
    ],
)
def test_widen_changes_only_what_blocks_the_fix(requirement, fix, expected) -> None:
    assert widen(requirement, fix) == expected


def _project(tmp_path: Path, deps: list[str], locked: dict[str, str]) -> Path:
    deps_toml = "".join(f'    "{d}",\n' for d in deps)
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = [\n{deps_toml}]\n',
        encoding="utf-8",
    )
    lock = (
        'version = 1\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
    )
    for name, version in locked.items():
        lock += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
    (tmp_path / "uv.lock").write_text(lock, encoding="utf-8")
    return tmp_path


def _result(*fixes: tuple[str, str, str]) -> ScanResult:
    results = [
        TriageResult(
            vuln=Vulnerability(
                cve=f"GHSA-{pkg}",
                package=pkg,
                version=installed,
                severity=Severity.HIGH,
                fix_version=fix,
            ),
            verdict=Verdict.ACTION,
        )
        for pkg, installed, fix in fixes
    ]
    return ScanResult(
        project_path=".", package_manager="pip", total_dependencies=3, results=results
    )


def _fake_lock(decide):
    calls: list[tuple[str, list[str]]] = []

    def run(root: Path, executable: str, specs: list[str], timeout: int):
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        calls.append((text, list(specs)))
        return decide(text, specs)

    return run, calls


@pytest.fixture(autouse=True)
def _uv_on_path(monkeypatch):
    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")


OWN = "error: No solution found\n  cause: Because your project depends on {0} we can conclude ..."


def test_own_pins_are_widened_and_verified_together(tmp_path, monkeypatch) -> None:
    project = _project(
        tmp_path, ["requests==2.31.0", "idna>=3.4,<3.7"], {"requests": "2.31.0", "idna": "3.6"}
    )
    run, calls = _fake_lock(
        lambda text, specs: (
            (0, "Resolved\n", "")
            if "requests==2.33.0" in text and "<4" in text
            else (1, "", "No solution found")
        )
    )
    monkeypatch.setattr(fp, "_run_lock", run)
    checks = {
        "requests": FixCheck("blocked", "requests", "2.33.0", reason="own-pin"),
        "idna": FixCheck("blocked", "idna", "3.15", reason="own-pin"),
    }
    plan = build_fix_plan(
        _result(("requests", "2.31.0", "2.33.0"), ("idna", "3.6", "3.15")), project, checks
    )
    assert plan.status == "verified"
    assert '-    "requests==2.31.0",' in plan.diff and '+    "requests==2.33.0",' in plan.diff
    assert '+    "idna>=3.4,<4",' in plan.diff
    assert plan.command == "uv lock --upgrade-package idna==3.15 --upgrade-package requests==2.33.0"
    # One combined resolution, on a copy: the project itself is untouched.
    assert len(calls) == 1
    assert "requests==2.31.0" in (project / "pyproject.toml").read_text(encoding="utf-8")


def test_fixes_that_conflict_are_left_out_with_the_reason(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, ["a==1.0", "b==1.0"], {"a": "1.0", "b": "1.0"})

    def decide(text, specs):
        # a and b cannot both move: each alone resolves.
        return (
            (1, "", "error: No solution found\n  cause: a 2.0 conflicts with b 2.0")
            if "a==2.0" in text and "b==2.0" in text
            else (0, "", "")
        )

    run, _ = _fake_lock(decide)
    monkeypatch.setattr(fp, "_run_lock", run)
    checks = {p: FixCheck("blocked", p, "2.0", reason="own-pin") for p in ("a", "b")}
    plan = build_fix_plan(_result(("a", "1.0", "2.0"), ("b", "1.0", "2.0")), project, checks)
    assert plan.status == "partial"
    assert [i.package for i in plan.included] == ["a"]
    (left,) = plan.left_out
    assert left.package == "b" and "does not resolve together" in left.why
    assert "b==1.0" in plan.diff or "b==2.0" not in plan.diff


def test_a_blocking_package_the_project_pins_is_moved_too(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, ["botocore==1.29.0"], {"botocore": "1.29.0", "urllib3": "1.26.20"})

    def decide(text, specs):
        if "botocore>=1.29.0" in text:  # loosened copy: let uv pick
            return (
                0,
                "Update botocore v1.29.0 -> v1.44.2\nUpdate urllib3 v1.26.20 -> v2.8.0\n",
                "",
            )
        if "botocore==1.44.2" in text:
            return (0, "", "")
        return (1, "", "No solution found")

    run, _ = _fake_lock(decide)
    monkeypatch.setattr(fp, "_run_lock", run)
    checks = {
        "urllib3": FixCheck(
            "blocked", "urllib3", "2.8.0", reason="dependency", also_upgrade=["botocore"]
        )
    }
    plan = build_fix_plan(_result(("urllib3", "1.26.20", "2.8.0")), project, checks)
    assert plan.status == "verified"
    (item,) = plan.included
    assert item.also_upgrade == ["botocore==1.44.2"] and item.major_jump
    assert '+    "botocore==1.44.2",' in plan.diff
    assert plan.command.endswith(
        "--upgrade-package urllib3==2.8.0 --upgrade-package botocore==1.44.2"
    )


def test_python_floor_and_cooldown_are_reported_not_planned(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, ["tornado"], {"tornado": "6.5"})
    monkeypatch.setattr(
        fp, "_run_lock", lambda *a: (_ for _ in ()).throw(AssertionError("no lock"))
    )
    checks = {
        "tornado": FixCheck(
            "blocked",
            "tornado",
            "6.6",
            reason="python",
            next_step="tornado 6.6 only supports Python >=3.11: raise requires-python",
        )
    }
    plan = build_fix_plan(_result(("tornado", "6.5", "6.6")), project, checks)
    assert plan.status == "none" and plan.diff == ""
    assert "requires-python" in plan.left_out[0].why


def test_no_uv_lock_is_unsupported(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    plan = build_fix_plan(_result(("a", "1", "2")), tmp_path, {})
    assert plan.status == "unsupported" and "uv.lock" in plan.note


def _cli(tmp_path, monkeypatch, *args):
    import io

    from depquiet import cli

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1"\n', encoding="utf-8"
    )
    monkeypatch.setattr("sys.stdin", io.StringIO('{"dependencies": []}'))
    return cli.main(["--path", str(tmp_path), "--stdin", *args])


def test_cli_fix_plan_needs_network(tmp_path, monkeypatch, capsys) -> None:
    from depquiet import cli

    monkeypatch.setattr(cli, "build_fix_plan", lambda *a, **k: pytest.fail("planned offline"))
    _cli(tmp_path, monkeypatch, "--offline", "--fix-plan")
    assert "--fix-plan needs network access" in capsys.readouterr().err


def test_cli_writes_the_diff_to_the_file(tmp_path, monkeypatch, capsys) -> None:
    from depquiet import cli

    plan = fp.FixPlan("verified", diff="--- a/pyproject.toml\n+++ b/pyproject.toml\n")
    monkeypatch.setattr(cli, "check_fixes", lambda result, path, **k: ({}, ""))
    monkeypatch.setattr(cli, "build_fix_plan", lambda *a, **k: plan)
    out = tmp_path / "plan.diff"
    _cli(tmp_path, monkeypatch, "--fix-plan", str(out))
    assert out.read_text(encoding="utf-8") == plan.diff
    assert "git apply" in capsys.readouterr().err
