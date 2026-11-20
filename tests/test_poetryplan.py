"""Fix plans for Poetry projects.

Verified by hand with Poetry 2.5.1 and pip-audit on two projects where
botocore holds urllib3 below its fix: legacy ``[tool.poetry.dependencies]``
with exact pins (10 alerts -> 0) and PEP 621 ``[project]`` with ranges
(16 -> 1, the one left being a filtered dev-only alert). These tests fake
the resolver.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import pytest

import depquiet.fixplan as fp
import depquiet.poetryplan as pp
from depquiet.fixplan import FixPlan, PlanEdit, PlanItem, _set_poetry_constraint, apply_fix_plan
from depquiet.models import (
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
    version_key,
)
from depquiet.poetryplan import allows, build_poetry_plan, is_poetry_project, widen_poetry


@pytest.mark.parametrize(
    ("constraint", "version", "expected"),
    [
        ("2.31.0", "2.31.0", True),  # a bare version is an exact pin
        ("2.31.0", "2.33.0", False),
        ("==2.31.0", "2.33.0", False),
        ("^2.31", "2.33.0", True),
        ("^2.31", "3.0.0", False),
        ("^0.4.2", "0.4.9", True),  # ^ keeps the leftmost non-zero number
        ("^0.4.2", "0.5.0", False),
        ("~1.29", "1.29.165", True),
        ("~1.29", "1.30.0", False),
        ("~1", "1.44.3", True),
        (">=1.25.4,<1.27", "2.8.0", False),
        (">=1.25.4, <1.27", "1.26.20", True),
        (">=2.31 <3", "2.33.0", True),
        ("*", "9.9", True),
        ("2.*", "2.33.0", True),
        ("^1.0 || ^2.0", "2.5", None),  # alternatives are not rewritten
        ("git+https://x", "1.0", None),
    ],
)
def test_allows(constraint, version, expected) -> None:
    assert allows(constraint, version) is expected


@pytest.mark.parametrize(
    ("constraint", "version", "expected"),
    [
        ("2.31.0", "2.33.0", "2.33.0"),  # exact stays exact
        ("==2.31.0", "2.33.0", "==2.33.0"),
        ("^1.29", "2.1.0", "^2.1.0"),
        ("~1.29", "1.44.3", "~1.44.3"),
        (">=2.31,<2.32", "2.33.0", ">=2.31,<3"),
        ("^2.31", "2.33.0", None),  # already allowed
        ("^1.0 || ^2.0", "3.0", None),  # cannot be read: not rewritten
    ],
)
def test_widen_poetry(constraint, version, expected) -> None:
    assert widen_poetry(constraint, version) == expected


PYPROJECT = """\
[project]
name = "demo"
keywords = ["2.31.0"]

[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"
other = "2.31.0"
"Botocore" = { version = "1.29.0", extras = ["crt"] }

[tool.poetry.group.dev.dependencies]
requests = "2.31.0"

[tool.other]
requests = "2.31.0"
"""


def test_poetry_edit_touches_only_that_package_in_poetry_tables() -> None:
    after = _set_poetry_constraint(PYPROJECT, "requests", "2.31.0", "2.33.0")
    data = tomllib.loads(after)
    deps = data["tool"]["poetry"]["dependencies"]
    assert deps["requests"] == "2.33.0"
    assert deps["other"] == "2.31.0"  # same version string, another package
    assert data["tool"]["poetry"]["group"]["dev"]["dependencies"]["requests"] == "2.33.0"
    assert data["tool"]["other"]["requests"] == "2.31.0"  # not a Poetry table
    assert data["project"]["keywords"] == ["2.31.0"]


def test_poetry_edit_handles_the_table_form_and_name_spelling() -> None:
    after = _set_poetry_constraint(PYPROJECT, "botocore", "1.29.0", "1.44.3")
    assert tomllib.loads(after)["tool"]["poetry"]["dependencies"]["Botocore"] == {
        "version": "1.44.3",
        "extras": ["crt"],
    }


# --- a fake Poetry ----------------------------------------------------------------

RELEASES = {
    "requests": ["2.31.0", "2.33.0", "2.34.2"],
    "botocore": ["1.29.0", "1.44.3"],
    "urllib3": ["1.26.20", "2.8.0"],
    "legacy-sdk": ["1.0.0"],
}
# What each release requires of urllib3.
NEEDS = {
    ("botocore", "1.29.0"): ">=1.25.4,<1.27",
    ("botocore", "1.44.3"): ">=1.25.4,<3",
    ("requests", "2.31.0"): ">=1.21.1,<3",
    ("requests", "2.33.0"): ">=1.21.1,<3",
    ("requests", "2.34.2"): ">=1.21.1,<3",
    ("legacy-sdk", "1.0.0"): "<2",
}


def _lock_text(versions: dict[str, str]) -> str:
    out = []
    for name, version in versions.items():
        out.append(f'[[package]]\nname = "{name}"\nversion = "{version}"\n')
        need = NEEDS.get((name, version))
        if need:
            out.append(f'\n[package.dependencies]\nurllib3 = "{need}"\n')
        out.append("\n")
    return "".join(out)


def _locked(root: Path) -> dict[str, str]:
    data = tomllib.loads((root / "poetry.lock").read_text())
    return {p["name"]: p["version"] for p in data["package"]}


def _fake_update(
    root: Path, executable: str, names: list[str], timeout: int, limit: int | None = 400
) -> tuple[int, str]:
    """Move each named package to the newest release the constraints allow."""
    own = tomllib.loads((root / "pyproject.toml").read_text())["tool"]["poetry"]["dependencies"]
    versions = _locked(root)
    for name in [n for n in names if n != "urllib3"]:
        allowed = [v for v in RELEASES[name] if allows(own.get(name, "*"), v)]
        if not allowed:
            return 1, f"no version of {name} matches"
        versions[name] = allowed[-1]
    if "urllib3" in names:
        needs = [NEEDS[(n, v)] for n, v in versions.items() if (n, v) in NEEDS]
        allowed = [v for v in RELEASES["urllib3"] if all(allows(n, v) for n in needs)]
        versions["urllib3"] = allowed[-1]
    (root / "poetry.lock").write_text(_lock_text(versions))
    return 0, ""


def _project(tmp_path: Path, deps: dict[str, str]) -> Path:
    lines = "\n".join(f'{name} = "{spec}"' for name, spec in deps.items())
    (tmp_path / "pyproject.toml").write_text(
        f'[tool.poetry]\nname = "demo"\n\n[tool.poetry.dependencies]\npython = "^3.11"\n{lines}\n'
    )
    versions = {name: RELEASES[name][0] for name in deps}
    versions["urllib3"] = "1.26.20"
    (tmp_path / "poetry.lock").write_text(_lock_text(versions))
    return tmp_path


def _scan(*fixes: tuple[str, str, str]) -> ScanResult:
    results = [
        TriageResult(
            vuln=Vulnerability(
                f"PYSEC-2026-{n}", package, installed, Severity.HIGH, fix_version=fix
            ),
            verdict=Verdict.ACTION,
        )
        for n, (package, installed, fix) in enumerate(fixes)
    ]
    return ScanResult(".", "pip", len(results), results)


@pytest.fixture
def poetry(monkeypatch):
    monkeypatch.setattr(pp.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(pp, "_run_update", _fake_update)


def test_plan_moves_the_holder_and_keeps_exact_pins_exact(tmp_path, poetry) -> None:
    project = _project(tmp_path, {"requests": "2.31.0", "botocore": "1.29.0"})
    scan = _scan(("requests", "2.31.0", "2.33.0"), ("urllib3", "1.26.20", "2.8.0"))
    plan = build_poetry_plan(scan, project)
    assert (plan.status, plan.tool) == ("verified", "poetry")
    by = {i.package: i for i in plan.included}
    assert by["urllib3"].also_upgrade == ["botocore==1.44.3"]
    assert by["urllib3"].version == "2.8.0" and by["urllib3"].major_jump
    assert plan.command == "poetry update --lock requests urllib3 botocore"
    changed = [line for line in plan.diff.splitlines() if re.match(r"[+-][^+-]", line)]
    assert changed == [
        '-requests = "2.31.0"',
        '-botocore = "1.29.0"',
        '+requests = "2.33.0"',
        '+botocore = "1.44.3"',
    ]
    # Planned on copies: the project is untouched.
    assert 'botocore = "1.29.0"' in (project / "pyproject.toml").read_text()
    assert _locked(project)["urllib3"] == "1.26.20"


def test_range_that_already_allows_the_holder_needs_no_edit(tmp_path, poetry) -> None:
    project = _project(tmp_path, {"botocore": "^1.29"})
    plan = build_poetry_plan(_scan(("urllib3", "1.26.20", "2.8.0")), project)
    assert plan.status == "verified"
    assert plan.diff == "" and plan.command == "poetry update --lock urllib3 botocore"


def test_holder_with_no_release_that_allows_the_fix_is_left_out(tmp_path, poetry) -> None:
    project = _project(tmp_path, {"legacy-sdk": "1.0.0"})
    plan = build_poetry_plan(_scan(("urllib3", "1.26.20", "2.8.0")), project)
    assert plan.status == "none"
    [item] = plan.left_out
    assert "held below 2.8.0 by legacy-sdk" in item.why


def test_partial_plan_keeps_what_resolves(tmp_path, poetry) -> None:
    project = _project(tmp_path, {"requests": "2.31.0", "legacy-sdk": "1.0.0"})
    scan = _scan(("requests", "2.31.0", "2.33.0"), ("urllib3", "1.26.20", "2.8.0"))
    plan = build_poetry_plan(scan, project)
    assert plan.status == "partial"
    assert [i.package for i in plan.included] == ["requests"]
    assert [i.package for i in plan.left_out] == ["urllib3"]


def test_constraint_depquiet_cannot_rewrite_is_left_out(tmp_path, poetry) -> None:
    project = _project(tmp_path, {"requests": "2.31.0 || 2.31.1"})
    plan = build_poetry_plan(_scan(("requests", "2.31.0", "2.33.0")), project)
    assert "does not rewrite" in plan.left_out[0].why


def test_without_poetry_on_path_the_plan_is_unsupported(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, {"requests": "2.31.0"})
    monkeypatch.setattr(pp.shutil, "which", lambda name: None)
    plan = build_poetry_plan(_scan(("requests", "2.31.0", "2.33.0")), project)
    assert plan.status == "unsupported" and "poetry on PATH" in plan.note


def test_uv_lock_wins_over_poetry_lock(tmp_path) -> None:
    (tmp_path / "poetry.lock").write_text("")
    assert is_poetry_project(tmp_path)
    (tmp_path / "uv.lock").write_text("")
    assert not is_poetry_project(tmp_path)


def _applied_plan() -> FixPlan:
    item = PlanItem(
        "requests",
        "2.33.0",
        "2.31.0",
        edits=[PlanEdit("pyproject.toml", "requests", "2.31.0", "2.33.0", kind="poetry")],
        included=True,
    )
    return FixPlan("verified", items=[item], tool="poetry")


def test_apply_runs_poetry_and_never_creates_a_virtualenv(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, {"requests": "2.31.0"})
    seen: dict[str, object] = {}

    def run(cmd, cwd, env, **kwargs):
        seen.update(cmd=cmd, env=env)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(fp.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(fp.subprocess, "run", run)
    assert apply_fix_plan(_applied_plan(), project) == ""
    assert seen["cmd"] == [
        "/usr/bin/poetry", "update", "--lock", "requests", "--no-interaction", "--no-ansi",
    ]  # fmt: skip
    assert seen["env"]["POETRY_VIRTUALENVS_CREATE"] == "false"  # type: ignore[index]
    assert 'requests = "2.33.0"' in (project / "pyproject.toml").read_text()


def test_failed_apply_restores_pyproject_and_poetry_lock(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, {"requests": "2.31.0"})
    before = {n: (project / n).read_text() for n in ("pyproject.toml", "poetry.lock")}

    def run(cmd, cwd, **kwargs):
        (Path(cwd) / "poetry.lock").write_text("half written")
        return subprocess.CompletedProcess(cmd, 1, "", "SolverProblemError")

    monkeypatch.setattr(fp.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(fp.subprocess, "run", run)
    assert "nothing was changed" in apply_fix_plan(_applied_plan(), project)
    assert {n: (project / n).read_text() for n in before} == before


def test_check_fixes_alone_points_poetry_users_to_fix_plan(tmp_path, monkeypatch, capsys) -> None:
    import io

    from depquiet.cli import main

    project = _project(tmp_path, {"requests": "2.31.0"})
    monkeypatch.setattr("sys.stdin", io.StringIO('{"dependencies": []}'))
    main(["--path", str(project), "--stdin", "--check-fixes"])
    err = capsys.readouterr().err
    assert re.search(r"for a Poetry project use\s+--fix-plan", err)


# --- the Python floor -----------------------------------------------------------------

_SOUPSIEVE_ERROR = (
    "Because no versions of soupsieve match >4.1.2 and soupsieve (4.1.1) requires Python "
    ">=3.11.5, soupsieve is forbidden. So, because soupsieve (4.1.2) requires Python "
    ">=3.11.5 and pf1 depends on soupsieve (>=4.0.0), version solving failed. For "
    'soupsieve, a possible solution would be to set the `python` property to ">=3.11.5,<4"'
)


def _soup_update(
    root: Path, executable: str, names: list[str], timeout: int, limit: int | None = 400
) -> tuple[int, str]:
    """Poetry on the soupsieve trap, as seen in a real run with Poetry 2.4.

    Asked for soupsieve as a transitive package, it resolves and keeps 2.8.3 while
    requires-python admits 3.10; required directly, it fails and names the Python
    each release needs.
    """
    data = tomllib.loads((root / "pyproject.toml").read_text())
    floor = data["project"]["requires-python"].split(",")[0].lstrip(">=")
    low = version_key(floor) < version_key("3.11.5")
    direct = any(d.startswith("soupsieve") for d in data["project"]["dependencies"])
    if low and direct:
        return 1, _SOUPSIEVE_ERROR[-limit:] if limit else _SOUPSIEVE_ERROR
    # Asked to update soupsieve on a 3.10 floor, Poetry moves it to 2.10, the newest
    # release that installs there (seen with Poetry 2.4).
    soup = "4.1.2" if not low else ("2.10" if "soupsieve" in names else "2.8.3")
    versions = {"beautifulsoup4": "4.14.3", "soupsieve": soup}
    (root / "poetry.lock").write_text(
        "".join(f'[[package]]\nname = "{n}"\nversion = "{v}"\n\n' for n, v in versions.items())
    )
    return 0, ""


def _soup_project(tmp_path: Path, poetry_python: str = "") -> Path:
    extra = f'\n[tool.poetry.dependencies]\npython = "{poetry_python}"\n' if poetry_python else ""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "pf1"\nversion = "0.1.0"\nrequires-python = ">=3.10,<4"\n'
        'dependencies = ["beautifulsoup4>=4.13"]\n\n[tool.poetry]\npackage-mode = false\n' + extra
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "beautifulsoup4"\nversion = "4.14.3"\n\n'
        '[[package]]\nname = "soupsieve"\nversion = "2.8.3"\n'
    )
    return tmp_path


@pytest.fixture
def soup_poetry(monkeypatch):
    monkeypatch.setattr(pp.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(pp, "_run_update", _soup_update)


def test_a_fix_that_needs_a_newer_python_gets_the_floor_from_poetry(tmp_path, soup_poetry) -> None:
    project = _soup_project(tmp_path)
    plan = build_poetry_plan(_scan(("soupsieve", "2.8.3", "4.0.0")), project)
    assert plan.status == "none"
    [item] = plan.left_out
    assert "needs Python >=3.11.5" in item.why and "--raise-python-floor" in item.why
    floor = plan.python_floor
    assert floor is not None and not floor.adopted
    assert (floor.floor, floor.unblocked, floor.alerts) == ("3.11.5", ["soupsieve"], 1)
    assert floor.dropped == "3.10 and 3.11 below 3.11.5"
    assert "verified with Poetry's resolver" in "\n".join(fp.python_floor_lines(floor, "poetry"))


def test_raise_python_floor_puts_the_floor_in_the_poetry_plan(tmp_path, soup_poetry) -> None:
    project = _soup_project(tmp_path)
    plan = build_poetry_plan(
        _scan(("soupsieve", "2.8.3", "4.0.0")), project, raise_python_floor=True
    )
    assert plan.status == "verified" and plan.python_floor and plan.python_floor.adopted
    [item] = plan.included
    assert (item.version, item.python_floor) == ("4.1.2", "3.11.5")
    assert '-requires-python = ">=3.10,<4"' in plan.diff
    assert '+requires-python = ">=3.11.5,<4"' in plan.diff
    assert plan.command == "poetry update --lock soupsieve"
    # Planned on copies: the project is untouched.
    assert ">=3.10,<4" in (project / "pyproject.toml").read_text()


def test_a_poetry_python_constraint_is_reported_not_rewritten(tmp_path, soup_poetry) -> None:
    project = _soup_project(tmp_path, poetry_python=">=3.10,<4")
    plan = build_poetry_plan(
        _scan(("soupsieve", "2.8.3", "4.0.0")), project, raise_python_floor=True
    )
    assert plan.status == "none" and plan.python_floor is not None
    assert "[tool.poetry.dependencies]" in plan.python_floor.problem
    assert "needs Python >=3.11.5" in plan.left_out[0].why


def test_the_newest_release_on_the_current_python_goes_in_as_a_partial_fix(
    tmp_path, soup_poetry
) -> None:
    project = _soup_project(tmp_path)
    scan = _scan(
        ("soupsieve", "2.8.3", "2.8.4"),
        ("soupsieve", "2.8.3", "2.10.0"),
        ("soupsieve", "2.8.3", "4.0.0"),
    )
    plan = build_poetry_plan(scan, project)
    [partial] = plan.included
    assert (partial.installed, partial.version) == ("2.8.3", "2.10")
    assert partial.partial == "closes 2 of 3 alerts; the other 1 need Python >=3.11.5"
    assert plan.status == "partial" and plan.command == "poetry update --lock soupsieve"
    assert [i.version for i in plan.left_out] == ["4.0.0"]
    # With the floor raised, the full fix goes in and there is no partial one.
    raised = build_poetry_plan(scan, project, raise_python_floor=True)
    assert all(not i.partial for i in raised.items)
