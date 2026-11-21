"""A plan that fits only by splitting the lock, and build failures that name the package.

Real cases from the resolver check of the Python floor study (2026-11-20):

- NVIDIA warp requires Python >=3.11 and locks soupsieve with advisories fixed
  only in releases that need 3.11.5. uv still resolves soupsieve 4.0: it splits
  the lock and gives the oldest Pythons beautifulsoup4 4.6.3 (2018), which does
  not use soupsieve. The plan was right to call that verified, but said only
  "an older version". Reproduced on an own fixture with uv 0.11.32: the split is
  at 3.11.5.
- faraday, infinigen and wagtail: uv had to build the project itself, and every
  fix came back "Build failures usually indicate a problem with the package or
  the build environment", which names neither the package nor the error.
"""

from __future__ import annotations

from pathlib import Path

import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck, _explain, check_fix
from depquiet.fixplan import build_fix_plan, fix_plan_markdown, python_floor_lines
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

SPLIT_LOCK = """version = 1
revision = 3
requires-python = ">=3.11"
resolution-markers = [
    "python_full_version >= '3.11.5'",
    "python_full_version < '3.11.5'",
]
"""

SPLIT_REPORT = "Update beautifulsoup4 v4.15.0 -> v4.6.3, v4.15.0\nUpdate soupsieve v2.10 -> v4.0\n"
CLEAN_REPORT = "Update soupsieve v2.10 -> v4.0\n"

# uv 0.11.32, a project whose version is read from a module that is not there.
BUILD_ERROR = """Using CPython 3.14.6
  \u00d7 Failed to build `demo @
  │ file:///tmp/depquiet-fixplan-x/project`
  ├─▶ The build backend returned an error
  ╰─▶ Call to `setuptools.build_meta.build_editable` failed (exit status: 1)

      [stdout]
      discovered packages -- []

      [stderr]
      Traceback (most recent call last):
        File "<string>", line 14, in <module>
          raise ModuleNotFoundError(module_name)
      ModuleNotFoundError: demo


hint: Build failures usually indicate a problem with the package or the build environment
"""


def _project(tmp_path: Path, requires: str = ">=3.11") -> Path:
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = "{requires}"\n'
        'dependencies = ["beautifulsoup4"]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        f'version = 1\nrequires-python = "{requires}"\n\n'
        '[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n'
        '[[package]]\nname = "beautifulsoup4"\nversion = "4.15.0"\n\n'
        '[[package]]\nname = "soupsieve"\nversion = "2.10"\n',
        encoding="utf-8",
    )
    return tmp_path


def _result() -> ScanResult:
    return ScanResult(
        project_path=".",
        package_manager="pip",
        total_dependencies=3,
        results=[
            TriageResult(
                vuln=Vulnerability(
                    "GHSA-1", "soupsieve", "2.10", Severity.HIGH, fix_version="4.0.0"
                ),
                verdict=Verdict.ACTION,
            )
        ],
    )


def _checks() -> dict[str, FixCheck]:
    return {"soupsieve": FixCheck("resolves", "soupsieve", "4.0.0")}


def _uv(monkeypatch, *, splits: bool = True) -> list[Path]:
    written: list[Path] = []

    def run(root: Path, executable: str, specs: list[str], timeout: int):
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        if not splits or '">=3.11.5"' in text:
            return 0, CLEAN_REPORT, ""
        return 0, SPLIT_REPORT, ""

    def write(root: Path, executable: str, specs: list[str], timeout: int):
        written.append(root)
        (root / "uv.lock").write_text(SPLIT_LOCK, encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)
    monkeypatch.setattr(fp, "_write_lock", write)
    return written


def test_the_plan_says_which_floor_avoids_the_split(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path)
    _uv(monkeypatch)
    plan = build_fix_plan(_result(), project, _checks())
    assert plan.status == "verified" and plan.diff == ""
    option = plan.python_floor
    assert option is not None and not option.adopted
    assert (option.floor, option.refined_from, option.avoids) == (
        "3.11.5",
        "3.11",
        ["beautifulsoup4"],
    )
    assert option.unblocked == []
    assert [c.package for c in plan.downgrades] == ["beautifulsoup4"]
    assert "Raising requires-python to >=3.11.5 avoids it (verified" in plan.downgrade_warning()
    lines = "\n".join(python_floor_lines(option))
    assert "would keep one current beautifulsoup4 for every Python" in lines
    assert "with >=3.11, uv splits the lock at 3.11.5" in lines
    assert "Add --raise-python-floor" in lines
    assert "does not let the waiting fixes" not in lines
    # The project itself is never touched.
    assert '">=3.11"' in (project / "pyproject.toml").read_text(encoding="utf-8")


def test_raise_python_floor_adopts_it(tmp_path, monkeypatch) -> None:
    _uv(monkeypatch)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    option = plan.python_floor
    assert option is not None and option.adopted
    assert '+requires-python = ">=3.11.5"' in plan.diff
    assert plan.downgrades == []
    text = fix_plan_markdown(plan, _result())
    assert (
        "Raises `requires-python` to `>=3.11.5`, so every Python gets the same beautifulsoup4"
        in text
    )
    assert "`>=3.11.5` rather than `>=3.11`" in text
    data = plan.to_dict()["python_floor"]
    assert data["adopted"] and data["unblocks"] == [] and data["avoids_older"] == ["beautifulsoup4"]
    assert "The plan raises requires-python to >=3.11.5" in plan.note


def test_no_split_no_probe(tmp_path, monkeypatch) -> None:
    written = _uv(monkeypatch, splits=False)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks(), raise_python_floor=True)
    assert plan.python_floor is None and plan.downgrades == [] and written == []


def test_a_pinned_python_has_no_floor_to_raise(tmp_path, monkeypatch) -> None:
    _uv(monkeypatch)
    plan = build_fix_plan(_result(), _project(tmp_path, "==3.11.*"), _checks())
    assert plan.python_floor is None
    assert [c.package for c in plan.downgrades] == ["beautifulsoup4"]


def test_a_build_failure_names_the_package_and_the_error() -> None:
    text = _explain(BUILD_ERROR)
    assert text.startswith("uv could not build demo (the project itself or a local path")
    assert "ModuleNotFoundError: demo" in text
    assert "usually indicate" not in text


def test_a_registry_build_failure_is_named_too() -> None:
    error = BUILD_ERROR.replace("demo @\n  │ file:///tmp/depquiet-fixplan-x/project", "lxml==4.9.0")
    assert _explain(error).startswith("uv could not build lxml==4.9.0 from source.")


def test_check_fix_reports_the_build_failure(tmp_path, monkeypatch) -> None:
    import depquiet.fixcheck as fc

    monkeypatch.setattr(fc.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fc, "_run_lock", lambda *a: (1, "", BUILD_ERROR))
    check = check_fix(_project(tmp_path), "soupsieve", "4.0.0")
    assert check.status == "error" and "uv could not build demo" in check.detail
