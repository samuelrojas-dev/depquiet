"""A fix that carries advisories of its own is not where the plan stops.

Real case (LightRAG, 2026-11-27): the plan moved virtualenv to 21.14.10 and
langgraph-sdk to 0.4.4, the releases its advisories named. A scan of the new
lock flagged both again: 21.14.10 has PYSEC-2026-4402 (fixed in 21.14.13) and
0.4.4 has CVE-2026-118667 (fixed in 0.4.6).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck
from depquiet.fixplan import build_fix_plan
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
        'dependencies = ["langgraph>=1.2"]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.11"\n\n'
        '[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n'
        '[[package]]\nname = "virtualenv"\nversion = "21.3.2"\n\n'
        '[[package]]\nname = "langgraph-sdk"\nversion = "0.3.14"\n',
        encoding="utf-8",
    )
    return tmp_path


def _result() -> ScanResult:
    def r(package: str, version: str, cve: str, fix: str) -> TriageResult:
        return TriageResult(
            Vulnerability(cve, package, version, Severity.HIGH, fix_version=fix), Verdict.ACTION
        )

    return ScanResult(
        ".",
        "pip",
        2,
        [
            r("virtualenv", "21.3.2", "PYSEC-2026-4372", "21.14.10"),
            r("langgraph-sdk", "0.3.14", "PYSEC-2026-4240", "0.4.4"),
        ],
    )


def _checks() -> dict[str, FixCheck]:
    return {
        "virtualenv": FixCheck("resolves", "virtualenv", "21.14.10"),
        "langgraph-sdk": FixCheck("resolves", "langgraph-sdk", "0.4.4"),
    }


ADVISORIES = {
    ("virtualenv", "21.14.10"): [{"id": "PYSEC-2026-4402", "fixed_in": ["21.14.13"]}],
    ("virtualenv", "21.14.13"): [],
    ("langgraph-sdk", "0.4.4"): [{"id": "CVE-2026-118667", "fixed_in": ["0.4.6"]}],
    ("langgraph-sdk", "0.4.6"): [],
}


@pytest.fixture
def uv(monkeypatch):
    calls: list[list[str]] = []
    refuse: set[str] = set()

    def run(root: Path, executable: str, specs: list[str], timeout: int):
        calls.append(list(specs))
        if refuse & set(specs):
            return 1, "", "No solution found: virtualenv==21.14.13 needs packaging>=26.3"
        lines = [f"Update {s.split('==')[0]} v0 -> v{s.split('==')[1]}" for s in specs if "==" in s]
        return 0, "", "\n".join(lines) + "\n"

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)
    monkeypatch.setattr(fp, "_release_advisories", lambda pairs: {p: ADVISORIES[p] for p in pairs})
    return calls, refuse


def test_the_plan_moves_on_to_the_release_that_fixes_the_fix(tmp_path, uv) -> None:
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    got = {i.package: (i.version, i.stepped_from) for i in plan.included}
    assert got == {"virtualenv": ("21.14.13", "21.14.10"), "langgraph-sdk": ("0.4.6", "0.4.4")}
    assert "virtualenv==21.14.13" in plan.command and "langgraph-sdk==0.4.6" in plan.command
    included = {i["package"]: i for i in plan.to_dict()["included"]}
    assert included["virtualenv"]["stepped_from"] == "21.14.10"


def test_the_terminal_and_the_pull_request_say_why(tmp_path, uv) -> None:
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    out = io.StringIO()
    fp.print_fix_plan(plan, out)
    assert "(21.14.10, the advisory's fix, has advisories of its own, fixed in 21.14.13)" in (
        out.getvalue()
    )
    item = next(i for i in plan.included if i.package == "virtualenv")
    assert "21.14.10, the advisory's fix, has advisories of its own, fixed in 21.14.13" in (
        fp._how(item)
    )


def test_a_later_release_that_does_not_resolve_falls_back_to_the_fix(tmp_path, uv) -> None:
    _, refuse = uv
    refuse.add("virtualenv==21.14.13")
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    got = {i.package: (i.version, i.stepped_from) for i in plan.included}
    assert got["virtualenv"] == ("21.14.10", "")
    assert got["langgraph-sdk"] == ("0.4.6", "0.4.4")


def test_without_an_answer_from_pypi_the_plan_keeps_the_fix(tmp_path, uv, monkeypatch) -> None:
    monkeypatch.setattr(fp, "_release_advisories", lambda pairs: {})
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    assert {i.package: i.version for i in plan.included} == {
        "virtualenv": "21.14.10",
        "langgraph-sdk": "0.4.4",
    }


@pytest.mark.parametrize(
    ("advisories", "expected"),
    [
        ([{"fixed_in": ["21.14.13"]}, {"fixed_in": ["21.14.12", "22.0.1"]}], "21.14.13"),
        ([{"fixed_in": ["2.2.0", "1.30.0"]}], "1.30.0"),
        ([{"fixed_in": []}, {"fixed_in": ["21.14.9"]}], ""),
        ([{"fixed_in": ["21.14.13"], "withdrawn": "2026-11-20T00:00:00Z"}], ""),
    ],
)
def test_next_fix(advisories, expected) -> None:
    version = "1.29.0" if expected == "1.30.0" else "21.14.10"
    assert fp._next_fix(version, advisories) == expected


@pytest.mark.advisory_lookups
def test_release_advisories_reads_pypi(monkeypatch) -> None:
    def urlopen(url, timeout):
        if "missing" in url:
            raise OSError("offline")
        assert url == "https://pypi.org/pypi/langgraph-sdk/0.4.4/json"
        payload = {"vulnerabilities": [{"id": "CVE-2026-118667", "fixed_in": ["0.4.6"]}]}
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    got = fp._release_advisories([("langgraph_sdk", "0.4.4"), ("missing", "1.0")])
    assert got == {("langgraph_sdk", "0.4.4"): [{"id": "CVE-2026-118667", "fixed_in": ["0.4.6"]}]}
