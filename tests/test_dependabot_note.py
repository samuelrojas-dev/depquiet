"""The note on fixes Dependabot cannot open: their release needs a newer Python.

Dependabot resolves a uv project for the oldest Python requires-python allows
and ignores [tool.uv] environments. A stac-auth-proxy contributor showed it
with the Dependabot CLI, and on depquiet-floor-test (requires-python >=3.10,
environments >= 3.11.5) Dependabot moved pillow to 12.3.0 and opened nothing
for soupsieve, while the fix-pr Action moved both (2026-11-27).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.models import ScanResult


def _project(tmp_path: Path, environments: bool) -> Path:
    text = '[project]\nname = "x"\nversion = "0"\nrequires-python = ">=3.10"\n'
    if environments:
        text += "\n[tool.uv]\nenvironments = [\"python_full_version >= '3.11.5'\"]\n"
    (tmp_path / "pyproject.toml").write_text(text, encoding="utf-8")
    return tmp_path


def _plan() -> fp.FixPlan:
    items = [
        fp.PlanItem("pillow", "13.0.0", "12.2.0", included=True),
        fp.PlanItem("soupsieve", "4.0.0", "2.8.3", included=True),
        fp.PlanItem("requests", "2.33.0", "2.31.0", included=True),
    ]
    return fp.FixPlan("verified", items=items, note="Verified with uv's resolver only.")


@pytest.mark.python_lookups
def test_fixes_that_need_a_newer_python_are_named(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, environments=True)
    monkeypatch.setattr(
        fp,
        "_release_pythons",
        lambda packages: {"pillow": "3.11", "soupsieve": "3.11.5", "requests": "3.9"},
    )
    plan = _plan()
    fp._note_newer_pythons(plan, project)
    assert plan.needs_newer_python == {"pillow": "3.11", "soupsieve": "3.11.5"}
    assert plan.project_python == "3.10"
    note = plan.dependabot_note()
    assert "oldest Python requires-python allows (3.10)" in note
    assert "pillow 13.0.0 needs Python >=3.11" in note
    assert "soupsieve 4.0.0 needs Python >=3.11.5" in note
    assert "does not read [tool.uv] environments (python_full_version >= '3.11.5')" in note
    assert "requests" not in note


@pytest.mark.python_lookups
def test_no_note_when_every_fix_installs_on_the_oldest_python(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, environments=True)
    monkeypatch.setattr(fp, "_release_pythons", lambda packages: {"requests": "3.9"})
    plan = _plan()
    fp._note_newer_pythons(plan, project)
    assert plan.dependabot_note() == ""
    assert plan.to_dict()["dependabot_cannot"] is None


@pytest.mark.python_lookups
def test_unknown_python_is_not_guessed(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, environments=False)
    monkeypatch.setattr(fp, "_release_pythons", lambda packages: {"pillow": ""})
    plan = _plan()
    fp._note_newer_pythons(plan, project)
    assert plan.dependabot_note() == ""


@pytest.mark.python_lookups
def test_without_environments_the_note_says_the_lock_is_split(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, environments=False)
    monkeypatch.setattr(fp, "_release_pythons", lambda packages: {"soupsieve": "3.11.5"})
    plan = _plan()
    fp._note_newer_pythons(plan, project)
    assert plan.lock_environments == []
    assert plan.dependabot_note().endswith("uv locks them only for the Pythons they support.")


@pytest.mark.python_lookups
def test_the_pull_request_and_the_terminal_say_why(tmp_path, monkeypatch) -> None:
    project = _project(tmp_path, environments=True)
    monkeypatch.setattr(fp, "_release_pythons", lambda packages: {"pillow": "3.11"})
    plan = _plan()
    fp._note_newer_pythons(plan, project)
    body = fp.fix_plan_markdown(plan, ScanResult(".", "uv", 0, []))
    assert "### Why Dependabot did not open this" in body
    assert "pillow 13.0.0 needs Python >=3.11" in body
    out = io.StringIO()
    fp.print_fix_plan(plan, file=out)
    assert "Dependabot resolves for the oldest Python" in out.getvalue()
    data = json.loads(json.dumps(plan.to_dict()))
    assert data["dependabot_cannot"]["needs_newer_python"] == {"pillow": "3.11"}
    assert data["dependabot_cannot"]["requires_python_oldest"] == "3.10"


def test_tests_never_ask_pypi(tmp_path) -> None:
    """Without the marker the lookup is stubbed: no note, no network."""
    plan = _plan()
    fp._note_newer_pythons(plan, _project(tmp_path, environments=True))
    assert plan.dependabot_note() == ""
