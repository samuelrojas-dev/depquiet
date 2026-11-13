"""Fix plans for fixes hidden by the project's exclude-newer cooldown.

The exemption is the narrowest one uv supports: ``exclude-newer-package``
for that package only, one second after the fix was published. Verified
by hand against uv 0.11.32: the package moves to the fix and no further,
even with ``uv lock --upgrade``, and the rest of the project keeps the
cooldown.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.fixcheck import FixCheck
from depquiet.fixplan import _set_cooldown, build_fix_plan, cutoff_after, published_at
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

HINT = (
    "hint: `requests` was filtered by `exclude-newer` to only include packages uploaded "
    "before 2025-06-01T00:00:00Z. The requested version, v2.32.4, was published at "
    "2025-06-09T16:43:05.728Z. Consider using `exclude-newer-package` to override the cutoff."
)
HEAD = '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests>=2.31"]\n\n'


def _uv(tmp_path: Path, tool_uv: str, uv_toml: str | None = None) -> Path:
    (tmp_path / "pyproject.toml").write_text(HEAD + tool_uv, encoding="utf-8")
    if uv_toml is not None:
        (tmp_path / "uv.toml").write_text(uv_toml, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.32.3"\n', encoding="utf-8"
    )
    return tmp_path


def _scan() -> ScanResult:
    vuln = Vulnerability(
        cve="GHSA-9hjg-9r4m-mvj7",
        package="requests",
        version="2.32.3",
        severity=Severity.HIGH,
        fix_version="2.32.4",
    )
    return ScanResult(
        project_path=".",
        package_manager="pip",
        total_dependencies=1,
        results=[TriageResult(vuln=vuln, verdict=Verdict.ACTION)],
    )


def _checks() -> dict[str, FixCheck]:
    return {"requests": FixCheck("blocked", "requests", "2.32.4", detail=HINT, reason="cooldown")}


@pytest.fixture(autouse=True)
def _uv_on_path(monkeypatch):
    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")


def _resolves_only_with_exemption(monkeypatch) -> list[str]:
    seen: list[str] = []

    def run(root: Path, executable: str, specs: list[str], timeout: int):
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        if (root / "uv.toml").exists():
            text += (root / "uv.toml").read_text(encoding="utf-8")
        seen.append(text)
        ok = 'requests = "2025-06-09T16:43:06Z"' in text
        return (0, "Resolved", "") if ok else (1, "", HINT)

    monkeypatch.setattr(fp, "_run_lock", run)
    return seen


def test_published_time_and_cutoff() -> None:
    assert published_at(HINT) == "2025-06-09T16:43:05Z"
    assert cutoff_after("2025-06-09T16:43:05Z") == "2025-06-09T16:43:06Z"
    assert cutoff_after("2025-12-31T23:59:59Z") == "2026-01-01T00:00:00Z"
    assert published_at("No solution found") == ""


def test_plan_adds_a_package_cutoff_next_to_exclude_newer(tmp_path, monkeypatch) -> None:
    project = _uv(tmp_path, '[tool.uv]\nexclude-newer = "2025-06-01T00:00:00Z"\n')
    _resolves_only_with_exemption(monkeypatch)
    plan = build_fix_plan(_scan(), project, _checks())
    assert plan.status == "verified"
    assert '+exclude-newer-package = { requests = "2025-06-09T16:43:06Z" }' in plan.diff
    assert plan.command == "uv lock --upgrade-package requests==2.32.4"
    [item] = plan.included
    assert item.published == "2025-06-09T16:43:05Z"
    assert plan.to_dict()["included"][0]["cooldown_exemption"] == {
        "published": "2025-06-09T16:43:05Z",
        "cutoff": "2025-06-09T16:43:06Z",
        "remove_after": "",  # a fixed cut-off has no date of its own
    }
    assert "younger than your cooldown" in plan.note
    # Planned on a copy: the project is untouched.
    assert "exclude-newer-package" not in (project / "pyproject.toml").read_text()


def test_existing_exemptions_are_kept(tmp_path, monkeypatch) -> None:
    tool = (
        '[tool.uv]\nexclude-newer = "2025-06-01T00:00:00Z"\n'
        'exclude-newer-package = { "django" = "2025-07-01T00:00:00Z", setuptools = false }\n'
    )
    project = _uv(tmp_path, tool)
    _resolves_only_with_exemption(monkeypatch)
    plan = build_fix_plan(_scan(), project, _checks())
    assert plan.status == "verified"
    after = fp._edit_text((project / "pyproject.toml").read_text(), plan.included[0].edits[0])
    per = tomllib.loads(after)["tool"]["uv"]["exclude-newer-package"]
    assert per == {
        "django": "2025-07-01T00:00:00Z",
        "setuptools": False,
        "requests": "2025-06-09T16:43:06Z",
    }


def test_older_exemption_for_the_same_package_is_moved_forward(tmp_path) -> None:
    text = HEAD + (
        '[tool.uv]\nexclude-newer = "2025-06-01T00:00:00Z"\n'
        'exclude-newer-package = { Requests = "2025-06-05T00:00:00Z" }\n'
    )
    after = _set_cooldown(text, "pyproject.toml", "requests", "2025-06-09T16:43:06Z")
    assert tomllib.loads(after)["tool"]["uv"]["exclude-newer-package"] == {
        "requests": "2025-06-09T16:43:06Z"
    }


def test_sub_table_form_is_edited_in_place(tmp_path) -> None:
    text = HEAD + (
        '[tool.uv]\nexclude-newer = "2025-06-01T00:00:00Z"\n\n'
        '[tool.uv.exclude-newer-package]\ndjango = "2025-07-01T00:00:00Z"\n'
    )
    after = _set_cooldown(text, "pyproject.toml", "requests", "2025-06-09T16:43:06Z")
    assert tomllib.loads(after)["tool"]["uv"]["exclude-newer-package"] == {
        "django": "2025-07-01T00:00:00Z",
        "requests": "2025-06-09T16:43:06Z",
    }


def test_exemption_goes_to_uv_toml_when_the_cooldown_is_set_there(tmp_path, monkeypatch) -> None:
    project = _uv(tmp_path, "", uv_toml='exclude-newer = "2025-06-01T00:00:00Z"\n')
    _resolves_only_with_exemption(monkeypatch)
    plan = build_fix_plan(_scan(), project, _checks())
    assert plan.status == "verified"
    assert "+++ b/uv.toml" in plan.diff
    assert '+exclude-newer-package = { requests = "2025-06-09T16:43:06Z" }' in plan.diff


def test_cooldown_not_in_project_files_is_left_out_with_the_exact_setting(
    tmp_path, monkeypatch
) -> None:
    project = _uv(tmp_path, "")  # e.g. UV_EXCLUDE_NEWER in the environment
    _resolves_only_with_exemption(monkeypatch)
    plan = build_fix_plan(_scan(), project, _checks())
    assert plan.status == "none"
    [item] = plan.left_out
    assert "not set in pyproject.toml or uv.toml" in item.why
    assert 'requests = "2025-06-09T16:43:06Z"' in item.why


def test_removing_the_only_exemption_removes_the_line() -> None:
    text = HEAD + '[tool.uv]\nexclude-newer = "2025-06-01T00:00:00Z"\n'
    added = _set_cooldown(text, "pyproject.toml", "requests", "2025-06-09T16:43:06Z")
    assert _set_cooldown(added, "pyproject.toml", "requests", "") == text


def test_dotted_package_names_are_quoted() -> None:
    # Unquoted, TOML reads zope.interface as a table "zope" with key "interface".
    text = HEAD + '[tool.uv]\nexclude-newer = "2025-06-01T00:00:00Z"\n'
    after = _set_cooldown(text, "pyproject.toml", "zope.interface", "2025-06-09T16:43:06Z")
    assert tomllib.loads(after)["tool"]["uv"]["exclude-newer-package"] == {
        "zope.interface": "2025-06-09T16:43:06Z"
    }


def test_windows_line_endings_are_kept() -> None:
    text = (HEAD + '[tool.uv]\nexclude-newer = "2025-06-01T00:00:00Z"\n').replace("\n", "\r\n")
    after = _set_cooldown(text, "pyproject.toml", "requests", "2025-06-09T16:43:06Z")
    assert after.count("\n") == after.count("\r\n")


def test_rolling_cooldown_plan_says_when_to_remove_the_entry(tmp_path, monkeypatch) -> None:
    project = _uv(tmp_path, '[tool.uv]\nexclude-newer = "7 days"\n')
    _resolves_only_with_exemption(monkeypatch)
    plan = build_fix_plan(_scan(), project, _checks())
    [item] = plan.included
    assert item.expires == "2025-06-16"
    assert plan.to_dict()["included"][0]["cooldown_exemption"]["remove_after"] == "2025-06-16"
    assert "holds the package on that release" in plan.note


@pytest.mark.parametrize(
    ("cooldown", "entries", "stale"),
    [
        # Rolling window: on 2026-11-13 a 7-day cooldown admits up to 2026-11-06.
        ('"7 days"', '{ requests = "2025-06-09T16:43:06Z" }', ["requests"]),
        ('"P1W"', '{ requests = "2025-06-09T16:43:06Z" }', ["requests"]),
        ('"7 days"', '{ requests = "2026-11-10T00:00:00Z" }', []),
        # A fixed date moved past the entry.
        ('"2025-07-01T00:00:00Z"', '{ requests = "2025-06-09T16:43:06Z" }', ["requests"]),
        ('"2025-06-01T00:00:00Z"', '{ requests = "2025-06-09T16:43:06Z" }', []),
        # false (no cooldown for it) and per-package windows are never stale.
        ('"7 days"', '{ requests = false, idna = "3 days" }', []),
    ],
)
def test_stale_exemptions(tmp_path, cooldown, entries, stale) -> None:
    from datetime import UTC, datetime

    project = _uv(
        tmp_path, f"[tool.uv]\nexclude-newer = {cooldown}\nexclude-newer-package = {entries}\n"
    )
    now = datetime(2026, 11, 13, tzinfo=UTC)
    assert [name for name, _, _ in fp.stale_exemptions(project, now)] == stale


def test_scan_warns_about_a_stale_exemption(tmp_path, monkeypatch, capsys) -> None:
    import io

    from depquiet.cli import main

    project = _uv(
        tmp_path,
        '[tool.uv]\nexclude-newer = "7 days"\n'
        'exclude-newer-package = { requests = "2025-06-09T16:43:06Z" }\n',
    )
    monkeypatch.setattr("sys.stdin", io.StringIO('{"dependencies": []}'))
    main(["--path", str(project), "--stdin", "--offline"])
    err = capsys.readouterr().err
    assert "exclude-newer-package holds requests" in err
    assert "Remove the entry" in err
