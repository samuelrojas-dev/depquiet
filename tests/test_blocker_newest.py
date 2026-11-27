"""A package is said to hold a fix back for good only if its newest release does.

Real case (Blocker Index study, 2026-11-27): in camel, uv could not lock pillow
13.0.0 with crawl4ai loosened, and depquiet said no version of crawl4ai allowed
the fix. crawl4ai 0.9.6 requires only pillow>=10.4: camel's own psutil<6 and its
agentops<0.4 kept uv on crawl4ai 0.6.3. semgrep, on the other hand, really does
cap mcp in its newest release (mcp==1.29.0).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet.dashboard import dashboard_markdown
from depquiet.fixcheck import FixCheck
from depquiet.fixplan import build_fix_plan
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

UV_SAYS = "Because semgrep==1.187.0 depends on mcp==1.29.0, we can conclude that ..."


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
        'dependencies = ["pillow>=12", "semgrep>=1.100"]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.11"\n\n'
        '[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n'
        '[[package]]\nname = "pillow"\nversion = "12.2.0"\n\n'
        '[[package]]\nname = "semgrep"\nversion = "1.187.0"\n\n'
        '[[package]]\nname = "mcp"\nversion = "1.29.0"\n',
        encoding="utf-8",
    )
    return tmp_path


def _result() -> ScanResult:
    def r(package: str, version: str, fix: str) -> TriageResult:
        return TriageResult(
            Vulnerability(f"GHSA-{package}", package, version, Severity.HIGH, fix_version=fix),
            Verdict.ACTION,
        )

    return ScanResult(
        ".", "pip", 4, [r("mcp", "1.29.0", "1.30.0"), r("pillow", "12.2.0", "13.0.0")]
    )


def _checks() -> dict[str, FixCheck]:
    return {
        "mcp": FixCheck("blocked", "mcp", "1.30.0", reason="dependency", also_upgrade=["semgrep"]),
        "pillow": FixCheck("resolves", "pillow", "13.0.0"),
    }


@pytest.fixture
def uv(monkeypatch):
    def run(root: Path, executable: str, specs: list[str], timeout: int):
        if "mcp==1.30.0" in specs:
            return 1, "", f"No solution found when resolving dependencies:\n  {UV_SAYS}\n"
        return 0, "", "Update pillow v12.2.0 -> v13.0.0\n"

    monkeypatch.setattr(fp.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(fp, "_run_lock", run)


def _plan(tmp_path, monkeypatch, newest):
    monkeypatch.setattr(fp, "_newest_requirements", lambda blockers, package: newest)
    plan = build_fix_plan(_result(), _project(tmp_path), _checks())
    return plan, next(i for i in plan.items if i.package == "mcp")


def test_a_blocker_whose_newest_release_caps_the_fix_holds_it_back(
    tmp_path, monkeypatch, uv
) -> None:
    plan, mcp = _plan(tmp_path, monkeypatch, {"semgrep": ("1.187.0", ["mcp==1.29.0"])})
    assert mcp.blocked_by == ["semgrep"]
    assert mcp.why.startswith(
        "blocked by semgrep, and no release of it allows the fix: the newest, "
        "semgrep 1.187.0 requires mcp==1.29.0. uv: "
    )
    assert "semgrep==1.187.0 depends on mcp==1.29.0" in mcp.why
    body = dashboard_markdown(_result(), plan, pr_line="")
    assert "No release of `semgrep` lets these fixes in yet" in body


def test_a_blocker_whose_newest_release_allows_the_fix_is_not_blamed(
    tmp_path, monkeypatch, uv
) -> None:
    plan, mcp = _plan(tmp_path, monkeypatch, {"semgrep": ("1.200.0", ["mcp>=1.29"])})
    assert mcp.blocked_by == []
    assert mcp.why.startswith(
        "held back through semgrep, though the newest release allows the fix "
        "(semgrep 1.200.0): something else in the project keeps uv from moving to it."
    )
    body = dashboard_markdown(_result(), plan, pr_line="")
    assert "Held back by another package" not in body
    assert "### 🔧 Needs a change in your project" in body
    assert plan.to_dict()["left_out"][0]["blocked_by"] == []


def test_when_pypi_cannot_say_nothing_is_claimed(tmp_path, monkeypatch, uv) -> None:
    _, mcp = _plan(tmp_path, monkeypatch, {"semgrep": None})
    assert mcp.blocked_by == []
    assert "PyPI could not say whether the newest release allows mcp 1.30.0" in mcp.why
    assert "no release of" not in mcp.why


def test_only_the_blockers_that_cap_the_fix_are_named(monkeypatch) -> None:
    """private-gpt: pandasai 3.0.0 caps pillow below 11; llama-index-core does not."""
    item = fp.PlanItem("pillow", "13.0.0", "10.4.0")
    newest = {
        "pandasai": ("3.0.0", ["pillow<11.0.0,>=10.1.0"]),
        "llama-index-core": ("0.14.26", ["pillow>=9.0.0"]),
    }
    monkeypatch.setattr(fp, "_newest_requirements", lambda blockers, package: newest)
    fp._explain_blockers(item, ["pandasai", "llama-index-core"], "no solution")
    assert item.blocked_by == ["pandasai"]
    assert "the newest, pandasai 3.0.0 requires pillow<11.0.0,>=10.1.0" in item.why


@pytest.mark.parametrize(
    ("requirement", "version", "excluded"),
    [
        ("pillow (>=9.0.0)", "13.0.0", False),
        ("pillow<11.0.0,>=10.1.0", "13.0.0", True),
        ('unstructured==0.16.20; python_version < "3.13" and extra == "owl"', "0.24.1", True),
        ("wcmatch~=8.3", "11.2", True),
        ("wcmatch<12,>=10.1", "11.2", False),
        ("PyPDF2", "3.9.0", False),
    ],
)
def test_excludes(requirement, version, excluded) -> None:
    assert fp._excludes(requirement, version) is excluded


@pytest.mark.python_lookups
def test_newest_requirements_reads_pypi(monkeypatch) -> None:
    payload = {
        "info": {
            "version": "0.2.90",
            "requires_dist": [
                "pillow (>=9.0.0)",
                'yt-dlp<2025,>=2024.11.4; extra == "owl"',
                "pillowfight>=1",
                "PyPDF2",
            ],
        }
    }

    def urlopen(url, timeout):
        if "missing" in url:
            raise OSError("offline")
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    assert fp._newest_requirements(["camel-ai"], "Pillow") == {
        "camel-ai": ("0.2.90", ["pillow (>=9.0.0)"])
    }
    assert fp._newest_requirements(["camel-ai"], "yt_dlp") == {
        "camel-ai": ("0.2.90", ["yt-dlp<2025,>=2024.11.4"])
    }
    assert fp._newest_requirements(["camel-ai"], "pypdf2")["camel-ai"] == ("0.2.90", ["PyPDF2"])
    assert fp._newest_requirements(["missing"], "pillow") == {"missing": None}
