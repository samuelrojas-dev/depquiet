"""SARIF paths are relative to the repository root, as GitHub code scanning reads them.

The Action's own smoke test scans ``benchmarks/fixtures/real-npm-express/project``
and uploaded alerts on ``app.js:1``, a file that does not exist at the root:
any user with ``path:`` set to a subfolder got alerts GitHub could not link.
"""

from __future__ import annotations

from depquiet.models import Severity, TriageResult, Verdict, Vulnerability
from depquiet.sarif import _build_locations, _repo_prefix


def _tr(imports: list[str]) -> TriageResult:
    v = Vulnerability(cve="CVE-1", package="lodash", version="4.17.20", severity=Severity.HIGH)
    return TriageResult(vuln=v, verdict=Verdict.ACTION, reachable_imports=imports)


def _uris(locations: list[dict]) -> list[str]:
    return [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in locations]


def test_prefix_is_the_path_from_the_git_root(tmp_path) -> None:
    (tmp_path / ".git").mkdir()
    project = tmp_path / "services" / "web"
    project.mkdir(parents=True)
    assert _repo_prefix(str(project)) == "services/web"
    assert _repo_prefix(str(tmp_path)) == ""


def test_imports_given_with_the_project_path(tmp_path, monkeypatch) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "services" / "web").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    locations = _build_locations(_tr(["services/web/app.js"]), "services/web", "npm")
    assert _uris(locations) == ["services/web/app.js"]


def test_relative_imports_are_read_from_the_project(tmp_path) -> None:
    (tmp_path / ".git").mkdir()
    project = tmp_path / "web"
    project.mkdir()
    assert _uris(_build_locations(_tr(["src/app.js"]), str(project), "npm")) == ["web/src/app.js"]


def test_manifest_fallback_picks_the_file_the_project_has(tmp_path) -> None:
    (tmp_path / ".git").mkdir()
    project = tmp_path / "py"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    assert _uris(_build_locations(_tr([]), str(project), "pip")) == ["py/pyproject.toml"]
