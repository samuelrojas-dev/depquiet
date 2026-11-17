"""Inputs read as the README documents them, and an SBOM that is a real inventory.

Found in an end-to-end audit of 0.47.2:
- ``gh api .../dependabot/alerts --paginate`` prints one JSON array per page, back to
  back; depquiet answered "invalid JSON on stdin".
- ``snyk test --all-projects --json`` prints an array of reports; depquiet read it as
  Dependabot alerts and produced one empty alert instead of the real ones.
- A SARIF file with only code findings (Semgrep, CodeQL) was reported as
  "No vulnerabilities found", exit 0.
- ``--sbom`` listed only the packages with an alert, not the lockfile's inventory.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from depquiet.cli import _read_stdin_report, _wrap_report_list, main
from depquiet.parsers.dependabot import DependabotParser
from depquiet.parsers.sarif import code_findings
from depquiet.parsers.snyk import SnykParser

FIXTURES = Path(__file__).parent / "fixtures"


def _alert(number: int, ghsa: str, cve: str, severity: str = "high") -> dict:
    return {
        "number": number,
        "state": "open",
        "dependency": {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "manifest_path": "package-lock.json",
            "scope": "runtime",
        },
        "security_advisory": {
            "ghsa_id": ghsa,
            "cve_id": cve,
            "summary": "s",
            "severity": severity,
        },
        "security_vulnerability": {
            "vulnerable_version_range": "< 4.17.21",
            "first_patched_version": {"identifier": "4.17.21"},
        },
    }


PAGE_1 = [_alert(1, "GHSA-aaaa-aaaa-aaaa", "CVE-2021-23337")]
PAGE_2 = [_alert(2, "GHSA-bbbb-bbbb-bbbb", "CVE-2020-28500", "medium")]


def _snyk_project(manager: str, package: str) -> dict:
    return {
        "ok": False,
        "packageManager": manager,
        "vulnerabilities": [
            {
                "id": f"SNYK-{package.upper()}-1",
                "title": "t",
                "severity": "high",
                "packageName": package,
                "version": "1.0.0",
                "fixedIn": ["2.0.0"],
                "from": ["app@1", f"{package}@1.0.0"],
                "identifiers": {"CVE": ["CVE-2024-1111", "CVE-2024-2222"]},
            }
        ],
    }


def _run(tmp_path, monkeypatch, capsys, stdin: str, *extra: str) -> tuple[int, str, str]:
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {}}')
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(["--stdin", "--offline", "--path", str(tmp_path), *extra])
    out = capsys.readouterr()
    return code, out.out, out.err


# Dependabot pages


def test_paginated_pages_become_one_list() -> None:
    text = json.dumps(PAGE_1) + "\n" + json.dumps(PAGE_2)
    assert [a["number"] for a in _read_stdin_report(text)] == [1, 2]


def test_slurped_pages_become_one_list() -> None:
    assert [a["number"] for a in _read_stdin_report(json.dumps([PAGE_1, PAGE_2]))] == [1, 2]


def test_two_objects_back_to_back_stay_invalid() -> None:
    try:
        _read_stdin_report('{"a": 1}{"b": 2}')
    except json.JSONDecodeError:
        return
    raise AssertionError("two objects must not be merged")


def test_paginated_dependabot_output_is_read(tmp_path, monkeypatch, capsys) -> None:
    text = json.dumps(PAGE_1) + json.dumps(PAGE_2)
    code, out, _ = _run(tmp_path, monkeypatch, capsys, text, "--json")
    rows = json.loads(out)["results"]
    assert code == 1
    assert sorted(r["cve"] for r in rows) == ["CVE-2020-28500", "CVE-2021-23337"]


def test_dependabot_keeps_the_ghsa_as_an_alias() -> None:
    [v] = DependabotParser.parse({"alerts": PAGE_1}, Path("."))
    assert v.cve == "CVE-2021-23337" and v.aliases == ["GHSA-aaaa-aaaa-aaaa"]


def test_dependabot_skips_an_alert_without_a_package() -> None:
    alert = _alert(3, "GHSA-cccc-cccc-cccc", "CVE-2024-3")
    alert["dependency"]["package"] = {}
    assert DependabotParser.parse({"alerts": [alert]}, Path(".")) == []


# Arrays that are not Dependabot


def test_snyk_all_projects_is_read_as_snyk(tmp_path, monkeypatch, capsys) -> None:
    text = json.dumps([_snyk_project("npm", "lodash"), _snyk_project("pip", "requests")])
    code, out, _ = _run(tmp_path, monkeypatch, capsys, text, "--json")
    rows = json.loads(out)["results"]
    assert code == 1
    assert sorted(r["package"] for r in rows) == ["lodash", "requests"]
    assert all(r["cve"] == "CVE-2024-1111" for r in rows)


def test_snyk_keeps_every_other_id_as_an_alias() -> None:
    [v] = SnykParser.parse(_snyk_project("npm", "lodash"), Path("."))
    assert v.aliases == ["CVE-2024-2222", "SNYK-LODASH-1"]


def test_an_unknown_array_is_refused(tmp_path, monkeypatch, capsys) -> None:
    code, _, err = _run(tmp_path, monkeypatch, capsys, "[1, 2]")
    assert code == 2 and "neither Dependabot alerts nor snyk" in err
    assert _wrap_report_list([{"x": 1}]) is None


# SARIF with code findings


def _sarif(results: list[dict]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "t", "rules": []}}, "results": results}],
    }


CODE_FINDING = {
    "ruleId": "python.lang.security.eval",
    "level": "error",
    "message": {"text": "Detected eval() usage"},
    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}],
}
DEPENDENCY_FINDING = {
    "ruleId": "CVE-2021-23337",
    "level": "error",
    "message": {"text": "lodash command injection"},
    "properties": {"packageName": "lodash", "installedVersion": "4.17.20"},
}


def test_code_only_sarif_is_not_reported_clean(tmp_path, monkeypatch, capsys) -> None:
    code, out, err = _run(tmp_path, monkeypatch, capsys, json.dumps(_sarif([CODE_FINDING])))
    assert code == 2
    assert "No vulnerabilities found" not in out
    assert "1 SARIF result names no package" in err


def test_mixed_sarif_says_what_it_left_out(tmp_path, monkeypatch, capsys) -> None:
    sarif = _sarif([CODE_FINDING, DEPENDENCY_FINDING])
    assert code_findings(sarif) == 1
    code, out, _ = _run(tmp_path, monkeypatch, capsys, json.dumps(sarif))
    assert code == 1
    assert "1 SARIF result names no package" in out


# SBOM inventory


UV_LOCK = """version = 1
requires-python = ">=3.11"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "idna" }]

[[package]]
name = "idna"
version = "3.10"
source = { registry = "https://pypi.org/simple" }
"""

PIP_AUDIT = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.31.0",
            "vulns": [{"id": "PYSEC-2026-1", "fix_versions": ["2.32.0"], "aliases": []}],
        },
        {"name": "idna", "version": "3.10", "vulns": []},
    ]
}


def _sbom_scan(project: Path, monkeypatch, capsys, out: Path) -> str:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(PIP_AUDIT)))
    main(["--stdin", "--offline", "--scanner", "pip", "--path", str(project), "--sbom", str(out)])
    return capsys.readouterr().err


def test_sbom_lists_every_locked_package(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests"]\n'
    )
    (tmp_path / "uv.lock").write_text(UV_LOCK)
    out = tmp_path / "sbom.json"
    err = _sbom_scan(tmp_path, monkeypatch, capsys, out)
    names = sorted(c["name"] for c in json.loads(out.read_text())["components"])
    assert names == ["idna", "requests"]
    assert "not a full inventory" not in err


def test_sbom_without_a_lockfile_says_it_is_partial(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "requirements.in").write_text("requests\n")
    out = tmp_path / "sbom.json"
    err = _sbom_scan(tmp_path, monkeypatch, capsys, out)
    names = [c["name"] for c in json.loads(out.read_text())["components"]]
    assert names == ["requests"]
    assert "not a full inventory" in err
