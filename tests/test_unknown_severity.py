"""A severity the scanner did not state is unknown, never "moderate".

Alerts without a severity are stored as MODERATE with ``severity_known=False``.
Before 0.47.2 several parsers marked that placeholder as measured, and a policy
rule ``severity: moderate`` + ``action: filter`` dismissed every pip-audit alert
with exit 0.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from depquiet.cli import main
from depquiet.models import Severity, TriageResult, Verdict, Vulnerability
from depquiet.parsers.dependabot import DependabotParser
from depquiet.parsers.grype import GrypeParser
from depquiet.parsers.sarif import _extract_severity
from depquiet.parsers.snyk import SnykParser
from depquiet.parsers.trivy import TrivyParser
from depquiet.policy import PolicyRule
from depquiet.stats import stats_from_json

HERE = Path(".")


@pytest.mark.parametrize(
    ("word", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("Medium", Severity.MODERATE),
        ("moderate", Severity.MODERATE),
        ("Negligible", Severity.INFO),
        ("informational", Severity.INFO),
        ("UNKNOWN", None),
        ("", None),
        (None, None),
        ("banana", None),
    ],
)
def test_parse_states_only_what_was_said(word, expected) -> None:
    assert Severity.parse(word) is expected


def _trivy(severity):
    entry = {"VulnerabilityID": "CVE-2024-1", "PkgName": "lodash", "InstalledVersion": "1"}
    if severity is not None:
        entry["Severity"] = severity
    block = {"Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm"}
    return {"Results": [{**block, "Vulnerabilities": [entry]}]}


def _grype(severity):
    vuln = {"id": "CVE-2024-1", "fix": {"versions": [], "state": "unknown"}}
    if severity is not None:
        vuln["severity"] = severity
    return {"matches": [{"vulnerability": vuln, "artifact": {"name": "x", "version": "1"}}]}


def _snyk(severity):
    entry = {"id": "SNYK-1", "packageName": "x", "version": "1", "identifiers": {}}
    if severity is not None:
        entry["severity"] = severity
    return {"vulnerabilities": [entry]}


def _dependabot(severity):
    advisory = {"ghsa_id": "GHSA-1", "cve_id": "CVE-2024-1", "summary": "s"}
    if severity is not None:
        advisory["severity"] = severity
    return {
        "alerts": [
            {
                "state": "open",
                "dependency": {"package": {"ecosystem": "npm", "name": "x"}, "scope": "runtime"},
                "security_advisory": advisory,
                "security_vulnerability": {"vulnerable_version_range": "< 2"},
            }
        ]
    }


PARSERS = [
    (TrivyParser, _trivy),
    (GrypeParser, _grype),
    (SnykParser, _snyk),
    (DependabotParser, _dependabot),
]


@pytest.mark.parametrize(("parser", "build"), PARSERS)
@pytest.mark.parametrize("stated", [None, "UNKNOWN", "Unknown", ""])
def test_parsers_keep_a_missing_severity_unknown(parser, build, stated) -> None:
    [v] = parser.parse(build(stated), HERE)
    assert v.severity_known is False
    assert v.severity_label == "unknown"


@pytest.mark.parametrize(("parser", "build"), PARSERS)
def test_parsers_keep_a_stated_severity(parser, build) -> None:
    [v] = parser.parse(build("high"), HERE)
    assert v.severity_known is True and v.severity is Severity.HIGH


def test_sarif_security_severity_is_a_cvss_score() -> None:
    assert (
        _extract_severity({"properties": {"security-severity": "9.8"}}, None) is Severity.CRITICAL
    )
    assert _extract_severity({"properties": {"security-severity": "7.5"}}, None) is Severity.HIGH
    assert _extract_severity({"properties": {"severity": "unknown"}}, None) is None


def _vuln(known: bool) -> Vulnerability:
    return Vulnerability("PYSEC-1", "p", "1", Severity.MODERATE, severity_known=known)


def test_severity_rule_never_matches_an_unknown_severity() -> None:
    rule = PolicyRule(id="r", action=Verdict.FILTERED, severity=[Severity.MODERATE])
    assert rule.matches(TriageResult(vuln=_vuln(True), verdict=Verdict.ACTION))
    assert not rule.matches(TriageResult(vuln=_vuln(False), verdict=Verdict.ACTION))


def test_dismiss_moderate_policy_does_not_hide_pip_audit_alerts(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / ".depquiet-policy.yaml").write_text(
        "rules:\n  - id: dismiss-moderate\n    action: filter\n    severity: moderate\n"
    )
    audit = {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.31.0",
                "vulns": [{"id": "PYSEC-2026-1", "fix_versions": ["2.32.0"], "aliases": []}],
            }
        ]
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(audit)))
    code = main(["--stdin", "--offline", "--scanner", "pip", "--json", "--path", str(tmp_path)])
    row = json.loads(capsys.readouterr().out)["results"][0]
    assert row["verdict"] == "action" and code == 1


def test_stats_counts_unknown_as_unknown() -> None:
    stats = stats_from_json({"results": [{"cve": "PYSEC-1", "severity": "unknown"}]})
    assert stats.severity_counts == {"unknown": 1}


def test_result_order_in_json_is_by_severity(tmp_path, monkeypatch, capsys) -> None:
    rows = [("CVE-2024-1", "low"), ("CVE-2024-2", "critical"), ("CVE-2024-3", "moderate")]
    data = _trivy(None)
    entries = data["Results"][0]["Vulnerabilities"]
    entries.clear()
    for cve, sev in rows:
        entries.append(
            {
                "VulnerabilityID": cve,
                "PkgName": f"p{cve[-1]}",
                "InstalledVersion": "1",
                "Severity": sev.upper(),
            }
        )
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {}}')
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(data)))
    main(["--stdin", "--offline", "--json", "--path", str(tmp_path)])
    order = [r["severity"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert order == ["critical", "moderate", "low"]
