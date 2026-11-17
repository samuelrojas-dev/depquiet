"""explain says only what the scan established: found by CVE alias, no made-up
severity, and KEV "not listed" only when KEV was actually checked."""

from __future__ import annotations

import io
import json

from depquiet.cli import main
from depquiet.explain import explain_triage, find_cve, find_cve_in_json
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability

AUDIT = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.31.0",
            "vulns": [
                {
                    "id": "PYSEC-2026-1873",
                    "fix_versions": ["2.32.0"],
                    "aliases": ["CVE-2024-35195"],
                    "description": "Session verify=False sticks",
                }
            ],
        }
    ]
}


def _saved_scan(tmp_path, monkeypatch, capsys, *extra: str) -> dict:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    args = ["--stdin", "--offline", "--scanner", "pip", "--json", "--path", str(tmp_path)]
    main([*args, *extra])
    return json.loads(capsys.readouterr().out)


def _kev(exp):
    return next(s for s in exp.signals if s.name == "CISA KEV")


def test_saved_scan_is_found_by_cve_alias(tmp_path, monkeypatch, capsys) -> None:
    data = _saved_scan(tmp_path, monkeypatch, capsys)
    for name in ("CVE-2024-35195", "cve-2024-35195", "PYSEC-2026-1873"):
        tr = find_cve_in_json(data, name)
        assert tr is not None and tr.vuln.cve == "PYSEC-2026-1873"
    assert find_cve_in_json(data, "CVE-1999-0001") is None


def test_live_scan_is_found_by_cve_alias() -> None:
    v = Vulnerability("PYSEC-1", "p", "1", Severity.LOW, aliases=["CVE-2024-1"])
    result = ScanResult(".", "pip", 1, [TriageResult(vuln=v, verdict=Verdict.ACTION)])
    assert find_cve(result, "cve-2024-1") is not None


def test_own_id_wins_over_another_rows_alias() -> None:
    a = Vulnerability("GHSA-a", "p", "1", Severity.LOW, aliases=["CVE-2024-9"])
    b = Vulnerability("CVE-2024-9", "q", "1", Severity.LOW)
    result = ScanResult(
        ".", "pip", 2, [TriageResult(vuln=x, verdict=Verdict.ACTION) for x in (a, b)]
    )
    found = find_cve(result, "CVE-2024-9")
    assert found is not None and found.vuln.package == "q"


def test_unknown_severity_stays_unknown(tmp_path, monkeypatch, capsys) -> None:
    data = _saved_scan(tmp_path, monkeypatch, capsys)
    assert data["results"][0]["severity"] == "unknown"
    tr = find_cve_in_json(data, "CVE-2024-35195")
    assert tr is not None
    assert tr.vuln.severity_known is False
    assert explain_triage(tr).severity == "unknown"


def test_saved_scan_keeps_its_aliases_for_epss(tmp_path, monkeypatch, capsys) -> None:
    data = _saved_scan(tmp_path, monkeypatch, capsys)
    tr = find_cve_in_json(data, "PYSEC-2026-1873")
    assert tr is not None and tr.vuln.cve_id == "CVE-2024-35195"
    epss = next(s for s in explain_triage(tr).signals if s.name == "EPSS score")
    assert "has no CVE id" not in epss.detail


def test_kev_not_checked_without_kev(tmp_path, monkeypatch, capsys) -> None:
    data = _saved_scan(tmp_path, monkeypatch, capsys)
    assert data["kev_checked"] is False
    tr = find_cve_in_json(data, "CVE-2024-35195")
    kev = _kev(explain_triage(tr, data["kev_checked"]))
    assert kev.value == "not checked" and "--kev" in kev.detail


def test_kev_not_listed_only_when_checked(tmp_path, monkeypatch, capsys) -> None:
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}))
    data = _saved_scan(tmp_path, monkeypatch, capsys, "--kev-file", str(kev_file))
    assert data["kev_checked"] is True
    tr = find_cve_in_json(data, "CVE-2024-35195")
    assert _kev(explain_triage(tr, True)).value == "not listed"


def test_kev_unknown_for_old_saved_scans() -> None:
    v = Vulnerability("CVE-2024-1", "p", "1", Severity.LOW)
    kev = _kev(explain_triage(TriageResult(vuln=v, verdict=Verdict.ACTION), None))
    assert kev.value == "not checked" and "does not record" in kev.detail


def test_kev_checked_but_no_cve_id_is_not_checked() -> None:
    v = Vulnerability("GHSA-xxxx", "p", "1", Severity.LOW)
    kev = _kev(explain_triage(TriageResult(vuln=v, verdict=Verdict.ACTION), True))
    assert kev.value == "not checked" and "no CVE id" in kev.detail


def test_explain_cli_end_to_end(tmp_path, monkeypatch, capsys) -> None:
    data = _saved_scan(tmp_path, monkeypatch, capsys)
    saved = tmp_path / "scan.json"
    saved.write_text(json.dumps(data))
    assert main(["explain", "CVE-2024-35195", "--from-json", str(saved)]) == 0
    out = capsys.readouterr().out
    assert "PYSEC-2026-1873" in out
    assert "Severity: UNKNOWN" in out
    assert "CISA KEV: not checked" in out
    assert "has no CVE id or alias" not in out
