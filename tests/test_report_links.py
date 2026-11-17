"""A URL from a scanner report becomes a link only when it is a web address.

0.47.2 wrote ``href="javascript:alert(document.domain)"`` into the HTML report
for a SARIF rule whose helpUri was a javascript: URL: a click ran the script.
"""

from __future__ import annotations

import io
import json

import pytest

from depquiet.cli import main
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability
from depquiet.summary import render_summary


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox",
        "https://example.com/a b",
        'https://example.com/"onmouseover="x',
    ],
)
def test_non_web_urls_are_dropped(url: str) -> None:
    assert Vulnerability("CVE-1", "p", "1", Severity.LOW, url=url).url == ""


def test_web_urls_are_kept() -> None:
    url = "https://github.com/advisories/GHSA-p6mc-m468-83gw"
    assert Vulnerability("CVE-1", "p", "1", Severity.LOW, url=url).url == url


def test_markdown_link_cannot_be_closed_early() -> None:
    v = Vulnerability("CVE-1", "p", "1", Severity.LOW, url="https://x.test/a)[evil](https://e")
    result = ScanResult(".", "npm", 1, [TriageResult(vuln=v, verdict=Verdict.ACTION)])
    summary = render_summary(result)
    assert "[CVE-1](https://x.test/a%29[evil]%28https://e)" in summary


def test_crafted_sarif_writes_no_javascript_link(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {}}')
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "t",
                        "rules": [
                            {"id": "CVE-2021-23337", "helpUri": "javascript:alert(document.domain)"}
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "CVE-2021-23337",
                        "level": "error",
                        "message": {"text": "lodash"},
                        "properties": {"packageName": "lodash", "installedVersion": "4.17.20"},
                    }
                ],
            }
        ],
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(sarif)))
    report = tmp_path / "r.html"
    sarif_out = tmp_path / "out.sarif"
    main(
        [
            "--stdin",
            "--offline",
            "--path",
            str(tmp_path),
            "--html",
            str(report),
            "--sarif",
            str(sarif_out),
        ]
    )
    capsys.readouterr()
    assert "javascript:" not in report.read_text().lower()
    assert "javascript:" not in sarif_out.read_text().lower()
