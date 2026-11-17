"""Report wording seen on a real Windows run of 0.47.5."""

from __future__ import annotations

import io
import json

from depquiet.cli import main
from depquiet.engine import scan
from depquiet.output import _source_label


def test_header_says_what_produced_the_alerts() -> None:
    assert _source_label("pip") == "Python, via pip-audit"
    assert _source_label("pip+npm") == "Python, via pip-audit + npm audit"
    assert _source_label("cargo") == "cargo"


def test_nothing_scanned_names_the_full_path(tmp_path) -> None:
    result = scan(project=tmp_path, skip_epss=True)
    assert not result.scanned
    assert f"in {tmp_path.resolve()}: run depquiet" in result.note
    assert ".." not in result.note


def test_one_blank_line_before_the_kev_note(tmp_path, monkeypatch, capsys) -> None:
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-1"}]}))
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    audit = {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.31.0",
                "vulns": [{"id": "PYSEC-1", "fix_versions": ["2.32.0"], "aliases": []}],
            }
        ]
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(audit)))
    main(
        [
            "--stdin",
            "--offline",
            "--scanner",
            "pip",
            "--path",
            str(tmp_path),
            "--kev-file",
            str(kev),
        ]
    )
    out = capsys.readouterr().out
    assert "vulnerable function.\n\n🛡️  KEV" in out
