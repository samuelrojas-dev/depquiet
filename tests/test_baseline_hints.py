"""Baseline messages from a large real scan (218 pip-audit alerts, 13 packages)."""

from __future__ import annotations

import io
import json

from depquiet.cli import main

AUDIT = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.28.0",
            "vulns": [{"id": "PYSEC-1", "fix_versions": ["2.32.0"], "aliases": []}],
        }
    ]
}


def _scan(tmp_path, monkeypatch, capsys, *extra: str) -> tuple[int, str, str]:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    code = main(["--stdin", "--offline", "--scanner", "pip", "--path", str(tmp_path), *extra])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_empty_v2_baseline_says_why(tmp_path, monkeypatch, capsys) -> None:
    _, out, _ = _scan(tmp_path, monkeypatch, capsys, "--json", "--project-id", "me/app")
    scan = tmp_path / "scan.json"
    scan.write_text(out)
    assert main(["baseline", "create", str(scan), "-o", str(tmp_path / "b.json")]) == 0
    err = capsys.readouterr().err
    assert "0 accepted contexts" in err
    assert "accepts npm component evidence only" in err
    assert f"depquiet --baseline {scan}" in err


def test_baseline_counts_agree_in_number(tmp_path, monkeypatch, capsys) -> None:
    _, out, _ = _scan(tmp_path, monkeypatch, capsys, "--json")
    scan = tmp_path / "scan.json"
    scan.write_text(out)
    code, out, _ = _scan(tmp_path, monkeypatch, capsys, "--baseline", str(scan))
    assert code == 0
    assert "📊 Baseline: 1 known finding suppressed, 0 new findings remain" in out
