"""After a scan with fixable alerts, the report says how to get the verified plan."""

from __future__ import annotations

import io
import json

import pytest

from depquiet.cli import main

AUDIT = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.31.0",
            "vulns": [{"id": "PYSEC-1", "fix_versions": ["2.33.0"], "aliases": []}],
        }
    ]
}


def _scan(tmp_path, monkeypatch, capsys, *flags: str) -> str:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    main(["--path", str(tmp_path), "--stdin", "--offline", "--scanner", "pip", *flags])
    return capsys.readouterr().out


@pytest.mark.parametrize(
    ("lock", "resolver"),
    [("uv.lock", "uv"), ("poetry.lock", "Poetry"), ("package-lock.json", "npm")],
)
def test_the_report_points_to_the_plan(tmp_path, monkeypatch, capsys, lock, resolver) -> None:
    (tmp_path / lock).write_text("version = 1\n", encoding="utf-8")
    out = _scan(tmp_path, monkeypatch, capsys)
    assert (
        f"Next: depquiet --fix-plan works out one change for these alerts and checks it with "
        f"{resolver} on a copy of the project. It changes nothing; depquiet --fix applies it."
        in out
    )


def test_no_hint_without_a_lock_or_in_json(tmp_path, monkeypatch, capsys) -> None:
    assert "Next:" not in _scan(tmp_path, monkeypatch, capsys)
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    assert "Next:" not in _scan(tmp_path, monkeypatch, capsys, "--json")
