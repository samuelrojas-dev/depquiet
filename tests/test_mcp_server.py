"""depquiet as an MCP server: two read-only tools over the CLI's JSON.

The tool functions are plain Python and run without the MCP SDK; the server
itself is built only when ``mcp`` is installed (``depquiet[mcp]``).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import depquiet.fixplan as fp
from depquiet import cli, mcp_server
from depquiet.mcp_server import plan_fixes, triage_alerts

AUDIT = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.31.0",
            "vulns": [{"id": "PYSEC-2026-1", "fix_versions": ["2.32.0"], "aliases": []}],
        }
    ]
}


def _project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    return tmp_path


def _stdin(monkeypatch, audit: dict = AUDIT, offline: bool = True) -> None:
    """Feed the scan a pip-audit report instead of running pip-audit."""
    real_main = cli.main
    extra = ["--offline"] if offline else []

    def main(argv):
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(audit)))
        return real_main(["--stdin", "--scanner", "pip", *extra, *argv])

    monkeypatch.setattr(cli, "main", main)


def test_triage_returns_trimmed_alerts(tmp_path, monkeypatch) -> None:
    _stdin(monkeypatch)
    out = triage_alerts(str(_project(tmp_path)))
    assert out["ok"] and out["total"] == 1 and out["counts"] == {"action": 1}
    [alert] = out["alerts"]
    assert alert["package"] == "requests" and alert["fix_version"] == "2.32.0"
    assert "decision_trace" not in alert and "evidence" not in alert
    assert "plan_fixes" in out["next"]


def test_a_missing_folder_is_an_error(tmp_path) -> None:
    out = triage_alerts(str(tmp_path / "nope"))
    assert out == {
        "ok": False,
        "error": f"No such folder: {tmp_path / 'nope'}. Pass the absolute path of the project.",
    }


def test_plan_returns_the_plan_and_never_applies(tmp_path, monkeypatch) -> None:
    # --fix-plan needs the network, so not --offline; no alerts, so no lookups.
    _stdin(monkeypatch, {"dependencies": []}, offline=False)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1"\ndependencies = ["requests"]\n', encoding="utf-8"
    )
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    plan = fp.FixPlan(
        "none",
        items=[fp.PlanItem("requests", "2.32.0", why="needs a newer Python")],
        note="n",
        python_floor=fp.PythonFloor("3.10", unblocked=["requests"], alerts=1),
    )
    seen: dict = {}
    monkeypatch.setattr(cli, "check_fixes", lambda *a, **k: ({}, ""))
    monkeypatch.setattr(cli, "build_fix_plan", lambda *a, **k: seen.update(k) or plan)
    before = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    out = plan_fixes(str(tmp_path))
    assert out["ok"] and out["applied"] is False
    assert out["plan"]["status"] == "none" and out["diff"] is None
    assert "raise_python_floor=true" in out["hint"]
    assert seen["raise_python_floor"] is False and seen["include_filtered"] is False
    plan_fixes(str(tmp_path), raise_python_floor=True, include_filtered=True)
    assert seen["raise_python_floor"] is True and seen["include_filtered"] is True
    assert (tmp_path / "pyproject.toml").read_text(encoding="utf-8") == before


def test_other_projects_get_the_plan_s_explanation(tmp_path, monkeypatch) -> None:
    _stdin(monkeypatch, {"dependencies": []}, offline=False)
    out = plan_fixes(str(_project(tmp_path)))
    assert out["ok"] and out["diff"] is None
    assert "works on uv projects" in out["plan"]["note"]


def test_the_tools_never_write_to_stdout(tmp_path, monkeypatch, capsys) -> None:
    """On stdio, stdout is the MCP protocol channel."""
    _stdin(monkeypatch)
    triage_alerts(str(_project(tmp_path)))
    assert capsys.readouterr().out == ""


def test_server_needs_the_sdk_and_says_how_to_get_it(monkeypatch) -> None:
    def no_sdk():
        raise ImportError("no mcp")

    monkeypatch.setattr(mcp_server, "build_server", no_sdk)
    with pytest.raises(SystemExit, match=r"depquiet\[mcp\]"):
        mcp_server.main()


def test_server_registers_both_tools_read_only() -> None:
    pytest.importorskip("mcp")
    import asyncio

    server = mcp_server.build_server()
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    assert set(tools) == {"triage_alerts", "plan_fixes"}
    assert all(t.annotations and t.annotations.read_only_hint for t in tools.values())
