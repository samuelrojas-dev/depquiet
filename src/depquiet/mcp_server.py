"""depquiet as an MCP server, for coding agents (Claude Code, Cursor, Copilot...).

Agents already diagnose stuck dependency alerts by hand: read the lock, guess
which floor or pin blocks the fix, relock, look again. depquiet does that
deterministically and checks the answer with the project's own resolver, so
an agent can ask it instead of guessing.

Two tools, both read-only: nothing here edits the project or relocks it. A
plan is checked on a temporary copy, as with ``depquiet --fix-plan``, and the
agent applies the diff itself (or runs the printed command) when the user
agrees.

- ``triage_alerts``: the scan, trimmed to what an agent needs per alert.
- ``plan_fixes``: the verified fix plan, with its diff.

Runs over stdio: ``depquiet-mcp`` (``pip install 'depquiet[mcp]'``). Both tools
run the CLI in-process with ``--json`` and capture its output: on stdio,
stdout is the protocol channel, and every subprocess depquiet starts already
captures its own.

Like the CLI, a plan runs ``uv lock --dry-run`` (or Poetry) on a copy of the
project, and resolving can build source distributions: point it at projects
you would resolve yourself.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
from pathlib import Path
from typing import Any

# Per alert, what an agent needs to decide and act; the CLI's --json has more
# (evidence, decision trace), which costs context without changing the answer.
_ALERT_FIELDS = (
    "cve",
    "title",
    "package",
    "version",
    "severity",
    "verdict",
    "reasons",
    "fix_version",
    "fix_package",
    "is_dev",
    "dependency_type",
    "introduced_by",
    "python_scope",
    "epss_score",
    "url",
)


def _run(argv: list[str]) -> tuple[int, dict[str, Any] | None, str]:
    """Run ``depquiet`` in-process; returns (exit code, parsed JSON or None, stderr)."""
    from depquiet.cli import main

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    try:
        data = json.loads(out.getvalue())
    except json.JSONDecodeError:
        data = None
    return code, data if isinstance(data, dict) else None, err.getvalue().strip()


def _project(path: str) -> Path | str:
    """The project folder, or an error message."""
    folder = Path(path).expanduser()
    if not folder.is_dir():
        return f"No such folder: {path}. Pass the absolute path of the project."
    return folder.resolve()


def _error(message: str, stderr: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False, "error": message}
    if stderr:
        out["details"] = stderr[-2000:]
    return out


def triage_alerts(path: str, offline: bool = False) -> dict[str, Any]:
    """Scan a project and sort its dependency alerts into action, review and filtered."""
    project = _project(path)
    if isinstance(project, str):
        return _error(project)
    argv = ["--json", "--path", str(project)]
    if offline:
        argv.append("--offline")
    _code, data, stderr = _run(argv)
    if data is None:
        return _error("depquiet could not scan this project.", stderr)
    results = data.get("results", [])
    alerts = [
        {k: r.get(k) for k in _ALERT_FIELDS if r.get(k) not in (None, [], "")} for r in results
    ]
    counts: dict[str, int] = {}
    for r in results:
        counts[r.get("verdict", "unknown")] = counts.get(r.get("verdict", "unknown"), 0) + 1
    return {
        "ok": True,
        "project": str(project),
        "total": len(results),
        "counts": counts,
        "alerts": alerts,
        "notes": stderr or None,
        "next": (
            "plan_fixes gives the verified change that closes the action alerts."
            if counts.get("action")
            else None
        ),
    }


def plan_fixes(
    path: str,
    raise_python_floor: bool = False,
    include_filtered: bool = False,
) -> dict[str, Any]:
    """The change that closes the project's alerts, verified with uv or Poetry on a copy."""
    project = _project(path)
    if isinstance(project, str):
        return _error(project)
    with tempfile.TemporaryDirectory(prefix="depquiet-mcp-") as tmp:
        diff_file = Path(tmp) / "plan.diff"
        report_file = Path(tmp) / "plan.md"
        argv = [
            "--json",
            "--path",
            str(project),
            "--fix-plan",
            str(diff_file),
            "--fix-plan-report",
            str(report_file),
        ]
        if raise_python_floor:
            argv.append("--raise-python-floor")
        if include_filtered:
            argv.append("--fix-filtered")
        _code, data, stderr = _run(argv)
        diff = diff_file.read_text(encoding="utf-8") if diff_file.exists() else ""
        report = report_file.read_text(encoding="utf-8") if report_file.exists() else ""
    if data is None:
        return _error("depquiet could not plan fixes for this project.", stderr)
    plan = data.get("fix_plan")
    if plan is None:
        return _error("No fix plan: depquiet plans fixes for uv and Poetry projects.", stderr)
    floor = plan.get("python_floor") or {}
    hint = None
    if floor.get("unblocks") and not floor.get("adopted"):
        hint = (
            f"Raising requires-python to {floor.get('floor')} would let more fixes in "
            "(it drops older Python versions): call again with raise_python_floor=true "
            "if the user agrees."
        )
    return {
        "ok": True,
        "project": str(project),
        "plan": plan,
        "diff": diff or None,
        "pull_request_description": report or None,
        "notes": stderr or None,
        "hint": hint,
        "applied": False,
    }


_INSTRUCTIONS = (
    "depquiet triages dependency vulnerability alerts and plans the change that closes "
    "them, verified with the project's own resolver (uv or Poetry) on a temporary copy. "
    "Use triage_alerts to see which alerts matter, then plan_fixes for the exact diff and "
    "lock command. Neither tool edits the project: show the user the plan, and apply the "
    "diff or run the command only when they agree. Raising requires-python drops Python "
    "versions; ask before passing raise_python_floor=true."
)


def build_server() -> Any:
    """The MCP server with both tools; needs the ``mcp`` package (``depquiet[mcp]``)."""
    from mcp.server.mcpserver import MCPServer
    from mcp.types import ToolAnnotations

    from depquiet import __version__

    server = MCPServer(name="depquiet", version=__version__, instructions=_INSTRUCTIONS)
    read_only = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
    server.tool(
        name="triage_alerts",
        description=(
            "Scan a Python or JavaScript project (absolute path) and sort its dependency "
            "alerts into action, review and filtered, with the reason for each: dev-only, "
            "test-only, unreachable, and which Pythons a vulnerable locked copy serves."
        ),
        annotations=read_only,
    )(triage_alerts)
    server.tool(
        name="plan_fixes",
        description=(
            "Work out the change that closes the project's alerts (uv or Poetry), verified "
            "with the resolver on a temporary copy: requirement edits as a diff, the lock "
            "command, what else the lock moves, downgrades, and whether raising "
            "requires-python would unblock more fixes. Never edits the project."
        ),
        annotations=read_only,
    )(plan_fixes)
    return server


def main() -> None:
    try:
        server = build_server()
    except ImportError:
        raise SystemExit("depquiet-mcp needs the MCP SDK: pip install 'depquiet[mcp]'") from None
    server.run("stdio")
