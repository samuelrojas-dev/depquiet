"""An alert whose vulnerable copy only older Pythons install says so.

With ``requires-python = ">=3.11"``, uv locks soupsieve twice: 2.10 for
``python_full_version < '3.11.5'`` and 4.x above, because the patched releases
need 3.11.5. Seen in four public projects in November 2026. The verdict stays
ACTION (those installs are exposed); the report says who is.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from depquiet.cli import main
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability
from depquiet.output import print_scan_result
from depquiet.pyscope import apply_python_scopes, python_scopes

LOCK = """version = 1
requires-python = ">=3.10, <3.15"
resolution-markers = [
    "python_full_version >= '3.11.5' and sys_platform == 'win32'",
    "python_full_version >= '3.11.5' and sys_platform != 'win32'",
    "python_full_version >= '3.11' and python_full_version < '3.11.5' and sys_platform == 'win32'",
    "python_full_version >= '3.11' and python_full_version < '3.11.5' and sys_platform != 'win32'",
    "python_full_version < '3.11'",
]

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "beautifulsoup4" }]

[[package]]
name = "beautifulsoup4"
version = "4.14.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "soupsieve"
version = "2.10"
source = { registry = "https://pypi.org/simple" }
resolution-markers = [
    "python_full_version >= '3.11' and python_full_version < '3.11.5' and sys_platform == 'win32'",
    "python_full_version >= '3.11' and python_full_version < '3.11.5' and sys_platform != 'win32'",
    "python_full_version < '3.11'",
]

[[package]]
name = "soupsieve"
version = "4.1.1"
source = { registry = "https://pypi.org/simple" }
resolution-markers = [
    "python_full_version >= '3.11.5' and sys_platform == 'win32'",
    "python_full_version >= '3.11.5' and sys_platform != 'win32'",
]
"""


def _project(tmp_path: Path, lock: str = LOCK) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\nversion = "0.1.0"\nrequires-python = ">=3.10, <3.15"\n'
        'dependencies = ["beautifulsoup4"]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(lock, encoding="utf-8")
    (tmp_path / "app.py").write_text("import bs4\n", encoding="utf-8")
    return tmp_path


def test_the_older_copy_is_scoped(tmp_path) -> None:
    assert python_scopes(_project(tmp_path)) == {("soupsieve", "2.10"): "3.11.5"}


def test_a_cap_at_or_below_the_floor_is_ignored(tmp_path) -> None:
    lock = LOCK.replace('requires-python = ">=3.10, <3.15"', 'requires-python = ">=3.12"')
    assert python_scopes(_project(tmp_path, lock)) == {}


def test_a_single_copy_or_no_markers_is_ignored(tmp_path) -> None:
    lock = LOCK.split('[[package]]\nname = "soupsieve"\nversion = "4.1.1"')[0]
    assert python_scopes(_project(tmp_path, lock)) == {}
    old_copy = LOCK.index('version = "2.10"')
    markers_start = LOCK.index("resolution-markers", old_copy)
    markers_end = LOCK.index("]\n", markers_start) + 2
    no_markers = LOCK[:markers_start] + LOCK[markers_end:]
    assert python_scopes(_project(tmp_path, no_markers)) == {}


def test_no_lock_no_scope(tmp_path) -> None:
    assert python_scopes(tmp_path) == {}


def _result() -> ScanResult:
    rows = [
        TriageResult(
            vuln=Vulnerability("PYSEC-1", "soupsieve", "2.10", Severity.HIGH, fix_version="4.0"),
            verdict=Verdict.ACTION,
        ),
        TriageResult(
            vuln=Vulnerability("PYSEC-2", "soupsieve", "4.1.1", Severity.LOW, fix_version="4.2"),
            verdict=Verdict.ACTION,
        ),
    ]
    return ScanResult(".", "pip", 1, rows)


def test_apply_marks_only_the_scoped_copy(tmp_path, capsys) -> None:
    result = _result()
    assert apply_python_scopes(result, _project(tmp_path)) == 1
    assert [r.python_scope for r in result.results] == ["3.11.5", ""]
    assert result.results[0].verdict is Verdict.ACTION  # still exposed
    print_scan_result(result)
    out = capsys.readouterr().out
    assert out.count("only installed on Python below 3.11.5") == 1


def test_json_carries_the_scope(tmp_path, monkeypatch, capsys) -> None:
    project = _project(tmp_path)
    audit = {
        "dependencies": [
            {
                "name": "soupsieve",
                "version": "2.10",
                "vulns": [{"id": "PYSEC-1", "fix_versions": ["4.0"], "aliases": []}],
            }
        ]
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(audit)))
    main(["--stdin", "--offline", "--scanner", "pip", "--json", "--path", str(project)])
    [row] = json.loads(capsys.readouterr().out)["results"]
    assert row["python_scope"] == "<3.11.5" and row["verdict"] == "action"
