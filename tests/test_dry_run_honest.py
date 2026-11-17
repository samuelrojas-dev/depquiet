"""--fix --dry-run reports attempts, not fixes, and keeps the scan's exit code.

0.47.2 printed "[dry-run] ✅ Fixed 8 vulnerabilities" and exited 0 on a project
where 5 of those 8 upgrades cannot install (botocore 1.29.0 holds urllib3 below
1.27), while 10 ACTION alerts were still open.
"""

from __future__ import annotations

import io
import json
from unittest.mock import patch

from depquiet.cli import main
from depquiet.fix import FixReport, FixResult, print_fix_report


def test_dry_run_never_says_fixed(capsys) -> None:
    report = FixReport(
        fixed=[FixResult("urllib3", "1.26.20", "2.8.0", "PYSEC-1", True, "Would run: uv lock")]
    )
    print_fix_report(report, dry_run=True)
    err = capsys.readouterr().err
    assert "Fixed" not in err
    assert "Would try 1 upgrade." in err and "--check-fixes" in err
    assert "Would run: uv lock" in err


def test_real_fix_still_says_fixed(capsys) -> None:
    report = FixReport(fixed=[FixResult("lodash", "4.17.20", "4.17.21", "CVE-1", True)])
    print_fix_report(report)
    assert "✅ Fixed 1 alert:" in capsys.readouterr().err


AUDIT = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.31.0",
            "vulns": [{"id": "PYSEC-2026-1", "fix_versions": ["2.32.0"], "aliases": []}],
        }
    ]
}

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
"""


def test_dry_run_exit_code_is_the_scans(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests>=2.31"]\n'
    )
    (tmp_path / "uv.lock").write_text(UV_LOCK)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    with patch("depquiet.fix.subprocess.run") as run_command:
        code = main(
            [
                "--path",
                str(tmp_path),
                "--stdin",
                "--offline",
                "--scanner",
                "pip",
                "--fix",
                "--dry-run",
            ]
        )
    run_command.assert_not_called()
    assert code == 1  # the ACTION alert is still open: nothing ran
    err = capsys.readouterr().err
    assert "Would try 1 upgrade." in err and "Fixed" not in err
