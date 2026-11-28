"""With --fix-plan, the report groups alerts by package, so the plan is not buried.

On a fresh 0.48.0 run with 21 alerts (20 of them tornado), each alert took three
or four lines with its own fix check, and the plan the user asked for started
on line 79. Grouped by package, the shape of the plan, it starts on line 22.
"""

from __future__ import annotations

from types import SimpleNamespace

from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability
from depquiet.output import print_scan_result


def _row(cve: str, package: str, fix: str, status: str = "resolves", kev=None) -> TriageResult:
    row = TriageResult(
        vuln=Vulnerability(cve, package, "1.0", Severity.HIGH, fix_version=fix),
        verdict=Verdict.ACTION,
        reachable_imports=["app.py"],
    )
    row.fix_check = SimpleNamespace(status=status, command="uv lock", detail="", next_step="")
    row.kev_entry = kev
    return row


def _result() -> ScanResult:
    rows = [_row(f"PYSEC-2026-{i}", "tornado", f"6.5.{i}") for i in range(1, 6)]
    rows.append(_row("PYSEC-2026-99", "tornado", "6.6.1", status="blocked"))
    rows.append(_row("PYSEC-2026-50", "pytest", "9.0.3", status="blocked"))
    return ScanResult(".", "pip", 2, rows)


def test_grouped_by_package_when_a_plan_follows(capsys) -> None:
    print_scan_result(_result(), plan_follows=True)
    out = capsys.readouterr().out
    assert "tornado  6 alerts  FIX: update to 6.6.1" in out
    assert "PYSEC-2026-1, PYSEC-2026-2, PYSEC-2026-3, PYSEC-2026-4 and 2 more" in out
    assert "pytest  1 alert  FIX: update to 9.0.3" in out
    assert "Fix checks for 7 alerts: 5 resolve on their own, 2 blocked." in out
    assert "fix check:" not in out


def test_a_known_exploited_alert_stays_visible(capsys) -> None:
    result = _result()
    result.results[2].kev_entry = object()
    print_scan_result(result, plan_follows=True)
    assert "KNOWN EXPLOITED: PYSEC-2026-3" in capsys.readouterr().out


def test_without_a_plan_every_alert_is_listed(capsys) -> None:
    print_scan_result(_result())
    out = capsys.readouterr().out
    assert out.count("fix check:") == 7 and "Fix checks for" not in out


def test_a_fix_in_the_parent_names_the_parent(capsys) -> None:
    """npm audit's fix for postcss-selector-parser was "@tailwindcss/typography 0.5.4"."""
    row = TriageResult(
        vuln=Vulnerability(
            "GHSA-psp",
            "postcss-selector-parser",
            "<6.1.5",
            Severity.HIGH,
            fix_version="0.5.4",
            fix_package="@tailwindcss/typography",
        ),
        verdict=Verdict.ACTION,
    )
    print_scan_result(ScanResult(".", "npm", 1, [row]), plan_follows=True)
    out = capsys.readouterr().out
    assert "postcss-selector-parser  1 alert  FIX: update @tailwindcss/typography to 0.5.4" in out


def test_a_first_scan_groups_by_package_too(capsys) -> None:
    """depquiet-floor-test (2026-11-27): 71 alerts on 170 lines, pillow's with two fixes."""
    rows = [
        TriageResult(
            vuln=Vulnerability(f"PYSEC-{i}", "pillow", "12.2.0", Severity.HIGH, fix_version=fix),
            verdict=Verdict.ACTION,
            dependency_type="transitive",
            introduced_by=["app"],
        )
        for i, fix in enumerate(["12.3.0", "13.0.0", "12.3.0"])
    ]
    print_scan_result(ScanResult(".", "pip", 1, rows))
    out = capsys.readouterr().out
    assert "pillow  3 alerts  FIX: update to 13.0.0" in out
    assert "via app" in out
    assert "FIX: update to 12.3.0" not in out
