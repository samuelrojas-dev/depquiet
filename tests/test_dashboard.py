"""The dashboard: every vulnerable package in one state, with what to do about it.

The cases come from real runs: wagtail (2026-11-27), where semgrep held back
mcp, opentelemetry-api and wcmatch with no release of semgrep allowing the
fixes, and depquiet-floor-test, where pillow and soupsieve needed a newer
Python than requires-python allowed.
"""

from __future__ import annotations

import pytest

import depquiet.fixplan as fp
from depquiet.dashboard import PR_PLACEHOLDER, dashboard_markdown
from depquiet.models import FilterReason, ScanResult, Severity, TriageResult, Verdict, Vulnerability


def _r(package: str, cve: str, fix: str = "", filtered: FilterReason | None = None):
    vuln = Vulnerability(cve, package, "1.0", Severity.HIGH, fix_version=fix)
    if filtered is None:
        return TriageResult(vuln, Verdict.ACTION)
    return TriageResult(vuln, Verdict.FILTERED, reasons=[filtered])


def _scan(*results: TriageResult) -> ScanResult:
    return ScanResult(".", "uv", 10, list(results))


def _item(package: str, version: str, **kwargs) -> fp.PlanItem:
    return fp.PlanItem(package, version, kwargs.pop("installed", "1.0"), **kwargs)


def test_every_state_is_listed_with_what_to_do() -> None:
    scan = _scan(
        _r("pillow", "GHSA-1", "13.0.0"),
        _r("pillow", "GHSA-2", "13.0.0"),
        _r("mcp", "CVE-1", "1.30.0"),
        _r("mcp", "CVE-2", "1.30.0"),
        _r("wcmatch", "CVE-3", "11.2"),
        _r("soupsieve", "PYSEC-1", "4.0.0"),
        _r("abandoned", "GHSA-3"),
        _r("black", "PYSEC-2", "24.3.0", filtered=FilterReason.DEV_DEPENDENCY),
    )
    floor = fp.PythonFloor(
        "3.11.5", unblocked=["soupsieve"], lock_environment="python_full_version >= '3.11.5'"
    )
    plan = fp.FixPlan(
        "partial",
        items=[
            _item("pillow", "13.0.0", installed="12.2.0", included=True),
            _item(
                "mcp",
                "1.30.0",
                why="blocked by semgrep, and no version of it allows the fix: x",
                blocked_by=["semgrep"],
            ),
            _item(
                "wcmatch",
                "11.2",
                why="blocked by semgrep, and no version of it allows the fix",
                blocked_by=["semgrep"],
            ),
            _item("soupsieve", "4.0.0", why="needs Python >=3.11.5"),
        ],
        python_floor=floor,
        needs_newer_python={"pillow": "3.11"},
        project_python="3.10",
    )
    body = dashboard_markdown(scan, plan, "0.60.0", "2026-11-27", pr_line="PR: #2")
    assert "8 advisories in 6 packages (2026-11-27, depquiet 0.60.0)." in body
    assert "| ✅ Fixed in the fix pull request | 1 | 2 |" in body
    assert "| ⛓ Held back by another package | 2 | 3 |" in body
    assert "| 🔧 Needs a change in your project | 1 | 1 |" in body
    assert "| ⏳ No fixed version reported | 1 | 1 |" in body
    assert "| 💤 Deprioritized (not dismissed) | 1 | 1 |" in body
    assert "PR: #2" in body
    assert (
        "`pillow` 12.2.0 → 13.0.0 (2 advisories). Dependabot cannot open this one: it "
        "needs Python >=3.11." in body
    )
    assert "**`semgrep`** holds back `mcp`, `wcmatch` (3 advisories)" in body
    assert "only a change in `semgrep` unblocks them: nothing in this project can." in body
    assert "raising requires-python to >=3.11.5 lets it install (verified)" in body
    assert "`[tool.uv] environments = [\"python_full_version >= '3.11.5'\"]` instead" in body
    assert "`abandoned` (1 advisory): the scan reported no fixed version." in body
    assert (
        "`black` (1 advisory): reaches the project only through development dependencies." in body
    )
    assert "it does not dismiss them" in body


def test_without_a_plan_the_fixes_are_listed_from_the_scan() -> None:
    scan = _scan(_r("requests", "GHSA-9", "2.33.0"), _r("left", "GHSA-8"))
    body = dashboard_markdown(scan, None)
    assert "| 🆙 Fixed release available | 1 | 1 |" in body
    assert "- `requests` → 2.33.0 (1 advisory)" in body
    assert "`left` (1 advisory): the scan reported no fixed version." in body
    assert "Fixed in the fix pull request" not in body


def test_the_action_fills_in_the_pull_request_link() -> None:
    scan = _scan(_r("pillow", "GHSA-1", "13.0.0"))
    plan = fp.FixPlan("verified", items=[_item("pillow", "13.0.0", included=True)])
    assert PR_PLACEHOLDER in dashboard_markdown(scan, plan)
    assert PR_PLACEHOLDER not in dashboard_markdown(scan, plan, pr_line="")


def test_no_open_advisories() -> None:
    body = dashboard_markdown(_scan(), None)
    assert "No open advisories." in body
    assert "|---|" not in body


@pytest.mark.parametrize(
    ("reason", "text"),
    [
        (FilterReason.TEST_ONLY, "imported only from tests"),
        (FilterReason.UNREACHABLE, "not imported by your code"),
        (FilterReason.IGNORED, "ignored in your depquiet configuration"),
    ],
)
def test_deprioritized_reasons_are_plain(reason, text) -> None:
    body = dashboard_markdown(_scan(_r("x", "CVE-9", "2", filtered=reason)), None)
    assert f"`x` (1 advisory): {text}." in body


def test_blocked_by_is_recorded_when_no_release_of_the_parent_allows_the_fix() -> None:
    item = _item("mcp", "1.30.0")
    plan = fp.FixPlan("partial", items=[item])
    item.why = "blocked by semgrep, and no version of it allows the fix: no solution"
    item.blocked_by = ["semgrep"]
    assert plan.to_dict()["left_out"][0]["blocked_by"] == ["semgrep"]


def test_an_npm_fix_through_a_parent_names_the_parent() -> None:
    vuln = Vulnerability("GHSA-7", "immutable", "3.7.6", Severity.HIGH, fix_version="1.1.0")
    vuln.fix_package = "draft-js"
    body = dashboard_markdown(_scan(TriageResult(vuln, Verdict.ACTION)), None)
    assert (
        "- `immutable` (1 advisory): upgrade `draft-js` to 1.1.0, which pulls in the fix." in body
    )


def test_a_parent_fix_that_moves_the_parent_back_is_not_offered() -> None:
    vuln = Vulnerability("GHSA-7", "immutable", "3.7.6", Severity.HIGH, fix_version="1.1.0")
    vuln.fix_package = "draftail"
    scan = _scan(TriageResult(vuln, Verdict.ACTION))
    body = dashboard_markdown(scan, None, installed={"draftail": "2.0.1"})
    assert "Fixed release available" not in body
    assert "npm audit's only fix moves `draftail` back from 2.0.1 to 1.1.0; not offered." in body


def test_an_npm_fix_within_the_declared_ranges_says_npm_audit_fix() -> None:
    vuln = Vulnerability("GHSA-6", "uuid", "11.1.0", Severity.MODERATE, fix_in_range=True)
    body = dashboard_markdown(_scan(TriageResult(vuln, Verdict.ACTION)), None)
    assert "- `uuid` (1 advisory): `npm audit fix` updates it within your declared ranges." in body
    assert "No fixed version reported" not in body
