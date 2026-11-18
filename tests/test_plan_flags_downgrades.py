"""A plan that moves packages to older versions says so.

On a public uv SDK, the plan that keeps Python 3.9 showed
``jupyterlab 4.5.7 → 2.3.2,``: uv's line was ``v4.5.7 -> v2.3.2, v4.x`` (one copy
per Python version), depquiet kept only the first new version, and nothing
said that jupyterlab 2.3.2 (2020) is a downgrade.
"""

from __future__ import annotations

import io

from depquiet.fixplan import (
    FixPlan,
    LockChange,
    PlanItem,
    PythonFloor,
    _uv_lock_changes,
    fix_plan_markdown,
    print_fix_plan,
)
from depquiet.models import ScanResult

REPORT = """Resolved 300 packages in 9s
Update jupyterlab v4.5.7 -> v2.3.2, v4.6.6
Update notebook v7.5.6 -> v6.4.8, v7.6.3
Update webcolors v24.11.1, v25.10.0 -> v25.10.0
Update async-lru v2.0.5, v2.3.0 -> v2.3.0
"""


def test_every_final_version_is_kept() -> None:
    changes = {c.package: c for c in _uv_lock_changes(REPORT, [])}
    assert changes["jupyterlab"].new == "2.3.2, 4.6.6"
    assert changes["webcolors"].old == "24.11.1, 25.10.0" and changes["webcolors"].new == "25.10.0"


def test_downgrades_are_flagged_and_listed_first() -> None:
    changes = _uv_lock_changes(REPORT, [])
    assert [c.package for c in changes][:2] == ["jupyterlab", "notebook"]
    assert changes[0].describe() == "⚠ jupyterlab 4.5.7 → 2.3.2, 4.6.6 (an older version)"
    # Collapsing a forked lock onto its newer copy is not a downgrade.
    assert not LockChange("webcolors", "24.11.1, 25.10.0", "25.10.0").downgrade
    assert not LockChange("x", "1.0", "2.0").downgrade
    assert not LockChange("x", "", "2.0").downgrade


def _plan(floor: PythonFloor | None = None) -> FixPlan:
    return FixPlan(
        "verified",
        items=[PlanItem("anyio", "4.14.2", "4.12.1", included=True)],
        lock_changes=_uv_lock_changes(REPORT, []),
        note="Verified with uv's resolver only.",
        python_floor=floor,
    )


def test_the_report_warns() -> None:
    plan = _plan(PythonFloor("3.11", unblocked=["pytest"]))
    text = fix_plan_markdown(plan, ScanResult(".", "pip", 1, []))
    assert "**The lock moves jupyterlab, notebook to an older version" in text
    assert "raising requires-python (see Python floor) may avoid it" in text
    out = io.StringIO()
    print_fix_plan(plan, out)
    assert "to an older version to fit the fixes together" in out.getvalue()


def test_no_warning_without_downgrades() -> None:
    plan = FixPlan("verified", lock_changes=[LockChange("x", "1.0", "2.0")])
    assert plan.downgrade_warning() == ""
