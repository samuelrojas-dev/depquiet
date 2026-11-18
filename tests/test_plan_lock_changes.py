"""The fix plan names everything the verified lock moves, not only the fixes.

On microbiomedata/nmdc-lakehouse, the plan said "setuptools 81.0.0 → 84.1.0" and
nothing else, while the same lock change moved oaklib 0.7.4 → 0.7.5 (the parent
that held setuptools back) and dropped six packages only oaklib 0.7.4 required.
A reviewer would have found those in uv.lock unexplained.
"""

from __future__ import annotations

import io
import json

from depquiet.fixplan import FixPlan, LockChange, PlanItem, _uv_lock_changes, print_fix_plan
from depquiet.poetryplan import _lock_changes
from depquiet.scanners import _tail

UV_REPORT = """Resolved 226 packages in 18.17s
Remove appdirs v1.4.4
Remove eutils v0.6.1
Update oaklib v0.7.4 -> v0.7.5
Add tzdata v2026.1
Update setuptools v81.0.0 -> v84.1.0
"""


def _item(package: str, version: str, *also: str) -> PlanItem:
    return PlanItem(package, version, included=True, also_upgrade=list(also))


def test_uv_report_lists_moves_additions_and_removals_besides_the_fix() -> None:
    changes = _uv_lock_changes(UV_REPORT, [_item("setuptools", "84.1.0")])
    assert [c.describe() for c in changes] == [
        "oaklib 0.7.4 → 0.7.5",
        "tzdata 2026.1 (added)",
        "appdirs 1.4.4 (removed: nothing requires it any more)",
        "eutils 0.6.1 (removed: nothing requires it any more)",
    ]


def test_parents_the_plan_already_names_are_not_repeated() -> None:
    changes = _uv_lock_changes(UV_REPORT, [_item("setuptools", "84.1.0", "oaklib==0.7.5")])
    assert "oaklib" not in [c.package for c in changes]


def test_poetry_lock_comparison() -> None:
    before = {"oaklib": {"name": "oaklib", "version": "0.7.4"}, "eutils": {"version": "0.6.1"}}
    after = {"oaklib": {"name": "oaklib", "version": "0.7.5"}, "new-dep": {"version": "1.0"}}
    changes = _lock_changes(before, after, planned=set())
    assert [c.describe() for c in changes] == [
        "oaklib 0.7.4 → 0.7.5",
        "new-dep 1.0 (added)",
        "eutils 0.6.1 (removed: nothing requires it any more)",
    ]


def test_printed_plan_and_json_name_the_changes() -> None:
    plan = FixPlan(
        "verified",
        items=[PlanItem("setuptools", "84.1.0", "81.0.0", included=True)],
        lock_changes=[LockChange("oaklib", "0.7.4", "0.7.5")],
    )
    out = io.StringIO()
    print_fix_plan(plan, out)
    assert "It also changes uv.lock:\n     · oaklib 0.7.4 → 0.7.5" in out.getvalue()
    assert plan.to_dict()["lock_changes"] == [{"package": "oaklib", "from": "0.7.4", "to": "0.7.5"}]
    json.dumps(plan.to_dict())


def test_a_traceback_becomes_its_last_line() -> None:
    stderr = (
        "Traceback (most recent call last):\n"
        '  File "/x/requests/adapters.py", line 742, in send\n'
        "    raise ReadTimeout(e, request=request)\n"
        "requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='pypi.org'): Read timed out.\n"
    )
    assert _tail(stderr) == (
        "requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='pypi.org'): Read timed out."
    )
    assert _tail("plain\nmessage") == "plain message"
