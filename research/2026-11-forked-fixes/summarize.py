"""Summarize out/*.json into the counts in README.md and forked_fixes.csv.

Run from this folder: python summarize.py
"""

import collections
import csv
import json
import re
from pathlib import Path

HERE = Path(__file__).parent
STARS = {
    row["repository"]: int(row["stars"])
    for row in csv.DictReader(
        (HERE.parent / "2026-11-python-floor" / "blocked_copies_top1000.csv").open()
    )
}
PARTIAL = re.compile(
    r"(?:Python >=(\S+)|newer Pythons) gets? (\S+), which closes all (\d+) alerts; "
    r"older Pythons keep (\S+), which closes (\d+)"
)

runs = [json.loads(p.read_text()) for p in sorted((HERE / "out").glob("*.json"))]
outcome: collections.Counter[str] = collections.Counter()
forked = []
for run in runs:
    plan = run.get("fix_plan")
    if (run.get("error") or "").startswith("fetch"):
        outcome["no uv.lock at HEAD"] += 1
        continue
    if not plan:
        outcome["no fix plan"] += 1
        continue
    items = [i for i in plan["included"] if i.get("forked_below")]
    if items:
        outcome["at least one forked fix"] += 1
    elif plan["included"]:
        outcome["other fixes only"] += 1
    elif all("requires-python" in i["why"] or "newer Python" in i["why"] for i in plan["left_out"]):
        outcome["no fix fits: every fix needs a newer Python"] += 1
    else:
        outcome["not checked: uv could not build the project from the files fetched"] += 1
    for item in items:
        m = PARTIAL.search(item["partial"])
        assert m, item["partial"]
        forked.append(
            [
                run["repo"],
                STARS.get(run["repo"], ""),
                run["sha"][:12],
                item["package"],
                m[2].rstrip(","),
                m[4].rstrip(","),
                m[1] or "",
                int(m[3]),
                int(m[5]),
            ]
        )

forked.sort(key=lambda row: (-int(row[1] or 0), row[3]))
with (HERE / "forked_fixes.csv").open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(
        [
            "repository",
            "stars",
            "commit",
            "package",
            "newer_pythons_get",
            "older_pythons_keep",
            "split_at_python",
            "alerts_closed_newer",
            "alerts_closed_older",
        ]
    )
    writer.writerows(forked)

print(f"projects: {len(runs)}")
for name, count in outcome.most_common():
    print(f"  {name}: {count}")
print(f"forked fixes: {len(forked)} in {len({r[0] for r in forked})} projects")
check = HERE / "advisory_check.csv"
if check.exists():
    bad = {
        (r["repository"], r["package"])
        for r in csv.DictReader(check.open())
        if r["new_on_older_copy"] or r["new_on_newer_copy"]
    }
    clean = [r for r in forked if (r[0], r[3]) not in bad]
    print(
        f"  bringing advisories the locked release did not have: {len(forked) - len(clean)}"
        f" in {len({r[0] for r in forked if (r[0], r[3]) in bad})} projects"
    )
    print(
        f"  clean: {len(clean)} in {len({r[0] for r in clean})} projects, closing"
        f" {sum(r[7] for r in clean)} alerts on newer Pythons and {sum(r[8] for r in clean)}"
        " on older ones"
    )
print(f"  by package: {collections.Counter(r[3] for r in forked).most_common()}")
print(f"  alerts closed on newer Pythons: {sum(r[7] for r in forked)}")
print(f"  alerts closed on older Pythons too: {sum(r[8] for r in forked)}")
