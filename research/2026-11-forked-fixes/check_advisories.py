"""For each fix by Python range, list advisories its copies have that the locked release did not.

Needs network (pip-audit asks PyPI) and depquiet installed. Writes advisory_check.csv.
Run from this folder: python check_advisories.py
"""

import csv
import json
from pathlib import Path

from depquiet.fixplan import _advisories

HERE = Path(__file__).parent
rows = []
for path in sorted((HERE / "out").glob("*.json")):
    run = json.loads(path.read_text())
    for item in (run.get("fix_plan") or {}).get("included", []):
        if not item.get("forked_below"):
            continue
        now, low, high = item["installed"], item["forked_below"], item["version"]
        found = _advisories(item["package"], [now, low, high], 300)
        seen = set().union(*found[now]) if found.get(now) else set()

        def new(version: str, found=found, seen=seen) -> list[str]:
            return sorted(min(ids) for ids in found.get(version, []) if not ids & seen)

        rows.append(
            [run["repo"], item["package"], now, low, high, " ".join(new(low)), " ".join(new(high))]
        )

with (HERE / "advisory_check.csv").open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(
        [
            "repository",
            "package",
            "locked",
            "older_pythons_keep",
            "newer_pythons_get",
            "new_on_older_copy",
            "new_on_newer_copy",
        ]
    )
    writer.writerows(rows)
bad = sum(1 for r in rows if r[5] or r[6])
print(f"{len(rows)} fixes; {bad} bring advisories the locked release did not have")
