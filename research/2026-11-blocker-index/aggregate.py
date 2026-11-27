"""Blocker Index: which packages hold back the most security fixes in popular uv projects.

Reads one depquiet JSON per repository (``out/*.json``, from ``one.sh``) and counts,
for every package that holds a fix back, how many repositories, vulnerable
packages and advisories it holds back. Two kinds:

- no release of the blocker allows the fix ("blocked by X, and no version of it
  allows the fix"): only a change upstream unblocks it;
- only an older release allows it (``needs_older``): the project would have to
  move its own dependency back.

A third column counts fixes that need a newer Python than the project's
requires-python allows (the Python floor), which is the project's own call.

Advisory counts are unique advisory ids per repository, from the alerts depquiet
marks action or review (not the deprioritized ones), so a blocker is credited
only with alerts someone would act on.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def verified() -> set[tuple[str, str, str]]:
    """(repo, held, blocker) whose blocker's newest release still caps the fix (verify_blockers.py).

    depquiet up to 0.60.3 also blamed a package whose newest release allows the
    fix (crawl4ai in camel): those claims are left out.
    """
    path = Path(__file__).parent / "verified_blockers.json"
    rows = json.loads(path.read_text(encoding="utf-8"))
    return {(r["repo"], pep503(r["held"]), r["blocker"]) for r in rows if r["confirmed"]}


def main(out_dir: Path, dest: Path) -> None:
    repos = sorted(out_dir.glob("*.json"))
    confirmed = verified()
    per_blocker: dict[str, dict] = defaultdict(
        lambda: {"repos": set(), "held": set(), "advisories": 0, "older": set(), "none": set()}
    )
    floor_repos: set[str] = set()
    floor_advisories = 0
    rows: list[dict] = []
    stats = {"repos": 0, "scanned": 0, "with_action": 0, "with_plan": 0, "errors": 0,
             "action_advisories": 0, "fixed_advisories": 0, "held_advisories": 0}
    for path in repos:
        data = json.loads(path.read_text(encoding="utf-8"))
        meta = data.get("_meta", {})
        repo = meta.get("repo", path.stem)
        stats["repos"] += 1
        if "error" in data or not data.get("scanned", True):
            stats["errors"] += 1
            continue
        stats["scanned"] += 1
        advisories: dict[str, set[str]] = defaultdict(set)
        for r in data.get("results", []):
            if r.get("verdict") in ("action", "review"):
                advisories[pep503(r["package"])].add(r["cve"])
        if not advisories:
            continue
        stats["with_action"] += 1
        stats["action_advisories"] += sum(len(v) for v in advisories.values())
        plan = data.get("fix_plan") or {}
        if plan.get("status") not in (None, "unsupported"):
            stats["with_plan"] += 1
        for item in plan.get("included", []):
            stats["fixed_advisories"] += len(advisories.get(pep503(item["package"]), ()))
        floor = plan.get("python_floor") or {}
        needs_python = {pep503(p) for p in floor.get("unblocks") or []}
        for item in plan.get("left_out", []):
            key = pep503(item["package"])
            n = len(advisories.get(key, ()))
            # A fix that a higher requires-python lets in was held back by the Python
            # floor, not by the package a first attempt named (depquiet <0.60.2 kept it).
            older = item.get("needs_older") or []
            blockers = [] if key in needs_python else [
                b for b in item.get("blocked_by") or []
                if (repo, key, b) in confirmed or any(o.startswith(f"{b} ") for o in older)
            ]
            if blockers:
                stats["held_advisories"] += n
            for blocker in blockers:
                b = per_blocker[pep503(blocker)]
                b["repos"].add(repo)
                b["held"].add(key)
                b["advisories"] += n
                kind = "older" if any(o.startswith(f"{blocker} ") for o in older) else "none"
                b[kind].add(repo)
                rows.append({"repo": repo, "blocker": blocker, "held": item["package"],
                             "advisories": n, "kind": kind,
                             "why": item.get("why", "")[:300]})
            if key in needs_python:
                floor_repos.add(repo)
                floor_advisories += n
    ranked = sorted(per_blocker.items(), key=lambda kv: (-len(kv[1]["repos"]), -kv[1]["advisories"]))
    with (dest / "blocker_index.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["blocker", "repos", "held_packages", "advisories",
                    "repos_no_release_allows", "repos_only_older_allows", "held"])
        for name, b in ranked:
            w.writerow([name, len(b["repos"]), len(b["held"]), b["advisories"], len(b["none"]),
                        len(b["older"]), " ".join(sorted(b["held"]))])
    with (dest / "blocked_fixes.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["repo", "blocker", "held", "advisories", "kind", "why"])
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["blocker"], r["repo"], r["held"])))
    summary = {**stats, "blockers": len(ranked), "python_floor_repos": len(floor_repos),
               "python_floor_advisories": floor_advisories,
               "top": [(n, len(b["repos"]), len(b["held"]), b["advisories"]) for n, b in ranked[:15]]}
    (dest / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
