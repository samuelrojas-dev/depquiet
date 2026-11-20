"""Copy-level summary of rows.json, plus blocked_copies.csv."""

import collections
import csv
import json
import sys

root = sys.argv[1]
out = sys.argv[2]
with open(f"{root}/rows.json") as fh:
    d = json.load(fh)
rows = d["rows"]
repos = d["repos"]
with open(f"{root}/withlock.txt") as fh:
    stars = {line.split()[0]: int(line.split()[2]) for line in fh}
act = [r for r in rows if r["verdict"] == "action"]
copies = collections.defaultdict(lambda: {"cves": 0, "blocked": 0, "needs": ""})
for r in act:
    c = copies[(r["repo"], r["package"], r["version"])]
    c["cves"] += 1
    if r["status"] == "needs-newer-python":
        c["blocked"] += 1
        c["needs"] = max(c["needs"], r["needs"])
blocked = {k: c for k, c in copies.items() if c["blocked"]}
act_repos = {k[0] for k in copies}
b_repos = {k[0] for k in blocked}
trap = {k[0] for k, c in blocked.items() if c["needs"] == "3.11.5"}
trap311 = {r for r in trap if repos[r]["floor"].startswith("3.11")}
print(
    f"repos analysed: {len(repos)}; with action alerts: {len(act_repos)}; "
    f"with a vulnerable copy no fix reaches on their lowest Python: {len(b_repos)}"
)
print(f"vulnerable copies: {len(copies)}; blocked: {len(blocked)}")
needing = sum(1 for r in act if r["status"] == "needs-newer-python")
print(f"action alerts: {len(act)}; needing newer Python: {needing}")
print(f"soupsieve 3.11.5 trap: {len(trap)} repos; already at a 3.11 floor: {len(trap311)}")
print(sorted(trap311))
print("blocked copies by package:", collections.Counter(k[1] for k in blocked).most_common())
with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(
        [
            "repository",
            "stars",
            "lowest_supported_python",
            "package",
            "locked_version",
            "action_alerts",
            "alerts_needing_newer_python",
            "lowest_python_with_a_fix",
        ]
    )
    for (repo, pkg, ver), c in sorted(
        blocked.items(), key=lambda kv: (-stars.get(kv[0][0].replace("__", "/"), 0), kv[0][1])
    ):
        name = repo.replace("__", "/")
        w.writerow(
            [
                name,
                stars.get(name, ""),
                repos[repo]["floor"],
                pkg,
                ver,
                c["cves"],
                c["blocked"],
                c["needs"],
            ]
        )
