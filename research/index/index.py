"""One month of the Python floor index, from a sample made by 2026-11-python-floor/collect.sh.

Writes <out>/summary.md, <out>/blocked_copies.csv and <out>/repos.txt, and adds (or
replaces) the month's row in history.csv. Read-only: it only reads the collected scans.

Usage: python index.py STUDY_DIR OUT_DIR HISTORY_CSV MONTH
"""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

FIELDS = [
    "month",
    "repos_checked",
    "with_lock",
    "uv",
    "poetry",
    "analysed",
    "with_action_alerts",
    "blocked_repos",
    "blocked_share",
    "vulnerable_copies",
    "blocked_copies",
    "action_alerts",
    "blocked_alerts",
    "soupsieve_trap_repos",
    "soupsieve_trap_at_311",
]


def measure(study: Path) -> dict[str, object]:
    data = json.loads((study / "rows.json").read_text())
    rows, repos = data["rows"], data["repos"]
    locks = [line.split() for line in (study / "withlock.txt").read_text().splitlines() if line]
    candidates = sum(1 for line in (study / "candidates.txt").read_text().splitlines() if line)
    action = [r for r in rows if r["verdict"] == "action"]
    copies: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    needs: dict[tuple[str, str, str], str] = {}
    for r in action:
        key = (r["repo"], r["package"], r["version"])
        copies[key].add(r["status"])
        if r["status"] == "needs-newer-python":
            needs[key] = max(needs.get(key, ""), r["needs"])
    blocked = {k for k, s in copies.items() if "needs-newer-python" in s}
    with_action = {k[0] for k in copies}
    blocked_repos = {k[0] for k in blocked}
    trap = {k[0] for k in blocked if needs.get(k) == "3.11.5"}
    trap_311 = {r for r in trap if repos[r]["floor"].startswith("3.11")}
    return {
        "repos_checked": candidates,
        "with_lock": len(locks),
        "uv": sum(1 for line in locks if line[-1] == "uv.lock"),
        "poetry": sum(1 for line in locks if line[-1] == "poetry.lock"),
        "analysed": len(repos),
        "with_action_alerts": len(with_action),
        "blocked_repos": len(blocked_repos),
        "blocked_share": f"{len(blocked_repos) / len(with_action):.0%}" if with_action else "",
        "vulnerable_copies": len(copies),
        "blocked_copies": len(blocked),
        "action_alerts": len(action),
        "blocked_alerts": sum(1 for r in action if r["status"] == "needs-newer-python"),
        "soupsieve_trap_repos": len(trap),
        "soupsieve_trap_at_311": len(trap_311),
    }


def summary(month: str, m: dict[str, object]) -> str:
    trap = f"{m['soupsieve_trap_repos']} / {m['soupsieve_trap_at_311']}"
    return f"""# Python floor index, {month}

The most-starred Python repos pushed in the last 30 days: how many hold an alert that no
fixed release reaches on their oldest supported Python. Method and limits:
[../../2026-11-python-floor/README.md](../../2026-11-python-floor/README.md).

| | |
|---|--:|
| Repos checked | {m["repos_checked"]} |
| With a lock (uv / Poetry) | {m["with_lock"]} ({m["uv"]} / {m["poetry"]}) |
| Analysed | {m["analysed"]} |
| With at least one *action* alert | {m["with_action_alerts"]} |
| **Blocked by the Python floor** | **{m["blocked_repos"]} ({m["blocked_share"]})** |
| Vulnerable copies blocked | {m["blocked_copies"]} of {m["vulnerable_copies"]} |
| *Action* alerts blocked | {m["blocked_alerts"]} of {m["action_alerts"]} |
| soupsieve 3.11.5 trap: repos / already requiring 3.11 | {trap} |

Per-copy data: [`blocked_copies.csv`](blocked_copies.csv). Sample: [`repos.txt`](repos.txt).
"""


def main() -> None:
    study, out, history, month = (
        Path(sys.argv[1]),
        Path(sys.argv[2]),
        Path(sys.argv[3]),
        sys.argv[4],
    )
    out.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve().parent.parent / "2026-11-python-floor"
    subprocess.run(
        [sys.executable, str(here / "summarize.py"), str(study), str(out / "blocked_copies.csv")],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    shutil.copy(study / "withlock.txt", out / "repos.txt")
    m = measure(study)
    (out / "summary.md").write_text(summary(month, m))
    previous = []
    if history.exists():
        with history.open() as fh:
            previous = [row for row in csv.DictReader(fh) if row["month"] != month]
    with history.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows([*previous, {"month": month, **m}])
    print(summary(month, m))


if __name__ == "__main__":
    main()
