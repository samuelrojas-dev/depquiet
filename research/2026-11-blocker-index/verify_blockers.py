"""Check every "no release of X allows it" against X's newest release on PyPI.

depquiet up to 0.60.3 said a package held a fix back, with no release of it
allowing the fix, whenever uv could not lock the fix with that package loosened.
That only says no version of it fits with the rest of the project. In camel,
crawl4ai was blamed for pillow 13.0.0, yet crawl4ai 0.9.6 requires only
pillow>=10.4 (camel's own psutil<6 and agentops<0.4 were the cause).

This keeps a blocker only if its newest release still leaves the fix out, the
rule depquiet applies from 0.60.4. The PyPI answers are saved in
newest_releases.json, so the result can be reproduced without the network:

    python3 verify_blockers.py slim            # use the saved answers
    python3 verify_blockers.py slim --refresh  # ask PyPI again
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
SAVED = HERE / "newest_releases.json"
CLAUSE = re.compile(r"^\s*(===|==|!=|~=|<=|>=|<|>)\s*(\S+?)\s*$")
NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def key(version: str) -> tuple:
    parts = []
    for piece in re.split(r"[.+-]", version):
        m = re.match(r"(\d+)(.*)", piece)
        parts.append((int(m.group(1)), m.group(2)) if m else (-1, piece))
    return tuple(parts)


def satisfies(version: str, op: str, bound: str) -> bool:
    if bound.endswith(".*") and op in ("==", "!="):
        hit = version == bound[:-2] or version.startswith(bound[:-1])
        return hit if op == "==" else not hit
    v, b = key(version), key(bound)
    if op == "~=":
        prefix = bound.rsplit(".", 1)[0]
        return v >= b and (version == prefix or version.startswith(prefix + "."))
    return {"==": v == b, "===": v == b, "!=": v != b, "<": v < b, "<=": v <= b,
            ">": v > b, ">=": v >= b}[op]


def caps(requirement: str, version: str) -> bool:
    """Whether a requirement keeps its package below the fixed version: only an upper bound does."""
    head = requirement.split(";", 1)[0].replace("(", " ").replace(")", " ")
    m = NAME.match(head)
    spec = head[m.end():] if m else ""
    spec = re.sub(r"^\s*\[[^\]]*\]", "", spec)
    for clause in (c.strip() for c in spec.split(",") if c.strip()):
        parsed = CLAUSE.match(clause)
        if parsed is None or parsed.group(1) in (">", ">=", "!="):
            continue
        op, bound = parsed.groups()
        if not satisfies(version, op, bound) and key(version) >= key(bound.removesuffix(".*")):
            return True
    return False


def newest(name: str) -> dict:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{pep503(name)}/json", timeout=30) as r:
        info = json.load(r).get("info") or {}
    return {"version": info.get("version"), "requires_dist": info.get("requires_dist") or []}


def main(slim: Path, refresh: bool) -> None:
    items = []  # (repo, held, fix version, blocker)
    for path in sorted(slim.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        repo = data.get("_meta", {}).get("repo", path.stem)
        plan = data.get("fix_plan") or {}
        floor = {pep503(p) for p in ((plan.get("python_floor") or {}).get("unblocks") or [])}
        for item in plan.get("left_out", []):
            if pep503(item["package"]) in floor:
                continue
            older = item.get("needs_older") or []
            for blocker in item.get("blocked_by") or []:
                if not any(o.startswith(f"{blocker} ") for o in older):
                    items.append((repo, item["package"], item.get("version") or "", blocker))
    saved = json.loads(SAVED.read_text(encoding="utf-8")) if SAVED.exists() and not refresh else {}
    for blocker in sorted({b for *_, b in items}):
        if pep503(blocker) not in saved:
            saved[pep503(blocker)] = newest(blocker)
    SAVED.write_text(json.dumps(saved, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    verdicts = []
    for repo, held, version, blocker in items:
        release = saved[pep503(blocker)]
        found = [r.split(";", 1)[0].strip() for r in release["requires_dist"]
                 if NAME.match(r) and pep503(NAME.match(r).group(1)) == pep503(held)
                 and caps(r, version)]
        found = list(dict.fromkeys(found))
        verdicts.append({"repo": repo, "held": held, "fix_version": version, "blocker": blocker,
                         "newest": release["version"], "caps": found, "confirmed": bool(found)})
    (HERE / "verified_blockers.json").write_text(json.dumps(verdicts, indent=1) + "\n",
                                                encoding="utf-8")
    ok = sum(v["confirmed"] for v in verdicts)
    print(f"{ok} of {len(verdicts)} blocker claims hold against the newest release")
    for v in verdicts:
        mark = "holds " if v["confirmed"] else "WRONG "
        print(f"  {mark} {v['repo']}: {v['blocker']} {v['newest']} -> {v['held']} {v['fix_version']}"
              f" {v['caps'] or ''}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), "--refresh" in sys.argv)
