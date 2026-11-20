"""How many open alerts in popular uv projects cannot be fixed without dropping a Python version.

For every alert depquiet reports with a fix version, ask PyPI: does any release at or above
the fix still install on the project's lowest supported Python? If none does, the alert can
only close by raising requires-python (or by a marker), whatever Dependabot tries.

Read-only: PyPI metadata and the scans; nothing is resolved or locked.
"""

import json
import re
import sys
import tomllib
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

ROOT = Path(sys.argv[1])
CACHE = ROOT / "pypi_cache"
CACHE.mkdir(exist_ok=True)


def pypi(package: str) -> dict:
    path = CACHE / f"{package.lower()}.json"
    if path.exists():
        return json.loads(path.read_text())
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{package}/json", timeout=30) as r:
            data = json.load(r)
    except Exception:
        data = {}
    # Keep only what we need: requires_python per release.
    slim = {}
    for ver, files in (data.get("releases") or {}).items():
        rp = next((f.get("requires_python") for f in files if f.get("requires_python")), None)
        yanked = files and all(f.get("yanked") for f in files)
        if files and not yanked:
            slim[ver] = rp or ""
    path.write_text(json.dumps(slim))
    return slim


def stable(v: str) -> bool:
    try:
        return not Version(v).is_prerelease
    except InvalidVersion:
        return False


def floor_of(spec: str) -> str:
    found = re.findall(r">=\s*(\d+(?:\.\d+){0,2})", spec or "")
    # Applications often pin one Python: "==3.12.*" starts at 3.12.0, "==3.14.7" at 3.14.7.
    found += re.findall(r"==\s*(\d+\.\d+(?:\.\d+)?)(?:\.\*)?", spec or "")
    return max(found, key=Version) if found else ""


def admits(rp: str, python: str) -> bool:
    if not rp:
        return True
    try:
        return Version(python) in SpecifierSet(rp)
    except (InvalidSpecifier, InvalidVersion):
        return True


def lowest_python(rp: str) -> str:
    """Lowest 3.x.y the specifier admits, scanning patch levels."""
    for minor in range(6, 16):
        for patch in range(0, 20):
            v = f"3.{minor}.{patch}"
            if admits(rp, v):
                return v
    return ""


rows = []
per_repo = {}
for scan in sorted((ROOT / "scans").glob("*.json")):
    name = scan.stem
    try:
        data = json.loads(scan.read_text())
    except json.JSONDecodeError:
        continue
    lock = ROOT / "repos" / name / "uv.lock"
    try:
        rp = tomllib.loads(lock.read_text()).get("requires-python", "")
    except Exception:
        rp = ""
    floor = floor_of(rp)
    if not floor:
        continue
    results = data.get("results", [])
    per_repo[name] = {"floor": floor, "requires_python": rp, "alerts": len(results)}
    for r in results:
        fix = r.get("fix_version")
        if not fix:
            continue
        releases = pypi(r["package"])
        try:
            fixv = Version(fix)
        except InvalidVersion:
            continue
        fixed = {v: p for v, p in releases.items() if stable(v) and Version(v) >= fixv}
        if not fixed:
            status, need = "no-fixed-release-on-pypi", ""
        elif any(admits(p, floor) for p in fixed.values()):
            status, need = "fixable-within-floor", ""
        else:
            needs = [lowest_python(p) for p in fixed.values() if p]
            need = min((n for n in needs if n), key=Version, default="")
            status = "needs-newer-python"
        rows.append(
            {
                "repo": name,
                "floor": floor,
                "package": r["package"],
                "version": r.get("version"),
                "fix": fix,
                "verdict": r.get("verdict"),
                "status": status,
                "needs": need,
                "python_scope": r.get("python_scope"),
            }
        )

(ROOT / "rows.json").write_text(json.dumps({"repos": per_repo, "rows": rows}, indent=1))

repos_scanned = len(per_repo)
with_alerts = sum(1 for v in per_repo.values() if v["alerts"])
print(f"repos with a usable uv.lock and requires-python floor: {repos_scanned}")
print(f"repos with at least one alert: {with_alerts}")
print(f"alerts with a fix version: {len(rows)}")
for verdict in ("action", "review", "filtered", None):
    sub = [r for r in rows if verdict is None or r["verdict"] == verdict]
    c = Counter(r["status"] for r in sub)
    print(f"\n[{verdict or 'all'}] {len(sub)} alerts: {dict(c)}")
blocked = [r for r in rows if r["status"] == "needs-newer-python"]
by_repo = defaultdict(list)
for r in blocked:
    by_repo[r["repo"]].append(r)
print(f"\nrepos with alerts that need a newer Python: {len(by_repo)} / {with_alerts}")
print("packages:", Counter(r["package"] for r in blocked).most_common(15))
print("needs:", Counter(r["needs"] for r in blocked).most_common(10))
patch_level = [r for r in blocked if r["needs"].count(".") == 2 and not r["needs"].endswith(".0")]
print(
    f"of those, needing a patch-level floor (like 3.11.5): {len(patch_level)} alerts in "
    f"{len({r['repo'] for r in patch_level})} repos"
)
