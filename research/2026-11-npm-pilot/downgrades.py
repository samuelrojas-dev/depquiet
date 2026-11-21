"""How often is npm audit's only fix a semver-major *downgrade*?

For each fix npm audit marks isSemVerMajor, compare its target version with the version
the lock has at node_modules/<name>. Read-only.
"""
import glob, json, re

def key(v):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(map(int, m.groups())) if m else None

down = up = unknown = 0
repos_major, repos_down = set(), set()
for f in glob.glob("audits/*.json"):
    repo = f.split("/")[-1][:-5]
    try:
        audit = json.load(open(f))
        lock = json.load(open(f"repos/{repo}/package-lock.json"))["packages"]
    except Exception:
        continue
    seen = set()
    for v in (audit.get("vulnerabilities") or {}).values():
        fa = v["fixAvailable"]
        if not (isinstance(fa, dict) and fa.get("isSemVerMajor") and "name" in fa):
            continue
        repos_major.add(repo)
        target = (fa["name"], fa["version"])
        if target in seen:
            continue
        seen.add(target)
        now, then = key(lock.get(f"node_modules/{target[0]}", {}).get("version")), key(target[1])
        if not now or not then:
            unknown += 1
        elif then < now:
            down += 1
            repos_down.add(repo)
        else:
            up += 1
print(f"distinct semver-major fixes: downgrade {down}, upgrade {up}, unknown {unknown}")
print(f"repos with a semver-major fix: {len(repos_major)}; with a downgrade among them: {len(repos_down)}")
