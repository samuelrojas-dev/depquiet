"""npm audit's fixAvailable per vulnerable package: a fix, a semver-major fix, or none."""
import collections, glob, json

ok = errors = with_vulns = repos_nofix = repos_major = 0
kinds = collections.Counter()
for f in glob.glob("audits/*.json"):
    try:
        audit = json.load(open(f))
    except Exception:
        errors += 1
        continue
    if "vulnerabilities" not in audit:
        errors += 1
        continue
    ok += 1
    vulns = audit["vulnerabilities"]
    if not vulns:
        continue
    with_vulns += 1
    found = set()
    for v in vulns.values():
        fa = v["fixAvailable"]
        kind = "none" if fa is False else ("semver-major" if isinstance(fa, dict) and fa.get("isSemVerMajor") else "fix")
        kinds[kind] += 1
        found.add(kind)
    repos_nofix += "none" in found
    repos_major += "semver-major" in found
print(f"audited {ok}, errors {errors}, with vulnerabilities {with_vulns}")
print(f"vulnerable packages by fixAvailable: {dict(kinds)}")
print(f"repos with a package without fix: {repos_nofix}; with a semver-major-only fix: {repos_major}")
