"""For npm audit's semver-major and no-fix cases: is there a fixed release in the same major?

If so, a scoped `overrides` entry could close the alert without a major upgrade of anything.
Read-only: lockfiles, `npm audit` output and registry metadata.
"""
import json, glob, sys, urllib.request, collections, pathlib, re
sys.path.insert(0, sys.argv[1])
from depquiet.npm_semver import match_npm_range

CACHE = pathlib.Path("registry"); CACHE.mkdir(exist_ok=True)
def versions(pkg):
    p = CACHE / (pkg.replace("/", "__") + ".json")
    if not p.exists():
        req = urllib.request.Request(f"https://registry.npmjs.org/{pkg.replace('/', '%2f')}",
                                     headers={"Accept": "application/vnd.npm.install-v1+json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r: data = json.load(r)
            vs = [v for v in data.get("versions", {}) if re.fullmatch(r"\d+\.\d+\.\d+", v)]
        except Exception: vs = []
        p.write_text(json.dumps(vs))
    return json.loads(p.read_text())

def key(v): return tuple(int(x) for x in v.split("."))
def line(v):  # npm caret compatibility line
    a, b, c = key(v); return (a,) if a else ((0, b) if b else (0, 0, c))

out = collections.Counter(); repos = collections.defaultdict(set); examples = []
for f in sorted(glob.glob("audits/*.json")):
    repo = pathlib.Path(f).stem
    try: d = json.load(open(f)); lock = json.load(open(f"repos/{repo}/package-lock.json"))
    except Exception: continue
    pk = lock.get("packages") or {}
    for name, v in (d.get("vulnerabilities") or {}).items():
        fa = v["fixAvailable"]
        kind = "nofix" if fa is False else ("major" if isinstance(fa, dict) and fa.get("isSemVerMajor") else None)
        if not kind: continue
        ranges = [x["range"] for x in v["via"] if isinstance(x, dict) and x.get("name") == name]
        if not ranges:  # vulnerable only through a dependency: not this package's own advisory
            out[kind, "transitive-only"] += 1; continue
        installed = {pk[n]["version"] for n in v.get("nodes", []) if n in pk and "version" in pk[n]}
        installed = {i for i in installed if re.fullmatch(r"\d+\.\d+\.\d+", i)}
        if not installed: out[kind, "unknown-version"] += 1; continue
        rel = versions(name)
        def fixed(r): return all(match_npm_range(r, rg)[0] == "not_matched" for rg in ranges)
        same = all(any(line(r) == line(i) and key(r) > key(i) and fixed(r) for r in rel) for i in installed)
        anyfix = any(fixed(r) and all(key(r) > key(i) for i in installed) for r in rel)
        res = "same-line-fix" if same else ("newer-line-fix-only" if anyfix else "no-fixed-release")
        out[kind, res] += 1; repos[kind, res].add(repo)
        if res == "same-line-fix" and len(examples) < 12: examples.append((repo, name, sorted(installed), kind))
for k in sorted(out): print(k, out[k], "packages in", len(repos[k]), "repos")
print("repos with a same-line override candidate:", len(repos["major","same-line-fix"] | repos["nofix","same-line-fix"]))
for e in examples: print("  e.g.", e)
