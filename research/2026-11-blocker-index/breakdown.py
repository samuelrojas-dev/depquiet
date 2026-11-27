"""Where every action/review advisory of the sample ends up, by its package's plan outcome."""
import json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

def pep503(n): return re.sub(r"[-_.]+", "-", n).lower()

out = Path(sys.argv[1])
cat_adv = Counter(); cat_repos = defaultdict(set); other = Counter(); errors = []
timeouts = []
for p in sorted(out.glob("*.json")):
    d = json.loads(p.read_text())
    m = d.get("_meta", {}); repo = m.get("repo", p.stem)
    if "error" in d or not d.get("scanned", True):
        errors.append((repo, d.get("error") or d.get("note", "not scanned"), m.get("exit"), m.get("seconds"))); continue
    adv = defaultdict(set); fixv = {}
    for r in d.get("results", []):
        if r.get("verdict") in ("action", "review"):
            k = pep503(r["package"]); adv[k].add(r["cve"]); fixv[k] = fixv.get(k) or r.get("fix_version")
    if not adv: continue
    plan = d.get("fix_plan")
    if not plan or plan.get("status") == "unsupported":
        for k, s in adv.items(): cat_adv["no plan (" + ((plan or {}).get("note","")[:40] or "none") + ")"] += len(s); cat_repos["no plan"].add(repo)
        continue
    floor = {pep503(x) for x in ((plan.get("python_floor") or {}).get("unblocks") or [])}
    inc = {pep503(i["package"]) for i in plan.get("included", [])}
    left = {pep503(i["package"]): i for i in plan.get("left_out", [])}
    for k, s in adv.items():
        n = len(s)
        if k in inc: c = "fixed in the verified plan"
        elif k in floor: c = "needs a newer Python (requires-python)"
        elif k in left and left[k].get("needs_older") and not k in floor: c = "only an older release of a direct dependency allows it"
        elif k in left and left[k].get("blocked_by"): c = "held back by another package (no release allows it)"
        elif not fixv.get(k): c = "no fixed version reported"
        elif k in left:
            why = left[k].get("why", "")
            c = "left out: other"
            key = re.sub(r"[0-9.]+", "N", why)[:70]
            other[key] += n
        else: c = "not planned (filtered from plan)"
        cat_adv[c] += n; cat_repos[c].add(repo)
total = sum(cat_adv.values())
print("total action/review advisories:", total)
for c, n in cat_adv.most_common():
    print(f"{n:6d} {100*n/total:5.1f}%  repos={len(cat_repos[c]):3d}  {c}")
print("\nerrors:", len(errors))
for e in errors: print("  ", e)
print("\nother reasons (top):")
for k, n in other.most_common(15): print(f"{n:6d}  {k}")
