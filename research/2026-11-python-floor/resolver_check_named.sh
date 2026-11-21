#!/usr/bin/env bash
# Resolver check of the 7 named workspace projects (results: resolver_check.csv): shallow clone,
# run depquiet --fix-plan --raise-python-floor (uv lock on temporary copies), keep the JSON,
# delete the clone. It runs third-party build code: use a disposable machine.
export PATH="$HOME/.local/bin:$HOME/dqv/bin:$PATH"
mkdir -p ~/verify2/results && cd ~/verify2 || exit 1
for r in pydantic/pydantic:main python-telegram-bot/python-telegram-bot:master \
         PrefectHQ/prefect:main microsoft/graphrag:main vectorize-io/hindsight:main \
         mlflow/mlflow:master apache/airflow:main; do
  repo=${r%%:*}; br=${r##*:}; d=${repo//\//__}
  rm -rf src
  git clone -q --depth 1 --single-branch -b "$br" "https://github.com/$repo.git" src ||
    { echo "$repo clone-failed"; continue; }
  timeout 1500 depquiet --path src --fix-plan results/$d.diff --raise-python-floor --json \
    > results/$d.json 2> results/$d.err
  python3 - "$repo" "results/$d.json" src/uv.lock <<'PY'
import json, re, sys
repo, out, lock = sys.argv[1:]
text = open(lock).read()
sv = re.search(r'name = "soupsieve"\nversion = "([^"]+)"', text)
rp = re.search(r'^requires-python = "([^"]+)"', text, re.M)
try:
    p = json.load(open(out)).get("fix_plan") or {}
except Exception as e:
    print(repo, "| error", type(e).__name__); sys.exit()
f = p.get("python_floor") or {}
splits = [f"{c['package']} {c['to']}" for c in p.get("lock_changes") or [] if "," in (c["to"] or "")]
soup = [i.get("why", "")[:120] for i in p.get("left_out") or [] if i.get("package") == "soupsieve"]
print(repo, "| lock", rp and rp.group(1), "| soupsieve", sv and sv.group(1), "| status",
      p.get("status"), "| floor", f.get("floor"), "| adopted", f.get("adopted"), "| unblocks",
      f.get("unblocks"), "| avoids", f.get("avoids_older"), "| splits", splits,
      "| soupsieve left out:", soup)
PY
  rm -rf src ~/.cache/uv/sdists-v* 2>/dev/null
  df -h / | tail -1 | awk '{print "   disk free:", $4}'
done | tee ~/verify2/summary.txt
