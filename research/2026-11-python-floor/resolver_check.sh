#!/usr/bin/env bash
# Resolver check of the 3.11.5 trap (results: resolver_check.csv). Downloads only
# pyproject.toml and uv.lock and runs depquiet --fix-plan --raise-python-floor, which runs
# uv lock on temporary copies: run it in a disposable machine, not on your own.
export PATH="$HOME/.local/bin:$HOME/dqv/bin:$PATH"
mkdir -p ~/verify && cd ~/verify || exit 1
REPOS="JerBouma/FinanceDatabase:main ManimCommunity/manim:main NVIDIA/warp:main
Skyvern-AI/skyvern:main Thysrael/Horizon:main beetbox/beets:master
blacklanternsecurity/bbot:stable infobyte/faraday:master litestar-org/litestar:main
microsoft/data-formulator:main oraios/serena:main princeton-vl/infinigen:main
spotDL/spotify-downloader:master wagtail/wagtail:main zylon-ai/private-gpt:main"
for r in $REPOS; do
  repo=${r%%:*}; br=${r##*:}; d=${repo//\//__}
  rm -rf "$d"; mkdir -p "$d"
  curl -sfo "$d/pyproject.toml" "https://raw.githubusercontent.com/$repo/$br/pyproject.toml" &&
  curl -sfo "$d/uv.lock" "https://raw.githubusercontent.com/$repo/$br/uv.lock" ||
  { echo "$repo download-failed"; continue; }
  timeout 900 depquiet --path "$d" --fix-plan "$d/plan.diff" --raise-python-floor --json \
    > "$d/out.json" 2> "$d/err.txt"
  python3 - "$repo" "$d" <<'PY'
import json, re, sys
repo, d = sys.argv[1], sys.argv[2]
lock = open(f"{d}/uv.lock").read()
m = re.search(r'name = "soupsieve"\nversion = "([^"]+)"', lock)
rp = re.search(r'^requires-python = "([^"]+)"', lock, re.M)
try:
    p = json.load(open(f"{d}/out.json")).get("fix_plan") or {}
except Exception as e:
    print(repo, "error", type(e).__name__); sys.exit()
f = p.get("python_floor") or {}
print(repo, "| lock", rp and rp.group(1), "| soupsieve", m and m.group(1),
      "| status", p.get("status"), "| floor", f.get("floor"), "| adopted", f.get("adopted"),
      "| unblocks", f.get("unblocks"), "| problem", f.get("problem"))
PY
  rm -rf ~/.cache/uv/sdists-v* 2>/dev/null
done | tee ~/verify/summary.txt
df -h / | tail -1
