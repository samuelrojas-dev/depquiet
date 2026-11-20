#!/bin/bash
# Reproduce a sample and its scans (read-only: downloads a lock file and pyproject.toml per
# repo, scans the pinned versions; nothing resolves or installs).
# Needs: gh (authenticated), curl, depquiet and pip-audit on PATH, python3 with packaging.
#
#   ./collect.sh study                                   # first snapshot (uv only, 300 repos)
#   QUERY='stars:>500 pushed:>2026-10-20' PAGES=10 LOCKS='uv.lock poetry.lock' ./collect.sh top1000
#   QUERY='stars:200..500 pushed:>2026-10-20' PAGES=10 LOCKS='uv.lock poetry.lock' ./collect.sh mid
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
query=${QUERY:-stars:>1000 pushed:>2026-11-01}
locks=${LOCKS:-uv.lock}
out=${1:-study}; mkdir -p "$out/repos" "$out/scans"; cd "$out"
: > candidates.txt
for p in $(seq 1 "${PAGES:-3}"); do
  gh api -X GET search/repositories -f q="language:Python $query archived:false" \
    -f sort=stars -f per_page=100 -f page="$p" \
    --jq '.items[] | .full_name+" "+.default_branch+" "+(.stargazers_count|tostring)' >> candidates.txt
done
: > withlock.txt
while read -r repo br stars; do
  d=repos/${repo//\//__}
  for lock in $locks; do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "https://raw.githubusercontent.com/$repo/$br/$lock")" = 200 ]; then
      mkdir -p "$d"
      curl -s -o "$d/$lock" "https://raw.githubusercontent.com/$repo/$br/$lock"
      curl -s -o "$d/pyproject.toml" "https://raw.githubusercontent.com/$repo/$br/pyproject.toml"
      echo "$repo $br $stars $lock" >> withlock.txt
      break
    fi
  done
done < candidates.txt
for d in repos/*; do
  n=$(basename "$d")
  depquiet --path "$d" --offline --json > "scans/$n.json" 2> "scans/$n.err" || true
done
python3 "$here/analyze.py" .
python3 "$here/summarize.py" . blocked_copies.csv
