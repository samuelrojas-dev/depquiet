#!/bin/bash
# Reproduce the sample and the scans (read-only: downloads two files per repo, nothing resolves).
# Needs: gh (authenticated), curl, depquiet and pip-audit on PATH, python3 with packaging.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-study}; mkdir -p "$out/repos" "$out/scans"; cd "$out"
for p in 1 2 3; do
  gh api -X GET search/repositories -f q='language:Python stars:>1000 pushed:>2026-11-01 archived:false' \
    -f sort=stars -f per_page=100 -f page=$p --jq '.items[] | .full_name+" "+.default_branch+" "+(.stargazers_count|tostring)'
done > candidates.txt
: > withlock.txt
while read -r repo br stars; do
  d=repos/${repo//\//__}
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "https://raw.githubusercontent.com/$repo/$br/uv.lock")" = 200 ]; then
    mkdir -p "$d"
    curl -s -o "$d/uv.lock" "https://raw.githubusercontent.com/$repo/$br/uv.lock"
    curl -s -o "$d/pyproject.toml" "https://raw.githubusercontent.com/$repo/$br/pyproject.toml"
    echo "$repo $br $stars" >> withlock.txt
  fi
done < candidates.txt
for d in repos/*; do
  n=$(basename "$d")
  depquiet --path "$d" --offline --json > "scans/$n.json" 2> "scans/$n.err" || true
done
python3 "$here/analyze.py" .
python3 "$here/summarize.py" . blocked_copies.csv
