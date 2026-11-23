#!/usr/bin/env bash
# For each repo in repos.txt: fetch only uv.lock, uv.toml and every pyproject.toml at HEAD,
# run depquiet --fix-plan --json, keep the plan. Resumable: finished repos are skipped.
export PATH="$HOME/.local/bin:$HOME/dqv/bin:$PATH"
export UV_PROJECT_ENVIRONMENT=/tmp/uvenv_unused
cd ~/fork_study || exit 1
mkdir -p out
total=$(wc -l < repos.txt)
n=0
while read -r repo; do
  f="$HOME/fork_study/out/${repo//\//__}.json"
  [ -s "$f" ] && continue
  rm -rf /tmp/fs_work && mkdir -p /tmp/fs_work && cd /tmp/fs_work || exit 1
  if git clone -q --depth 1 --filter=blob:none --no-checkout "https://github.com/$repo.git" . 2>/dev/null \
     && git sparse-checkout set --no-cone '/uv.lock' '/uv.toml' '**/pyproject.toml' 2>/dev/null \
     && git checkout -q 2>/dev/null && [ -f uv.lock ]; then
    sha=$(git rev-parse HEAD)
    timeout 1200 depquiet --path . --fix-plan --json > "$HOME/fork_study/tmp.json" 2> "$HOME/fork_study/tmp.err"
    python3 ~/fork_study/wrap.py "$repo" "$sha" "$?" > "$f"
  else
    printf '{"repo": "%s", "error": "fetch failed or no uv.lock"}\n' "$repo" > "$f"
  fi
  cd ~/fork_study && rm -rf /tmp/fs_work
  n=$((n + 1))
  [ $((n % 10)) -eq 0 ] && uv cache clean -q
  echo "$(date +%H:%M) $(ls out | wc -l)/$total $repo"
done < repos.txt
echo DONE
