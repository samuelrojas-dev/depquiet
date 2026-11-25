#!/usr/bin/env bash
# For each repo in repos19.txt: full shallow clone at HEAD (deleted after each run),
# run depquiet --fix-plan --json, keep the plan. Resumable: finished repos are skipped.
export PATH="$HOME/.local/bin:$HOME/dqv/bin:$PATH"
export UV_PROJECT_ENVIRONMENT=/tmp/uvenv_unused
export SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0
cd ~/fork_study || exit 1
mkdir -p out_full
total=$(wc -l < repos19.txt)
n=0
while read -r repo; do
  f="$HOME/fork_study/out_full/${repo//\//__}.json"
  [ -s "$f" ] && continue
  rm -rf /tmp/fs_work && mkdir -p /tmp/fs_work && cd /tmp/fs_work || exit 1
  # Full shallow clone this time: the build may need sources, a README or git metadata.
  if git clone -q --depth 1 "https://github.com/$repo.git" . 2>/dev/null && [ -f uv.lock ]; then
    sha=$(git rev-parse HEAD)
    timeout 1200 depquiet --path . --fix-plan --json > "$HOME/fork_study/tmp.json" 2> "$HOME/fork_study/tmp.err"
    python3 ~/fork_study/wrap.py "$repo" "$sha" "$?" > "$f"
  else
    printf '{"repo": "%s", "error": "fetch failed or no uv.lock"}\n' "$repo" > "$f"
  fi
  cd ~/fork_study && rm -rf /tmp/fs_work
  n=$((n + 1))
  uv cache clean -q  # every repo: the VM disk is small
  echo "$(date +%H:%M) $(ls out_full | wc -l)/$total $repo"
done < repos19.txt
echo DONE
