#!/bin/bash
# Blocker Index: re-run the repos the first machine could not check (custom indexes, OSV).
# Usage on the VM:  bash vm_rerun.sh        (takes 1-2 hours; safe to leave running)
# Output: ~/bi-rerun.tar.gz  -> send that file back.
set -u
W=$HOME/bi-rerun; mkdir -p "$W/out" "$W/work"; cd "$W"
python3 -m venv venv 2>/dev/null || { sudo apt-get install -y python3-venv && python3 -m venv venv; }
./venv/bin/pip install -q --upgrade pip
./venv/bin/pip install -q "depquiet==0.60.2" pip-audit uv
export PATH="$W/venv/bin:$PATH"
cat > repos.txt <<'LIST'
AgriciDaniel/claude-seo main
Alishahryar1/free-claude-code main
BerriAI/litellm main
HKUDS/DeepCode main
NanmiCoder/MediaCrawler main
PostHog/posthog master
Textualize/textual main
apache/airflow main
chidiwilliams/buzz main
debpalash/VoiceStudio main
exo-explore/exo main
experientiallabs/experiential main
fishaudio/fish-speech main
hsliuping/TradingAgents-CN v3.0
huggingface/lerobot main
jianchang512/pyvideotrans main
jumpserver/jumpserver dev
k2-fsa/OmniVoice master
langflow-ai/langflow main
m-bain/whisperX main
microsoft/agent-lightning main
microsoft/data-formulator main
microsoft/graphrag main
mitmproxy/mitmproxy main
nesquena/hermes-webui master
p-e-w/heretic master
run-llama/llama_index main
vectorize-io/hindsight main
verl-project/verl main
LIST
one() {
  repo=$1; branch=$2; name=${repo//\//__}; out=$W/out/$name.json
  [ -s "$out" ] && return
  dir=$W/work/$name; rm -rf "$dir"
  if ! timeout 300 git clone -q --depth 1 --branch "$branch" "https://github.com/$repo" "$dir"; then
    echo "{\"error\": \"clone failed\", \"_meta\": {\"repo\": \"$repo\"}}" > "$out"; return
  fi
  commit=$(git -C "$dir" rev-parse HEAD); start=$(date +%s)
  SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0 timeout 1500 depquiet --path "$dir" --fix-plan - --json > "$out.tmp" 2> "$W/out/$name.err"
  rc=$?; secs=$(( $(date +%s) - start ))
  python3 - "$out.tmp" "$out" "$repo" "$commit" "$rc" "$secs" <<'PY'
import json, sys
tmp, out, repo, commit, rc, secs = sys.argv[1:]
try: data = json.load(open(tmp))
except Exception: data = {"error": f"no json (exit {rc})"}
data["_meta"] = {"repo": repo, "commit": commit, "exit": int(rc), "seconds": int(secs)}
json.dump(data, open(out, "w"))
PY
  rm -f "$out.tmp"; rm -rf "$dir"
  echo "done: $repo (${secs}s, exit $rc)"
}
while read -r repo branch; do one "$repo" "$branch"; done < repos.txt
tar czf "$HOME/bi-rerun.tar.gz" -C "$W" out
echo "ALL DONE -> $HOME/bi-rerun.tar.gz ($(ls $W/out/*.json | wc -l) results)"
