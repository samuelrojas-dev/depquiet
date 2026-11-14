#!/usr/bin/env bash
# Re-measure the README's headline table inside a disposable Ubuntu VM.
# Usage, in the VM:
#   git clone https://github.com/samuelrojas-dev/depquiet
#   bash depquiet/benchmarks/fixcheck_study/remeasure.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
sudo apt-get update -q
sudo apt-get install -y -q git python3-venv
python3 -m venv "$HOME/dq-old"
python3 -m venv "$HOME/dq-new"
"$HOME/dq-old/bin/pip" install -q --upgrade pip
"$HOME/dq-new/bin/pip" install -q --upgrade pip
# The version that measured the table, and the latest release, both from PyPI.
"$HOME/dq-old/bin/pip" install -q "depquiet==0.39.0" pip-audit
"$HOME/dq-new/bin/pip" install -q depquiet pip-audit
export PATH="$HOME/dq-new/bin:$PATH"   # pip-audit for the single shared audit
"$HOME/dq-new/bin/python" "$HERE/remeasure.py" \
  "$HOME/dq-old/bin/depquiet" "$HOME/dq-new/bin/depquiet" --out "$HOME/remeasure"
echo
echo "Done. Results in ~/remeasure/remeasure.md and ~/remeasure/remeasure.json."
echo "Serving them on port 8000; open http://localhost:8080 on your computer."
cd "$HOME/remeasure" && python3 -m http.server 8000
