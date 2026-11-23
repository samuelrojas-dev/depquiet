"""Wrap one depquiet --json run as {repo, sha, rc, fix_plan, error}."""

import json
import sys
from pathlib import Path

repo, sha, rc = sys.argv[1:]
home = Path.home() / "fork_study"
try:
    data = json.loads((home / "tmp.json").read_text())
except Exception:
    data = None
err = (home / "tmp.err").read_text(errors="replace")[-800:]
print(
    json.dumps(
        {
            "repo": repo,
            "sha": sha,
            "rc": int(rc),
            "fix_plan": (data or {}).get("fix_plan"),
            "error": None if data else err,
        }
    )
)
