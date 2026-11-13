"""Re-measure the README's headline table with the current depquiet.

For each project and commit in results.json: clone it, run pip-audit once on
its uv.lock (pinned, ``--no-deps``: no project code runs), then give that same
report to two depquiet versions and compare every verdict. One report for both
means a difference comes from depquiet, not from advisories published since.

    python remeasure.py OLD_DEPQUIET NEW_DEPQUIET --out DIR

OLD_DEPQUIET and NEW_DEPQUIET are paths to the two ``depquiet`` executables.
Run it in a disposable VM, like the study itself (``remeasure.sh`` does that).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _version(exe: str) -> str:
    return subprocess.run([exe, "--version"], capture_output=True, text=True).stdout.strip()


def _checkout(repo: str, commit: str, root: Path) -> Path:
    dest = root / "repos" / repo.replace("/", "__")
    if not dest.exists():
        subprocess.run(
            [
                "git",
                "clone",
                "-q",
                "--filter=blob:none",
                "--no-checkout",
                f"https://github.com/{repo}",
                str(dest),
            ],
            check=True,
            timeout=1800,
        )
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", commit], check=True, timeout=1800)
    return dest


def _verdicts(exe: str, project: Path, audit: str) -> dict[str, tuple[str, list[str]]]:
    r = subprocess.run(
        [exe, "--path", str(project), "--stdin", "--offline", "--json", "--scanner", "pip"],
        input=audit,
        capture_output=True,
        text=True,
        timeout=900,
    )
    out: dict[str, tuple[str, list[str]]] = {}
    for x in json.loads(r.stdout)["results"]:
        key = f"{x['cve']} {x['package']} {x.get('version', '')}"
        out[key] = (x["verdict"].lower(), list(x["reasons"]))
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("old")
    parser.add_argument("new")
    parser.add_argument("--out", type=Path, default=Path.home() / "remeasure")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    from depquiet.scanners import run_pip_audit  # the new version's scanner

    old_v, new_v = _version(args.old), _version(args.new)
    rows = []
    for study in json.loads((HERE / "results.json").read_text(encoding="utf-8")):
        repo, commit = study["project"], study.get("commit", "")
        print(f"{repo} @ {commit} ...", flush=True)
        row: dict[str, object] = {"project": repo, "commit": commit}
        try:
            project = _checkout(repo, commit, args.out)
            audit = json.dumps(run_pip_audit(project))
            old, new = _verdicts(args.old, project, audit), _verdicts(args.new, project, audit)
        except Exception as e:  # one project must not stop the run
            row["error"] = f"{type(e).__name__}: {e}"[:300]
            rows.append(row)
            print(f"   error: {row['error']}", flush=True)
            continue
        changed = [
            {"alert": k, "old": old[k], "new": new.get(k)}
            for k in old
            if new.get(k, ("missing", []))[0] != old[k][0]
        ]
        row.update(
            alerts=len(new),
            filtered_old=sum(v[0] == "filtered" for v in old.values()),
            filtered_new=sum(v[0] == "filtered" for v in new.values()),
            new_filter_reasons=sorted(
                {r for v in new.values() if v[0] == "filtered" for r in v[1]}
            ),
            changed=changed,
        )
        rows.append(row)
        print(
            f"   alerts {row['alerts']}, filtered {row['filtered_old']} -> {row['filtered_new']},"
            f" verdicts changed: {len(changed)}",
            flush=True,
        )

    (args.out / "remeasure.json").write_text(
        json.dumps({"old": old_v, "new": new_v, "rows": rows}, indent=1), encoding="utf-8"
    )
    lines = [
        f"Same pip-audit report per project; {old_v} vs {new_v}.",
        "",
        "| Project | Commit | Alerts | Filtered (old) | Filtered (new) | Verdicts changed |",
        "|:--|:--|--:|--:|--:|--:|",
    ]
    for r in rows:
        if "error" in r:
            lines.append(f"| {r['project']} | {r['commit']} | error: {r['error'][:80]} ||||")
            continue
        lines.append(
            f"| {r['project']} | {r['commit']} | {r['alerts']} | {r['filtered_old']} | "
            f"{r['filtered_new']} | {len(r['changed'])} |"  # type: ignore[arg-type]
        )
    (args.out / "remeasure.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
