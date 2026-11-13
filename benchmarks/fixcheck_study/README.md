# Fix-check study

Can the fix a scanner suggests be installed as-is? For 18 uv projects, `run.py` clones the
project, audits its `uv.lock` with pip-audit through depquiet, and asks uv's resolver
(`uv lock --dry-run --upgrade-package pkg==fix`) about each alert depquiet keeps.

- `results.json`: one row per project, with every resolver message.
- `summary.md`: the table and the list of blocked fixes.

Run on 2026-11-12, at each project's head (commits in the table), Ubuntu 26.04 VM, with
depquiet 0.39.0: each kept alert checked against its own nearest fix, and each package
against its highest fix. A first run on 2026-11-11 checked only the highest fix per package;
its numbers are in the git history of this folder.

`uv lock` can execute the cloned projects' build hooks, so run it only in a disposable
virtual machine with no shared folders: `vm.sh` installs what it needs there and runs the
study. `python run.py --out DIR --skip-check` audits without calling `uv lock`.

`remeasure.sh` re-measures the README's headline table with the latest release, in a
disposable VM: one pip-audit run per project at the study's commit, given to both depquiet
0.39.0 (which measured the table) and the latest release, so any difference in verdicts
comes from depquiet, not from advisories published since. No `uv lock` is involved.

