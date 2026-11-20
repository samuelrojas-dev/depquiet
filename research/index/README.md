# Python floor index

Once a month, [a workflow](../../.github/workflows/python-floor-index.yml) measures the
most-starred Python repos (more than 500 stars) pushed in the last 30 days: how many hold a
vulnerability alert that no fixed release reaches on their oldest supported Python, so no
upgrade closes it without dropping a Python version. Method and limits are those of the
[first study](../2026-11-python-floor/README.md); uv and Poetry projects count.

Each month gets a folder with `summary.md`, the per-copy data and the sample, and a row in
[`history.csv`](history.csv). The workflow opens the results as a pull request, reviewed
before they are merged.

| Month | Analysed | With action alerts | Blocked by the Python floor | soupsieve trap (already at 3.11) |
|---|--:|--:|--:|--:|
| [2026-11](2026-11/summary.md) | 261 | 196 | 98 (50%) | 65 (32) |

Run it by hand: Actions → Python floor index → Run workflow.
