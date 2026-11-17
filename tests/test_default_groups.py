"""Groups uv installs in a production sync are production, whatever their name.

``uv sync --frozen --no-dev`` leaves out only the group named ``dev``; the other
``tool.uv.default-groups`` are installed. 0.47.4 classified groups by name only, so
with ``default-groups = "all"`` a ``docs`` group that ships was filtered as
development-only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from depquiet.depgraph import _load_pyproject


def _graph(tmp_path: Path, tool_uv: str):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = []\n'
        '[dependency-groups]\ndev = ["pytest"]\ndocs = ["sphinx"]\ntest = ["coverage"]\n' + tool_uv
    )
    graph = _load_pyproject(tmp_path / "pyproject.toml")
    assert graph is not None
    return graph


def _dev(graph, name: str) -> bool:
    return graph.is_dev_only([name])


@pytest.mark.parametrize(
    ("tool_uv", "shipped"),
    [
        ("", set()),
        ('[tool.uv]\ndefault-groups = ["dev"]\n', set()),
        ('[tool.uv]\ndefault-groups = ["dev", "docs"]\n', {"sphinx"}),
        ('[tool.uv]\ndefault-groups = "all"\n', {"sphinx", "coverage"}),
    ],
)
def test_default_groups_other_than_dev_ship(tmp_path, tool_uv, shipped) -> None:
    graph = _graph(tmp_path, tool_uv)
    assert _dev(graph, "pytest")  # --no-dev leaves dev out
    for name in ("sphinx", "coverage"):
        assert _dev(graph, name) is (name not in shipped), name
