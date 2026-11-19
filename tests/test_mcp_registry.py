"""The MCP Registry entry (server.json) stays true to the package it names.

The registry runs a PyPI server as ``uvx <runtimeArguments> depquiet
<packageArguments>`` and accepts it only when the package README carries
``mcp-name: <name>``. The release workflow publishes server.json after PyPI,
so its version must be the package's.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from depquiet import cli

ROOT = Path(__file__).resolve().parents[1]
SERVER = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def test_versions_match_the_package() -> None:
    assert SERVER["version"] == VERSION
    assert [p["version"] for p in SERVER["packages"]] == [VERSION]


def test_the_readme_carries_the_registry_name() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"<!-- mcp-name: {SERVER['name']} -->" in readme
    assert SERVER["name"].startswith("io.github.samuelrojas-dev/")


def test_the_entry_runs_the_mcp_server_with_its_sdk() -> None:
    [package] = SERVER["packages"]
    assert package["registryType"] == "pypi" and package["identifier"] == "depquiet"
    assert package["runtimeHint"] == "uvx"
    # pip-audit too: someone arriving from the registry may not have it.
    assert package["runtimeArguments"] == [
        {"type": "named", "name": "--with", "value": "mcp>=2.3,<3"},
        {"type": "named", "name": "--with", "value": "pip-audit"},
    ]
    assert package["packageArguments"] == [{"type": "positional", "value": "mcp"}]
    assert package["transport"] == {"type": "stdio"}
    # The SDK range is the package's own mcp extra.
    extra = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "optional-dependencies"
    ]["mcp"]
    assert extra == ["mcp>=2.3,<3"]


def test_description_fits_the_registry_limit() -> None:
    assert 0 < len(SERVER["description"]) <= 100


def test_depquiet_mcp_subcommand_starts_the_server(monkeypatch) -> None:
    started: list[bool] = []
    monkeypatch.setattr("depquiet.mcp_server.main", lambda: started.append(True))
    assert cli.main(["mcp"]) == 0 and started == [True]
