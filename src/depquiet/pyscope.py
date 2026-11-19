"""Which Pythons a vulnerable locked copy serves, in a lock forked by Python version.

uv keeps one copy of a package per Python range when a newer release dropped
the older Pythons. With ``requires-python = ">=3.11"``, soupsieve ends up locked
twice: 2.10 for ``python_full_version < '3.11.5'`` and 4.1 for 3.11.5 and up,
because every patched soupsieve needs 3.11.5. Dependabot flags 2.10 and the alert
stays open, but only installs on Python 3.11.0-3.11.4 get that copy.

Seen in four public projects in November 2026. The verdict does not change:
those installs are still exposed. The report just says who is, and that raising
``requires-python`` to the bound would drop the copy (``--fix-plan
--raise-python-floor`` checks that with the resolver).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from depquiet.models import ScanResult, version_key

_UPPER = re.compile(r"python_(?:full_)?version\s*<\s*'(\d+(?:\.\d+){1,2})'")
_LOWER = re.compile(r">=\s*(\d+(?:\.\d+){0,2})")


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _floor(spec: str) -> str:
    """The lowest Python a ``requires-python`` admits ("" when it has no ``>=``)."""
    found = _LOWER.findall(spec or "")
    return max(found, key=version_key) if found else ""


def python_scopes(project: Path) -> dict[tuple[str, str], str]:
    """(package, version) -> "3.11.5" when that locked copy serves only Pythons below it.

    Only copies of a package locked more than once, whose every resolution
    marker caps the Python version, and only when the cap is above the
    project's floor (otherwise the copy serves nothing the project supports).
    """
    try:
        lock = tomllib.loads((project / "uv.lock").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return {}
    floor = _floor(str(lock.get("requires-python", "")))
    copies: dict[str, list[dict[str, Any]]] = {}
    for package in lock.get("package", []):
        if isinstance(package, dict) and "name" in package and "version" in package:
            copies.setdefault(_pep503(package["name"]), []).append(package)
    scopes: dict[tuple[str, str], str] = {}
    for name, entries in copies.items():
        if len(entries) < 2:
            continue
        for entry in entries:
            markers = entry.get("resolution-markers") or []
            caps = [_UPPER.findall(m) for m in markers if isinstance(m, str)]
            if not markers or not caps or any(not c for c in caps):
                continue
            cap = max((v for c in caps for v in c), key=version_key)
            if floor and version_key(cap) <= version_key(floor):
                continue
            scopes[(name, str(entry["version"]))] = cap
    return scopes


def apply_python_scopes(result: ScanResult, project: Path) -> int:
    """Set ``python_scope`` on alerts whose copy only older Pythons install; returns how many."""
    scopes = python_scopes(project)
    if not scopes:
        return 0
    count = 0
    for finding in result.results:
        cap = scopes.get((_pep503(finding.vuln.package), finding.vuln.version))
        if cap:
            finding.python_scope = cap
            count += 1
    return count
