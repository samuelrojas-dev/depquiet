"""Shared test setup."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_cve_alias_lookups(request, monkeypatch):
    """Scans in tests must not query OSV.dev for CVE aliases or write its cache.

    Tests of the lookup itself opt in with ``@pytest.mark.cve_alias_lookups``
    and fake the HTTP layer.
    """
    if request.node.get_closest_marker("cve_alias_lookups") is None:
        monkeypatch.setattr("depquiet.engine.resolve_cve_aliases", lambda vulns, **_: 0)


@pytest.fixture(autouse=True)
def _no_pip_audit_lookups(request, monkeypatch):
    """Fix plans in tests must not run pip-audit on candidate releases.

    Tests of that check opt in with ``@pytest.mark.advisory_lookups`` and fake it.
    """
    if request.node.get_closest_marker("advisory_lookups") is None:
        monkeypatch.setattr("depquiet.fixplan._advisories", lambda *a, **k: {})


@pytest.fixture(autouse=True)
def _no_pypi_python_lookups(request, monkeypatch):
    """Fix plans in tests must not ask PyPI about releases.

    Neither which Python a release needs nor what a blocker's newest release
    requires. Tests of those opt in with ``@pytest.mark.python_lookups`` and fake it.
    """
    if request.node.get_closest_marker("python_lookups") is None:
        monkeypatch.setattr("depquiet.fixplan._release_pythons", lambda *a, **k: {})
        monkeypatch.setattr("depquiet.fixplan._newest_requirements", lambda *a, **k: {})
