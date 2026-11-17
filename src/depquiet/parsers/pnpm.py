"""Parse ``pnpm audit --json`` into Vulnerability objects.

pnpm reports in the npm v6 audit layout, one entry per advisory:

{
  "advisories": {
    "1115540": {
      "module_name": "brace-expansion",
      "vulnerable_versions": "<1.1.13",
      "patched_versions": ">=1.1.13",
      "severity": "moderate",
      "github_advisory_id": "GHSA-f886-m6hf-6m8v",
      "url": "https://github.com/advisories/GHSA-f886-m6hf-6m8v",
      "findings": [
        {"version": "1.1.12", "paths": [".>serve>serve-handler>minimatch>brace-expansion"],
         "dev": true, "optional": false, "bundled": false}
      ]
    }
  }
}

Each finding is one installed version with the dependency paths that reach it
and pnpm's own statement of whether only development dependencies do. That
flag is what ``pnpm audit --prod`` filters on.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability

_FIRST_FIX = re.compile(r">=\s*(\d[\w.+-]*)")


class PnpmAuditParser:
    """Parse pnpm audit --json output (also npm v6 ``advisories`` reports)."""

    name = "pnpm"

    @staticmethod
    def detect(project: Path) -> bool:
        return (project / "pnpm-lock.yaml").exists()

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        advisories = audit_json.get("advisories")
        if not isinstance(advisories, dict):
            return []
        vulns: list[Vulnerability] = []
        seen: set[str] = set()
        for advisory_id, entry in advisories.items():
            if not isinstance(entry, dict):
                continue
            package = entry.get("module_name")
            if not isinstance(package, str) or not package:
                continue
            raw_url = entry.get("url")
            url = raw_url if isinstance(raw_url, str) else ""
            cve = entry.get("github_advisory_id")
            if not isinstance(cve, str) or not cve:
                cve = url.rsplit("/", 1)[-1] if "advisories" in url else f"GHSA-{advisory_id}"
            if f"{cve}:{package}" in seen:
                continue
            seen.add(f"{cve}:{package}")

            raw_findings = entry.get("findings")
            findings = (
                [f for f in raw_findings if isinstance(f, dict)]
                if isinstance(raw_findings, list)
                else []
            )
            paths = [
                p for f in findings for p in (f.get("paths") or []) if isinstance(p, str) and p
            ]
            # ``importer>package`` is a direct dependency of that importer.
            is_direct = any(p.count(">") == 1 for p in paths)
            # Only an explicit ``true`` on every installed version counts.
            dev_only = bool(findings) and all(f.get("dev") is True for f in findings)
            versions = sorted({f["version"] for f in findings if isinstance(f.get("version"), str)})
            advisory_range = entry.get("vulnerable_versions")
            advisory_range = advisory_range if isinstance(advisory_range, str) else ""
            patched = entry.get("patched_versions")
            fix = _FIRST_FIX.search(patched) if isinstance(patched, str) else None
            notes = [f"pnpm reports installed version {v} in the advisory range." for v in versions]

            vulns.append(
                Vulnerability(
                    cve=cve,
                    package=package,
                    version=advisory_range,
                    severity=Severity.parse(entry.get("severity")) or Severity.MODERATE,
                    severity_known=Severity.parse(entry.get("severity")) is not None,
                    title=str(entry.get("title") or "Unknown vulnerability"),
                    url=url,
                    fix_version=fix.group(1) if fix else "",
                    is_direct=is_direct,
                    is_dev=dev_only,
                    depth=0 if is_direct else 1,
                    version_kind="advisory_range",
                    advisory_range=advisory_range,
                    component_notes=notes,
                    scanner_dev_only=dev_only,
                )
            )
        return vulns

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """Run ``pnpm audit`` and parse it in one step."""
        from depquiet.scanners import run_pnpm_audit

        return cls.parse(run_pnpm_audit(project), project)
