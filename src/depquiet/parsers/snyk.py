"""Parser for Snyk CLI JSON output (``snyk test --json``).

Snyk is the leading commercial SCA tool. Supporting its output demonstrates
that depquiet is scanner-agnostic and can triage alerts from any source.

The JSON structure is:

    {
      "ok": false,
      "vulnerabilities": [
        {
          "id": "SNYK-JS-LODASH-567746",
          "title": "Prototype Pollution",
          "severity": "high",
          "packageName": "lodash",
          "version": "4.17.15",
          "fixedIn": ["4.17.21"],
          "from": ["my-app@1.0.0", "lodash@4.17.15"],
          "identifiers": {"CVE": ["CVE-2020-8203"]},
          "isUpgradable": true,
          "language": "js",
          "packageManager": "npm"
        }
      ],
      "dependencyCount": 847,
      "packageManager": "npm"
    }

Auto-detection: ``"vulnerabilities"`` key AND ``"packageManager"`` key
(npm audit also has ``"vulnerabilities"`` but as a dict, not a list).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability

# Map Snyk packageManager to depquiet ecosystem
_PM_MAP: dict[str, str] = {
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "pip": "pip",
    "poetry": "pip",
    "pipenv": "pip",
    "maven": "maven",
    "gradle": "maven",
    "nuget": "nuget",
    "rubygems": "rubygems",
    "gomodules": "go",
    "golang": "go",
    "composer": "composer",
    "cocoapods": "cocoapods",
    "hex": "hex",
    "cargo": "cargo",
}


class SnykParser:
    """Parse Snyk CLI ``snyk test --json`` output."""

    name = "snyk"

    @staticmethod
    def detect(project: Path) -> bool:
        # Snyk requires authentication — we never auto-run it
        return False

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        raw_vulns = audit_json.get("vulnerabilities", [])
        if not isinstance(raw_vulns, list):
            return []

        seen: set[str] = set()
        results: list[Vulnerability] = []

        for entry in raw_vulns:
            if not isinstance(entry, dict):
                continue

            # Extract CVE from identifiers, fall back to Snyk ID
            identifiers = entry.get("identifiers", {})
            cves = identifiers.get("CVE", [])
            cve = cves[0] if cves else entry.get("id", "")
            if not cve:
                continue

            pkg = entry.get("packageName", "")
            if not pkg:
                continue

            # Deduplicate by CVE:package
            key = f"{cve}:{pkg}"
            if key in seen:
                continue
            seen.add(key)

            # Severity
            measured = Severity.parse(entry.get("severity"))
            severity = measured or Severity.MODERATE

            # Title — truncate to 120 chars
            title = entry.get("title", "")
            if len(title) > 120:
                title = title[:117] + "..."

            # Fix version
            fixed_in = entry.get("fixedIn", [])
            fix_version = fixed_in[0] if fixed_in else ""

            # URL — Snyk advisories
            snyk_id = entry.get("id", "")
            url = f"https://security.snyk.io/vuln/{snyk_id}" if snyk_id else ""

            # Depth: from[] has the dependency chain, depth = len - 1
            from_chain = entry.get("from", [])
            depth = max(0, len(from_chain) - 1) if from_chain else 0
            is_direct = depth <= 1

            results.append(
                Vulnerability(
                    cve=cve,
                    package=pkg,
                    version=entry.get("version", ""),
                    severity=severity,
                    severity_known=measured is not None,
                    title=title,
                    url=url,
                    fix_version=fix_version,
                    is_direct=is_direct,
                    depth=depth,
                )
            )

        return results

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        # Snyk requires auth + org setup — don't auto-run
        return []
