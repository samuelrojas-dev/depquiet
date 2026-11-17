"""Parse Anchore Grype JSON output into Vulnerability objects.

Grype (https://github.com/anchore/grype) is a vulnerability scanner for
container images and filesystems.  ``grype dir:. -o json`` returns::

    {
      "matches": [
        {
          "vulnerability": {
            "id": "CVE-2024-...",
            "severity": "High",
            "fix": { "versions": ["1.2.3"], "state": "fixed" },
            "urls": ["https://..."],
            "description": "..."
          },
          "artifact": {
            "name": "lodash",
            "version": "4.17.20",
            "type": "npm",
            "language": "javascript"
          }
        }
      ]
    }

depquiet processes all matches, mapping each ``artifact`` to a Vulnerability
with its fix information.  OS packages are included — unlike Trivy, Grype
doesn't separate them by class, and the depquiet filters will handle them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability, short_title

# Map Grype artifact type / language to depquiet ecosystem names
_TYPE_MAP: dict[str, str] = {
    "npm": "npm",
    "python": "pip",
    "pip": "pip",
    "gem": "rubygems",
    "java-archive": "maven",
    "go-module": "go",
    "rust-crate": "cargo",
    "dotnet": "nuget",
    "php-composer": "composer",
}


class GrypeParser:
    """Parse ``grype dir:. -o json`` output."""

    name = "grype"

    @staticmethod
    def detect(project: Path) -> bool:
        """Grype is never auto-detected — use ``--stdin`` with grype JSON."""
        return False

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        """Parse Grype JSON into Vulnerability objects."""
        vulns: list[Vulnerability] = []
        seen: set[str] = set()

        for match in audit_json.get("matches", []):
            vuln_data = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            cve = vuln_data.get("id", "")
            pkg = artifact.get("name", "")

            # Deduplicate
            key = f"{cve}:{pkg}"
            if key in seen:
                continue
            seen.add(key)

            measured = Severity.parse(vuln_data.get("severity"))
            severity = measured or Severity.MODERATE

            # Fix version: modern Grype uses fix.versions[], older uses fixedInVersion
            fix_data = vuln_data.get("fix", {})
            fix_versions = fix_data.get("versions") or []
            fix_version = fix_versions[0] if fix_versions else ""

            # Build reference URL from urls list or dataSource
            urls = vuln_data.get("urls") or []
            url = urls[0] if urls else vuln_data.get("dataSource", "")

            description = vuln_data.get("description", "")
            title = short_title(description) if description else cve

            installed = artifact.get("version", "")

            vulns.append(
                Vulnerability(
                    cve=cve,
                    package=pkg,
                    version=installed,
                    severity=severity,
                    severity_known=measured is not None,
                    title=title,
                    url=url,
                    fix_version=fix_version,
                    is_direct=True,
                )
            )

        return vulns

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """Grype must be piped via ``--stdin``; scan is a no-op."""
        return []
