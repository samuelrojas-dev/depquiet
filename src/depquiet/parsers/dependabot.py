"""Parse GitHub Dependabot alerts JSON into Vulnerability objects.

GitHub Dependabot alerts can be exported via the REST API::

    gh api /repos/OWNER/REPO/dependabot/alerts --paginate > alerts.json

This returns a JSON array of alert objects, each with ``security_advisory``
(CVE/GHSA, severity, summary) and ``dependency`` (package name, ecosystem,
manifest path, scope).  depquiet wraps the array as ``{"alerts": [...]}``
before parsing so the engine always works with dicts.

Only *open* alerts are processed — dismissed/fixed alerts are skipped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability, short_title

# Map GitHub ecosystem names to depquiet package-manager names
_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pip": "pip",
    "composer": "composer",
    "go": "go",
    "maven": "maven",
    "nuget": "nuget",
    "rubygems": "rubygems",
    "rust": "cargo",
}


class DependabotParser:
    """Parse GitHub Dependabot alerts (exported via ``gh api``)."""

    name = "dependabot"

    @staticmethod
    def detect(project: Path) -> bool:
        """Dependabot is never auto-detected — use ``--stdin`` with exported JSON."""
        return False

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        """Parse Dependabot alerts JSON into Vulnerability objects.

        Expects ``{"alerts": [<alert>, ...]}`` — the CLI wraps the raw
        array before calling the engine.
        """
        vulns: list[Vulnerability] = []
        seen: set[str] = set()

        alerts = audit_json.get("alerts", [])
        for alert in alerts:
            # Skip non-open alerts
            state = alert.get("state", "open")
            if state != "open":
                continue

            # Extract dependency info
            dep = alert.get("dependency", {})
            pkg_info = dep.get("package", {})
            pkg_name = pkg_info.get("name", "")
            if not pkg_name:
                continue  # not an alert this parser can place
            scope = dep.get("scope", "runtime")
            is_dev = scope == "development"

            # Extract advisory info
            advisory = alert.get("security_advisory", {})
            cve_id = advisory.get("cve_id") or advisory.get("ghsa_id", "")
            summary = advisory.get("summary", "")
            measured = Severity.parse(advisory.get("severity"))
            severity = measured or Severity.MODERATE

            # Extract fix version
            sec_vuln = alert.get("security_vulnerability", {})
            patched = sec_vuln.get("first_patched_version") or {}
            fix_version = patched.get("identifier", "")
            vuln_range = sec_vuln.get("vulnerable_version_range", "")

            # Build reference URL
            ghsa_id = advisory.get("ghsa_id", "")
            url = f"https://github.com/advisories/{ghsa_id}" if ghsa_id else ""

            # Deduplicate
            key = f"{cve_id}:{pkg_name}"
            if key in seen:
                continue
            seen.add(key)

            vulns.append(
                Vulnerability(
                    cve=cve_id,
                    package=pkg_name,
                    version=vuln_range,
                    severity=severity,
                    severity_known=measured is not None,
                    title=short_title(summary) if summary else cve_id,
                    url=url,
                    fix_version=fix_version,
                    is_direct=True,
                    is_dev=is_dev,
                    aliases=[g for g in [advisory.get("ghsa_id") or ""] if g and g != cve_id],
                )
            )

        return vulns

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """Dependabot alerts must be piped via ``--stdin``; scan is a no-op."""
        return []
