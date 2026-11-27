"""Parse npm audit JSON output into Vulnerability objects.

npm audit --json returns a structure like:
{
  "vulnerabilities": {
    "<package>": {
      "name": "...",
      "severity": "high",
      "isDirect": true,
      "via": [
        { "source": 1234, "name": "...", "title": "...", "url": "...", "severity": "high",
          "cwe": [...], "cvss": {...}, "range": "..." }
        or just a string (transitive reference)
      ],
      "effects": [...],
      "range": "...",
      "fixAvailable": true | { "name": "...", "version": "...", "isSemVerMajor": false }
    }
  }
}
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability


def _read_package_json(project: Path) -> dict[str, Any]:
    """Read package.json to determine devDependencies."""
    pkg = project / "package.json"
    if pkg.exists():
        result: dict[str, Any] = json.loads(pkg.read_text())
        return result
    return {}


def _get_dev_packages(pkg_json: dict[str, Any]) -> set[str]:
    """Extract devDependency names from package.json."""
    return set(pkg_json.get("devDependencies", {}).keys())


class NpmAuditParser:
    """Parse npm audit --json output."""

    name = "npm"

    @staticmethod
    def detect(project: Path) -> bool:
        """Check if this is an npm project."""
        # ``npm audit`` needs npm's own lockfile. A Yarn or pnpm project is
        # scanned from its lockfile through OSV.dev instead of failing here first.
        return (project / "package-lock.json").exists() or (
            project / "npm-shrinkwrap.json"
        ).exists()

    @staticmethod
    def run_audit(project: Path) -> dict[str, Any]:
        """Run npm audit and return JSON output."""
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=project,
                capture_output=True,
                text=True,
                timeout=120,
            )
            # npm audit exits non-zero when vulnerabilities are found, which is normal
            return json.loads(result.stdout) if result.stdout else {}
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            return {}

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        """Parse npm audit JSON into Vulnerability objects."""
        from depquiet.npm_components import NpmComponentResolver

        vulns: list[Vulnerability] = []
        pkg_json = _read_package_json(project)
        dev_packages = _get_dev_packages(pkg_json)
        seen: set[str] = set()
        component_resolver = NpmComponentResolver(project)

        raw_vulns = audit_json.get("vulnerabilities", {})
        for pkg_name, pkg_data in raw_vulns.items():
            measured = Severity.parse(pkg_data.get("severity"))
            severity = measured or Severity.MODERATE
            is_direct = pkg_data.get("isDirect", False)
            is_dev = pkg_name in dev_packages

            via = pkg_data.get("via", [])
            for entry in via:
                if isinstance(entry, str):
                    # Transitive reference, skip (the source package has the real advisory)
                    continue

                cve = ""
                title = entry.get("title", "Unknown vulnerability")
                url = entry.get("url", "")
                source = entry.get("source", "")

                # Extract CVE from url (e.g. https://github.com/advisories/GHSA-xxxx)
                # or from title
                if url and "advisories" in url:
                    cve = url.rsplit("/", 1)[-1]
                if not cve and source:
                    cve = f"GHSA-{source}"

                key = f"{cve}:{pkg_name}"
                if key in seen:
                    continue
                seen.add(key)

                fix_available = pkg_data.get("fixAvailable", False)
                fix_version = ""
                fix_package = ""
                fix_in_range = fix_available is True
                if isinstance(fix_available, dict):
                    fix_version = fix_available.get("version", "")
                    if fix_available.get("name", pkg_name) != pkg_name:
                        fix_package = fix_available["name"]

                raw_range = entry.get("range", "")
                advisory_range = raw_range if isinstance(raw_range, str) else ""
                nodes = pkg_data.get("nodes", [])
                components, component_notes = component_resolver.resolve(
                    pkg_name, nodes, advisory_range
                )
                if not isinstance(raw_range, str):
                    component_notes.append(
                        "Scanner advisory range is malformed; association is unknown."
                    )
                resolution_complete = (
                    isinstance(nodes, list)
                    and bool(nodes)
                    and all(isinstance(node, str) for node in nodes)
                    and {component.location for component in components} == set(nodes)
                )

                vulns.append(
                    Vulnerability(
                        cve=cve,
                        package=pkg_name,
                        version=advisory_range,
                        severity=severity,
                        severity_known=measured is not None,
                        title=title,
                        url=url,
                        fix_version=fix_version,
                        fix_package=fix_package,
                        fix_in_range=fix_in_range,
                        is_direct=is_direct,
                        is_dev=is_dev,
                        depth=0 if is_direct else 1,
                        version_kind="advisory_range",
                        advisory_range=advisory_range,
                        components=components,
                        component_notes=component_notes,
                        component_resolution_complete=resolution_complete,
                    )
                )

        return vulns

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """Run audit and parse in one step."""
        audit_json = cls.run_audit(project)
        return cls.parse(audit_json, project)
