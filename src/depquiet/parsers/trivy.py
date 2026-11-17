"""Parse Trivy JSON output into Vulnerability objects.

Trivy (https://trivy.dev) is a comprehensive vulnerability scanner for
containers, filesystems, and IaC.  ``trivy fs --format json`` returns:

{
  "Results": [
    {
      "Target": "package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-...",
          "PkgName": "lodash",
          "InstalledVersion": "4.17.20",
          "FixedVersion": "4.17.21",
          "Severity": "HIGH",
          "Title": "Prototype Pollution in lodash",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-..."
        }
      ]
    }
  ]
}

depquiet parses lang-pkgs results (npm, pip, etc.) and maps them to the
same Vulnerability objects the other parsers produce.  Container OS
packages (``os-pkgs``) are skipped — they belong to a different triage
workflow.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability, short_title


class TrivyParser:
    """Parse ``trivy fs --format json`` output."""

    name = "trivy"

    @staticmethod
    def detect(project: Path) -> bool:
        """Trivy is never auto-detected — use ``--stdin`` with trivy JSON."""
        return False

    @staticmethod
    def run_audit(project: Path) -> dict[str, Any]:
        """Run ``trivy fs --format json`` on the project."""
        try:
            result = subprocess.run(
                ["trivy", "fs", "--format", "json", "--quiet", str(project)],
                capture_output=True,
                text=True,
                timeout=180,
            )
            return json.loads(result.stdout) if result.stdout else {}
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            return {}

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        """Parse Trivy JSON into Vulnerability objects.

        Only ``lang-pkgs`` results are processed — OS packages are skipped.
        """
        vulns: list[Vulnerability] = []
        seen: set[str] = set()

        for result_block in audit_json.get("Results", []):
            cls = result_block.get("Class", "")
            if cls != "lang-pkgs":
                continue

            raw_vulns = result_block.get("Vulnerabilities") or []
            for entry in raw_vulns:
                cve = entry.get("VulnerabilityID", "")
                pkg = entry.get("PkgName", "")
                key = f"{cve}:{pkg}"
                if key in seen:
                    continue
                seen.add(key)

                measured = Severity.parse(entry.get("Severity"))
                severity = measured or Severity.MODERATE
                title = entry.get("Title", cve)
                url = entry.get("PrimaryURL", "")
                fix_version = entry.get("FixedVersion", "")
                installed = entry.get("InstalledVersion", "")

                vulns.append(
                    Vulnerability(
                        cve=cve,
                        package=pkg,
                        version=installed,
                        severity=severity,
                        severity_known=measured is not None,
                        title=short_title(title) if title else cve,
                        url=url,
                        fix_version=fix_version,
                        is_direct=True,
                    )
                )

        return vulns

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """Run trivy and parse in one step."""
        audit_json = cls.run_audit(project)
        return cls.parse(audit_json, project)
