"""Parse SARIF v2.1.0 input into Vulnerability objects.

SARIF (Static Analysis Results Interchange Format) is the universal format
for static analysis and vulnerability scanner results.  Any tool that emits
SARIF can be triaged by depquiet::

    semgrep --sarif | depquiet --stdin
    codeql database analyze --format=sarif-latest | depquiet --stdin
    trivy fs --format sarif . | depquiet --stdin

We parse results from every run in the file.  Each result becomes a
Vulnerability keyed on its CVE (from ``ruleId``, ``rule.id``, or
``properties.cve``).  Severity comes from SARIF's ``level`` field or from
a CVSS score in ``properties`` when present.

The parser handles output from at least: CodeQL, Semgrep, Trivy SARIF,
Grype SARIF, Snyk SARIF, Checkmarx, and Fortify.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability, short_title

# SARIF level → depquiet severity
_LEVEL_MAP: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MODERATE,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

# CVSS 3.x score ranges → severity
_CVSS_THRESHOLDS: list[tuple[float, Severity]] = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MODERATE),
    (0.1, Severity.LOW),
    (0.0, Severity.INFO),
]


def _severity_from_cvss(score: float) -> Severity:
    """Map a CVSS 3.x score to a Severity enum."""
    for threshold, severity in _CVSS_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.INFO


def _extract_cve(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    """Best-effort CVE extraction from a SARIF result.

    Tries, in order:
    1. result.properties.cve or result.properties.cveId
    2. ruleId if it looks like a CVE
    3. rule.properties.cve or rule.properties.cveId
    4. rule.id if it looks like a CVE
    5. ruleId as-is (some scanners use non-CVE IDs like GHSA-*)
    """
    props = result.get("properties", {})

    # 1. result properties
    for key in ("cve", "cveId", "CVE"):
        val = props.get(key, "")
        if val:
            return str(val)

    # 2. ruleId that looks like CVE-*
    rule_id = result.get("ruleId", "")
    if rule_id.upper().startswith("CVE-"):
        return str(rule_id)

    # 3. rule properties
    if rule:
        rule_props = rule.get("properties", {})
        for key in ("cve", "cveId", "CVE"):
            val = rule_props.get(key, "")
            if val:
                return str(val)
        # 4. rule.id that looks like CVE
        rid = rule.get("id", "")
        if rid.upper().startswith("CVE-"):
            return str(rid)

    # 5. Fallback: use ruleId as identifier (GHSA-*, CWE-*, etc.)
    return rule_id or "UNKNOWN"


def _extract_package(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    """Best-effort package name extraction.

    Scanners put the affected component in different places:
    - result.properties.packageName / component / artifact
    - result.message.text may contain "in <package>"
    - rule.properties.packageName / component
    - The first physical location's URI may hint at the package
    """
    props = result.get("properties", {})

    # result properties
    for key in ("packageName", "package", "component", "artifact", "dependency"):
        val = props.get(key, "")
        if val:
            return str(val)

    # rule properties
    if rule:
        rule_props = rule.get("properties", {})
        for key in ("packageName", "package", "component", "artifact", "dependency"):
            val = rule_props.get(key, "")
            if val:
                return str(val)

    # Try parsing from message text: common patterns like
    # "Vulnerability in lodash" or "lodash 4.17.20"
    msg = result.get("message", {}).get("text", "")
    if msg:
        # "in <package>" pattern
        parts = msg.lower().split(" in ")
        if len(parts) > 1:
            candidate = parts[-1].split()[0].strip(".,;:'\"()")
            if candidate and not candidate.startswith("/"):
                return str(candidate)

    return ""


def _extract_version(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    """Best-effort version extraction."""
    props = result.get("properties", {})

    for key in ("version", "packageVersion", "installedVersion"):
        val = props.get(key, "")
        if val:
            return str(val)

    if rule:
        rule_props = rule.get("properties", {})
        for key in ("version", "packageVersion", "installedVersion"):
            val = rule_props.get(key, "")
            if val:
                return str(val)

    return ""


def _extract_fix_version(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    """Best-effort fix version extraction."""
    props = result.get("properties", {})

    for key in ("fixVersion", "fixedVersion", "fix_version", "fixAvailable"):
        val = props.get(key, "")
        if val and isinstance(val, str):
            return val

    if rule:
        rule_props = rule.get("properties", {})
        for key in ("fixVersion", "fixedVersion", "fix_version"):
            val = rule_props.get(key, "")
            if val and isinstance(val, str):
                return val

    return ""


def _extract_severity(result: dict[str, Any], rule: dict[str, Any] | None) -> Severity | None:
    """Extract severity from SARIF level, CVSS score, or properties; None if absent."""
    props = result.get("properties", {})

    # CVSS score takes priority — it's the most precise
    for key in ("cvssScore", "cvss_score", "cvssV3Score"):
        score = props.get(key)
        if score is not None:
            try:
                return _severity_from_cvss(float(score))
            except (ValueError, TypeError):
                pass

    # Explicit severity in properties
    # security-severity is normally a CVSS score ("7.5"), sometimes a word.
    for key in ("severity", "security-severity"):
        value = props.get(key, "")
        try:
            return _severity_from_cvss(float(value))
        except (ValueError, TypeError):
            named = Severity.parse(value)
            if named is not None:
                return named

    # rule.properties may have security-severity (CodeQL pattern)
    if rule:
        rule_props = rule.get("properties", {})
        sec_sev = rule_props.get("security-severity", "")
        if sec_sev:
            try:
                return _severity_from_cvss(float(sec_sev))
            except (ValueError, TypeError):
                pass
        named = Severity.parse(rule_props.get("severity"))
        if named is not None:
            return named

    # SARIF level
    level = result.get("level", "")
    if level in _LEVEL_MAP:
        return _LEVEL_MAP[level]

    # rule.defaultConfiguration.level
    if rule:
        default_level = rule.get("defaultConfiguration", {}).get("level", "")
        if default_level in _LEVEL_MAP:
            return _LEVEL_MAP[default_level]

    return None


class SarifParser:
    """Parse SARIF v2.1.0 JSON input."""

    name = "sarif"

    @staticmethod
    def detect(project: Path) -> bool:
        """SARIF is never auto-detected — use ``--stdin`` with SARIF JSON."""
        return False

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        """Parse a SARIF document into Vulnerability objects.

        Iterates over all runs and all results, building a rule index per run
        so that result metadata can be supplemented from the rule definition.
        """
        vulns: list[Vulnerability] = []
        seen: set[str] = set()

        for run in audit_json.get("runs", []):
            # Build rule index: ruleId → rule object
            tool = run.get("tool", {})
            driver = tool.get("driver", {})
            rules_list = driver.get("rules", [])
            rules_by_id: dict[str, dict[str, Any]] = {}
            for rule_obj in rules_list:
                rid = rule_obj.get("id", "")
                if rid:
                    rules_by_id[rid] = rule_obj

            # Also index rules from extensions (CodeQL pattern)
            for ext in tool.get("extensions", []):
                for rule_obj in ext.get("rules", []):
                    rid = rule_obj.get("id", "")
                    if rid:
                        rules_by_id[rid] = rule_obj

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                # Resolve rule index if present
                rule_index = result.get("ruleIndex")
                rule: dict[str, Any] | None = None
                if rule_id and rule_id in rules_by_id:
                    rule = rules_by_id[rule_id]
                elif rule_index is not None and 0 <= rule_index < len(rules_list):
                    rule = rules_list[rule_index]

                cve = _extract_cve(result, rule)
                pkg = _extract_package(result, rule)
                version = _extract_version(result, rule)
                fix_version = _extract_fix_version(result, rule)
                measured = _extract_severity(result, rule)

                # Skip results with no identifiable package — we can't triage
                # what we can't match against the dependency tree
                if not pkg:
                    continue

                # Deduplicate by CVE:package
                key = f"{cve}:{pkg}"
                if key in seen:
                    continue
                seen.add(key)

                # Title from message or rule description
                title = result.get("message", {}).get("text", "")
                if not title and rule:
                    desc = rule.get("shortDescription", {})
                    title = desc.get("text", "")
                if not title and rule:
                    title = rule.get("name", cve)
                title = short_title(title, 200) if title else cve

                # URL from rule helpUri or result properties
                url = ""
                if rule:
                    url = rule.get("helpUri", "")
                if not url:
                    url = result.get("properties", {}).get("url", "")

                vulns.append(
                    Vulnerability(
                        cve=cve,
                        package=pkg,
                        version=version,
                        severity=measured or Severity.MODERATE,
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
        """SARIF must be piped via ``--stdin``; scan is a no-op."""
        return []


def code_findings(audit_json: dict[str, Any]) -> int:
    """How many SARIF results name no package: code findings (CodeQL, Semgrep).

    depquiet triages dependency alerts, so these are not read; the caller says
    so, instead of reporting a clean scan.
    """
    count = 0
    for run in audit_json.get("runs", []):
        if not isinstance(run, dict):
            continue
        rules_list = (run.get("tool", {}).get("driver", {}) or {}).get("rules", []) or []
        rules_by_id = {r.get("id"): r for r in rules_list if isinstance(r, dict)}
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            rule = rules_by_id.get(result.get("ruleId", ""))
            index = result.get("ruleIndex")
            if rule is None and isinstance(index, int) and 0 <= index < len(rules_list):
                rule = rules_list[index]
            if not _extract_package(result, rule):
                count += 1
    return count
