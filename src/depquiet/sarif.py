"""SARIF output — integrates with GitHub Code Scanning and VS Code.

SARIF (Static Analysis Results Interchange Format) is the universal format
for vulnerability findings. GitHub Code Scanning, VS Code, and most CI
tools can consume it.

We emit SARIF v2.1.0 with one run per scan. Each ACTION or REVIEW result
becomes a result; FILTERED items are omitted (that's the point).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from depquiet import __version__
from depquiet.assessment import assess_finding, decision_trace_to_json
from depquiet.models import ScanResult, TriageResult, Verdict


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to a SARIF v2.1.0 document."""
    if not result.scanned:
        raise ValueError("Cannot generate SARIF from an incomplete scan.")
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}

    actionable = [r for r in result.results if r.verdict != Verdict.FILTERED]

    for tr in actionable:
        vuln = tr.vuln
        rule_id = vuln.cve or f"{vuln.package}-{vuln.severity_label}"
        level = _level(tr)

        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rule: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": vuln.title or f"{vuln.package} {vuln.severity_label}"},
                "defaultConfiguration": {"level": level},
            }
            if vuln.url:
                rule["helpUri"] = vuln.url
            rules.append(rule)

        sarif_result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": level,
            "message": {
                "text": _build_message(tr),
            },
            "locations": _build_locations(
                tr, result.project_path, tr.vuln.package_manager or result.package_manager
            ),
            "properties": {
                "assessment": assess_finding(tr).to_dict(),
                "evidence": asdict(tr.evidence),
                "decision_trace": decision_trace_to_json(tr),
            },
        }

        if not vuln.severity_known:
            sarif_result["properties"]["severity"] = "unknown"
        if tr.epss_score is not None:
            sarif_result.setdefault("properties", {})["epss_score"] = tr.epss_score

        if tr.kev_entry is not None:
            props = sarif_result.setdefault("properties", {})
            props["kev"] = True
            props["kev_date_added"] = tr.kev_entry.date_added
            props["kev_due_date"] = tr.kev_entry.due_date
            props["kev_ransomware_use"] = tr.kev_entry.ransomware_use

        results.append(sarif_result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depquiet",
                        "version": __version__,
                        "informationUri": "https://github.com/samuelrojas-dev/depquiet",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(result: ScanResult, path: Path) -> None:
    """Write SARIF output to a file."""
    sarif = to_sarif(result)
    path.write_text(json.dumps(sarif, indent=2))


def _level(tr: TriageResult) -> str:
    """SARIF level; with no severity from the scanner, ACTION is an error.

    A placeholder must not turn an ACTION item into a warning that code
    scanning merge protection lets through (the --fail-on rule).
    """
    if tr.vuln.severity_known:
        return _severity_to_level(tr.vuln.severity.value)
    return "error" if tr.verdict == Verdict.ACTION else "warning"


def _severity_to_level(severity: str) -> str:
    """Map vulnerability severity to SARIF level."""
    return {
        "critical": "error",
        "high": "error",
        "moderate": "warning",
        "low": "note",
        "info": "note",
    }.get(severity, "warning")


def _build_message(tr: TriageResult) -> str:
    """Build a human-readable message for a SARIF result."""
    vuln = tr.vuln
    parts = [f"{vuln.package}@{vuln.version}: {vuln.title or vuln.cve}"]

    if vuln.fix_version:
        parts.append(f"Fix: update to {vuln.fix_label}")

    if tr.epss_score is not None:
        parts.append(f"EPSS: {tr.epss_score:.1%}")

    if tr.kev_entry is not None:
        parts.append("⚠ CISA KEV: actively exploited")

    if tr.verdict == Verdict.REVIEW:
        parts.append("Verdict: REVIEW")
    else:
        parts.append("Verdict: ACTION REQUIRED")

    parts.append("Product impact remains under investigation")

    return " | ".join(parts)


def _repo_prefix(project_path: str) -> str:
    """The scanned folder's path from the repository root ("" at the root).

    GitHub code scanning resolves SARIF paths from the repository root. With
    ``--path some/sub/project``, a path relative to the scanned folder
    ("app.js") pointed at a file that does not exist: the Action's own smoke
    test opened alerts on ``app.js:1`` for ``benchmarks/.../project/app.js``.
    The root is the nearest folder with ``.git``; without one, the working
    directory, when the project is inside it.
    """
    project = Path(project_path).resolve()
    for folder in (project, *project.parents):
        if (folder / ".git").exists():
            return "" if folder == project else project.relative_to(folder).as_posix()
    try:
        prefix = project.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return ""
    return "" if prefix == "." else prefix


def _join(prefix: str, rel: str) -> str:
    return f"{prefix}/{rel}" if prefix else rel


_MANIFESTS = {
    "npm": ["package.json"],
    "pnpm": ["package.json"],
    "pip": ["requirements.txt", "pyproject.toml"],
    "uv": ["pyproject.toml", "uv.lock"],
}


def _build_locations(
    tr: TriageResult,
    project_path: str,
    package_manager: str = "npm",
) -> list[dict[str, Any]]:
    """Build SARIF locations from reachable imports or package files, from the repo root."""
    locations: list[dict[str, Any]] = []
    prefix = _repo_prefix(project_path)

    for imp in tr.reachable_imports[:5]:
        path = Path(imp)
        try:
            # Imports carry the project path as it was given: trim it first.
            uri = _join(prefix, path.relative_to(project_path).as_posix())
        except ValueError:
            # Outside the project and absolute: kept as it is. Relative: from the project.
            uri = imp if path.is_absolute() else _join(prefix, path.as_posix())
        locations.append({"physicalLocation": {"artifactLocation": {"uri": uri}}})

    if not locations:
        # Default to the package manifest: the first one the project has.
        candidates = _MANIFESTS.get(package_manager, ["package.json"])
        manifest = next((m for m in candidates if (Path(project_path) / m).exists()), candidates[0])
        locations.append(
            {"physicalLocation": {"artifactLocation": {"uri": _join(prefix, manifest)}}}
        )

    return locations
