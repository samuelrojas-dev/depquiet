"""Scan engine — orchestrates parsers, filters, and triage verdicts.

The engine is the core of depquiet. It:
1. Detects the package manager
2. Runs the appropriate scanner
3. Applies all filters in order
4. Assigns a verdict to each vulnerability
5. Returns a ScanResult with the full triage

Filter order matters for the output (we show the FIRST reason that matched),
but not for correctness — a vulnerability is filtered if ANY filter matches.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from depquiet.cve_aliases import resolve_cve_aliases
from depquiet.depgraph import DependencyGraph
from depquiet.filters.devdep import DevDepFilter
from depquiet.filters.epss import EpssFilter
from depquiet.filters.reachability import ReachabilityDecision, ReachabilityFilter
from depquiet.filters.templates import Template, TemplateFilter
from depquiet.models import (
    DecisionChange,
    DependencyEvidence,
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
    WorkspaceEvidence,
)
from depquiet.parsers.dependabot import DependabotParser
from depquiet.parsers.grype import GrypeParser
from depquiet.parsers.npm import NpmAuditParser
from depquiet.parsers.osv import OsvScanner, parse_osv_response, query_osv_batch
from depquiet.parsers.pip import PipAuditParser
from depquiet.parsers.pnpm import PnpmAuditParser
from depquiet.parsers.sarif import SarifParser, code_findings
from depquiet.parsers.sbom import SbomParser, is_cyclonedx, is_spdx
from depquiet.parsers.snyk import SnykParser
from depquiet.parsers.trivy import TrivyParser
from depquiet.parsers.uv import UvAuditParser, adverse_note, is_uv_audit
from depquiet.policy import Policy
from depquiet.scanners import (
    ScanError,
    run_npm_audit,
    run_pip_audit,
    run_pnpm_audit,
    run_uv_audit,
)


def _osv_batch_query(
    packages: list[tuple[str, str, str]],
) -> list[Vulnerability]:
    """Query OSV.dev for vulnerabilities matching SBOM packages."""
    if not packages:
        return []
    vulns: list[Vulnerability] = []
    for start in range(0, len(packages), 1000):
        batch = packages[start : start + 1000]
        try:
            response = query_osv_batch(batch)
            vulns.extend(parse_osv_response(response, batch))
        except (OSError, ValueError) as e:
            raise ScanError(f"could not query OSV.dev for the SBOM ({e}).") from e
    return vulns


class _Parser(Protocol):
    """Structural type for audit parsers."""

    name: str

    @staticmethod
    def detect(project: Path) -> bool: ...

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]: ...

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]: ...


_PARSERS: list[type[_Parser]] = [
    NpmAuditParser,
    PnpmAuditParser,
    PipAuditParser,
    TrivyParser,
    DependabotParser,
    GrypeParser,
    SnykParser,
]


_SCANNER_ECOSYSTEM = {"npm": "npm", "pnpm": "npm", "pip": "python", "uv": "python"}


_NATIVE_SCANNERS: dict[str, type[_Parser]] = {
    "npm": NpmAuditParser,
    "pnpm": PnpmAuditParser,
    "pip": PipAuditParser,
}


def _unscanned_note(project: Path, pm: str | None) -> str:
    """Say which other ecosystem this run leaves out, never silently.

    One run audits one package manager. A repository with a web client and a
    Python service has two dependency sets, and a clean npm report says
    nothing about the other.
    """
    if pm not in _NATIVE_SCANNERS:
        return ""
    others = [
        name
        for name, parser in _NATIVE_SCANNERS.items()
        if _SCANNER_ECOSYSTEM[name] != _SCANNER_ECOSYSTEM[pm] and parser.detect(project)
    ]
    if not others:
        return ""
    labels = {"npm": "npm", "pnpm": "pnpm", "pip": "Python"}
    return (
        f"Only {labels[pm]} dependencies were scanned. This project also declares "
        + " and ".join(labels[name] for name in others)
        + " dependencies; scan them with "
        + " / ".join(f"--scanner {name}" for name in others)
        + "."
    )


def _native_scanners(project: Path) -> list[str]:
    """One native scanner per ecosystem the project declares, in detection order."""
    chosen: dict[str, str] = {}
    for name, parser in _NATIVE_SCANNERS.items():
        ecosystem = _SCANNER_ECOSYSTEM[name]
        if ecosystem not in chosen and parser.detect(project):
            chosen[ecosystem] = name
    # npm and pnpm share an ecosystem: a pnpm lockfile without an npm one is pnpm.
    if chosen.get("npm") == "npm" and not NpmAuditParser.detect(project):
        chosen["npm"] = "pnpm"
    return list(chosen.values())


_LABELS = {"npm": "npm", "pnpm": "pnpm", "pip": "Python", "uv": "Python"}


def _scan_each(project: Path, scanners: list[str], **options: Any) -> ScanResult:
    """Scan each ecosystem on its own and merge the reports.

    Every finding keeps the package manager that reported it, so fixes,
    manifests and finding identities stay per ecosystem. An ecosystem that
    could not be scanned is named in the note; the merged report counts as
    scanned only when at least one ecosystem was, and never hides the other.
    """
    parts = [(name, scan(project, scanner=name, **options)) for name in scanners]
    results: list[TriageResult] = []
    notes: list[str] = []
    failed: list[str] = []
    for name, part in parts:
        for finding in part.results:
            finding.vuln.package_manager = name
            results.append(finding)
        own = _strip_unscanned_note(part.note)
        if not part.scanned:
            failed.append(f"{_LABELS[name]} dependencies were not scanned: {own}")
        elif own:
            notes.append(f"{_LABELS[name]}: {own}")
    scanned = [name for name, part in parts if part.scanned]
    return ScanResult(
        project_path=str(project),
        package_manager="+".join(scanned or scanners),
        total_dependencies=sum(part.total_dependencies for _, part in parts),
        results=results,
        scanned=bool(scanned),
        note=" ".join(failed + notes),
    )


def _strip_unscanned_note(note: str) -> str:
    """Drop "Only X was scanned ... --scanner" sentences: the merged run did scan it."""
    return re.sub(r"\s*Only \S+ dependencies were scanned\..*?--scanner [^.]*\.", "", note).strip()


def detect_package_manager(project: Path) -> str | None:
    """Auto-detect the project's package manager."""
    for parser in _PARSERS:
        if parser.detect(project):
            return parser.name
    return None


def scan(
    project: Path,
    *,
    epss_threshold: float | None = None,
    skip_epss: bool = False,
    template_dirs: list[Path] | None = None,
    audit_json: dict[str, Any] | None = None,
    always_flag: list[str] | None = None,
    policy: Policy | None = None,
    scanner: str | None = None,
) -> ScanResult:
    """Run a full triage scan on a project.

    Args:
        project: Path to the project root.
        epss_threshold: Filter alerts whose EPSS score is below this; None (default)
            keeps every alert and uses EPSS only to order the report.
        skip_epss: Don't query the EPSS API (fully offline mode).
        template_dirs: Extra directories to load community templates from.
        audit_json: Pre-parsed audit JSON (for testing / piped input).
        scanner: Native scanner to run ("npm" or "pip") instead of the first
            one detected, for projects with more than one ecosystem.

    Returns:
        ScanResult with all vulnerabilities and their triage verdicts.
    """
    # A project with npm and Python dependencies gets one run per ecosystem,
    # each triaged against its own graph, merged into one report.
    if scanner is None and audit_json is None:
        found = _native_scanners(project)
        if len(found) > 1:
            return _scan_each(
                project,
                found,
                epss_threshold=epss_threshold,
                skip_epss=skip_epss,
                template_dirs=template_dirs,
                always_flag=always_flag,
                policy=policy,
            )

    # Step 1: Detect and parse
    pm = scanner or detect_package_manager(project)
    unscanned = "" if audit_json is not None else _unscanned_note(project, pm)
    if pm is None and audit_json is None:
        # No native scanner detected — try OSV.dev lockfile scanning
        if not skip_epss and OsvScanner.detect(project):
            pm = "osv"
        else:
            if OsvScanner.detect(project):
                note = (
                    "found a lockfile, but scanning it queries OSV.dev and --offline is set. "
                    "Drop --offline, or pipe in scanner output with --stdin."
                )
            else:
                note = (
                    f"no supported manifest or lockfile in {project}. Run depquiet in a "
                    "project directory, pass --path, or pipe in scanner output with --stdin."
                )
            return ScanResult(
                project_path=str(project),
                package_manager="unknown",
                total_dependencies=0,
                results=[],
                scanned=False,
                note=note,
            )

    vulns: list[Vulnerability] = []
    scan_note = ""
    if audit_json is not None:
        # Use provided JSON (piped input or testing)
        # Auto-detect format — check SBOMs first, then scanner outputs
        if is_cyclonedx(audit_json) or is_spdx(audit_json):
            pm = pm or "sbom"
            vulns = SbomParser.parse(audit_json, project)
            if not vulns:
                # SBOM has no vulnerability data — extract packages
                # and query OSV.dev for advisories
                packages = SbomParser.extract_packages(audit_json)
                if not packages or skip_epss:
                    note = (
                        "SBOM has no embedded vulnerabilities and querying its packages "
                        "requires OSV.dev; --offline is set."
                        if skip_epss and packages
                        else "SBOM has no embedded vulnerabilities or readable packages to scan."
                    )
                    return ScanResult(str(project), pm, 0, [], scanned=False, note=note)
                try:
                    vulns = _osv_batch_query(packages)
                except ScanError as e:
                    return ScanResult(str(project), pm, 0, [], scanned=False, note=str(e))
        elif "runs" in audit_json and (
            "$schema" in audit_json or audit_json.get("version") == "2.1.0"
        ):
            vulns = SarifParser.parse(audit_json, project)
            skipped = code_findings(audit_json)
            if skipped:
                what = "1 SARIF result names" if skipped == 1 else f"{skipped} SARIF results name"
                scan_note = (
                    f"{what} no package: code findings (CodeQL, Semgrep and similar tools), "
                    "which depquiet does not triage. Review them in the tool that reported them."
                )
                if not vulns:
                    return ScanResult(
                        str(project), pm or "sarif", 0, [], scanned=False, note=scan_note
                    )
        elif "Results" in audit_json:
            vulns = TrivyParser.parse(audit_json, project)
        elif "matches" in audit_json:
            vulns = GrypeParser.parse(audit_json, project)
        elif "alerts" in audit_json:
            vulns = DependabotParser.parse(audit_json, project)
        elif "packageManager" in audit_json and isinstance(audit_json.get("vulnerabilities"), list):
            vulns = SnykParser.parse(audit_json, project)
        elif is_uv_audit(audit_json):
            pm = "uv"
            vulns = UvAuditParser.parse(audit_json, project)
            scan_note = adverse_note(audit_json)
        elif isinstance(audit_json.get("dependencies"), list):
            pm = "pip"
            vulns = PipAuditParser.parse(audit_json, project)
        elif isinstance(audit_json.get("vulnerabilities"), dict):
            pm = "npm"
            vulns = NpmAuditParser.parse(audit_json, project)
        elif isinstance(audit_json.get("advisories"), dict):
            # pnpm audit, and the npm v6 report it inherited the layout from.
            pm = "pnpm" if PnpmAuditParser.detect(project) else "npm"
            vulns = PnpmAuditParser.parse(audit_json, project)
        else:
            return ScanResult(
                str(project),
                pm or "unknown",
                0,
                [],
                scanned=False,
                note="unrecognized scanner JSON format; no vulnerability report was read.",
            )
    else:
        try:
            vulns, pm, scan_note = _run_scanner(pm, project, offline=skip_epss)
        except ScanError as e:
            return ScanResult(
                project_path=str(project),
                package_manager=pm or "unknown",
                total_dependencies=0,
                results=[],
                scanned=False,
                note=str(e),
            )

    scan_note = " ".join(part for part in (scan_note, unscanned) if part)
    if not vulns:
        return ScanResult(
            project_path=str(project),
            package_manager=pm or "unknown",
            total_dependencies=0,
            results=[],
            note=scan_note,
        )

    # Step 2: Initialize filters
    # A native scanner reports one ecosystem; paths through another ecosystem's
    # lockfile say nothing about its packages. Multi-ecosystem inputs (SBOM,
    # Trivy, OSV) keep the merged graph.
    graph = DependencyGraph.from_project(project, ecosystem=_SCANNER_ECOSYSTEM.get(pm or ""))
    contexts = _project_contexts(project, graph)
    epss_filter = EpssFilter(threshold=epss_threshold)
    template_filter = TemplateFilter(template_dirs=template_dirs)

    # Step 3: Batch EPSS lookup (one API call for all CVEs)
    # npm audit names advisories by GHSA id only: find their CVE ids first, or
    # EPSS and KEV never apply to npm projects.
    cve_lookups_failed = 0
    if not skip_epss:
        cve_lookups_failed = resolve_cve_aliases(vulns)
    if not skip_epss:
        all_cves = [v.cve_id for v in vulns if v.cve_id]
        epss_filter.lookup(all_cves)

    # Step 4: Triage each vulnerability
    results: list[TriageResult] = []
    for vuln in vulns:
        reasons: list[FilterReason] = []
        epss_score = None
        epss_percentile = None
        template_id = None
        template_reason = None
        evaluation = _evaluate_dependency(vuln, contexts, graph)
        decision = evaluation.decision
        evidence = evaluation.evidence

        # Skip all filters if package is in always_flag
        # Names compare the way package managers do: ``Django`` in the config
        # must protect ``django`` from the scanner, and ``PyYAML`` ``pyyaml``.
        _always = {_flag_key(name) for name in always_flag or []}
        if _flag_key(vuln.package) in _always:
            _epss = epss_filter.get_score(vuln.cve_id)
            results.append(
                TriageResult(
                    vuln=vuln,
                    verdict=Verdict.ACTION,
                    reasons=[],
                    epss_score=_epss[0] if _epss else None,
                    epss_percentile=_epss[1] if _epss else None,
                    reachable_imports=list(evidence.import_sites),
                    dependency_type=decision.dependency_type,
                    introduced_by=decision.introduced_by,
                    evidence=evidence,
                    decision_trace=[
                        DecisionChange(
                            source="always_flag",
                            previous_verdict=None,
                            verdict=Verdict.ACTION,
                            rule_id=vuln.package,
                            reason="Package is configured to always require action.",
                        )
                    ],
                )
            )
            continue

        # Filter 2 runs first because filter 1 uses its dependency paths.
        # Transitive packages are judged by the direct dependencies that pull
        # them in, never by the app's own imports.
        # A package may be declared as dev and also be required by a production
        # dependency. Every known root must be dev-only before suppressing it.
        if evaluation.dev_only:
            reasons.append(FilterReason.DEV_DEPENDENCY)
        elif _locked_for_development_only(vuln) and not _stale_dev_lock(vuln, graph):
            reasons.append(FilterReason.DEV_DEPENDENCY)
            note = (
                "The scanner reports every affected installed version as reached "
                "only from development dependencies; a production install omits them."
                if vuln.scanner_dev_only
                else "The lockfile marks every locked copy in the advisory range as "
                "development-only; a production install omits them."
            )
            if note not in evidence.observations:
                evidence.observations.insert(0, note)

        # A production dependency the project declares but never imports is
        # not proof of anything: frameworks and libraries load packages they
        # do not declare (Django database drivers, transformers' accelerate,
        # an ORM's dialect package). Without an edge in the lockfile that is
        # invisible, so it is shown for review, never dismissed.
        # The same holds for what such a dependency brings in: if uvicorn is
        # started from the command line, h11 parses every request, though
        # neither is imported. A transitive package reached only through
        # production dependencies the project never imports is kept too.
        declared_unused = (
            decision.unreachable
            and decision.dependency_type in ("direct", "transitive")
            and FilterReason.DEV_DEPENDENCY not in reasons
        )
        # Imported only from tests is not proof that production never loads it:
        # an ORM loads its database driver from a dialect name (Sequelize,
        # TypeORM, Knex -> pg), Next.js loads sharp, PyJWT loads cryptography.
        # Without a test the same package is kept for review, so adding a test
        # must not hide it. Shown for review, never dismissed.
        tested_only = (
            decision.test_only
            and not decision.unreachable
            and FilterReason.DEV_DEPENDENCY not in reasons
        )
        if decision.unreachable and not declared_unused:
            reasons.append(FilterReason.UNREACHABLE)
        if tested_only:
            note = (
                "Imported only from test code. A production dependency can still be "
                "loaded at runtime by another library (an ORM's database driver, an image "
                "processor, a crypto backend) without any import naming it, so it is kept "
                "for review."
            )
            if note not in evidence.observations:
                evidence.observations.insert(0, note)
        if declared_unused:
            note = (
                "Declared as a production dependency but never imported by the project. "
                "Another library may load it at runtime (database drivers, optional "
                "accelerators, plugins named in settings), which no lockfile records, "
                "so it is kept for review."
                if decision.dependency_type == "direct"
                else "Comes in only through production dependencies the project declares "
                "but never imports. Those may still run (a server started from the command "
                "line, a plugin named in settings), so it is kept for review."
            )
            if note not in evidence.observations:
                evidence.observations.insert(0, note)

        # Filter 3: Low EPSS score
        epss_data = epss_filter.get_score(vuln.cve_id)
        if epss_data:
            epss_score, epss_percentile = epss_data
        if epss_filter.check(vuln):
            reasons.append(FilterReason.LOW_EPSS)

        # Filter 4: Community template match
        tmpl = _find_context_template(template_filter, vuln, evaluation, graph)
        if tmpl and tmpl.not_imported and (declared_unused or tested_only):
            # A conditional template matches only when nothing imports the
            # package: the case kept above because another library may load
            # it (requests loads certifi on every HTTPS call). Its note is
            # context for the review, not a dismissal.
            note = f"Community template {tmpl.id}: {tmpl.reason}"
            if note not in evidence.observations:
                evidence.observations.append(note)
        elif tmpl:
            reasons.append(FilterReason.COMMUNITY_TEMPLATE)
            template_id = tmpl.id
            template_reason = tmpl.reason

        # Determine verdict
        if reasons:
            verdict = Verdict.FILTERED
        elif declared_unused or tested_only or vuln.severity in (Severity.LOW, Severity.INFO):
            verdict = Verdict.REVIEW
        else:
            verdict = Verdict.ACTION

        trace = [
            DecisionChange(
                source="engine",
                previous_verdict=None,
                verdict=verdict,
                reason=", ".join(r.value for r in reasons) or "No automatic filter matched.",
            )
        ]
        # Apply policy override (first matching rule wins)
        policy_id = None
        if policy is not None:
            # Create a temporary TriageResult for policy matching
            _temp = TriageResult(
                vuln=vuln,
                verdict=verdict,
                reasons=reasons,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
            )
            policy_verdict, policy_id = policy.apply(_temp)
            if policy_id is not None:
                rule = next(r for r in policy.rules if r.id == policy_id and r.matches(_temp))
                trace.append(
                    DecisionChange(
                        source="policy",
                        previous_verdict=verdict,
                        verdict=policy_verdict,
                        rule_id=policy_id,
                        reason=rule.reason or rule.description,
                        path=policy.path,
                    )
                )
                verdict = policy_verdict

        # Preserve observed import sites for every priority, before suppression.
        reachable_imports = list(evidence.import_sites)

        results.append(
            TriageResult(
                vuln=vuln,
                verdict=verdict,
                reasons=reasons,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                reachable_imports=reachable_imports,
                template_id=template_id,
                template_reason=template_reason,
                dependency_type=decision.dependency_type,
                introduced_by=decision.introduced_by,
                evidence=evidence,
                decision_trace=trace,
            )
        )

    # Sort: ACTION first, then REVIEW, then FILTERED
    order = {Verdict.ACTION: 0, Verdict.REVIEW: 1, Verdict.FILTERED: 2}
    rank = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MODERATE: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    results.sort(
        key=lambda r: (order[r.verdict], rank[r.vuln.severity] if r.vuln.severity_known else 2)
    )

    return ScanResult(
        project_path=str(project),
        package_manager=pm or "unknown",
        total_dependencies=len(set(v.package for v in vulns)),
        results=results,
        note=scan_note,
        cve_lookups_failed=cve_lookups_failed,
        epss_lookups_failed=epss_filter.failed,
    )


def _run_scanner(
    pm: str | None, project: Path, *, offline: bool
) -> tuple[list[Vulnerability], str, str]:
    """Run the detected scanner; fall back to OSV.dev lockfile scanning.

    Returns (vulnerabilities, scanner used, note). Raises ScanError when no
    scanner could produce a report, so the caller reports "not scanned"
    instead of "no vulnerabilities".
    """
    runners = {
        "npm": (run_npm_audit, NpmAuditParser.parse, "npm audit"),
        "pip": (run_pip_audit, PipAuditParser.parse, "pip-audit"),
        "pnpm": (run_pnpm_audit, PnpmAuditParser.parse, "pnpm audit"),
        "uv": (run_uv_audit, UvAuditParser.parse, "uv audit"),
    }
    if pm in runners:
        run, parse, label = runners[pm]
        try:
            report = run(project)
            extra = report.get("depquiet_notes") if isinstance(report, dict) else None
            note = " ".join(n for n in extra if isinstance(n, str)) if extra else ""
            if pm == "uv":
                note = " ".join(part for part in (note, adverse_note(report)) if part)
            return parse(report, project), str(pm), note
        except ScanError as e:
            first = _sentence(f"{label}: {e}")
        # A uv project often has uv and no pip-audit: uv audit reads the same lock.
        if (
            pm == "pip"
            and shutil.which("pip-audit") is None
            and shutil.which("uv")
            and (project / "uv.lock").exists()
        ):
            try:
                report = run_uv_audit(project)
                note = f"{first} Audited uv.lock with uv audit instead."
                note = " ".join(part for part in (note, adverse_note(report)) if part)
                return UvAuditParser.parse(report, project), "uv", note
            except ScanError as e:
                first = _sentence(f"{first} uv audit: {e}")
        if offline or not OsvScanner.detect(project):
            hint = " OSV.dev fallback is disabled by --offline." if offline else ""
            raise ScanError(
                f"{first}{hint} You can also pipe a scanner's JSON in with --stdin."
            ) from None
        try:
            vulns = OsvScanner.scan_checked(project)
        except ScanError as e:
            raise ScanError(f"{first} OSV.dev fallback failed too: {e}") from None
        return vulns, "osv", f"{first} Scanned lockfiles with OSV.dev instead."
    if pm == "osv":
        return OsvScanner.scan_checked(project), "osv", ""
    raise ScanError(f"no scanner available for {pm or 'this project'}.")


def _sentence(text: str) -> str:
    """``text`` ending with a period, so the next sentence does not run into it."""
    text = text.rstrip()
    return text if text.endswith((".", "!", "?")) else text + "."


def _locked_for_development_only(vuln: Vulnerability) -> bool:
    """Every reported copy the advisory can apply to is a dev-only install.

    Decided per locked copy, from the package manager's own resolution, so it
    holds when a production copy of the same name exists at an unaffected
    version, and does not depend on the name-level graph being complete.
    """
    if vuln.scanner_dev_only:
        return True
    if not vuln.component_resolution_complete:
        return False
    affected = [c for c in vuln.components if c.range_match != "not_matched"]
    return bool(affected) and all(c.lock_scope == "development" for c in affected)


def _stale_dev_lock(vuln: Vulnerability, graph: DependencyGraph) -> bool:
    """The lockfile marks the top-level copy dev-only, but a manifest declares
    the package for production: the lockfile predates the manifest.

    A nested copy (``node_modules/jest/node_modules/uuid``) is a different
    install and keeps its own scope.
    """
    if vuln.scanner_dev_only or not graph.declared_for_production(vuln.package):
        return False
    top = f"node_modules/{vuln.package}"
    return any(
        c.range_match != "not_matched"
        and c.location.replace("\\", "/").endswith(top)
        and c.location.replace("\\", "/").count("node_modules/") == 1
        for c in vuln.components
    )


def _import_sites(
    reachability: ReachabilityFilter, vuln: Vulnerability, decision: ReachabilityDecision
) -> list[str]:
    """Where the vulnerable package enters the app: its own imports, or for a
    transitive package, the imports of the direct dependencies that pull it in."""
    sites = reachability.named_imports_for(vuln.package)
    for ancestor in decision.imported_ancestors:
        found = reachability.named_imports_for(ancestor)
        sites += [s for s in found if s not in sites]
    return sites


def _guessed_only(
    reachability: ReachabilityFilter, vuln: Vulnerability, decision: ReachabilityDecision
) -> list[str]:
    """Packages kept on a module-name guess, with no import that names them."""
    return [
        name
        for name in dict.fromkeys([vuln.package, *decision.imported_ancestors])
        if reachability.find_imports_for(name) and not reachability.named_imports_for(name)
    ]


def _collect_evidence(
    reachability: ReachabilityFilter,
    vuln: Vulnerability,
    graph: DependencyGraph,
    decision: ReachabilityDecision,
) -> DependencyEvidence:
    """Capture observed usage without asserting vulnerable code execution."""
    sites = _import_sites(reachability, vuln, decision)
    used = bool(sites or decision.imported_ancestors) or reachability.is_used(vuln.package, graph)
    coverage_complete = reachability.analysis_coverage_complete and graph.coverage_complete
    usage = (
        "observed"
        if used
        else "not_observed"
        if decision.unreachable and coverage_complete
        else "unknown"
    )
    observations: list[str] = []
    if decision.imported_ancestors:
        observations.append(
            "Project references dependency roots: " + ", ".join(decision.imported_ancestors) + "."
        )
    if graph.is_executed(vuln.package):
        observations.append("Project commands reference this dependency's executable.")
    guessed = _guessed_only(reachability, vuln, decision)
    if guessed:
        observations.append(
            "No import names "
            + ", ".join(guessed)
            + " directly; the project imports a module with the same name prefix, which "
            "this package may or may not provide. Kept. Installing the project's "
            "dependencies where depquiet runs lets it read the real module names."
        )
    if used and not sites:
        observations.append("Usage is inferred from project references, not a verified call path.")
    if decision.unreachable:
        observations.append("No dependency usage was observed in the inspected project sources.")
    if decision.test_only:
        observations.append(
            "Every import found is in test code or test-runner configuration; "
            "no use was observed in application sources."
        )
    observations.extend(graph.coverage_observations)
    observations.extend(reachability.analysis_coverage_observations)
    observations.extend(reachability.dynamic_import_observations)
    return DependencyEvidence(
        usage=usage,
        import_sites=sites,
        observations=list(dict.fromkeys(observations)),
        graph_coverage_complete=graph.coverage_complete,
        analysis_coverage_complete=reachability.analysis_coverage_complete,
    )


@dataclass
class _ProjectContext:
    scope: str
    project: Path
    graph: DependencyGraph
    source: ReachabilityFilter


@dataclass
class _ContextEvaluation:
    context: _ProjectContext
    decision: ReachabilityDecision
    evidence: DependencyEvidence
    dev_only: bool
    relevance: str


@dataclass
class _DependencyEvaluation:
    decision: ReachabilityDecision
    evidence: DependencyEvidence
    dev_only: bool
    contexts: list[_ContextEvaluation]


def _project_contexts(project: Path, graph: DependencyGraph) -> list[_ProjectContext]:
    if not graph.workspace_graphs:
        return [_ProjectContext(".", project, graph, ReachabilityFilter(project))]
    project = project.resolve()
    roots = {scope: project / scope for scope in graph.workspace_graphs}
    contexts = []
    for scope, local in sorted(graph.workspace_graphs.items()):
        root = roots[scope]
        excluded = [
            other for name, other in roots.items() if name != scope and other.is_relative_to(root)
        ]
        contexts.append(
            _ProjectContext(scope, root, local, ReachabilityFilter(root, exclude_roots=excluded))
        )
    return contexts


def _flag_key(name: str) -> str:
    """Case- and separator-insensitive package name (PEP 503; npm names are lowercase)."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _evaluate_dependency(
    vuln: Vulnerability, contexts: list[_ProjectContext], graph: DependencyGraph
) -> _DependencyEvaluation:
    """Judge each workspace independently, then retain any used/uncertain context.

    Scanner findings are not bound to an individual workspace installation.
    Selection therefore uses conservative name relationships and observations;
    no candidate version/location is silently assigned to only one workspace.
    """
    evaluated = []
    for context in contexts:
        local, source = context.graph, context.source
        decision = source.decide(vuln, local)
        evidence = _collect_evidence(source, vuln, local, decision)
        roots = list(decision.introduced_by)
        known = local.directness(vuln.package)
        if known == "direct":
            roots.append(vuln.package)
        complete = local.coverage_complete and source.analysis_coverage_complete
        dev_only = local.coverage_complete and (
            local.is_dev_only(roots)
            or (not graph.workspace_graphs and DevDepFilter.check(vuln) and not roots)
        )
        relevance = (
            "dependency"
            if known != "unknown" or roots
            else "observed"
            if evidence.usage == "observed"
            else "uncertain"
            if not complete
            else "not_declared"
        )
        evaluated.append(_ContextEvaluation(context, decision, evidence, dev_only, relevance))
    if not graph.workspace_graphs:
        only = evaluated[0]
        return _DependencyEvaluation(only.decision, only.evidence, only.dev_only, evaluated)

    selected = [item for item in evaluated if item.relevance != "not_declared"]
    # An incomplete member/discovery can conceal a production path for any
    # report row. Local positive evidence is retained, but absence cannot win.
    graph_complete = graph.coverage_complete and all(
        item.context.graph.coverage_complete for item in evaluated
    )
    analysis_complete = all(item.context.source.analysis_coverage_complete for item in evaluated)
    unreachable = (
        bool(selected)
        and graph_complete
        and analysis_complete
        and all(item.decision.unreachable for item in selected)
    )
    types = {item.decision.dependency_type for item in selected}
    kind = "direct" if "direct" in types else "transitive" if "transitive" in types else "unknown"
    decision = ReachabilityDecision(
        unreachable=unreachable,
        dependency_type=kind,
        introduced_by=sorted({name for item in selected for name in item.decision.introduced_by}),
        imported_ancestors=sorted(
            {name for item in selected for name in item.decision.imported_ancestors}
        ),
        # Every relevant workspace must agree; a mix proves nothing here.
        test_only=bool(selected)
        and graph_complete
        and analysis_complete
        and all(item.decision.test_only for item in selected),
    )
    sites = sorted({site for item in selected for site in item.evidence.import_sites})
    usage = (
        "observed"
        if any(item.evidence.usage == "observed" for item in selected)
        else "not_observed"
        if unreachable
        else "unknown"
    )
    observations = [
        "Declared workspaces were analyzed independently; finding associations use dependency "
        "names, not a verified workspace installation or vulnerable call path.",
        *graph.coverage_observations,
    ]
    for item in evaluated:
        observations.extend(
            f"Workspace {item.context.scope}: {note}" for note in item.evidence.observations
        )
    evidence = DependencyEvidence(
        usage=usage,
        import_sites=sites,
        observations=list(dict.fromkeys(observations)),
        graph_coverage_complete=graph_complete,
        analysis_coverage_complete=analysis_complete,
        workspace_contexts=[
            WorkspaceEvidence(
                path=item.context.scope,
                relevance=item.relevance,
                dependency_type=item.decision.dependency_type,
                usage=item.evidence.usage,
                dev_only=item.dev_only,
                graph_coverage_complete=item.context.graph.coverage_complete,
                analysis_coverage_complete=item.context.source.analysis_coverage_complete,
                introduced_by=list(item.decision.introduced_by),
                import_sites=list(item.evidence.import_sites),
                observations=list(item.evidence.observations),
            )
            for item in evaluated
        ],
    )
    # Development-only is a property of declarations, as in ``npm --omit=dev``:
    # a member that uses a package it does not declare gets it from another
    # member's install. Every member that does declare it, directly or through
    # a dependency, must reach it only from development dependencies.
    declared = [item for item in selected if item.relevance == "dependency"]
    dev_only = bool(declared) and graph_complete and all(item.dev_only for item in declared)
    return _DependencyEvaluation(decision, evidence, dev_only, evaluated)


def _find_context_template(
    templates: TemplateFilter,
    vuln: Vulnerability,
    evaluation: _DependencyEvaluation,
    graph: DependencyGraph,
) -> Template | None:
    first = evaluation.contexts[0].context
    if not graph.workspace_graphs:
        return templates.find_match(
            vuln.ids, vuln.package, project=first.project, graph=graph, reachability=first.source
        )
    explicit = templates.find_match(vuln.ids, vuln.package, allow_conditional=False)
    if explicit is not None:
        return explicit
    selected = [item for item in evaluation.contexts if item.relevance != "not_declared"]
    if (
        not selected
        or not evaluation.evidence.graph_coverage_complete
        or not evaluation.evidence.analysis_coverage_complete
    ):
        return None
    matches = [
        templates.find_match(
            vuln.ids,
            vuln.package,
            project=item.context.project,
            graph=item.context.graph,
            reachability=item.context.source,
        )
        for item in selected
    ]
    match = matches[0]
    return (
        match
        if match is not None and all(item and item.id == match.id for item in matches)
        else None
    )
