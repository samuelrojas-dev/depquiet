"""Data models for vulnerability findings and triage verdicts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_str(cls, s: str) -> Severity:
        return cls(s.lower()) if s.lower() in cls._value2member_map_ else cls.MODERATE

    @classmethod
    def parse(cls, s: object) -> Severity | None:
        """The severity a scanner stated, or None when it stated none.

        "unknown", an empty value or anything unrecognized is None: such an
        alert is stored as MODERATE with ``severity_known=False``, and nothing
        may treat that placeholder as a measured severity.
        """
        word = str(s or "").strip().lower()
        if word in cls._value2member_map_:
            return cls(word)
        return _SEVERITY_SYNONYMS.get(word)


# Words scanners use for the same levels. "negligible" (Grype) is below low.
_SEVERITY_SYNONYMS = {
    "medium": Severity.MODERATE,
    "informational": Severity.INFO,
    "negligible": Severity.INFO,
}


class Verdict(Enum):
    """Remediation priority, independent of proven product impact."""

    ACTION = "action"  # Fix this now
    REVIEW = "review"  # Worth looking at, not urgent
    FILTERED = "filtered"  # Deprioritized or suppressed; impact remains unverified


class FilterReason(Enum):
    """Why a vulnerability was filtered out."""

    UNREACHABLE = "unreachable"
    # Imported, but only from test files and test-runner configuration.
    TEST_ONLY = "test_only"
    DEV_DEPENDENCY = "dev_dependency"
    LOW_EPSS = "low_epss"
    COMMUNITY_TEMPLATE = "community_template"
    IGNORED = "ignored"


@dataclass
class ComponentEvidence:
    """A lockfile-resolved candidate, not an observed runtime installation.

    ``range_match`` is matched, not_matched or unknown against an advisory
    range. It never establishes product impact or actual execution.
    """

    ecosystem: str
    package: str
    version: str
    location: str
    lockfile: str
    lockfile_sha256: str
    range_match: str = "unknown"
    reason: str = ""
    # "development" when the lockfile marks this copy as installed only for
    # devDependencies (npm's ``dev`` flag), "production" otherwise, "" unknown.
    lock_scope: str = ""

    @property
    def instance_id(self) -> str:
        identity = {
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "location": self.location,
            "lockfile": self.lockfile,
        }
        raw = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "component-sha256:" + hashlib.sha256(raw).hexdigest()

    def to_dict(self) -> dict[str, str]:
        data = {
            "instance_id": self.instance_id,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "location": self.location,
            "lockfile": self.lockfile,
            "lockfile_sha256": self.lockfile_sha256,
            "range_match": self.range_match,
            "reason": self.reason,
        }
        if self.lock_scope:
            data["lock_scope"] = self.lock_scope
        return data

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ComponentEvidence:
        fields = ("ecosystem", "package", "version", "location", "lockfile", "lockfile_sha256")
        if not isinstance(raw, dict) or any(
            not isinstance(raw.get(name), str) or not raw[name] for name in fields
        ):
            raise ValueError("Invalid component evidence: nonempty string fields are required")
        if re.fullmatch(r"[a-fA-F0-9]{64}", raw["lockfile_sha256"]) is None:
            raise ValueError("Invalid component evidence: lockfile SHA-256 is required")
        match = raw.get("range_match", "unknown")
        if not isinstance(match, str) or match not in {"matched", "not_matched", "unknown"}:
            raise ValueError("Invalid component evidence: unknown range-match status")
        reason = raw.get("reason", "")
        if not isinstance(reason, str):
            raise ValueError("Invalid component evidence: reason must be a string")
        lock_scope = raw.get("lock_scope", "")
        if lock_scope not in {"", "development", "production"}:
            raise ValueError("Invalid component evidence: unknown lock scope")
        component = cls(
            ecosystem=raw["ecosystem"],
            package=raw["package"],
            version=raw["version"],
            location=raw["location"],
            lockfile=raw["lockfile"],
            lockfile_sha256=raw["lockfile_sha256"],
            range_match=match,
            reason=reason,
            lock_scope=lock_scope,
        )
        if "instance_id" in raw and raw["instance_id"] != component.instance_id:
            raise ValueError("Invalid component evidence: instance ID conflicts with its fields")
        return component


# C0 controls except tab and newline, DEL and C1 controls: what terminals act on.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


_WEB_URL = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)


def strip_control(text: str) -> str:
    """``text`` without the control characters a terminal would interpret."""
    return _CONTROL.sub("", text)


def clip(text: str, limit: int) -> str:
    """``text`` cut to ``limit`` characters, marked with … when cut."""
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def first_items(items: list[str], shown: int) -> str:
    """The first ``shown`` items, then how many more: a cut list never looks complete."""
    more = len(items) - shown
    return ", ".join(items[:shown]) + (f" and {more} more" if more > 0 else "")


@dataclass
class Vulnerability:
    """A single vulnerability finding from a scanner."""

    cve: str
    package: str
    version: str
    severity: Severity
    title: str = ""
    url: str = ""
    fix_version: str = ""
    # Package to upgrade to get ``fix_version`` when it isn't this package
    # (npm audit: the fix for a transitive package is often a new version of
    # the direct dependency that pulls it in). Empty means this package.
    fix_package: str = ""
    # Which functions in the package are vulnerable (from advisory)
    vulnerable_functions: list[str] = field(default_factory=list)
    # Whether it's a direct or transitive dependency
    is_direct: bool = True
    # Whether it's a devDependency
    is_dev: bool = False
    # Depth in dependency tree (0 = direct)
    depth: int = 0
    # Preserve the scanner's legacy version field while separately identifying
    # ranges and resolved lockfile candidates. Never infer an installed version.
    version_kind: str = "reported"
    advisory_range: str = ""
    components: list[ComponentEvidence] = field(default_factory=list)
    component_notes: list[str] = field(default_factory=list)
    component_resolution_complete: bool = False
    # Package manager whose scanner reported this finding ("npm", "pip"...),
    # set when one scan covers several ecosystems; "" means the scan's own.
    package_manager: str = ""
    # The scanner itself states that every installed version it reports is
    # reached only from development dependencies (pnpm's per-finding ``dev``).
    scanner_dev_only: bool = False
    # False when the scanner gave no severity and ``severity`` is a placeholder
    # (pip-audit and uv audit report none). A severity gate must not treat a
    # placeholder as a measurement: ``--fail-on high`` counts these as meeting it.
    severity_known: bool = True
    # Other identifiers of the same advisory (``CVE-...`` for a GHSA or PYSEC id).
    # KEV lists CVE ids only, and uv audit and pip-audit put the CVE here.
    aliases: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Scanner reports are text from outside: an escape sequence in a title
        # would reach the terminal (clear the screen, rewrite earlier lines).
        for name in ("cve", "package", "version", "title", "url", "fix_version", "fix_package"):
            value = getattr(self, name)
            if isinstance(value, str):
                setattr(self, name, strip_control(value))
        self.aliases = [strip_control(a) if isinstance(a, str) else a for a in self.aliases]
        # Reports become links in HTML, Markdown and SARIF: only a web address
        # is kept, never javascript: or data: from a crafted report.
        if not isinstance(self.url, str) or not _WEB_URL.fullmatch(self.url):
            self.url = ""

    @property
    def severity_label(self) -> str:
        """The severity to show: ``unknown`` when the scanner reported none."""
        return self.severity.value if self.severity_known else "unknown"

    @property
    def cve_id(self) -> str:
        """The CVE id of the advisory, its own or an alias; empty if it has none."""
        return next((i for i in self.ids if i.upper().startswith("CVE-")), "")

    @property
    def ids(self) -> list[str]:
        """The advisory id first, then its aliases, without duplicates."""
        return list(dict.fromkeys([i for i in (self.cve, *self.aliases) if i]))

    @property
    def key(self) -> str:
        return f"{self.cve}:{self.package}"

    @property
    def fix_label(self) -> str:
        """``4.17.21``, or ``express@4.22.3`` when the fix is upgrading another package."""
        if not self.fix_version:
            return ""
        return f"{self.fix_package}@{self.fix_version}" if self.fix_package else self.fix_version


@dataclass
class DecisionChange:
    """One priority decision, retained when a later rule overrides it."""

    source: str
    previous_verdict: Verdict | None
    verdict: Verdict
    rule_id: str = ""
    reason: str = ""
    path: str = ""
    author: str = ""
    expires: str = ""


@dataclass
class WorkspaceEvidence:
    """Dependency-name analysis in one declared workspace, not instance binding."""

    path: str
    relevance: str = "unknown"
    dependency_type: str = "unknown"
    usage: str = "unknown"
    dev_only: bool = False
    graph_coverage_complete: bool = False
    analysis_coverage_complete: bool = False
    introduced_by: list[str] = field(default_factory=list)
    import_sites: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Any) -> WorkspaceEvidence:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str) or not raw["path"]:
            raise ValueError("Invalid workspace evidence: path is required")
        enums = {
            "relevance": {"dependency", "observed", "uncertain", "not_declared", "unknown"},
            "dependency_type": {"direct", "transitive", "unknown"},
            "usage": {"observed", "not_observed", "unknown"},
        }
        for name, allowed in enums.items():
            if not isinstance(raw.get(name), str) or raw[name] not in allowed:
                raise ValueError(f"Invalid workspace evidence: {name}")
        for name in ("dev_only", "graph_coverage_complete", "analysis_coverage_complete"):
            if type(raw.get(name)) is not bool:
                raise ValueError(f"Invalid workspace evidence: {name} must be boolean")
        arrays = {}
        for name in ("introduced_by", "import_sites", "observations"):
            value = raw.get(name, [])
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"Invalid workspace evidence: {name} must contain strings")
            arrays[name] = list(value)
        return cls(
            path=raw["path"],
            relevance=raw["relevance"],
            dependency_type=raw["dependency_type"],
            usage=raw["usage"],
            dev_only=raw["dev_only"],
            graph_coverage_complete=raw["graph_coverage_complete"],
            analysis_coverage_complete=raw["analysis_coverage_complete"],
            introduced_by=arrays["introduced_by"],
            import_sites=arrays["import_sites"],
            observations=arrays["observations"],
        )


@dataclass
class DependencyEvidence:
    """Observations from dependency analysis, not proof of exploitability."""

    analysis: str = "dependency_imports"
    usage: str = "unknown"  # observed | not_observed | unknown
    import_sites: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    # None on legacy saved reports whose coverage was not recorded.
    graph_coverage_complete: bool | None = None
    analysis_coverage_complete: bool | None = None
    workspace_contexts: list[WorkspaceEvidence] = field(default_factory=list)


@dataclass
class TriageResult:
    """Result of triaging a single vulnerability."""

    vuln: Vulnerability
    verdict: Verdict
    reasons: list[FilterReason] = field(default_factory=list)
    epss_score: float | None = None
    epss_percentile: float | None = None
    reachable_imports: list[str] = field(default_factory=list)
    template_id: str | None = None
    template_reason: str | None = None
    kev_entry: Any = None  # KevEntry when CVE is in the CISA KEV catalog
    # "direct", "transitive" or "unknown", from the project's manifests and
    # lockfiles (see depquiet.depgraph); "" when reachability wasn't evaluated.
    dependency_type: str = ""
    # For transitive packages: the direct dependencies that pull them in.
    introduced_by: list[str] = field(default_factory=list)
    evidence: DependencyEvidence = field(default_factory=DependencyEvidence)
    decision_trace: list[DecisionChange] = field(default_factory=list)
    # depquiet.fixcheck.FixCheck when --check-fixes asked the resolver.
    fix_check: Any = None
    # "3.11.5" when uv.lock holds this vulnerable copy only for Pythons below
    # that version (a lock forked by Python version; see depquiet.pyscope).
    python_scope: str = ""

    @property
    def reason_summary(self) -> str:
        if not self.reasons:
            return "no automatic filter matched; product impact unverified"
        return ", ".join(r.value.replace("_", " ") for r in self.reasons)


@dataclass
class ScanResult:
    """Aggregate result of a full scan."""

    project_path: str
    package_manager: str
    total_dependencies: int
    results: list[TriageResult]
    # False when nothing was scanned (no supported project found). An empty
    # result must never read as "no vulnerabilities" in that case.
    scanned: bool = True
    note: str = ""
    project_id: str = ""
    # Advisories whose CVE id could not be looked up (network failure). EPSS
    # and KEV are keyed by CVE, so those advisories went unchecked.
    cve_lookups_failed: int = 0
    # CVEs whose EPSS score could not be fetched (network failure or an
    # unreadable answer): the report is not ordered by their score.
    epss_lookups_failed: int = 0
    # True once the scan was matched against the CISA KEV catalog. Without it,
    # "not on KEV" is unknown, not a finding.
    kev_checked: bool = False

    @property
    def action(self) -> list[TriageResult]:
        return [r for r in self.results if r.verdict == Verdict.ACTION]

    @property
    def review(self) -> list[TriageResult]:
        return [r for r in self.results if r.verdict == Verdict.REVIEW]

    @property
    def filtered(self) -> list[TriageResult]:
        return [r for r in self.results if r.verdict == Verdict.FILTERED]

    @property
    def filter_rate(self) -> float:
        return len(self.filtered) / len(self.results) * 100 if self.results else 0


def version_key(version: str) -> tuple[Any, ...]:
    """Order release numbers well enough to compare fixes (4.2.1 > 4.0.9)."""
    parts: list[Any] = []
    for piece in re.split(r"[.+-]", version):
        parts.append((0, int(piece)) if piece.isdigit() else (1, piece))
    return tuple(parts)


_PRERELEASE = re.compile(
    r"(?i)\d\.?(?:a|b|c|rc|alpha|beta|pre|preview|dev)\.?\d*(?:$|[.+-])"  # PEP 440
    r"|-[0-9a-z]"  # semver: 2.0.0-beta.1
)


def is_prerelease(version: str) -> bool:
    """True for alpha, beta, rc and dev versions (``26.10.0rc1``, ``2.0.0-beta.1``).

    Advisories sometimes list only a release candidate as the fix; the
    report has to say so, since most projects never install one by accident.
    """
    return bool(_PRERELEASE.search(version.strip()))


def epss_percent(score: float) -> str:
    """An EPSS score as a percentage that never rounds a real score to 0%.

    Most scores are below 1%; ``0%`` would read as "no chance".
    """
    if score >= 0.01:
        return f"{score:.0%}"
    if score >= 0.001:
        return f"{score:.1%}"
    return "<0.1%"


def short_title(text: str, width: int = 120) -> str:
    """An advisory summary or description as one clean line of at most *width*.

    Markdown is stripped before cutting: cutting the raw text first left
    titles like "urllib3's streaming API is" once a long link was removed.
    """
    text = re.sub(r"(?m)^\s*#{1,6}\s*(Impact|Summary|Description|Details)\b:?", " ", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)  # [text](url) -> text
    text = re.sub(r"[#*`]+", "", text)
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    cut = text[: width - 1].rsplit(" ", 1)[0]
    return cut + "…"


def nearest_fix(installed: str, fixes: list[str]) -> str:
    """The lowest fixed version above ``installed``.

    Scanners list every release line that carries the fix (``0.3.81, 1.2.22``);
    the nearest one above what is installed is the smallest upgrade. Without
    an installed version, or none above it, the first listed fix is kept.
    """
    if not fixes:
        return ""
    if installed:
        try:
            above = [f for f in fixes if version_key(f) > version_key(installed)]
            if above:
                return min(above, key=version_key)
        except TypeError:  # pieces that do not compare (1.0 vs 1.0rc1 shapes)
            pass
    return fixes[0]
