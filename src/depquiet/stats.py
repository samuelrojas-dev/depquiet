"""``depquiet stats`` — aggregate scan statistics.

Produces summary metrics from a scan or a saved ``--json`` output:
filter rate, verdict breakdown, reason distribution, severity histogram,
top affected packages, and EPSS score distribution.  Useful for security
dashboards, management reports, and trend tracking.

Output is human-readable by default, or ``--json`` for machine consumption.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from depquiet.models import (
    FilterReason,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)

# ---------------------------------------------------------------------------
# Stats model
# ---------------------------------------------------------------------------


@dataclass
class EpssDistribution:
    """EPSS score distribution buckets."""

    unavailable: int = 0
    low: int = 0  # < 10%
    medium: int = 0  # 10-50%
    high: int = 0  # 50-90%
    critical: int = 0  # >= 90%


@dataclass
class ScanStats:
    """Aggregate statistics for a scan."""

    total_vulnerabilities: int = 0
    total_dependencies: int = 0

    # Verdict breakdown
    action_count: int = 0
    review_count: int = 0
    filtered_count: int = 0
    filter_rate: float = 0.0

    # Severity breakdown
    severity_counts: dict[str, int] = field(default_factory=dict)

    # Filter reason breakdown (only for filtered verdicts)
    reason_counts: dict[str, int] = field(default_factory=dict)

    # Top affected packages (by count)
    top_packages: list[tuple[str, int]] = field(default_factory=list)

    # EPSS distribution
    epss: EpssDistribution = field(default_factory=EpssDistribution)

    # Fix availability
    fixable_count: int = 0
    unfixable_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_vulnerabilities": self.total_vulnerabilities,
            "total_dependencies": self.total_dependencies,
            "verdicts": {
                "action": self.action_count,
                "review": self.review_count,
                "filtered": self.filtered_count,
            },
            "filter_rate": round(self.filter_rate, 1),
            "severity": self.severity_counts,
            "filter_reasons": self.reason_counts,
            "top_packages": [{"package": pkg, "count": cnt} for pkg, cnt in self.top_packages],
            "epss_distribution": {
                "unavailable": self.epss.unavailable,
                "low": self.epss.low,
                "medium": self.epss.medium,
                "high": self.epss.high,
                "critical": self.epss.critical,
            },
            "fix_availability": {
                "fixable": self.fixable_count,
                "no_fix": self.unfixable_count,
            },
        }


# ---------------------------------------------------------------------------
# Compute stats
# ---------------------------------------------------------------------------


def compute_stats(
    results: list[TriageResult],
    total_dependencies: int = 0,
    *,
    top_n: int = 10,
) -> ScanStats:
    """Compute aggregate statistics from a list of TriageResults."""
    stats = ScanStats(
        total_vulnerabilities=len(results),
        total_dependencies=total_dependencies,
    )

    if not results:
        return stats

    # Verdict counts
    for tr in results:
        if tr.verdict == Verdict.ACTION:
            stats.action_count += 1
        elif tr.verdict == Verdict.REVIEW:
            stats.review_count += 1
        elif tr.verdict == Verdict.FILTERED:
            stats.filtered_count += 1

    stats.filter_rate = (
        stats.filtered_count / stats.total_vulnerabilities * 100
        if stats.total_vulnerabilities
        else 0.0
    )

    # Severity counts
    sev_counter: Counter[str] = Counter()
    for tr in results:
        sev_counter[tr.vuln.severity_label] += 1
    # Ordered by severity level
    for sev in ("critical", "high", "moderate", "low", "info", "unknown"):
        if sev in sev_counter:
            stats.severity_counts[sev] = sev_counter[sev]

    # Filter reason counts (only for filtered results)
    reason_counter: Counter[str] = Counter()
    for tr in results:
        for reason in tr.reasons:
            reason_counter[reason.value] += 1
    stats.reason_counts = dict(reason_counter.most_common())

    # Top packages
    pkg_counter: Counter[str] = Counter()
    for tr in results:
        pkg_counter[tr.vuln.package] += 1
    stats.top_packages = pkg_counter.most_common(top_n)

    # EPSS distribution
    for tr in results:
        if tr.epss_score is None:
            stats.epss.unavailable += 1
        elif tr.epss_score < 0.10:
            stats.epss.low += 1
        elif tr.epss_score < 0.50:
            stats.epss.medium += 1
        elif tr.epss_score < 0.90:
            stats.epss.high += 1
        else:
            stats.epss.critical += 1

    # Fix availability
    for tr in results:
        if tr.vuln.fix_version:
            stats.fixable_count += 1
        else:
            stats.unfixable_count += 1

    return stats


def stats_from_json(data: dict[str, Any], *, top_n: int = 10) -> ScanStats:
    """Compute stats from a depquiet --json output dict."""
    results: list[TriageResult] = []
    for entry in data.get("results", []):
        vuln = Vulnerability(
            cve=entry.get("cve", ""),
            package=entry.get("package", ""),
            version=entry.get("version", ""),
            severity=Severity.parse(entry.get("severity")) or Severity.MODERATE,
            severity_known=Severity.parse(entry.get("severity")) is not None,
            title=entry.get("title", ""),
            fix_version=entry.get("fix_version", ""),
            is_dev="dev_dependency" in entry.get("reasons", []),
        )
        reasons = [
            FilterReason(r)
            for r in entry.get("reasons", [])
            if r in FilterReason._value2member_map_
        ]
        results.append(
            TriageResult(
                vuln=vuln,
                verdict=Verdict(entry.get("verdict", "review")),
                reasons=reasons,
                epss_score=entry.get("epss_score"),
                reachable_imports=entry.get("reachable_imports", []),
            )
        )
    total_deps = data.get("total_dependencies", 0)
    return compute_stats(results, total_deps, top_n=top_n)


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

_VERDICT_BARS = {
    "action": "🔴",
    "review": "🟡",
    "filtered": "🟢",
}

_SEV_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "moderate": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def _bar(count: int, total: int, width: int = 20) -> str:
    """Render a simple text bar chart segment."""
    if total == 0:
        return ""
    filled = round(count / total * width)
    return "█" * filled + "░" * (width - filled)


def format_stats(stats: ScanStats) -> str:
    """Format ScanStats as a human-readable report."""
    lines: list[str] = []
    total = stats.total_vulnerabilities

    lines.append("depquiet scan statistics")
    lines.append("=" * 40)
    lines.append("")

    # Summary
    lines.append(f"Total vulnerabilities: {total}")
    if stats.total_dependencies:
        lines.append(f"Total dependencies:   {stats.total_dependencies}")
    lines.append(f"Filter rate:          {stats.filter_rate:.1f}%")
    lines.append("")

    # Verdict breakdown
    lines.append("Verdicts:")
    for label, count, icon in [
        ("ACTION", stats.action_count, _VERDICT_BARS["action"]),
        ("REVIEW", stats.review_count, _VERDICT_BARS["review"]),
        ("FILTERED", stats.filtered_count, _VERDICT_BARS["filtered"]),
    ]:
        bar = _bar(count, total)
        pct = count / total * 100 if total else 0
        lines.append(f"  {icon} {label:10s} {count:4d} ({pct:5.1f}%) {bar}")
    lines.append("")

    # Severity
    if stats.severity_counts:
        lines.append("Severity:")
        for sev, count in stats.severity_counts.items():
            icon = _SEV_ICONS.get(sev, "·")
            pct = count / total * 100 if total else 0
            bar = _bar(count, total)
            lines.append(f"  {icon} {sev:10s} {count:4d} ({pct:5.1f}%) {bar}")
        lines.append("")

    # Filter reasons
    if stats.reason_counts:
        lines.append("Filter reasons:")
        reason_total = sum(stats.reason_counts.values())
        for reason, count in stats.reason_counts.items():
            label = reason.replace("_", " ")
            pct = count / reason_total * 100 if reason_total else 0
            lines.append(f"  {label:25s} {count:4d} ({pct:5.1f}%)")
        lines.append("")

    # Top packages
    if stats.top_packages:
        lines.append("Top affected packages:")
        for pkg, count in stats.top_packages:
            lines.append(f"  {pkg:30s} {count:4d}")
        lines.append("")

    # EPSS distribution
    epss_total = (
        stats.epss.unavailable
        + stats.epss.low
        + stats.epss.medium
        + stats.epss.high
        + stats.epss.critical
    )
    if epss_total:
        lines.append("EPSS distribution:")
        for label, count in [
            ("<10% (low)", stats.epss.low),
            ("10-50% (medium)", stats.epss.medium),
            ("50-90% (high)", stats.epss.high),
            (">=90% (critical)", stats.epss.critical),
            ("unavailable", stats.epss.unavailable),
        ]:
            if count:
                pct = count / epss_total * 100
                lines.append(f"  {label:20s} {count:4d} ({pct:5.1f}%)")
        lines.append("")

    # Fix availability
    if stats.fixable_count or stats.unfixable_count:
        lines.append("Fix availability:")
        lines.append(
            f"  Fixable:   {stats.fixable_count:4d} ({stats.fixable_count / total * 100:.1f}%)"
            if total
            else f"  Fixable:   {stats.fixable_count:4d}"
        )
        lines.append(
            f"  No fix:    {stats.unfixable_count:4d} ({stats.unfixable_count / total * 100:.1f}%)"
            if total
            else f"  No fix:    {stats.unfixable_count:4d}"
        )
        lines.append("")

    return "\n".join(lines)


def format_stats_json(stats: ScanStats) -> str:
    """Format ScanStats as JSON."""
    return json.dumps(stats.to_dict(), indent=2)
