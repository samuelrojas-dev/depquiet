"""Suppression file — .depquiet-ignore for per-CVE / per-package accepted risk.

Enterprise teams need a way to acknowledge vulnerabilities they accept without
disabling the tool. The ignore file provides:

- Per-CVE suppression: ``CVE-2024-1234``
- Per-CVE+package suppression: ``CVE-2024-1234:lodash``
- Required reason for audit trail
- Optional expiry date so suppressions don't rot forever
- Warning on expired entries

File format (.depquiet-ignore)::

    ignores:
      - cve: CVE-2024-1234
        reason: "Mitigated by WAF rule WR-123"
        expires: 2025-06-01
        author: alice

      - cve: CVE-2024-5678
        package: lodash
        reason: "Only used in tests, no production exposure"

      - package: deprecated-pkg
        reason: "Migration planned for Q2"
        expires: 2025-07-01
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from depquiet.models import DecisionChange, FilterReason, ScanResult, Verdict


@dataclass
class IgnoreEntry:
    """A single suppression entry."""

    cve: str | None = None
    package: str | None = None
    reason: str = ""
    expires: date | None = None
    author: str = ""
    # The ``expires`` text when it is not a readable date. Such an entry counts
    # as expired: a typo must not turn a temporary suppression into a permanent one.
    expires_invalid: str = ""

    @property
    def key(self) -> str:
        """Unique key for matching: 'CVE', 'CVE:pkg', or ':pkg'."""
        parts: list[str] = []
        if self.cve:
            parts.append(self.cve)
        if self.package:
            parts.append(self.package)
        return ":".join(parts) if parts else ""

    def is_expired(self, today: date | None = None) -> bool:
        """Check if this entry has expired."""
        if self.expires_invalid:
            return True
        if self.expires is None:
            return False
        if today is None:
            today = date.today()
        return today > self.expires


@dataclass
class IgnoreFile:
    """Parsed .depquiet-ignore file."""

    entries: list[IgnoreEntry] = field(default_factory=list)
    path: str = ""

    @property
    def active(self) -> list[IgnoreEntry]:
        """Return only non-expired entries."""
        return [e for e in self.entries if not e.is_expired()]

    @property
    def expired(self) -> list[IgnoreEntry]:
        """Return only expired entries."""
        return [e for e in self.entries if e.is_expired()]

    def matches(self, cve: str, package: str) -> IgnoreEntry | None:
        """Find the first active entry that matches the given CVE+package.

        Match priority:
        1. Exact CVE+package match
        2. CVE-only match (any package)
        3. Package-only match (any CVE)
        """
        cve_pkg_match: IgnoreEntry | None = None
        cve_match: IgnoreEntry | None = None
        pkg_match: IgnoreEntry | None = None

        for entry in self.active:
            if entry.cve and entry.package:
                if entry.cve == cve and entry.package == package:
                    cve_pkg_match = entry
            elif entry.cve:
                if entry.cve == cve:
                    cve_match = entry
            elif entry.package and entry.package == package:
                pkg_match = entry

        return cve_pkg_match or cve_match or pkg_match

    def matches_package(self, package: str) -> IgnoreEntry | None:
        """Find the first active entry that matches just a package name.

        Used for license suppressions where there is no CVE.
        """
        for entry in self.active:
            if entry.package and entry.package == package and not entry.cve:
                return entry
        return None


_IGNORE_NAMES = (".depquiet-ignore", ".depquiet-ignore.yaml", ".depquiet-ignore.yml")


def load_ignore(project: Path, *, ignore_path: Path | None = None) -> IgnoreFile | None:
    """Load a .depquiet-ignore file from the project root or explicit path.

    Returns None if no ignore file exists.
    """
    if ignore_path is not None:
        if ignore_path.is_file():
            return _parse_ignore(ignore_path)
        print(f"Warning: ignore file not found: {ignore_path}", file=sys.stderr)
        return None

    for name in _IGNORE_NAMES:
        candidate = project / name
        if candidate.is_file():
            return _parse_ignore(candidate)

    return None


def _parse_ignore_yaml(text: str) -> list[dict[str, str]]:
    """Parse ignore YAML into a list of entry dicts.

    Handles the subset of YAML needed:
    - Top-level ``ignores:`` key containing a list of dicts
    - Each list item starts with ``- key: value``
    - Continuation lines are ``key: value``
    """
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    in_ignores = False

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped == "ignores:" or stripped.startswith("ignores:"):
            in_ignores = True
            continue

        if not in_ignores:
            continue

        # New list item
        if stripped.startswith("- "):
            if current is not None:
                entries.append(current)
            current = {}
            rest = stripped[2:].strip()
            if ":" in rest:
                k, v = rest.split(":", 1)
                current[k.strip()] = _scalar(v)
            continue

        if current is None:
            continue

        # Key: value line
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            current[k.strip()] = _scalar(v)

    if current is not None:
        entries.append(current)

    return entries


def _scalar(value: str) -> str:
    """A YAML scalar: quotes removed, or a trailing `` # comment`` dropped."""
    value = value.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        if end > 0:
            return value[1:end]
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


def _parse_date(s: str) -> date | None:
    """Parse an ISO date (YYYY-MM-DD)."""
    s = s.strip().strip("'\"")
    if not s:
        return None
    try:
        parts = s.split("-")
        if len(parts) == 3:
            return date(int(parts[0]), int(parts[1]), int(parts[2]))
    except (ValueError, IndexError):
        pass
    return None


def _parse_ignore(path: Path) -> IgnoreFile | None:
    """Parse a .depquiet-ignore file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Warning: could not read {path}: {exc}", file=sys.stderr)
        return None

    try:
        raw_entries = _parse_ignore_yaml(text)
    except Exception:
        print(f"Warning: invalid YAML in {path}", file=sys.stderr)
        return None
    if not raw_entries and any(
        line.strip() and not line.strip().startswith("#") for line in text.splitlines()
    ):
        print(
            f"Warning: no entries read from {path} (expected a top-level 'ignores:' list "
            "of '- cve: ...' items); nothing is ignored",
            file=sys.stderr,
        )

    entries: list[IgnoreEntry] = []
    for raw in raw_entries:
        cve = raw.get("cve", "").strip() or None
        package = raw.get("package", "").strip() or None
        reason = raw.get("reason", "").strip()
        author = raw.get("author", "").strip()
        expires_text = raw.get("expires", "").strip()
        expires = _parse_date(expires_text)
        expires_invalid = expires_text if expires_text and expires is None else ""

        if not cve and not package:
            print(
                f"Warning: ignore entry needs 'cve' or 'package' in {path}",
                file=sys.stderr,
            )
            continue

        if expires_invalid:
            print(
                f"Warning: unreadable expires {expires_invalid!r} for {cve or package} in "
                f"{path}: the suppression is treated as expired (write YYYY-MM-DD)",
                file=sys.stderr,
            )

        if not reason:
            print(
                f"Warning: ignore entry missing 'reason' for {cve or package} in {path}",
                file=sys.stderr,
            )

        entries.append(
            IgnoreEntry(
                cve=cve,
                package=package,
                reason=reason,
                expires=expires,
                author=author,
                expires_invalid=expires_invalid,
            )
        )

    return IgnoreFile(entries=entries, path=str(path))


def apply_ignores(result: ScanResult, ignore_file: IgnoreFile) -> ScanResult:
    """Apply ignore suppressions to a scan result.

    Matching entries change the verdict to FILTERED and add the IGNORED
    reason. Only ACTION and REVIEW items are suppressed — already-filtered
    items are left as-is.

    Returns the same ScanResult object (mutated in place).
    """
    for tr in result.results:
        if tr.verdict == Verdict.FILTERED:
            continue
        # An entry may name the CVE of an advisory reported as GHSA or PYSEC.
        entry = next(
            (
                m
                for m in (ignore_file.matches(i, tr.vuln.package) for i in tr.vuln.ids or [""])
                if m is not None
            ),
            None,
        )
        if entry is not None:
            tr.decision_trace.append(
                DecisionChange(
                    source="ignore",
                    previous_verdict=tr.verdict,
                    verdict=Verdict.FILTERED,
                    rule_id=entry.key,
                    reason=entry.reason,
                    path=ignore_file.path,
                    author=entry.author,
                    expires=entry.expires.isoformat() if entry.expires is not None else "",
                )
            )
            tr.verdict = Verdict.FILTERED
            if FilterReason.IGNORED not in tr.reasons:
                tr.reasons.append(FilterReason.IGNORED)
    return result


def print_ignore_warnings(ignore_file: IgnoreFile) -> None:
    """Print warnings for expired ignore entries to stderr."""
    expired = ignore_file.expired
    if not expired:
        return

    print(
        f"\n⚠️  {len(expired)} expired {'suppression' if len(expired) == 1 else 'suppressions'} "
        f"in {ignore_file.path}:",
        file=sys.stderr,
    )
    for entry in expired:
        target = entry.cve or entry.package or "?"
        if entry.cve and entry.package:
            target = f"{entry.cve} ({entry.package})"
        when = (
            f"unreadable expires {entry.expires_invalid!r}"
            if entry.expires_invalid
            else f"expired {entry.expires}"
        )
        print(f"   {target}  {when}  — {entry.reason}", file=sys.stderr)
    print(
        "   Remove or update these entries to clear this warning.",
        file=sys.stderr,
    )
