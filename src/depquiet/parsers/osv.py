"""Lockfile scanner backed by the OSV.dev API.

OSV.dev (https://osv.dev) is Google's open, free vulnerability database
covering npm, PyPI, crates.io, Go, Maven, NuGet, Packagist, RubyGems,
Pub, and more.  It powers ``osv-scanner``, ``deps.dev``, and GitHub's
advisory database.

This module parses lockfiles directly (no external scanner required) and
queries OSV.dev's batch API to find known vulnerabilities, making depquiet
a fully standalone tool::

    depquiet                  # auto-detects lockfile, queries OSV.dev
    depquiet --offline        # skips OSV.dev (and EPSS), scan-only mode

Supported lockfiles:
- package-lock.json (npm)
- yarn.lock (Yarn v1)
- requirements.txt / Pipfile.lock (Python)
- go.sum (Go)
- Cargo.lock (Rust)
- pom.xml (Maven — top-level dependencies only)
- pubspec.lock (Dart/Flutter)
- Gemfile.lock (Ruby)
- composer.lock (PHP)
- packages.lock.json (NuGet / C#)

The batch API accepts up to 1000 queries per request, so even large projects
need only a single HTTP call.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from depquiet.models import Severity, Vulnerability, short_title
from depquiet.scanners import ScanError

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

# Ecosystem names as OSV.dev expects them
_ECOSYSTEM_NPM = "npm"
_ECOSYSTEM_PYPI = "PyPI"
_ECOSYSTEM_GO = "Go"
_ECOSYSTEM_CARGO = "crates.io"
_ECOSYSTEM_MAVEN = "Maven"
_ECOSYSTEM_NUGET = "NuGet"
_ECOSYSTEM_PACKAGIST = "Packagist"
_ECOSYSTEM_RUBYGEMS = "RubyGems"
_ECOSYSTEM_PUB = "Pub"


# ---------------------------------------------------------------------------
# Lockfile parsers — each returns [(name, version, ecosystem)]
# ---------------------------------------------------------------------------

PackageInfo = tuple[str, str, str]  # (name, version, ecosystem)


def _parse_package_lock(path: Path) -> list[PackageInfo]:
    """Parse npm package-lock.json (v2/v3 format with 'packages')."""
    data = json.loads(path.read_text())
    results: list[PackageInfo] = []
    seen: set[str] = set()

    # v2/v3 format
    packages = data.get("packages", {})
    for key, info in packages.items():
        if not key:  # root package
            continue
        name = info.get("name", "")
        if not name:
            # Extract name from key: "node_modules/lodash" or
            # "node_modules/@scope/name"
            parts = key.split("node_modules/")
            name = parts[-1] if parts else ""
        version = info.get("version", "")
        if name and version:
            k = f"{name}@{version}"
            if k not in seen:
                seen.add(k)
                results.append((name, version, _ECOSYSTEM_NPM))

    # v1 format fallback
    if not results:
        deps = data.get("dependencies", {})
        for name, info in deps.items():
            version = info.get("version", "")
            if version:
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, version, _ECOSYSTEM_NPM))

    return results


_YARN_REAL_NAME = re.compile(r"^((?:@[^/@\s]+/)?[^/@\s]+)@npm:")


def _parse_yarn_lock(path: Path) -> list[PackageInfo]:
    """Parse yarn.lock: Yarn 1 (``version "1.2.3"``) and Berry (``version: 1.2.3``)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()
    name = version = ""

    def flush() -> None:
        # Berry lists the project's own workspaces with a placeholder version.
        local = name == "__metadata" or version == "0.0.0-use.local"
        if name and version and not local and f"{name}@{version}" not in seen:
            seen.add(f"{name}@{version}")
            results.append((name, version, _ECOSYSTEM_NPM))

    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith((" ", "#")):
            flush()
            # Header: ``lodash@^4.17.20:`` or ``"@scope/pkg@npm:^1.0.0, @scope/pkg@npm:^1.1.0":``
            header = line.rstrip(":").strip("\"'")
            at = header.find("@", 1)
            name, version = (header[:at] if at > 0 else header), ""
        elif line.startswith(("  version ", "  version:")) and name:
            version = line.split('"')[1] if '"' in line else line.split()[-1]
        elif line.startswith("  resolution:") and name:
            # Berry names the installed package here. Under an alias
            # (``"x-cjs@npm:x@^4"``) the header carries only the alias.
            real = _YARN_REAL_NAME.match(line.split(":", 1)[1].strip().strip("\"'"))
            if real:
                name = real.group(1)
    flush()
    return results


def _parse_requirements_txt(path: Path) -> list[PackageInfo]:
    """Parse requirements.txt (pinned versions only)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle "package==version" or "package===version"
        match = re.match(r"^([a-zA-Z0-9._-]+)\s*={2,3}\s*([^\s;#]+)", line)
        if match:
            name = match.group(1).lower()
            version = match.group(2)
            k = f"{name}@{version}"
            if k not in seen:
                seen.add(k)
                results.append((name, version, _ECOSYSTEM_PYPI))

    return results


def _parse_pipfile_lock(path: Path) -> list[PackageInfo]:
    """Parse Pipfile.lock."""
    data = json.loads(path.read_text())
    results: list[PackageInfo] = []
    seen: set[str] = set()

    for section in ("default", "develop"):
        packages = data.get(section, {})
        for name, info in packages.items():
            version = info.get("version", "").lstrip("=")
            if version:
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name.lower(), version, _ECOSYSTEM_PYPI))

    return results


def _parse_go_sum(path: Path) -> list[PackageInfo]:
    """Parse go.sum."""
    results: list[PackageInfo] = []
    seen: set[str] = set()

    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version = parts[1].split("/")[0].lstrip("v")
        k = f"{module}@{version}"
        if k not in seen:
            seen.add(k)
            results.append((module, version, _ECOSYSTEM_GO))

    return results


def _parse_cargo_lock(path: Path) -> list[PackageInfo]:
    """Parse Cargo.lock (TOML-like, no external dependency needed)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()
    text = path.read_text()

    name = ""
    version = ""
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if name and version:
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, version, _ECOSYSTEM_CARGO))
            name = ""
            version = ""
        elif line.startswith("name = "):
            name = line.split('"')[1]
        elif line.startswith("version = "):
            version = line.split('"')[1]

    # Last package
    if name and version:
        k = f"{name}@{version}"
        if k not in seen:
            seen.add(k)
            results.append((name, version, _ECOSYSTEM_CARGO))

    return results


def _parse_pubspec_lock(path: Path) -> list[PackageInfo]:
    """Parse pubspec.lock (YAML-like, simple line parsing)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()
    text = path.read_text()

    current_name = ""
    for line in text.splitlines():
        # Package name at indent level 2: "  package_name:"
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            current_name = line.strip().rstrip(":")
        elif '    version: "' in line and current_name:
            version = line.split('"')[1]
            k = f"{current_name}@{version}"
            if k not in seen:
                seen.add(k)
                results.append((current_name, version, _ECOSYSTEM_PUB))
            current_name = ""

    return results


def _parse_gemfile_lock(path: Path) -> list[PackageInfo]:
    """Parse Gemfile.lock (GEM section)."""
    results: list[PackageInfo] = []
    seen: set[str] = set()
    text = path.read_text()
    in_specs = False

    for line in text.splitlines():
        if line.strip() == "GEM":
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line.startswith("      "):
            # Dependency of a gem, skip
            continue
        if in_specs and line.startswith("    "):
            # "    gem_name (version)"
            match = re.match(r"^\s{4}(\S+)\s+\(([^)]+)\)", line)
            if match:
                name = match.group(1)
                version = match.group(2)
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, version, _ECOSYSTEM_RUBYGEMS))
        elif in_specs and not line.startswith(" "):
            in_specs = False

    return results


def _parse_composer_lock(path: Path) -> list[PackageInfo]:
    """Parse composer.lock (PHP)."""
    data = json.loads(path.read_text())
    results: list[PackageInfo] = []
    seen: set[str] = set()

    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "").lstrip("v")
            if name and version:
                k = f"{name}@{version}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, version, _ECOSYSTEM_PACKAGIST))

    return results


def _parse_packages_lock_json(path: Path) -> list[PackageInfo]:
    """Parse packages.lock.json (NuGet / C#)."""
    data = json.loads(path.read_text())
    results: list[PackageInfo] = []
    seen: set[str] = set()

    deps = data.get("dependencies", {})
    for _framework, packages in deps.items():
        for name, info in packages.items():
            resolved = info.get("resolved", "")
            if resolved:
                k = f"{name}@{resolved}"
                if k not in seen:
                    seen.add(k)
                    results.append((name, resolved, _ECOSYSTEM_NUGET))

    return results


# Lockfile → parser mapping
def _parse_pnpm_lock(path: Path) -> list[PackageInfo]:
    """Parse pnpm-lock.yaml (lockfile v5 to v9)."""
    from depquiet.pnpm_lock import parse_pnpm_lock

    return [(name, version, _ECOSYSTEM_NPM) for name, version in parse_pnpm_lock(path).packages]


def _parse_python_lock(path: Path) -> list[PackageInfo]:
    """Parse uv.lock / poetry.lock (every registry package they pin)."""
    from depquiet.scanners import lock_pins

    pins, dropped = lock_pins(path)
    out: list[PackageInfo] = []
    for pin in pins + dropped:
        name, version = pin.split("==", 1)
        out.append((name, version, _ECOSYSTEM_PYPI))
    return out


_LOCKFILE_PARSERS: list[tuple[str, Any]] = [
    ("uv.lock", _parse_python_lock),
    ("poetry.lock", _parse_python_lock),
    ("package-lock.json", _parse_package_lock),
    ("yarn.lock", _parse_yarn_lock),
    ("pnpm-lock.yaml", _parse_pnpm_lock),
    ("Pipfile.lock", _parse_pipfile_lock),
    ("requirements.txt", _parse_requirements_txt),
    ("go.sum", _parse_go_sum),
    ("Cargo.lock", _parse_cargo_lock),
    ("pubspec.lock", _parse_pubspec_lock),
    ("Gemfile.lock", _parse_gemfile_lock),
    ("composer.lock", _parse_composer_lock),
    ("packages.lock.json", _parse_packages_lock_json),
]


def detect_lockfiles(project: Path) -> list[tuple[Path, str]]:
    """Find all lockfiles in a project directory.

    Returns list of (path, lockfile_name) tuples.
    """
    found: list[tuple[Path, str]] = []
    for lockfile_name, _ in _LOCKFILE_PARSERS:
        path = project / lockfile_name
        if path.exists():
            found.append((path, lockfile_name))
    return found


def parse_lockfiles(project: Path, unreadable: list[str] | None = None) -> list[PackageInfo]:
    """Parse all lockfiles in a project, returning deduplicated packages.

    A lockfile that cannot be parsed is skipped; its name is appended to
    ``unreadable`` so the caller can refuse to present the rest as a full scan.
    """
    all_packages: list[PackageInfo] = []
    seen: set[str] = set()

    for lockfile_name, parser_func in _LOCKFILE_PARSERS:
        path = project / lockfile_name
        if path.exists():
            try:
                packages = parser_func(path)
            except (ValueError, KeyError, IndexError, TypeError, AttributeError, OSError) as e:
                if unreadable is not None:
                    unreadable.append(f"{lockfile_name} ({e})")
                continue
            for pkg in packages:
                key = f"{pkg[2]}:{pkg[0]}@{pkg[1]}"
                if key not in seen:
                    seen.add(key)
                    all_packages.append(pkg)

    return all_packages


# ---------------------------------------------------------------------------
# OSV.dev API
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MODERATE,
    "MEDIUM": Severity.MODERATE,
    "LOW": Severity.LOW,
}


def _cvss3_base_score(vector: str) -> float | None:
    """Compute CVSS 3.0/3.1 Base using FIRST's section 7.1 equations.

    https://www.first.org/cvss/v3.1/specification-document#7-CVSS-v31-Equations
    Temporal/environmental metrics do not lower the advisory's Base severity.
    """
    parts = vector.split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    try:
        metrics = dict(part.split(":") for part in parts[1:])
        if len(metrics) != len(parts) - 1 or metrics["S"] not in ("U", "C"):
            return None
        changed = metrics["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[
            metrics["PR"]
        ]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = (impact_values[metrics[key]] for key in ("C", "I", "A"))
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    base = min((1.08 if changed else 1) * (impact + exploitability), 10)
    # FIRST Appendix A avoids floating-point errors when rounding up to tenths.
    scaled = round(base * 100000)
    return ((scaled + 9999) // 10000) / 10


def _osv_severity(vuln_data: dict[str, Any]) -> Severity | None:
    """Extract severity from OSV vulnerability data; None when it gives none."""
    # database_specific may have severity
    db_specific = vuln_data.get("database_specific", {})
    sev = db_specific.get("severity", "")
    if sev and sev.upper() in _SEVERITY_MAP:
        return _SEVERITY_MAP[sev.upper()]

    # CVSS from severity[] array: the API normally supplies vectors, not numbers.
    scores: list[float] = []
    for sev_entry in vuln_data.get("severity", []):
        score_str = sev_entry.get("score", "")
        if score_str:
            score: float | None
            try:
                score = float(score_str)
            except (ValueError, TypeError):
                score = _cvss3_base_score(str(score_str))
            if score is not None and 0 <= score <= 10:
                scores.append(score)
    if scores:
        score = max(scores)
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MODERATE
        return Severity.LOW if score > 0 else Severity.INFO
    # A vector depquiet cannot score (CVSS v4, say) makes the severity unknown, not
    # moderate: the alert is kept with severity_known=False and reported as
    # "unknown". It used to end the whole scan, which hid every other alert
    # (textual's poetry.lock, PYSEC-2026-4320, Blocker Index study 2026-11-27).
    return None


def _extract_fix_version(vuln_data: dict[str, Any], package_name: str) -> str:
    """Extract fix version from OSV affected[].ranges[].events[]."""
    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for range_info in affected.get("ranges", []):
            for event in range_info.get("events", []):
                fixed = event.get("fixed", "")
                if fixed:
                    return str(fixed)
    return ""


def _osv_request(req: urllib.request.Request, timeout: int) -> dict[str, Any]:
    """Read one OSV response, preserving lookup failures as scan failures."""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (OSError, ValueError) as e:
        raise ScanError(f"could not query OSV.dev ({e}).") from e
    if not isinstance(data, dict) or "error" in data:
        raise ScanError("OSV.dev returned an invalid response.")
    return data


def query_osv_batch(packages: list[PackageInfo], timeout: int = 30) -> dict[str, Any]:
    """Query package versions and hydrate every advisory with its full record.

    ``querybatch`` only returns advisory IDs and modification timestamps. The
    detail endpoint supplies severity, aliases, fixes and descriptions needed
    for triage. Pagination and 1000-query batches must both complete before a
    report can be treated as scanned.
    """
    all_results: list[dict[str, Any]] = [{"vulns": []} for _ in packages]
    details: dict[str, dict[str, Any]] = {}
    for start in range(0, len(packages), 1000):
        pending: list[tuple[int, dict[str, Any]]] = [
            (start + i, {"version": version, "package": {"name": name, "ecosystem": ecosystem}})
            for i, (name, version, ecosystem) in enumerate(packages[start : start + 1000])
        ]
        seen_tokens: set[tuple[int, str]] = set()
        while pending:
            req = urllib.request.Request(
                _OSV_BATCH_URL,
                data=json.dumps({"queries": [query for _, query in pending]}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            response = _osv_request(req, timeout)
            results = response.get("results")
            if not isinstance(results, list) or len(results) != len(pending):
                raise ScanError("OSV.dev returned an incomplete batch response.")
            next_pending: list[tuple[int, dict[str, Any]]] = []
            for (index, query), result in zip(pending, results, strict=True):
                if not isinstance(result, dict) or not isinstance(result.get("vulns", []), list):
                    raise ScanError("OSV.dev returned an invalid package result.")
                for stub in result.get("vulns", []):
                    vuln_id = stub.get("id") if isinstance(stub, dict) else None
                    if not isinstance(vuln_id, str) or not vuln_id:
                        raise ScanError("OSV.dev returned an advisory without an ID.")
                    if vuln_id not in details:
                        detail_req = urllib.request.Request(
                            _OSV_VULN_URL + urllib.parse.quote(vuln_id, safe="")
                        )
                        detail = _osv_request(detail_req, timeout)
                        if detail.get("id") != vuln_id:
                            raise ScanError(f"OSV.dev returned an invalid record for {vuln_id}.")
                        details[vuln_id] = detail
                    all_results[index]["vulns"].append(details[vuln_id])
                token = result.get("next_page_token")
                if token:
                    if not isinstance(token, str) or (index, token) in seen_tokens:
                        raise ScanError("OSV.dev returned an invalid pagination token.")
                    seen_tokens.add((index, token))
                    next_pending.append((index, {**query, "page_token": token}))
            pending = next_pending
    return {"results": all_results}


def parse_osv_response(
    response: dict[str, Any],
    packages: list[PackageInfo],
) -> list[Vulnerability]:
    """Convert OSV batch response into Vulnerability objects."""
    vulns: list[Vulnerability] = []
    seen: set[str] = set()

    results_list = response.get("results", [])
    for i, result in enumerate(results_list):
        if i >= len(packages):
            break
        pkg_name, pkg_version, _ecosystem = packages[i]

        for osv_vuln in result.get("vulns", []):
            vuln_id = osv_vuln.get("id", "")

            # Prefer CVE alias over OSV ID
            cve = vuln_id
            for alias in osv_vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve = alias
                    break

            key = f"{cve}:{pkg_name}"
            if key in seen:
                continue
            seen.add(key)

            summary = osv_vuln.get("summary", "")
            details = osv_vuln.get("details", "")
            title = summary or short_title(details, 200) or cve

            measured = _osv_severity(osv_vuln)
            fix_version = _extract_fix_version(osv_vuln, pkg_name)

            # URL: prefer the first reference of type WEB or ADVISORY
            url = ""
            for ref in osv_vuln.get("references", []):
                ref_type = ref.get("type", "")
                if ref_type in ("WEB", "ADVISORY"):
                    url = ref.get("url", "")
                    break
            if not url:
                refs = osv_vuln.get("references", [])
                url = refs[0].get("url", "") if refs else ""

            vulns.append(
                Vulnerability(
                    cve=cve,
                    package=pkg_name,
                    version=pkg_version,
                    severity=measured or Severity.MODERATE,
                    title=short_title(title, 200),
                    url=url,
                    fix_version=fix_version,
                    is_direct=True,
                    severity_known=measured is not None,
                )
            )

    return vulns


class OsvScanner:
    """Standalone vulnerability scanner using lockfiles + OSV.dev."""

    name = "osv"

    @staticmethod
    def detect(project: Path) -> bool:
        """Detect if any supported lockfile exists."""
        return len(detect_lockfiles(project)) > 0

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]:
        """Parse pre-fetched OSV response. Not typically used directly."""
        # This would need the packages list context, so it's a no-op
        # for the JSON piping path. OSV is used via scan().
        return []

    @classmethod
    def scan_checked(cls, project: Path) -> list[Vulnerability]:
        """Like :meth:`scan`, but raise ScanError if any OSV.dev query fails.

        A partial or failed lookup must not read as "no vulnerabilities".
        """
        unreadable: list[str] = []
        packages = parse_lockfiles(project, unreadable)
        if unreadable:
            # Scanning the lockfiles that did parse would look like a full report.
            raise ScanError("could not read " + "; ".join(unreadable) + ".")
        if not packages:
            raise ScanError("found lockfiles but could not read any packages from them.")
        all_vulns: list[Vulnerability] = []
        for i in range(0, len(packages), 1000):
            batch = packages[i : i + 1000]
            try:
                response = query_osv_batch(batch)
            except (OSError, json.JSONDecodeError, urllib.error.URLError) as e:
                raise ScanError(f"could not reach OSV.dev ({e}).") from e
            all_vulns.extend(parse_osv_response(response, batch))
        return all_vulns

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]:
        """Scan lockfiles, raising ScanError instead of returning partial results."""
        if not cls.detect(project):
            return []
        return cls.scan_checked(project)
