"""License compliance analysis — detect OSS license risk in dependencies.

Classifies dependency licenses into risk categories and flags copyleft
contamination in proprietary projects. Supports npm (package.json) and
Python projects.

Python: the packages are the project's locked ones (``uv.lock``,
``poetry.lock``, ``pdm.lock`` or fully pinned requirement files), never the
environment depquiet itself runs in. Each license comes from the project's
own virtual environment (``.venv``, ``venv``, ``env``: the METADATA files are
read, nothing is executed) when it holds that exact version, else from PyPI's
JSON API for that version. Offline, or when PyPI has no answer, the license is
UNKNOWN, which fails the check: an unread license is not a permissive one.

Usage::

    depquiet --license              # scan + license report
    depquiet --license --json       # machine-readable output
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class LicenseRisk(Enum):
    """License risk level for enterprise compliance."""

    LOW = "low"  # MIT, BSD, Apache-2.0, ISC, Unlicense
    MEDIUM = "medium"  # LGPL, MPL, EPL, CDDL (weak copyleft)
    HIGH = "high"  # GPL-2.0, GPL-3.0 (strong copyleft)
    CRITICAL = "critical"  # AGPL, SSPL, BUSL (network copyleft / source-available)
    UNKNOWN = "unknown"  # Unrecognized or missing license


# SPDX ID -> risk mapping.  Covers the most common ~60 licenses.
_LICENSE_RISK: dict[str, LicenseRisk] = {
    # -- LOW (permissive) --
    "MIT": LicenseRisk.LOW,
    "MIT-0": LicenseRisk.LOW,
    "ISC": LicenseRisk.LOW,
    "BSD-2-Clause": LicenseRisk.LOW,
    "BSD-3-Clause": LicenseRisk.LOW,
    "Apache-2.0": LicenseRisk.LOW,
    "Unlicense": LicenseRisk.LOW,
    "0BSD": LicenseRisk.LOW,
    "CC0-1.0": LicenseRisk.LOW,
    "Zlib": LicenseRisk.LOW,
    "BSL-1.0": LicenseRisk.LOW,
    "PSF-2.0": LicenseRisk.LOW,
    "Python-2.0": LicenseRisk.LOW,
    "BlueOak-1.0.0": LicenseRisk.LOW,
    "Artistic-2.0": LicenseRisk.LOW,
    "CC-BY-4.0": LicenseRisk.LOW,
    "CC-BY-3.0": LicenseRisk.LOW,
    "WTFPL": LicenseRisk.LOW,
    # -- MEDIUM (weak copyleft) --
    "LGPL-2.1": LicenseRisk.MEDIUM,
    "LGPL-2.1-only": LicenseRisk.MEDIUM,
    "LGPL-2.1-or-later": LicenseRisk.MEDIUM,
    "LGPL-3.0": LicenseRisk.MEDIUM,
    "LGPL-3.0-only": LicenseRisk.MEDIUM,
    "LGPL-3.0-or-later": LicenseRisk.MEDIUM,
    "MPL-2.0": LicenseRisk.MEDIUM,
    "EPL-1.0": LicenseRisk.MEDIUM,
    "EPL-2.0": LicenseRisk.MEDIUM,
    "CDDL-1.0": LicenseRisk.MEDIUM,
    "CDDL-1.1": LicenseRisk.MEDIUM,
    "CPL-1.0": LicenseRisk.MEDIUM,
    "CC-BY-SA-4.0": LicenseRisk.MEDIUM,
    "CC-BY-SA-3.0": LicenseRisk.MEDIUM,
    # -- HIGH (strong copyleft) --
    "GPL-2.0": LicenseRisk.HIGH,
    "GPL-2.0-only": LicenseRisk.HIGH,
    "GPL-2.0-or-later": LicenseRisk.HIGH,
    "GPL-3.0": LicenseRisk.HIGH,
    "GPL-3.0-only": LicenseRisk.HIGH,
    "GPL-3.0-or-later": LicenseRisk.HIGH,
    # -- CRITICAL (network copyleft / source-available) --
    "AGPL-3.0": LicenseRisk.CRITICAL,
    "AGPL-3.0-only": LicenseRisk.CRITICAL,
    "AGPL-3.0-or-later": LicenseRisk.CRITICAL,
    "SSPL-1.0": LicenseRisk.CRITICAL,
    "BUSL-1.1": LicenseRisk.CRITICAL,
    "Elastic-2.0": LicenseRisk.CRITICAL,
    "Commons-Clause": LicenseRisk.CRITICAL,
}

# Common non-SPDX license strings -> normalized SPDX ID
_LICENSE_ALIASES: dict[str, str] = {
    "apache-2.0 license": "Apache-2.0",
    "apache 2.0 license": "Apache-2.0",
    "mit license": "MIT",
    "mit": "MIT",
    "isc": "ISC",
    "bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "gpl-2.0": "GPL-2.0",
    "gpl-3.0": "GPL-3.0",
    "gplv2": "GPL-2.0",
    "gplv3": "GPL-3.0",
    "gnu general public license v2": "GPL-2.0",
    "gnu general public license v3": "GPL-3.0",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl-3.0": "LGPL-3.0",
    "lgplv2.1": "LGPL-2.1",
    "lgplv3": "LGPL-3.0",
    "agpl-3.0": "AGPL-3.0",
    "mpl-2.0": "MPL-2.0",
    "unlicense": "Unlicense",
    "public domain": "Unlicense",
    "cc0-1.0": "CC0-1.0",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    "artistic-2.0": "Artistic-2.0",
    "0bsd": "0BSD",
    "wtfpl": "WTFPL",
    "zlib": "Zlib",
}


@dataclass
class LicenseInfo:
    """License information for a single package."""

    package: str
    version: str
    license_id: str  # SPDX ID or raw string
    license_raw: str  # Original string from the package manager
    risk: LicenseRisk


@dataclass
class LicenseReport:
    """Aggregate license compliance report."""

    packages: list[LicenseInfo] = field(default_factory=list)
    project_path: str = ""
    package_manager: str = ""
    # Why part of the project could not be checked (no lockfile, ...).
    notes: list[str] = field(default_factory=list)

    @property
    def low(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.LOW]

    @property
    def medium(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.MEDIUM]

    @property
    def high(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.HIGH]

    @property
    def critical(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.CRITICAL]

    @property
    def unknown(self) -> list[LicenseInfo]:
        return [p for p in self.packages if p.risk == LicenseRisk.UNKNOWN]

    @property
    def has_issues(self) -> bool:
        """True if any HIGH, CRITICAL, or UNKNOWN licenses found, or a part was not checked."""
        return bool(self.high or self.critical or self.unknown or self.notes)


_RISK_ORDER = [
    LicenseRisk.LOW,
    LicenseRisk.MEDIUM,
    LicenseRisk.HIGH,
    LicenseRisk.CRITICAL,
    LicenseRisk.UNKNOWN,
]


def classify_license(raw: str) -> tuple[str, LicenseRisk]:
    """Classify a license string into an SPDX ID and risk level.

    Handles SPDX expressions (e.g., "MIT OR Apache-2.0") by taking the
    most permissive option (lowest risk). For AND expressions, takes the
    most restrictive (highest risk).
    """
    if not raw or raw.strip().lower() in ("none", "unknown", "unlicensed", "custom"):
        return raw or "UNKNOWN", LicenseRisk.UNKNOWN

    stripped = raw.strip()

    # Try direct SPDX match first
    if stripped in _LICENSE_RISK:
        return stripped, _LICENSE_RISK[stripped]

    # Try alias lookup
    lower = stripped.lower()
    if lower in _LICENSE_ALIASES:
        spdx = _LICENSE_ALIASES[lower]
        return spdx, _LICENSE_RISK[spdx]

    # Handle SPDX OR expressions — pick lowest risk (most permissive)
    risk_order = _RISK_ORDER
    if " OR " in stripped:
        parts = [p.strip().strip("()") for p in stripped.split(" OR ")]
        best_id = stripped
        best_risk = LicenseRisk.UNKNOWN
        for part in parts:
            pid, prisk = classify_license(part)
            if risk_order.index(prisk) < risk_order.index(best_risk):
                best_id = pid
                best_risk = prisk
        return best_id, best_risk

    # Handle SPDX AND expressions — pick highest risk (most restrictive)
    if " AND " in stripped:
        parts = [p.strip().strip("()") for p in stripped.split(" AND ")]
        worst_id = stripped
        worst_risk = LicenseRisk.LOW
        for part in parts:
            pid, prisk = classify_license(part)
            if risk_order.index(prisk) > risk_order.index(worst_risk):
                worst_id = pid
                worst_risk = prisk
        return worst_id, worst_risk

    return stripped, LicenseRisk.UNKNOWN


def scan_npm_licenses(project: Path) -> list[LicenseInfo]:
    """Extract license info from npm dependencies."""
    package_json = project / "package.json"
    if not package_json.exists():
        return []

    node_modules = project / "node_modules"
    if not node_modules.exists():
        return []

    results: list[LicenseInfo] = []

    for pkg_dir in sorted(node_modules.iterdir()):
        if pkg_dir.name.startswith("."):
            continue

        # Handle scoped packages (@scope/name)
        if pkg_dir.name.startswith("@") and pkg_dir.is_dir():
            for scoped_dir in sorted(pkg_dir.iterdir()):
                info = _read_npm_package_license(scoped_dir, f"{pkg_dir.name}/{scoped_dir.name}")
                if info:
                    results.append(info)
        else:
            info = _read_npm_package_license(pkg_dir, pkg_dir.name)
            if info:
                results.append(info)

    return results


def _read_npm_package_license(pkg_dir: Path, name: str) -> LicenseInfo | None:
    """Read license from a single npm package's package.json."""
    pkg_json = pkg_dir / "package.json"
    if not pkg_json.exists():
        return None

    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    version = data.get("version", "0.0.0")
    raw_license = ""

    # npm supports both "license" (string) and "licenses" (array of objects)
    if "license" in data:
        lic = data["license"]
        if isinstance(lic, str):
            raw_license = lic
        elif isinstance(lic, dict):
            raw_license = lic.get("type", "")
    elif "licenses" in data:
        lics = data["licenses"]
        if isinstance(lics, list):
            parts = []
            for item in lics:
                if isinstance(item, dict) and "type" in item:
                    parts.append(item["type"])
                elif isinstance(item, str):
                    parts.append(item)
            raw_license = " OR ".join(parts) if parts else ""

    if not raw_license:
        raw_license = "UNKNOWN"

    license_id, risk = classify_license(raw_license)
    return LicenseInfo(
        package=name,
        version=version,
        license_id=license_id,
        license_raw=raw_license,
        risk=risk,
    )


def scan_pip_licenses(
    project: Path, *, offline: bool = False, notes: list[str] | None = None
) -> list[LicenseInfo]:
    """Licenses of the project's locked Python packages (see the module docstring)."""
    locked = locked_python_packages(project)
    if locked is None:
        if notes is not None:
            notes.append(
                "Python: no uv.lock, poetry.lock, pdm.lock or fully pinned requirements "
                "file, so the dependency list (and its licenses) is not known."
            )
        return []
    installed = _venv_licenses(project)
    missing = [(n, v) for n, v in locked if installed.get(_pep503(n), ("", ""))[0] != v]
    fetched = {} if offline else _pypi_licenses(missing)
    results: list[LicenseInfo] = []
    for name, version in locked:
        key = _pep503(name)
        if installed.get(key, ("", ""))[0] == version:
            raw = installed[key][1]
        elif (key, version) in fetched:
            raw = fetched[(key, version)]
        else:
            raw = "UNKNOWN"
        license_id, risk = classify_license(raw)
        if raw == "UNKNOWN":
            why = "not in the project environment; " + (
                "PyPI not consulted (--offline)" if offline else "PyPI gave no license"
            )
            license_id, raw = "UNKNOWN", why
        results.append(
            LicenseInfo(
                package=name, version=version, license_id=license_id, license_raw=raw, risk=risk
            )
        )
    return results


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_python_packages(project: Path) -> list[tuple[str, str]] | None:
    """(name, version) of every locked package, or None without a lock/pins."""
    for lock in ("uv.lock", "poetry.lock", "pdm.lock"):
        path = project / lock
        if not path.is_file():
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        found: dict[str, tuple[str, str]] = {}
        for pkg in data.get("package", []):
            if not isinstance(pkg, dict):
                continue
            name, version = pkg.get("name"), pkg.get("version")
            source = pkg.get("source") or {}
            # The project itself and workspace members are not dependencies.
            if isinstance(source, dict) and ("editable" in source or "virtual" in source):
                continue
            if isinstance(name, str) and isinstance(version, str) and version:
                found.setdefault(f"{_pep503(name)}=={version}", (name, version))
        return sorted(found.values())

    from depquiet.scanners import pinned_requirements, requirement_files

    pins: dict[str, tuple[str, str]] = {}
    for req in requirement_files(project):
        parsed = pinned_requirements(req)
        if parsed is None:
            continue
        for pin in parsed[0]:
            name, _, version = pin.partition("==")
            pins.setdefault(pin, (name, version))
    return sorted(pins.values()) if pins else None


def _venv_licenses(project: Path) -> dict[str, tuple[str, str]]:
    """normalized name -> (version, license) from the project's own virtualenv."""
    from email.parser import Parser

    found: dict[str, tuple[str, str]] = {}
    for env in (".venv", "venv", "env"):
        root = project / env
        if not (root / "pyvenv.cfg").is_file():
            continue
        for meta in [
            *root.glob("lib/python*/site-packages/*.dist-info/METADATA"),
            *root.glob("Lib/site-packages/*.dist-info/METADATA"),
        ]:
            try:
                msg = Parser().parsestr(meta.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            name, version = msg.get("Name"), msg.get("Version")
            if name and version:
                found.setdefault(
                    _pep503(name),
                    (
                        version,
                        _license_of(
                            msg.get("License-Expression"),
                            msg.get("License"),
                            msg.get_all("Classifier") or [],
                        ),
                    ),
                )
    return found


def _license_of(expression: str | None, text: str | None, classifiers: list[str]) -> str:
    """PEP 639 expression, else a short License field, else the OSI classifier."""
    if expression and expression.strip():
        return expression.strip()
    # The License field sometimes holds the whole license text: not an id.
    osi = [
        _classifier_to_spdx(c) for c in classifiers if c.startswith("License :: OSI Approved :: ")
    ]
    short = (text or "").strip()
    if (
        short
        and short.lower() not in ("unknown", "none")
        and "\n" not in short
        and len(short) <= 80
    ):
        # A free-text field such as "Dual License" names no license; the
        # classifiers do. Several are joined with AND, so the most
        # restrictive one sets the risk (never an understated one).
        if classify_license(short)[1] is LicenseRisk.UNKNOWN and osi:
            return " AND ".join(dict.fromkeys(osi))
        return short
    if osi:
        return " AND ".join(dict.fromkeys(osi))
    return "UNKNOWN"


def _pypi_licenses(packages: list[tuple[str, str]]) -> dict[tuple[str, str], str]:
    """(normalized name, version) -> license, from PyPI's JSON API."""
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor

    def one(item: tuple[str, str]) -> tuple[tuple[str, str], str]:
        name, version = item
        url = f"https://pypi.org/pypi/{name}/{version}/json"
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                info = json.load(response).get("info") or {}
        except (OSError, ValueError):
            return (_pep503(name), version), "UNKNOWN"
        return (_pep503(name), version), _license_of(
            info.get("license_expression"), info.get("license"), info.get("classifiers") or []
        )

    if not packages:
        return {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(one, packages))


def _classifier_to_spdx(classifier: str) -> str:
    """Convert a PyPI classifier to an approximate SPDX ID."""
    mapping: dict[str, str] = {
        "MIT License": "MIT",
        "BSD License": "BSD-3-Clause",
        "Apache Software License": "Apache-2.0",
        "ISC License (ISCL)": "ISC",
        "GNU General Public License v2 (GPLv2)": "GPL-2.0",
        "GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
        "GNU General Public License v3 (GPLv3)": "GPL-3.0",
        "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
        "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.1",
        "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
        "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
        "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
        "GNU Affero General Public License v3": "AGPL-3.0",
        "GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
        "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "Eclipse Public License 1.0 (EPL-1.0)": "EPL-1.0",
        "Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
        "The Unlicense (Unlicense)": "Unlicense",
        "Public Domain": "Unlicense",
        "Python Software Foundation License": "PSF-2.0",
        "Artistic License": "Artistic-2.0",
        "Zlib License": "Zlib",
    }
    suffix = classifier.replace("License :: OSI Approved :: ", "")
    return mapping.get(suffix, suffix)


def scan_licenses(
    project: Path, package_manager: str | None = None, *, offline: bool = False
) -> LicenseReport:
    """Run a license scan on a project.

    Args:
        project: Path to the project root.
        package_manager: Force a specific package manager ("npm" or "pip").
                        Auto-detects if None.

    Returns:
        LicenseReport with all dependency license info.
    """
    pm = package_manager

    if pm is None:
        if (project / "package.json").exists():
            pm = "npm"
        elif any(
            (project / f).exists() for f in ("requirements.txt", "setup.py", "pyproject.toml")
        ):
            pm = "pip"
        else:
            pm = "unknown"

    # "npm+pip" from a scan that merged ecosystems: report each one's licenses.
    packages = []
    notes: list[str] = []
    for manager in pm.split("+"):
        if manager in ("npm", "pnpm"):
            packages += scan_npm_licenses(project)
        elif manager in ("pip", "uv"):
            packages += scan_pip_licenses(project, offline=offline, notes=notes)

    return LicenseReport(
        packages=packages,
        project_path=str(project),
        package_manager=pm,
        notes=notes,
    )


def print_license_report(report: LicenseReport) -> None:
    """Print a human-readable license compliance report to stderr."""
    for note in report.notes:
        print(f"\n  Not checked: {note}", file=sys.stderr)
    if not report.packages:
        print("\nNo dependencies found for license analysis.", file=sys.stderr)
        if report.notes:
            print("  License compliance: NOT CHECKED", file=sys.stderr)
        return

    total = len(report.packages)
    print(f"\ndepquiet license scan — {report.package_manager} ({total} packages)", file=sys.stderr)
    print(file=sys.stderr)

    if report.critical:
        n = len(report.critical)
        print(f"  {n} CRITICAL (AGPL/SSPL/BUSL)", file=sys.stderr)
        for p in report.critical:
            print(f"     {p.package}@{p.version}  {p.license_id}", file=sys.stderr)
        print(file=sys.stderr)

    if report.high:
        print(f"  {len(report.high)} HIGH (GPL — strong copyleft)", file=sys.stderr)
        for p in report.high:
            print(f"     {p.package}@{p.version}  {p.license_id}", file=sys.stderr)
        print(file=sys.stderr)

    if report.medium:
        print(f"  {len(report.medium)} MEDIUM (LGPL/MPL — weak copyleft)", file=sys.stderr)
        for p in report.medium:
            print(f"     {p.package}@{p.version}  {p.license_id}", file=sys.stderr)
        print(file=sys.stderr)

    if report.unknown:
        print(f"  {len(report.unknown)} UNKNOWN (review manually)", file=sys.stderr)
        for p in report.unknown:
            raw = f"  ({p.license_raw})" if p.license_raw and p.license_raw != "UNKNOWN" else ""
            print(f"     {p.package}@{p.version}{raw}", file=sys.stderr)
        print(file=sys.stderr)

    print(f"  {len(report.low)} LOW (permissive — MIT, BSD, Apache, etc.)", file=sys.stderr)
    print(file=sys.stderr)

    if report.has_issues:
        print(
            "  License compliance: FAIL — review HIGH/CRITICAL/UNKNOWN packages "
            "(and anything not checked) above",
            file=sys.stderr,
        )
    else:
        print("  License compliance: PASS", file=sys.stderr)
