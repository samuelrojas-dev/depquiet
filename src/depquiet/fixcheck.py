"""Ask uv's resolver whether each suggested fix can actually be installed.

A scanner says "update opentelemetry-api to 1.45.1". Whether that works
depends on everything else the project pins: on saleor it does not, because
saleor pins ``opentelemetry-semantic-conventions<0.59``, which requires
``opentelemetry-api==1.37.0``; and ``oauthlib 4.0.1`` is newer than saleor's own
``exclude-newer-package`` cut-off. ``uv lock --dry-run --upgrade-package
pkg==version`` answers that with uv's own resolver and writes nothing.

A blocked fix is not the end of the answer. The resolver's message says what
blocks it, and that decides the next step: a pin in your own pyproject
(change it), another package's pin (upgrade that package in the same step:
depquiet asks the resolver again with it, up to two rounds), a Python floor
older than the fix supports, or the project's own ``exclude-newer`` cooldown.

Opt-in (``--check-fixes``): one resolution per package, with network access
to the package index. Like any ``uv lock``, it may execute build hooks of the
project and its source distributions, so it is only for trusted checkouts.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depquiet.models import ScanResult, Verdict, clip, version_key

_PYTHON_MANAGERS = {"uv", "pip"}


@dataclass
class FixCheck:
    """The resolver's answer for one package upgrade."""

    status: str  # "resolves", "blocked" or "error"
    package: str
    version: str
    detail: str = ""
    # Why it is blocked: "own-pin", "dependency", "python", "cooldown" or "".
    reason: str = ""
    # What to do about it, in one sentence.
    next_step: str = ""
    # Packages that must be upgraded in the same step for the fix to resolve.
    also_upgrade: list[str] = field(default_factory=list)
    # ``name vOLD -> vNEW`` for every package that changes when it resolves.
    updates: list[str] = field(default_factory=list)
    # The lowest Python the fix supports ("3.11"), when that is what blocks it.
    python_floor: str = ""

    @property
    def command(self) -> str:
        extra = "".join(f" --upgrade-package {name}" for name in self.also_upgrade)
        return f"uv lock --upgrade-package {self.package}=={self.version}{extra}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "package": self.package,
            "version": self.version,
            "command": self.command,
            "detail": self.detail,
            "reason": self.reason,
            "next_step": self.next_step,
            "also_upgrade": self.also_upgrade,
            "updates": self.updates,
            "python_floor": self.python_floor or None,
        }


def fix_targets(result: ScanResult, *, include_filtered: bool = False) -> dict[str, str]:
    """Package -> the highest fixed version among its alerts still shown.

    That one upgrade clears every shown alert of the package. With
    ``include_filtered``, filtered alerts (development-only, test-only, ...)
    count too: depquiet says they need no action, but a scanner such as
    Dependabot keeps them open until the package moves.
    """
    targets: dict[str, str] = {}
    for package, version in _alert_targets(result, include_filtered=include_filtered):
        if package not in targets or version_key(version) > version_key(targets[package]):
            targets[package] = version
    return targets


def _alert_targets(result: ScanResult, *, include_filtered: bool = False) -> list[tuple[str, str]]:
    """(package, fix version) of every shown alert that has a Python fix."""
    pairs: list[tuple[str, str]] = []
    for finding in result.results:
        manager = finding.vuln.package_manager or result.package_manager
        if finding.verdict == Verdict.FILTERED and not include_filtered:
            continue
        if not finding.vuln.fix_version:
            continue
        if manager not in _PYTHON_MANAGERS or finding.vuln.fix_package:
            continue
        pairs.append((finding.vuln.package, finding.vuln.fix_version))
    return pairs


def _explain(stderr: str) -> str:
    """uv's ``hint:`` lines first (the actionable part), then its ``cause:`` lines."""
    hints: list[str] = []
    causes: list[str] = []
    current: list[str] | None = None
    for line in stderr.splitlines():
        stripped = line.strip()
        if stripped.startswith("hint:"):
            current = hints
            current.append(stripped[5:].strip())
        elif stripped.startswith("cause:"):
            current = causes
            current.append(stripped[6:].strip())
        elif stripped.startswith(("╰─▶", "├─▶")):
            # uv's graphical report (a terminal, or uv 0.11): the cause tree.
            current = causes
            current.append(stripped[3:].strip())
        elif current is not None and line.startswith((" ", "\t")) and stripped:
            current.append(stripped)
        else:
            current = None
    text = " ".join(hints + causes) or (stderr.strip().splitlines() or [""])[-1]
    return clip(re.sub(r"\s+", " ", text).strip(), 500)


_NAME = r"[A-Za-z0-9][A-Za-z0-9_.\-]*"
_EXTRA = r"(?:\[[^\]]*\])?"
_MARKER = r"(?:\{[^}]*\})?"
_SPEC = r"(?:==|>=|<=|!=|~=|<|>)[^\s,]*(?:,(?:==|>=|<=|!=|~=|<|>)[^\s,]*)*"
# A lock forked by Python version lists every locked version: ``v8.4.2, v9.2.0 -> v9.2.0``.
_UPDATE = re.compile(rf"Update ({_NAME}) (v[^\s,]+(?:, v[^\s,]+)* -> v\S+)", re.I)


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _own_pin(text: str, package: str, version: str) -> tuple[str, str] | None:
    """``posthog depends on aiohttp==3.13.5``: (``posthog``, ``==3.13.5``).

    A subject without a version is the project, a workspace member, or one of
    their extras or groups (``mlflow[extras]``, ``litellm:ci``). The request
    itself (``your project depends on aiohttp==<fix>``) is not a pin.
    """
    pattern = re.compile(
        rf"(?:Because |and )(your project|{_NAME}{_EXTRA}(?::{_NAME})?) depends on "
        rf"{re.escape(package)}{_EXTRA}{_MARKER}({_SPEC})",
        re.I,
    )
    for match in pattern.finditer(text):
        subject, spec = match.group(1), match.group(2)
        # The request itself, or a floor (``>=2.9.1``): neither holds an upgrade back.
        if spec == f"=={version}" or all(p.startswith(">") for p in spec.split(",")):
            continue
        return subject, spec
    return None


def _dependency_blockers(text: str, package: str, project_names: set[str]) -> list[str]:
    """Packages whose locked version pins ``package``: ``X==1.0 depends on package<2``."""
    pattern = re.compile(
        rf"({_NAME}){_EXTRA}{_MARKER}{_SPEC} depends? on {re.escape(package)}\b", re.I
    )
    names: list[str] = []
    for match in pattern.finditer(text):
        name = match.group(1)
        key = _pep503(name)
        if key != _pep503(package) and key not in project_names and name not in names:
            names.append(name)
    return names


def _lowest_python(spec: str) -> str:
    """``>=3.10`` → ``3.10``; ``>3.9.0`` → ``3.9.1``; an upper bound → "".

    uv writes ``>3.9.0`` for a package that excludes 3.9.0 itself
    (cryptography: ``>=3.9,!=3.9.0``): the lowest Python it takes is 3.9.1.
    """
    match = re.fullmatch(r"(>=|>)\s*(\d+(?:\.\d+)*)", spec.strip())
    if not match:
        return ""
    op, version = match.groups()
    if op == ">=":
        return version
    parts = version.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


_HINT = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+?) only supports ([<>=!~][^\s),]*)")


def _same_version(a: str, b: str) -> bool:
    """``4.0`` and ``4.0.0`` are the same release: uv's hint trims trailing zeros."""
    return re.sub(r"(\.0+)+$", "", a) == re.sub(r"(\.0+)+$", "", b)


def _python_hint(text: str, package: str, version: str) -> tuple[str | None, str] | None:
    """The Python range uv's hint says the fix needs: (None, spec) when it names the
    fix itself, (``name==version``, spec) when it names the package that limits it.

    uv writes ``soupsieve==4.0 only supports >=3.11.5`` for soupsieve 4.0.0, and for
    a transitive fix it can name a parent instead (``matplotlib==3.11.0 only
    supports >=3.11`` when only Python 3.11 matplotlibs take pillow 13): either
    way, that is the floor the fix needs.
    """
    hints = _HINT.findall(text)
    for name, ver, spec in hints:
        if _pep503(name) == _pep503(package) and _same_version(ver, version):
            return None, spec
    for name, ver, spec in hints:
        if _lowest_python(spec):
            return f"{name} {ver}", spec
    return None


def _classify(check: FixCheck, text: str) -> None:
    """Fill ``reason`` and ``next_step`` from the resolver's full message."""
    package, version = check.package, check.version
    if "filtered by `exclude-newer" in text:
        check.reason = "cooldown"
        check.next_step = (
            f"{package} {version} is newer than the project's exclude-newer cut-off: "
            "wait for the cut-off to pass, or exempt only this release (--fix-plan writes "
            "the exclude-newer-package entry)."
        )
        return
    floor = _python_hint(text, package, version)
    if floor:
        subject, spec = floor
        check.reason = "python"
        check.python_floor = _lowest_python(spec)
        needs = f"{package} {version}" if subject is None else f"{subject}, which it needs,"
        check.next_step = (
            f"{needs} only supports Python {spec}: raise "
            "requires-python, or limit the upgrade to those Python versions with a marker."
        )
        if check.python_floor:
            check.next_step += " --fix-plan checks whether raising it lets the fix install."
        return
    pin = _own_pin(text, package, version)
    if pin:
        subject, spec = pin
        owner = "your project" if subject == "your project" else subject
        check.reason = "own-pin"
        check.next_step = (
            f"{owner} requires {package}{spec}: widen that requirement to allow {version}."
        )


def _run_lock(
    project: Path, executable: str, specs: list[str], timeout: int
) -> tuple[int, str, str] | str:
    """``uv lock --dry-run`` with the upgrades: writes nothing."""
    return _lock(project, executable, specs, timeout, dry_run=True)


def _write_lock(
    project: Path, executable: str, specs: list[str], timeout: int
) -> tuple[int, str, str] | str:
    """``uv lock`` with the upgrades, written: only ever on a temporary copy."""
    return _lock(project, executable, specs, timeout, dry_run=False)


def _lock(
    project: Path, executable: str, specs: list[str], timeout: int, *, dry_run: bool
) -> tuple[int, str, str] | str:
    cmd = [executable, "lock", *(["--dry-run"] if dry_run else [])]
    for spec in specs:
        cmd += ["--upgrade-package", spec]
    try:
        r = subprocess.run(
            cmd,
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"uv lock timed out after {timeout} s."
    except OSError as e:
        return f"could not run uv lock: {e}"
    return r.returncode, r.stdout, r.stderr


def _updates(output: str) -> list[str]:
    return [f"{m.group(1)} {m.group(2)}" for m in _UPDATE.finditer(output)]


def check_fix(
    project: Path,
    package: str,
    version: str,
    *,
    timeout: int = 300,
    project_names: set[str] | None = None,
    rounds: int = 2,
) -> FixCheck:
    executable = shutil.which("uv")
    if executable is None:
        return FixCheck("error", package, version, "uv is not installed.")
    members = {_pep503(n) for n in project_names or set()}
    answer = _run_lock(project, executable, [f"{package}=={version}"], timeout)
    if isinstance(answer, str):
        return FixCheck("error", package, version, answer)
    code, stdout, stderr = answer
    output = f"{stdout}\n{stderr}"
    if code == 0:
        updates = _updates(output)
        mine = [u.split(" ", 1)[1] for u in updates if _pep503(u.split(" ")[0]) == _pep503(package)]
        return FixCheck("resolves", package, version, mine[0] if mine else "", updates=updates)
    if "No solution found" not in output:
        return FixCheck("error", package, version, _explain(stderr or stdout))
    check = FixCheck("blocked", package, version, _explain(stderr or stdout))
    _classify(check, stderr)
    if check.reason:
        return check
    # Another package's pin: ask again with it upgraded in the same step.
    extra: list[str] = []
    text = stderr
    for _ in range(rounds):
        new = [n for n in _dependency_blockers(text, package, members) if n not in extra]
        for name in extra:
            new += [n for n in _dependency_blockers(text, name, members) if n not in extra + new]
        if not new:
            break
        extra += new[: max(0, 4 - len(extra))]
        answer = _run_lock(project, executable, [f"{package}=={version}", *extra], timeout)
        if isinstance(answer, str):
            break
        code, stdout, stderr = answer
        if code == 0:
            check.status = "resolves"
            check.reason = "dependency"
            check.also_upgrade = list(extra)
            check.updates = _updates(f"{stdout}\n{stderr}")
            check.next_step = f"upgrade {', '.join(extra)} in the same step."
            return check
        if "No solution found" not in f"{stdout}\n{stderr}":
            break
        text = stderr
    if extra:
        check.reason = "dependency"
        check.also_upgrade = list(extra)
        # The retry's own answer often names the real wall: a pin on the blocker.
        for name in extra:
            pin = _own_pin(text, name, "")
            if pin:
                subject, spec = pin
                owner = "your project" if subject == "your project" else subject
                check.next_step = (
                    f"needs {name} upgraded too, but {owner} requires {name}{spec}: "
                    "widen that requirement."
                )
                break
        else:
            check.next_step = (
                f"needs {', '.join(extra)} upgraded too, and that does not resolve either."
            )
    return check


def check_fixes(
    result: ScanResult, project: Path, *, include_filtered: bool = False
) -> tuple[dict[str, FixCheck], str]:
    """Check every shown alert's fix; returns (checks by package, note)."""
    targets = fix_targets(result, include_filtered=include_filtered)
    if not targets:
        return {}, ""
    # The project's lockfile first: on a project without one, installing uv
    # would not help, so "needs uv on PATH" would send the user the wrong way.
    if not (project / "uv.lock").exists():
        return {}, (
            "--check-fixes works on projects with a uv.lock (on a Poetry project, "
            "--fix-plan verifies the fixes). On npm, --fix installs the fixes."
        )
    if shutil.which("uv") is None:
        return {}, "--check-fixes needs uv on PATH."
    names = _project_names(project)
    checks = {
        pkg: check_fix(project, pkg, version, project_names=names)
        for pkg, version in sorted(targets.items())
    }
    # An alert fixed in a lower version than its package's highest fix gets
    # its own answer when the highest is blocked: a backport (0.3.81 next to
    # 1.2.22) may install where the newest line does not.
    answers = {(pkg, check.version): check for pkg, check in checks.items()}
    for pair in sorted(set(_alert_targets(result, include_filtered=include_filtered))):
        package, version = pair
        if pair not in answers:
            if checks[package].status == "resolves":
                answers[pair] = checks[package]
            else:
                answers[pair] = check_fix(project, package, version, project_names=names)
    for finding in result.results:
        pair = (finding.vuln.package, finding.vuln.fix_version)
        if pair in answers and (include_filtered or finding.verdict != Verdict.FILTERED):
            finding.fix_check = answers[pair]
    return checks, ""


def _project_names(project: Path) -> set[str]:
    """Workspace members in ``uv.lock``: their names never need an upgrade."""
    try:
        text = (project / "uv.lock").read_text(encoding="utf-8")
    except OSError:
        return set()
    names = set()
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        source = re.search(r"^source = \{ (editable|virtual) =", block, re.M)
        if name and source:
            names.add(name.group(1))
    return names
