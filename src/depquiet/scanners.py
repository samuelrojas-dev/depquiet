"""Run the scanners depquiet invokes itself, and fail loudly when they can't.

A scanner that isn't installed, can't reach its database, or returns an error
must never look like "no vulnerabilities". Each runner here returns the
scanner's report or raises :class:`ScanError`; the engine then tries the
OSV.dev fallback and, if that fails too, reports the project as not scanned.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ScanError(Exception):
    """The scanner couldn't produce a report. The message says why and what to do."""


def _tail(text: str, limit: int = 300) -> str:
    # A Python traceback ends with the error itself; the frames before it are
    # noise in a one-line message ("requests.exceptions.ReadTimeout: ...").
    if "Traceback (most recent call last)" in text:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if lines:
            return lines[-1][-limit:]
    text = " ".join(text.split())
    return text[-limit:] if text else "no output"


def run_npm_audit(project: Path) -> dict[str, Any]:
    project = project.resolve()
    executable = shutil.which("npm")
    if executable is None:
        raise ScanError("npm is not installed or not on PATH.")
    try:
        r = subprocess.run(
            [executable, "audit", "--json"],
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError("npm audit timed out after 180 s.") from e
    except OSError as e:
        raise ScanError(f"could not run npm audit: {e}") from e
    try:
        data = json.loads(r.stdout) if r.stdout else {}
    except json.JSONDecodeError as e:
        raise ScanError(f"npm audit returned invalid JSON: {_tail(r.stderr or r.stdout)}") from e
    if (
        r.returncode not in (0, 1)
        or not isinstance(data, dict)
        or "error" in data
        or not isinstance(data.get("vulnerabilities"), dict)
    ):
        err = data.get("error") if isinstance(data, dict) else None
        summary = err.get("summary") if isinstance(err, dict) else None
        raise ScanError(f"npm audit failed: {summary or _tail(r.stderr)}")
    return data


def run_pnpm_audit(project: Path) -> dict[str, Any]:
    project = project.resolve()
    executable = shutil.which("pnpm")
    if executable is None:
        raise ScanError("pnpm is not installed or not on PATH.")
    try:
        r = subprocess.run(
            [executable, "audit", "--json"],
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError("pnpm audit timed out after 180 s.") from e
    except OSError as e:
        raise ScanError(f"could not run pnpm audit: {e}") from e
    try:
        data = json.loads(r.stdout) if r.stdout else {}
    except json.JSONDecodeError as e:
        raise ScanError(f"pnpm audit returned invalid JSON: {_tail(r.stderr or r.stdout)}") from e
    if (
        r.returncode not in (0, 1)
        or not isinstance(data, dict)
        or "error" in data
        or not isinstance(data.get("advisories"), dict)
    ):
        err = data.get("error") if isinstance(data, dict) else None
        message = err.get("message") if isinstance(err, dict) else None
        raise ScanError(f"pnpm audit failed: {message or _tail(r.stderr)}")
    return data


def lock_pins(lockfile: Path) -> tuple[list[str], list[str]]:
    """``name==version`` for every registry package in a uv.lock / poetry.lock.

    Local, path and git packages are skipped (nothing to look up). When a
    lockfile pins one name to several versions (platform markers, e.g. torch
    cpu/cuda), pip-audit rejects the duplicates, so the first pins and additional
    variants are returned separately. Callers must audit both lists.
    """
    data = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    pins: dict[str, str] = {}
    variants: list[str] = []
    seen: set[str] = set()
    for pkg in data.get("package") or []:
        source = pkg.get("source") or {}
        if any(k in source for k in ("virtual", "editable", "directory", "path", "git")):
            continue
        if source.get("type") in ("directory", "git", "file", "url"):
            continue
        name, version = re.sub(r"[-_.]+", "-", pkg["name"]).lower(), pkg["version"]
        pin = f"{name}=={version}"
        if pin in seen:
            continue
        seen.add(pin)
        if name in pins:
            variants.append(pin)
            continue
        pins[name] = version
    return [f"{n}=={v}" for n, v in sorted(pins.items())], variants


_PIN_LINE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*(?:;.*)?$"
)
# Options that neither add a requirement nor change which version is installed.
_NEUTRAL_OPTIONS = (
    "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
    "--no-binary", "--only-binary", "--prefer-binary", "--trusted-host", "--pre",
    "--require-hashes", "--use-feature", "--no-index",
)  # fmt: skip
_TOOLING_WORDS = frozenset(
    [
        "dev",
        "develop",
        "development",
        "test",
        "tests",
        "testing",
        "lint",
        "docs",
        "doc",
        "typing",
        "ci",
        "bench",
        "benchmark",
        "coverage",
        "qa",
        "debug",
        "precommit",
    ]
)


def _requirement_lines(path: Path) -> list[str]:
    """Logical lines of a requirements file: continuations joined, comments dropped."""
    lines: list[str] = []
    pending = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = pending + raw.strip()
        if line.endswith("\\"):
            pending = line[:-1].rstrip() + " "
            continue
        pending = ""
        line = re.split(r"(?:^|\s)#", line, maxsplit=1)[0].strip()
        if line:
            lines.append(line)
    return lines


def pinned_requirements(
    path: Path, unpinned: list[str] | None = None
) -> tuple[list[str], list[Path]] | None:
    """Exact pins of a requirements file, when exact pins are all it holds.

    Returns ``(pins, included files)`` for a file made of ``name==version``
    lines, the output of ``pip-compile``, ``uv pip compile`` or ``pip freeze``.
    Such a file can be audited as written, with no resolver run. Returns
    ``None`` when any requirement is a range, a bare name or a wildcard:
    what gets installed then depends on resolution. Editable, URL and path
    entries have no registry version to look up and are left out.

    With ``unpinned`` given, a requirement that is not an exact pin is
    appended to it instead of failing the file, and the exact pins are still
    returned: a partial list, for when pip cannot resolve the file at all.
    """
    pins: list[str] = []
    includes: list[Path] = []
    for line in _requirement_lines(path):
        line = re.sub(r"\s+--hash[= ]\S+", "", line).strip()
        if line.startswith(("-r", "--requirement")):
            target = line.split(None, 1)[1] if " " in line else line[2:]
            includes.append((path.parent / target.strip()).resolve())
        elif (
            line.startswith(("-e", "--editable"))
            or "://" in line
            or " @ " in line
            or line.startswith(("./", "../", "/"))
        ):
            continue
        elif line.startswith("-"):
            if not line.startswith(_NEUTRAL_OPTIONS):
                return None
        else:
            match = _PIN_LINE.match(line)
            if match is None and unpinned is not None:
                unpinned.append(re.split(r"[\s<>=!~;\[]", line, maxsplit=1)[0])
                continue
            if match is None:
                return None
            name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
            pins.append(f"{name}=={match.group(2)}")
    return pins, includes


def is_tooling_requirements(path: Path) -> bool:
    """``requirements-dev.txt``, ``requirements/test.txt``, ``docs.txt``: yes."""
    stem = path.stem.lower().replace("pre-commit", "precommit").replace("pre_commit", "precommit")
    return any(word in _TOOLING_WORDS for word in re.split(r"[^a-z0-9]+", stem))


def requirement_files(project: Path) -> list[Path]:
    """Requirement files of a project that keeps no lockfile, root file first.

    ``requirements.txt`` and ``requirements*.txt`` at the root, and the
    ``requirements/*.txt`` layout (``base.txt``, ``production.txt``, ...).
    """
    found = sorted(p for p in project.glob("requirements*.txt") if p.is_file())
    folder = project / "requirements"
    if folder.is_dir():
        found += sorted(p for p in folder.glob("*.txt") if p.is_file())
    root = project / "requirements.txt"
    return ([root] if root in found else []) + [p for p in found if p != root]


@dataclass
class _RequirementPlan:
    """How the requirement files of a project are audited."""

    # Exact pins from compiled files: the whole closure, audited as written.
    pins: list[str] = field(default_factory=list)
    # Files pip has to resolve, each with the pins to fall back on (if any).
    resolve: list[tuple[Path, list[str]]] = field(default_factory=list)
    # Requirements in a resolved file that are not exact pins, by file.
    unpinned: dict[Path, list[str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def is_compiled_requirements(path: Path) -> bool:
    """Whether the file is a resolver's output, listing transitive packages too.

    ``pip-compile`` and ``uv pip compile`` annotate each pin with ``# via`` and
    sign the header; hash-checking files cannot omit a package. A hand-kept
    ``django==4.2`` file has none of these and may list top-level packages only.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return "# via" in text or "--hash=" in text or "autogenerated by" in text[:400].lower()


def _plan_requirements(project: Path) -> _RequirementPlan:
    plan = _RequirementPlan()
    files = requirement_files(project)
    audited = [f for f in files if not is_tooling_requirements(f)] or files
    skipped = [f for f in files if f not in audited]
    root = project / "requirements.txt"
    left_out: list[Path] = []
    partial: list[Path] = []
    queue, seen = list(audited), set()
    while queue:
        path = queue.pop(0)
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            parsed = pinned_requirements(path)
        except (OSError, UnicodeDecodeError):
            parsed = None
        if parsed is not None:
            queue += [p for p in parsed[1] if p.is_relative_to(project)]
        if parsed is not None and is_compiled_requirements(path):
            plan.pins += parsed[0]
        elif path == root or (root not in audited and parsed is None):
            # pip resolves it, so transitive packages are audited too. If
            # resolution fails, the pins it lists are still worth auditing.
            loose: list[str] = []
            try:
                lenient = pinned_requirements(path, loose)
            except (OSError, UnicodeDecodeError):
                lenient = None
            plan.resolve.append((path, lenient[0] if lenient else []))
            plan.unpinned[path] = loose
        elif parsed is not None:
            plan.pins += parsed[0]
            partial.append(path)
        else:
            left_out.append(path)

    def names(paths: list[Path]) -> str:
        return ", ".join(p.relative_to(project).as_posix() for p in paths)

    if skipped:
        plan.notes.append(f"Development requirement files were not audited: {names(skipped)}.")
    if partial:
        plan.notes.append(
            f"Audited the pinned versions listed in {names(partial)}; packages they pull "
            "in without listing were not resolved."
        )
    if left_out:
        plan.notes.append(f"Not audited, because not fully pinned: {names(left_out)}.")
    plan.pins = list(dict.fromkeys(plan.pins))
    return plan


def _pin_batches(pins: list[str]) -> list[list[str]]:
    """Keep each locked version, with at most one version per name per audit."""
    batches: list[list[str]] = []
    names: list[set[str]] = []
    for pin in pins:
        name = pin.split("==", 1)[0]
        for batch, batch_names in zip(batches, names, strict=True):
            if name not in batch_names:
                batch.append(pin)
                batch_names.add(name)
                break
        else:
            batches.append([pin])
            names.append({name})
    return batches


def run_uv_audit(project: Path) -> dict[str, Any]:
    """``uv audit`` on the project's ``uv.lock``, as written (``--frozen``).

    uv includes every group and extra by default (it only has ``--no-*``
    options), so the report covers the whole lockfile and the triage decides
    what is development-only.
    """
    project = project.resolve()
    executable = shutil.which("uv")
    if executable is None:
        raise ScanError("uv is not installed.")
    if not (project / "uv.lock").exists():
        raise ScanError("uv audit needs a uv.lock.")
    cmd = [
        executable,
        "audit",
        "--frozen",
        "--output-format",
        "json",
        "--preview-features",
        "audit-command,json-output",
    ]
    try:
        r = subprocess.run(
            cmd,
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError("uv audit timed out after 600 s.") from e
    except OSError as e:
        raise ScanError(f"could not run uv audit: {e}") from e
    try:
        data = json.loads(r.stdout) if r.stdout else None
    except ValueError:
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ScanError(f"uv audit failed: {_tail(r.stderr)}")
    return data


def run_pip_audit(project: Path) -> dict[str, Any]:
    """Audit the *project's* dependencies, never the environment depquiet runs in.

    uv.lock / poetry.lock: every pinned version, without resolving or installing
    (``--no-deps --disable-pip``). Requirement files: the same when they are
    fully pinned, otherwise pip-audit resolves ``requirements.txt``.
    pyproject.toml only: pip-audit resolves the local project.
    """
    project = project.resolve()
    executable = shutil.which("pip-audit")
    if executable is None:
        raise ScanError("pip-audit is not installed (pip install pip-audit).")
    with tempfile.TemporaryDirectory() as tmp:
        # (pip-audit arguments, pins to audit instead if those arguments fail)
        targets: list[tuple[list[str], list[str]]] = []
        notes: list[str] = []
        loose_by_file: dict[str, list[str]] = {}
        counter = 0

        def pin_targets(pins: list[str]) -> list[list[str]]:
            nonlocal counter
            written = []
            for batch in _pin_batches(pins):
                req = Path(tmp) / f"requirements-{counter}.txt"
                counter += 1
                req.write_text("\n".join(batch) + "\n", encoding="utf-8")
                written.append(["-r", str(req), "--no-deps", "--disable-pip"])
            return written

        lock = next(
            (project / n for n in ("uv.lock", "poetry.lock") if (project / n).exists()), None
        )
        if lock is not None:
            try:
                pins, variants = lock_pins(lock)
            except (ValueError, KeyError, OSError) as e:
                raise ScanError(f"could not read {lock.name}: {e}") from e
            targets = [(args, []) for args in pin_targets(pins + variants)]
            if not targets:
                raise ScanError(f"found no registry packages to audit in {lock.name}.")
        elif requirement_files(project):
            plan = _plan_requirements(project)
            notes = plan.notes
            targets = [(args, []) for args in pin_targets(plan.pins)]
            targets += [(["-r", str(path)], fallback) for path, fallback in plan.resolve]
            loose_by_file = {str(path): names for path, names in plan.unpinned.items()}
            if not targets:
                raise ScanError("the requirement files list no registry packages to audit.")
        elif (project / "pyproject.toml").exists():
            targets.append(([str(project)], []))
        else:
            raise ScanError(
                "no uv.lock, poetry.lock, requirements file or pyproject.toml to audit."
            )

        def audit(args: list[str]) -> dict[str, Any]:
            nonlocal counter
            out = Path(tmp) / f"audit-{counter}.json"
            counter += 1
            cmd = [executable, *args, "-f", "json", "--progress-spinner", "off", "-o", str(out)]
            try:
                r = subprocess.run(
                    cmd,
                    cwd=project,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=600,
                )
            except subprocess.TimeoutExpired as e:
                raise ScanError("pip-audit timed out after 600 s.") from e
            except OSError as e:
                raise ScanError(f"could not run pip-audit: {e}") from e
            try:
                data = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
            except (ValueError, OSError):
                data = None
            if (
                r.returncode not in (0, 1)
                or not isinstance(data, dict)
                or not isinstance(data.get("dependencies"), list)
            ):
                raise ScanError(f"pip-audit failed: {_tail(r.stderr)}")
            return data

        report: dict[str, Any] | None = None
        for args, fallback in targets:
            try:
                parts = [audit(args)]
            except ScanError:
                if not fallback:
                    raise
                # pip could not resolve the file (a build dependency, a
                # conflict, a private index). Its exact pins can still be
                # looked up; what they pull in without listing cannot.
                parts = [audit(pinned) for pinned in pin_targets(fallback)]
                loose = loose_by_file.get(args[1], [])
                notes.append(
                    f"pip could not resolve {Path(args[1]).name}; audited the "
                    f"{len(fallback)} pinned versions it lists, without the packages "
                    "they pull in."
                    + (
                        f" Not audited, having no exact version: {', '.join(loose)}."
                        if loose
                        else ""
                    )
                )
            for data in parts:
                if report is None:
                    report = data
                else:
                    report["dependencies"].extend(data["dependencies"])
        if report is None:
            report = {"dependencies": []}
        if notes:
            report["depquiet_notes"] = notes
        return report
