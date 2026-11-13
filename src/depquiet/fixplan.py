"""One verified change that lets the suggested fixes install together.

``--check-fixes`` answers per package: this fix installs, or this pin blocks
it. A team then asks a different question: what do I change so that the
fixes install? Upgrading one package at a time (what bots do) does not tell
you whether two upgrades fit together, and a blocked fix is often blocked by
a requirement in your own ``pyproject.toml``.

``build_fix_plan`` takes the fix checks and:

1. For every fix blocked by the project's own requirement, widens that
   requirement just enough to allow the fix (``==2.31.0`` becomes
   ``==2.33.0``; ``<3.7`` becomes ``<4``; other clauses are kept).
2. Applies those edits to a temporary copy of the project and asks uv's
   resolver (``uv lock --dry-run --upgrade-package pkg==fix ...``) whether
   everything resolves together.
3. If not, adds the fixes one at a time and keeps each one that still
   resolves with the ones already kept, so the plan is the largest set that
   was verified as a whole.

A fix hidden by the project's ``exclude-newer`` cooldown gets the narrowest
exemption uv supports: an ``exclude-newer-package`` cut-off for that package
only, one second after the fix was published. The rest of the project keeps
the cooldown, and the package cannot move past the fix release either, which
is what uv's maintainers suggest instead of a blanket bypass (astral-sh/uv#18995).

The result is a unified diff of the ``pyproject.toml`` edits plus the
``uv lock`` command to run. Nothing in the project is changed. What is
verified is resolution only: whether the code works with the new versions
(a major version jump especially) is for the project's tests to say.

Like ``uv lock``, this can run the project's build hooks, so it is for
trusted code.
"""

from __future__ import annotations

import difflib
import re
import shutil
import tempfile
import tomllib
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path
from typing import Any

from depquiet.fixcheck import FixCheck, _explain, _pep503, _run_lock, fix_targets
from depquiet.models import ScanResult, version_key

_REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<spec>[^;]*?)\s*(?P<marker>;.*)?$"
)
_CLAUSE = re.compile(r"^\s*(===|==|!=|~=|<=|>=|<|>)\s*(\S+?)\s*$")
_COPY_IGNORE = shutil.ignore_patterns(
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".tox",
    ".nox",
)


@dataclass
class PlanEdit:
    """One change in one file, before and after.

    ``requirement``: ``old`` and ``new`` are requirement strings.
    ``cooldown``: ``old`` and ``new`` are the package's ``exclude-newer-package``
    value ("" when absent).
    """

    file: str  # relative to the project
    package: str
    old: str
    new: str
    kind: str = "requirement"


@dataclass
class PlanItem:
    """One package's fix and how the plan handles it."""

    package: str
    version: str
    installed: str = ""
    edits: list[PlanEdit] = field(default_factory=list)
    also_upgrade: list[str] = field(default_factory=list)
    included: bool = False
    why: str = ""  # why it is left out
    published: str = ""  # set when the plan exempts the fix from a cooldown
    expires: str = ""  # when a rolling cooldown admits the fix by itself

    @property
    def major_jump(self) -> bool:
        return bool(self.installed) and _major(self.installed) != _major(self.version)


@dataclass
class FixPlan:
    status: str  # "verified", "partial", "none", "unsupported"
    items: list[PlanItem] = field(default_factory=list)
    diff: str = ""
    note: str = ""

    @property
    def included(self) -> list[PlanItem]:
        return [i for i in self.items if i.included]

    @property
    def left_out(self) -> list[PlanItem]:
        return [i for i in self.items if not i.included]

    @property
    def command(self) -> str:
        specs: list[str] = []
        for item in self.included:
            specs.append(f"{item.package}=={item.version}")
            specs.extend(n for n in item.also_upgrade if n not in specs)
        return "uv lock " + " ".join(f"--upgrade-package {s}" for s in specs) if specs else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "command": self.command,
            "diff": self.diff,
            "note": self.note,
            "included": [
                {
                    "package": i.package,
                    "version": i.version,
                    "installed": i.installed,
                    "major_version_change": i.major_jump,
                    "also_upgrade": i.also_upgrade,
                    "cooldown_exemption": (
                        {
                            "published": i.published,
                            "cutoff": i.edits[0].new,
                            "remove_after": i.expires,
                        }
                        if i.published
                        else None
                    ),
                    "edits": [e.__dict__ for e in i.edits],
                }
                for i in self.included
            ],
            "left_out": [
                {"package": i.package, "version": i.version, "why": i.why} for i in self.left_out
            ],
        }


def _major(version: str) -> str:
    return version.split(".", 1)[0]


def _satisfies(version: str, op: str, bound: str) -> bool:
    """Whether ``version`` meets one PEP 440 clause (good enough for release numbers)."""
    if bound.endswith(".*") and op in ("==", "!="):
        prefix = bound[:-2]
        hit = version == prefix or version.startswith(prefix + ".")
        return hit if op == "==" else not hit
    v, b = version_key(version), version_key(bound)
    if op in ("==", "==="):
        return v == b
    if op == "!=":
        return v != b
    if op == "<":
        return v < b
    if op == "<=":
        return v <= b
    if op == ">":
        return v > b
    if op == ">=":
        return v >= b
    if op == "~=":
        parts = bound.split(".")
        prefix = ".".join(parts[:-1]) if len(parts) > 1 else parts[0]
        return v >= b and (version == prefix or version.startswith(prefix + "."))
    return False


def widen(requirement: str, version: str) -> str | None:
    """The requirement changed just enough to allow ``version``; None if it already does.

    Clauses that ``version`` meets are kept. A failing exact pin moves to the
    fix, a failing upper bound moves to the fix's next major, ``~=`` becomes
    ``>=fix,<next major``, and a failing ``!=`` is dropped. Extras and
    markers are kept as written.
    """
    match = _REQUIREMENT.match(requirement)
    if not match:
        return None
    spec = match.group("spec").strip()
    clauses = [c for c in (part.strip() for part in spec.split(",")) if c]
    parsed = [_CLAUSE.match(c) for c in clauses]
    if not clauses or any(p is None for p in parsed):
        return None
    pairs = [(p.group(1), p.group(2)) for p in parsed if p is not None]
    if all(_satisfies(version, op, bound) for op, bound in pairs):
        return None
    cap = f"<{int(_major(version)) + 1}" if _major(version).isdigit() else ""
    out: list[str] = []
    for op, bound in pairs:
        if _satisfies(version, op, bound):
            out.append(f"{op}{bound}")
        elif op in ("==", "==="):
            out.append(f"=={version}")
        elif op in ("<", "<="):
            if cap:
                out.append(cap)
        elif op == "~=":
            out.append(f">={version}")
            if cap:
                out.append(cap)
        # a failing != is dropped; a failing > or >= cannot happen for a newer fix
    out = list(dict.fromkeys(out))
    name = match.group("name") + (match.group("extras") or "")
    marker = match.group("marker") or ""
    return f"{name}{','.join(out)}{marker}"


def _member_pyprojects(project: Path) -> list[Path]:
    """The root pyproject.toml and those of workspace members in uv.lock."""
    files = [project / "pyproject.toml"]
    try:
        lock = tomllib.loads((project / "uv.lock").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return [f for f in files if f.is_file()]
    for pkg in lock.get("package", []):
        source = pkg.get("source") or {}
        path = source.get("editable") or source.get("virtual")
        if isinstance(path, str):
            candidate = (project / path / "pyproject.toml").resolve()
            if candidate.is_file() and candidate not in [f.resolve() for f in files]:
                files.append(candidate)
    return [f for f in files if f.is_file()]


def _requirement_strings(data: dict[str, Any]) -> list[str]:
    """Every requirement string a uv project declares."""
    found: list[str] = []
    project = data.get("project") or {}
    found += project.get("dependencies") or []
    for reqs in (project.get("optional-dependencies") or {}).values():
        found += reqs or []
    for reqs in (data.get("dependency-groups") or {}).values():
        found += [r for r in reqs or [] if isinstance(r, str)]
    uv = (data.get("tool") or {}).get("uv") or {}
    for key in ("constraint-dependencies", "override-dependencies", "dev-dependencies"):
        found += uv.get(key) or []
    return [r for r in found if isinstance(r, str)]


def _edits_for(project: Path, package: str, version: str) -> list[PlanEdit]:
    edits: list[PlanEdit] = []
    key = _pep503(package)
    for path in _member_pyprojects(project):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        for req in dict.fromkeys(_requirement_strings(data)):
            match = _REQUIREMENT.match(req)
            if not match or _pep503(match.group("name")) != key:
                continue
            new = widen(req, version)
            if new is not None and new != req:
                rel = str(path.resolve().relative_to(project.resolve())).replace("\\", "/")
                edits.append(PlanEdit(file=rel, package=package, old=req, new=new))
    return edits


def _edit_text(text: str, edit: PlanEdit) -> str:
    if edit.kind == "cooldown":
        return _set_cooldown(text, edit.file, edit.package, edit.new)
    for quote in ('"', "'"):
        text = text.replace(f"{quote}{edit.old}{quote}", f"{quote}{edit.new}{quote}")
    return text


def _apply(root: Path, edits: list[PlanEdit]) -> None:
    for edit in edits:
        path = root / edit.file
        path.write_text(_edit_text(path.read_text(encoding="utf-8"), edit), encoding="utf-8")


# --- exclude-newer cooldown exemptions ------------------------------------------

_PUBLISHED = re.compile(r"published at (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z")
_KEY = r"(?:\"[^\"]+\"|'[^']+'|[A-Za-z0-9_.-]+)"
_INLINE = re.compile(
    r"^(?P<lead>\s*exclude-newer-package\s*=\s*\{)(?P<body>.*)\}(?P<tail>\s*(?:#.*)?)$"
)
_ENTRY = re.compile(rf"\s*(?P<key>{_KEY})\s*=\s*(?P<value>\"[^\"]*\"|'[^']*'|true|false)\s*")


def published_at(detail: str) -> str:
    """The fix's upload time from uv's cooldown hint, as ``YYYY-MM-DDTHH:MM:SSZ``."""
    match = _PUBLISHED.search(detail)
    return f"{match.group(1)}Z" if match else ""


def cutoff_after(published: str) -> str:
    """One second after ``published``: admits that upload and nothing newer."""
    from datetime import datetime, timedelta

    moment = datetime.strptime(published, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return (moment + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _section(lines: list[str], header: str) -> tuple[int, int] | None:
    """Line range (start, end) of a TOML table; header "" is the top level."""
    if header == "":
        start = 0
    else:
        target = re.compile(rf"^\s*\[\s*{re.escape(header)}\s*\]\s*(#.*)?$")
        found = next((i for i, line in enumerate(lines) if target.match(line)), None)
        if found is None:
            return None
        start = found + 1
    end = next(
        (i for i in range(start, len(lines)) if lines[i].lstrip().startswith("[")), len(lines)
    )
    return start, end


def _cooldown_file(project: Path) -> tuple[str, str] | None:
    """(file, table) where the project sets ``exclude-newer``, if it does."""
    for name, table in (("pyproject.toml", "tool.uv"), ("uv.toml", "")):
        try:
            data = tomllib.loads((project / name).read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        section: Any = data
        for part in [p for p in table.split(".") if p]:
            section = section.get(part, {}) if isinstance(section, dict) else {}
        if isinstance(section, dict) and "exclude-newer" in section:
            return name, table
    return None


def _set_cooldown(text: str, file: str, package: str, value: str) -> str:
    """Set (or with value "" remove) ``package`` in ``exclude-newer-package``."""
    table = "tool.uv" if file.endswith("pyproject.toml") else ""
    nl = "\r\n" if "\r\n" in text else "\n"
    # TOML reads an unquoted ``zope.interface`` as a nested table.
    name = package if re.fullmatch(r"[A-Za-z0-9_-]+", package) else f'"{package}"'
    lines = text.splitlines(keepends=True)
    span = _section(lines, table)
    if span is None:
        return text
    start, end = span
    key = _pep503(package)

    def same(raw: str) -> bool:
        return _pep503(raw.strip("\"'")) == key

    for i in range(start, end):
        match = _INLINE.match(lines[i].rstrip("\r\n"))
        if not match:
            continue
        entries = [(m.group("key"), m.group("value")) for m in _ENTRY.finditer(match.group("body"))]
        kept = [(k, v) for k, v in entries if not same(k)]
        if value:
            kept.append((name, f'"{value}"'))
        if not kept:
            del lines[i]
            return "".join(lines)
        body = ", ".join(f"{k} = {v}" for k, v in kept)
        newline = nl if lines[i].endswith("\n") else ""
        lines[i] = f"{match.group('lead')} {body} }}{match.group('tail')}{newline}"
        return "".join(lines)

    sub = _section(lines, f"{table}.exclude-newer-package" if table else "exclude-newer-package")
    if sub is not None:
        s_start, s_end = sub
        for i in range(s_start, s_end):
            entry = re.match(rf"^\s*(?P<key>{_KEY})\s*=", lines[i])
            if entry and same(entry.group("key")):
                if value:
                    lines[i] = f'{name} = "{value}"{nl}'
                else:
                    del lines[i]
                return "".join(lines)
        if value:
            lines.insert(s_start, f'{name} = "{value}"{nl}')
        return "".join(lines)

    if not value:
        return text
    anchor = next(
        (i for i in range(start, end) if re.match(r"^\s*exclude-newer\s*=", lines[i])), None
    )
    if anchor is None:
        return text
    if not lines[anchor].endswith("\n"):
        lines[anchor] += nl
    lines.insert(anchor + 1, f'exclude-newer-package = {{ {name} = "{value}" }}{nl}')
    return "".join(lines)


_DURATION = re.compile(
    r"^\s*(\d+)\s*(second|minute|hour|day|week)s?\s*$|^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?)?$",
    re.I,
)


def _parse_moment(value: str) -> Any:
    from datetime import date, datetime

    text = value.strip()
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            moment = datetime.combine(date.fromisoformat(text), datetime.min.time())
        except ValueError:
            return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _parse_window(value: str) -> Any:
    """A relative cooldown ("7 days", "1 week", "P7D") as a timedelta, else None."""
    from datetime import timedelta

    match = _DURATION.match(value.strip())
    if not match:
        return None
    if match.group(1):
        unit = match.group(2).lower()
        return timedelta(**{f"{unit}s": int(match.group(1))})
    weeks, days, hours = (int(g or 0) for g in match.group(3, 4, 5))
    window = timedelta(weeks=weeks, days=days, hours=hours)
    return window if window else None


def _global_cooldown(project: Path) -> tuple[str, str, str] | None:
    """(file, table, raw exclude-newer value) where the project sets it."""
    where = _cooldown_file(project)
    if where is None:
        return None
    file, table = where
    data = tomllib.loads((project / file).read_text(encoding="utf-8"))
    section: Any = data
    for part in [p for p in table.split(".") if p]:
        section = section.get(part, {})
    return file, table, str(section.get("exclude-newer", ""))


def cooldown_expiry(project: Path, published: str) -> str:
    """When a rolling cooldown starts admitting ``published`` by itself (YYYY-MM-DD)."""
    found = _global_cooldown(project)
    window = _parse_window(found[2]) if found else None
    moment = _parse_moment(published) if published else None
    if window is None or moment is None:
        return ""
    return str((moment + window).date())


def stale_exemptions(project: Path, now: Any = None) -> list[tuple[str, str, str]]:
    """Per-package cut-offs older than the project's own cut-off.

    An ``exclude-newer-package`` date only helps while it is newer than the
    global cut-off. Once the cooldown moves past it (a rolling window, or a
    date moved forward), it holds that package back on old releases, which
    can bring vulnerabilities back. Returns (package, entry, global cut-off).
    """
    from datetime import datetime

    found = _global_cooldown(project)
    if found is None:
        return []
    file, table, raw = found
    window = _parse_window(raw)
    cutoff = (now or datetime.now(UTC)) - window if window is not None else _parse_moment(raw)
    if cutoff is None:
        return []
    data = tomllib.loads((project / file).read_text(encoding="utf-8"))
    section: Any = data
    for part in [p for p in table.split(".") if p]:
        section = section.get(part, {})
    per = section.get("exclude-newer-package", {}) if isinstance(section, dict) else {}
    stale: list[tuple[str, str, str]] = []
    for name, value in per.items() if isinstance(per, dict) else []:
        if not isinstance(value, str) or _parse_window(value) is not None:
            continue
        moment = _parse_moment(value)
        if moment is not None and moment < cutoff:
            stale.append((name, value, cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")))
    return stale


def _current_cooldown(project: Path, file: str, table: str, package: str) -> str:
    try:
        data = tomllib.loads((project / file).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    section: Any = data
    for part in [p for p in table.split(".") if p]:
        section = section.get(part, {}) if isinstance(section, dict) else {}
    per = section.get("exclude-newer-package", {}) if isinstance(section, dict) else {}
    if not isinstance(per, dict):
        return ""
    for name, val in per.items():
        if _pep503(name) == _pep503(package):
            return str(val).lower() if isinstance(val, bool) else str(val)
    return ""


def _cooldown_edits(project: Path, check: FixCheck) -> list[PlanEdit] | str:
    """The exemption for one fix, or why none can be written."""
    published = published_at(check.detail)
    if not published:
        return "uv did not say when the fix was published, so no exemption was planned."
    where = _cooldown_file(project)
    if where is None:
        return (
            "the exclude-newer cut-off is not set in pyproject.toml or uv.toml (an "
            f"environment variable or user config?): exempt {check.package} there with "
            f'exclude-newer-package = {{ {check.package} = "{cutoff_after(published)}" }}'
        )
    file, table = where
    old = _current_cooldown(project, file, table, check.package)
    new = cutoff_after(published)
    after = _set_cooldown((project / file).read_text(encoding="utf-8"), file, check.package, new)
    try:
        parsed = tomllib.loads(after)
    except tomllib.TOMLDecodeError:
        return f"depquiet could not edit {file} safely; add the exemption by hand."
    section: Any = parsed
    for part in [p for p in table.split(".") if p]:
        section = section.get(part, {})
    per = section.get("exclude-newer-package", {}) if isinstance(section, dict) else {}
    if not isinstance(per, dict) or not any(
        _pep503(k) == _pep503(check.package) and v == new for k, v in per.items()
    ):
        return f"depquiet could not edit {file} safely; add the exemption by hand."
    return [PlanEdit(file=file, package=check.package, old=old, new=new, kind="cooldown")]


def _locked_versions(project: Path) -> dict[str, str]:
    try:
        lock = tomllib.loads((project / "uv.lock").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return {
        _pep503(p["name"]): p.get("version", "")
        for p in lock.get("package", [])
        if isinstance(p, dict) and "name" in p
    }


def _resolves(root: Path, executable: str, items: list[PlanItem], timeout: int) -> str | None:
    """None when the items resolve together, else uv's explanation."""
    specs: list[str] = []
    for item in items:
        specs.append(f"{item.package}=={item.version}")
        specs.extend(n for n in item.also_upgrade if n not in specs)
    answer = _run_lock(root, executable, specs, timeout)
    if isinstance(answer, str):
        return answer
    code, stdout, stderr = answer
    return None if code == 0 else _explain(stderr or stdout)


def _loosen(requirement: str, floor: str) -> str | None:
    """The requirement with its upper bounds and pins removed (floor kept)."""
    match = _REQUIREMENT.match(requirement)
    if not match:
        return None
    clauses = [c.strip() for c in match.group("spec").split(",") if c.strip()]
    kept = []
    for clause in clauses:
        parsed = _CLAUSE.match(clause)
        if parsed is None:
            return None
        if parsed.group(1) in (">", ">="):
            kept.append(clause)
    if not kept and floor:
        kept.append(f">={floor}")
    name = match.group("name") + (match.group("extras") or "")
    return f"{name}{','.join(kept)}{match.group('marker') or ''}"


def _plan_chain(
    project: Path,
    executable: str,
    item: PlanItem,
    blockers: list[str],
    installed: dict[str, str],
    timeout: int,
) -> str | None:
    """Fill ``item`` so that its blockers move too; a reason string if that fails.

    On a copy of the project, the blockers' requirements are loosened to let
    the resolver pick versions that allow the fix. The versions it picks are
    then written back in the project's own style (an exact pin stays an
    exact pin) and the result is resolved again: only that is proposed.
    """
    from depquiet.fixcheck import _updates

    loosened: list[PlanEdit] = []
    for blocker in blockers:
        floor = installed.get(_pep503(blocker), "")
        for edit in _edits_matching(project, blocker):
            new = _loosen(edit.old, floor)
            if new and new != edit.old:
                loosened.append(PlanEdit(edit.file, blocker, edit.old, new))
    with tempfile.TemporaryDirectory(prefix="depquiet-fixplan-") as tmp:
        root = Path(tmp) / "project"
        shutil.copytree(project, root, ignore=_COPY_IGNORE, symlinks=True)
        _apply(root, loosened)
        answer = _run_lock(
            root, executable, [f"{item.package}=={item.version}", *blockers], timeout
        )
        if isinstance(answer, str):
            return answer
        code, stdout, stderr = answer
        if code != 0:
            return (
                f"blocked by {', '.join(blockers)}, and no version of "
                f"{'it' if len(blockers) == 1 else 'them'} allows the fix: "
                f"{_explain(stderr or stdout)}"
            )
        picked = {
            _pep503(u.split(" ")[0]): u.split(" -> v")[-1] for u in _updates(f"{stdout}\n{stderr}")
        }
        final: list[PlanEdit] = []
        specs: list[str] = []
        for blocker in blockers:
            target = picked.get(_pep503(blocker))
            if not target:
                return f"blocked by {blocker}; uv did not report a version of it to move to."
            specs.append(f"{blocker}=={target}")
            final += [
                PlanEdit(e.file, blocker, e.old, new)
                for e in _edits_matching(project, blocker)
                if (new := widen(e.old, target)) is not None and new != e.old
            ]
        _revert(root, loosened)
        _apply(root, final)
        answer = _run_lock(root, executable, [f"{item.package}=={item.version}", *specs], timeout)
        if isinstance(answer, str) or answer[0] != 0:
            return f"blocked by {', '.join(blockers)}; the pinned versions did not verify."
    item.edits = final
    item.also_upgrade = specs
    return None


def _edits_matching(project: Path, package: str) -> list[PlanEdit]:
    """Every requirement of ``package`` the project declares, as no-op edits."""
    key = _pep503(package)
    found: list[PlanEdit] = []
    for path in _member_pyprojects(project):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        rel = str(path.resolve().relative_to(project.resolve())).replace("\\", "/")
        for req in dict.fromkeys(_requirement_strings(data)):
            match = _REQUIREMENT.match(req)
            if match and _pep503(match.group("name")) == key:
                found.append(PlanEdit(rel, package, req, req))
    return found


def build_fix_plan(
    result: ScanResult,
    project: Path,
    checks: dict[str, FixCheck],
    *,
    timeout: int = 300,
) -> FixPlan:
    found = shutil.which("uv")
    if found is None:
        return FixPlan("unsupported", note="--fix-plan needs uv on PATH.")
    executable = found
    if not (project / "uv.lock").is_file():
        return FixPlan("unsupported", note="--fix-plan works on projects with a uv.lock.")
    targets = fix_targets(result)
    installed = _locked_versions(project)
    items: list[PlanItem] = []
    for package, version in sorted(targets.items()):
        item = PlanItem(package, version, installed.get(_pep503(package), ""))
        check = checks.get(package)
        if check is None or check.status == "error":
            item.why = f"could not be checked: {check.detail if check else 'no answer'}"
        elif check.status == "resolves":
            item.also_upgrade = list(check.also_upgrade)
        elif check.reason == "own-pin":
            item.edits = _edits_for(project, package, version)
            if not item.edits:
                item.why = f"blocked by a requirement depquiet could not edit: {check.next_step}"
        elif check.reason == "cooldown":
            planned = _cooldown_edits(project, check)
            if isinstance(planned, str):
                item.why = planned
            else:
                item.edits = planned
                item.published = published_at(check.detail)
                item.expires = cooldown_expiry(project, item.published)
        elif check.reason == "dependency" and check.also_upgrade:
            # Another package holds it back, and the project pins that package:
            # find the blocker version that allows the fix, and pin that.
            chained = _plan_chain(project, executable, item, check.also_upgrade, installed, timeout)
            if isinstance(chained, str):
                item.why = chained
        else:
            item.why = check.next_step or check.detail
        items.append(item)

    candidates = [i for i in items if not i.why]
    if not candidates:
        return FixPlan("none", items=items, note="No fix could be planned.")

    with tempfile.TemporaryDirectory(prefix="depquiet-fixplan-") as tmp:
        root = Path(tmp) / "project"
        shutil.copytree(project, root, ignore=_COPY_IGNORE, symlinks=True)
        everything = [e for i in candidates for e in i.edits]
        _apply(root, everything)
        failure = _resolves(root, executable, candidates, timeout)
        if failure is None:
            for item in candidates:
                item.included = True
        else:
            # Keep each fix that still resolves with the ones already kept.
            shutil.rmtree(root)
            shutil.copytree(project, root, ignore=_COPY_IGNORE, symlinks=True)
            kept: list[PlanItem] = []
            for item in candidates:
                _apply(root, item.edits)
                reason = _resolves(root, executable, [*kept, item], timeout)
                if reason is None:
                    item.included = True
                    kept.append(item)
                else:
                    _revert(root, item.edits)
                    item.why = f"does not resolve together with the rest: {reason}"

    included = [i for i in items if i.included]
    diff = _diff(project, [e for i in included for e in i.edits])
    if not included:
        status = "none"
    elif all(i.included for i in items):
        status = "verified"
    else:
        status = "partial"
    note = "Verified with uv's resolver only: run your tests, above all for a major version change."
    if any(i.published for i in included):
        note += (
            " A cooldown exemption admits a release younger than your cooldown: check that "
            "it is the advisory's fix and comes from the project's usual publisher. Remove "
            "it once your cooldown admits the fix by itself: left in place, it holds the "
            "package on that release."
        )
    return FixPlan(status, items=items, diff=diff, note=note)


def _revert(root: Path, edits: list[PlanEdit]) -> None:
    _apply(root, [PlanEdit(e.file, e.package, e.new, e.old) for e in edits])


def _diff(project: Path, edits: list[PlanEdit]) -> str:
    by_file: dict[str, list[PlanEdit]] = {}
    for edit in edits:
        by_file.setdefault(edit.file, []).append(edit)
    chunks: list[str] = []
    for rel, file_edits in sorted(by_file.items()):
        before = (project / rel).read_text(encoding="utf-8")
        after = before
        for edit in file_edits:
            after = _edit_text(after, edit)
        chunks.extend(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=f"a/{rel}",
                tofile=f"b/{rel}",
            )
        )
    return "".join(chunks)


def print_fix_plan(plan: FixPlan, file: Any) -> None:
    """Human summary (to stderr); the diff itself is written by the caller."""
    print("\n🔧 Fix plan", file=file)
    if plan.status == "unsupported" or (plan.status == "none" and not plan.items):
        print(f"   {plan.note}", file=file)
        return
    for item in plan.included:
        jump = "  (major version change)" if item.major_jump else ""
        own = [e for e in item.edits if _pep503(e.package) == _pep503(item.package)]
        if item.published:
            how = (
                f"exempt it from your exclude-newer cooldown, only up to this release "
                f"(published {item.published[:10]}"
                + (f"; remove the entry after {item.expires}" if item.expires else "")
                + ")"
            )
        elif item.also_upgrade:
            moved = ", ".join(s.replace("==", " → ") for s in item.also_upgrade)
            how = f"also move {moved}, which holds it back"
        elif own:
            how = "widen your requirement"
        else:
            how = "upgrade"
        print(
            f"   ✓ {item.package} {item.installed or '?'} → {item.version}: {how}{jump}",
            file=file,
        )
    for item in plan.left_out:
        print(f"   ✗ {item.package} → {item.version}: {item.why[:200]}", file=file)
    if plan.included:
        verdict = (
            "all fixes resolve together"
            if plan.status == "verified"
            else (f"{len(plan.included)} of {len(plan.items)} fixes resolve together")
        )
        print(f"\n   Verified with uv's resolver: {verdict}.", file=file)
        print(f"   Then run: {plan.command}", file=file)
        print(f"   {plan.note}", file=file)
