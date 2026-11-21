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

A fix that only supports a newer Python than the project's ``requires-python``
(pytest 9 on a project that still declares ``>=3.9``) is checked once more,
on a copy with the floor raised to what the fix needs: if it resolves, the
plan says so, with the exact edit. Dropping a Python version is the
maintainer's decision (harmless for an application, a breaking change for a
published library), so the edit goes into the diff only with
``--raise-python-floor``.

The result is a unified diff of the ``pyproject.toml`` edits plus the
``uv lock`` command to run. Nothing in the project is changed. What is
verified is resolution only: whether the code works with the new versions
(a major version jump especially) is for the project's tests to say.

Like ``uv lock``, this can run the project's build hooks, so it is for
trusted code.
"""

from __future__ import annotations

import difflib
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path
from typing import Any

from depquiet.fixcheck import FixCheck, _explain, _pep503, _run_lock, _write_lock, fix_targets
from depquiet.models import ScanResult, Verdict, clip, first_items, version_key

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


def lockfile_name(tool: str) -> str:
    return {"poetry": "poetry.lock", "npm": "package-lock.json"}.get(tool, "uv.lock")


def resolver_name(tool: str) -> str:
    return {"poetry": "Poetry's", "npm": "npm's"}.get(tool, "uv's")


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
    # npm ``override``: the parent the override is scoped to ("" for a global one).
    scope: str = ""


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
    python_floor: str = ""  # set when the plan raises requires-python for it
    fixed_in: str = ""  # the advisory's fix, when ``version`` is a newer release already locked
    # Not asked for, but the verified lock moves it past the fix anyway.
    carried: bool = False
    # Set on the newest fix that installs on the current Python range, when the
    # full fix needs a newer Python: "closes 5 of 8 alerts; 3 need Python >=3.11.5".
    partial: str = ""
    # npm: who holds the vulnerable copy back ("typography 0.5.19 requires
    # postcss-selector-parser@6.0.10"), and npm audit's own fix when it is a downgrade.
    held_by: list[str] = field(default_factory=list)
    audit_note: str = ""
    # npm: copies of the package the plan leaves, and why ("glob 10.5.0 under ...").
    leaves: str = ""

    @property
    def major_jump(self) -> bool:
        return bool(self.installed) and _major(self.installed) != _major(self.version)


@dataclass
class LockChange:
    """A package the plan moves in the lockfile besides the fixes themselves."""

    package: str
    old: str  # "" when the plan adds it; "1.0, 2.0" in a lock forked by Python version
    new: str  # "" when the plan removes it

    @property
    def downgrade(self) -> bool:
        """Some copy ends older than every copy before: uv went back to fit the fixes.

        On a public uv SDK, keeping Python 3.9 took jupyterlab from 4.5.7 to
        2.3.2 (for 3.9) and 4.x (for newer Pythons): the plan must say so.
        """
        if not self.old or not self.new:
            return False
        olds = [v.strip() for v in self.old.split(",") if v.strip()]
        lowest = min(olds, key=version_key)
        return any(version_key(v.strip()) < version_key(lowest) for v in self.new.split(","))

    @property
    def order(self) -> tuple[int, str]:
        """Downgrades first, then moves (a parent that has to move), additions, removals."""
        kind = 3 if not self.new else 2 if not self.old else 0 if self.downgrade else 1
        return kind, self.package.lower()

    def describe(self) -> str:
        if not self.old:
            return f"{self.package} {self.new} (added)"
        if not self.new:
            return f"{self.package} {self.old} (removed: nothing requires it any more)"
        if self.downgrade:
            return f"⚠ {self.package} {self.old} → {self.new} (an older version)"
        return f"{self.package} {self.old} → {self.new}"


@dataclass
class PythonFloor:
    """Raising ``requires-python``: which fixes it lets install, verified on a copy."""

    floor: str  # "3.10": the new floor is ``>=3.10``
    edits: list[PlanEdit] = field(default_factory=list)
    unblocked: list[str] = field(default_factory=list)  # packages it lets install
    still_blocked: list[str] = field(default_factory=list)  # still do not resolve
    alerts: int = 0  # shown alerts the unblocked fixes clear
    dropped: str = ""  # "3.9", "3.8 and 3.9": the Python versions it stops supporting
    adopted: bool = False  # in the diff (--raise-python-floor)
    problem: str = ""  # why it could not be planned
    # Set when the floor the fixes asked for left uv splitting the lock just above
    # it, with older copies below the split: the floor the plan moved to instead.
    refined_from: str = ""
    avoids: list[str] = field(default_factory=list)  # the packages that split held back

    def to_dict(self) -> dict[str, Any]:
        return {
            "floor": f">={self.floor}",
            "drops_python": self.dropped or None,
            "unblocks": self.unblocked,
            "still_blocked": self.still_blocked,
            "alerts_cleared": self.alerts,
            "adopted": self.adopted,
            "problem": self.problem or None,
            "refined_from": f">={self.refined_from}" if self.refined_from else None,
            "avoids_older": self.avoids,
            "edits": [e.__dict__ for e in self.edits],
        }


@dataclass
class FixPlan:
    status: str  # "verified", "partial", "none", "unsupported"
    items: list[PlanItem] = field(default_factory=list)
    diff: str = ""
    note: str = ""
    tool: str = "uv"  # the resolver that verified it: "uv" or "poetry"
    # Everything else the verified lock moves: a parent that has to move with a
    # fix, packages that are no longer required. A reviewer sees these in the
    # lockfile diff, so the plan names them.
    lock_changes: list[LockChange] = field(default_factory=list)
    python_floor: PythonFloor | None = None
    # npm: the whole planned package.json, written by --apply.
    manifest: str = ""

    @property
    def downgrades(self) -> list[LockChange]:
        return [c for c in self.lock_changes if c.downgrade]

    def downgrade_warning(self) -> str:
        """One sentence for a plan that moves packages back, "" when it does not."""
        names = [c.package for c in self.downgrades]
        if not names:
            return ""
        text = (
            f"The lock moves {first_items(names, 4)} to an older version to fit the fixes "
            "together: check that before merging."
        )
        floor = self.python_floor
        if floor is not None and not floor.adopted and floor.avoids and not floor.unblocked:
            text += (
                f" Raising requires-python to >={floor.floor} avoids it (verified; see "
                "Python floor)."
            )
        elif floor is not None and not floor.adopted and floor.unblocked:
            text += (
                " In a lock forked by Python version this is usually the copy for the oldest "
                "Python you support; raising requires-python (see Python floor) may avoid it."
            )
        return text

    # Planned for filtered alerts too (--fix-filtered): the report lists them.
    include_filtered: bool = False

    @property
    def edits(self) -> list[PlanEdit]:
        """Every file edit of the plan: the fixes', then a raised Python floor."""
        found = [e for i in self.included for e in i.edits]
        if self.python_floor is not None and self.python_floor.adopted:
            found += self.python_floor.edits
        return found

    @property
    def included(self) -> list[PlanItem]:
        return [i for i in self.items if i.included]

    @property
    def left_out(self) -> list[PlanItem]:
        return [i for i in self.items if not i.included]

    @property
    def command(self) -> str:
        if self.tool == "npm":
            packages = list(
                dict.fromkeys(
                    n
                    for i in self.included
                    for n in [i.package, *[s.split("==")[0] for s in i.also_upgrade]]
                )
            )
            return "npm update " + " ".join(packages) if packages else ""
        if self.tool == "poetry":
            names: list[str] = []
            for item in self.included:
                for name in [item.package, *[s.split("==")[0] for s in item.also_upgrade]]:
                    if name not in names:
                        names.append(name)
            return "poetry update --lock " + " ".join(names) if names else ""
        specs: list[str] = []
        # A carried fix needs no flag of its own: the command that was verified moves it.
        for item in (i for i in self.included if not i.carried):
            specs.append(f"{item.package}=={item.version}")
            specs.extend(n for n in item.also_upgrade if n not in specs)
        return "uv lock " + " ".join(f"--upgrade-package {s}" for s in specs) if specs else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "tool": self.tool,
            "command": self.command,
            "diff": self.diff,
            "note": self.note,
            "included": [
                {
                    "package": i.package,
                    "version": i.version,
                    "fixed_in": i.fixed_in or None,
                    "carried": i.carried,
                    "partial": i.partial or None,
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
                    "held_by": i.held_by,
                    "npm_audit_note": i.audit_note or None,
                    "leaves": i.leaves or None,
                }
                for i in self.included
            ],
            "left_out": [
                {
                    "package": i.package,
                    "version": i.version,
                    "why": i.why,
                    "held_by": i.held_by,
                    "npm_audit_note": i.audit_note or None,
                }
                for i in self.left_out
            ],
            "lock_changes": [
                {"package": c.package, "from": c.old or None, "to": c.new or None}
                for c in self.lock_changes
            ],
            "python_floor": self.python_floor.to_dict() if self.python_floor else None,
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


def _set_poetry_constraint(text: str, package: str, old: str, new: str) -> str:
    """Replace one package's constraint in the ``[tool.poetry...]`` tables.

    Only on that package's own line: another package pinned to the same
    version string must not change with it.
    """
    key = _pep503(package)
    entry = re.compile(r"^\s*(?P<q>[\"']?)(?P<name>[A-Za-z0-9_.-]+)(?P=q)\s*=\s*(?P<value>.*)$")
    in_poetry = False
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("["):
            in_poetry = stripped.lstrip("[").strip().startswith("tool.poetry")
            continue
        match = entry.match(line.rstrip("\r\n")) if in_poetry else None
        if match is None or _pep503(match.group("name")) != key:
            continue
        for quote in ('"', "'"):
            if f"{quote}{old}{quote}" in match.group("value"):
                value = match.group("value").replace(
                    f"{quote}{old}{quote}", f"{quote}{new}{quote}", 1
                )
                lines[i] = line[: match.start("value")] + value + line[len(line.rstrip("\r\n")) :]
                break
    return "".join(lines)


def unique_edits(edits: list[PlanEdit]) -> list[PlanEdit]:
    """Edits without repeats: two fixes can ask for the same change to a shared holder."""
    seen: list[PlanEdit] = []
    for edit in edits:
        key = (edit.file, edit.package, edit.old, edit.kind)
        if all((e.file, e.package, e.old, e.kind) != key for e in seen):
            seen.append(edit)
    return seen


def _edit_text(text: str, edit: PlanEdit) -> str:
    if edit.kind == "python":
        return _set_requires_python(text, edit.old, edit.new)
    if edit.kind == "cooldown":
        return _set_cooldown(text, edit.file, edit.package, edit.new)
    if edit.kind == "poetry":
        return _set_poetry_constraint(text, edit.package, edit.old, edit.new)
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


def _locked_versions(project: Path, *, highest: bool = False) -> dict[str, str]:
    """Package -> its locked version.

    A lock forked by Python version holds a package twice (pytest 8.4.2 for
    Python 3.9, 9.2.0 for 3.10+). The lowest is the one an alert is about,
    so it is the default.
    """
    try:
        lock = tomllib.loads((project / "uv.lock").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    found: dict[str, str] = {}
    for p in lock.get("package", []):
        if not isinstance(p, dict) or "name" not in p:
            continue
        key, version = _pep503(p["name"]), str(p.get("version", ""))
        known = found.get(key)
        if (
            known is None
            or (highest and version_key(version) > version_key(known))
            or (not highest and version_key(version) < version_key(known))
        ):
            found[key] = version
    return found


def _resolves(
    root: Path,
    executable: str,
    items: list[PlanItem],
    timeout: int,
    output: list[str] | None = None,
) -> str | None:
    """None when the items resolve together, else uv's explanation.

    On success, uv's report (its Update/Add/Remove lines) replaces the
    contents of ``output``: the last success is the plan's final lock.
    """
    specs: list[str] = []
    for item in items:
        specs.append(f"{item.package}=={item.version}")
        specs.extend(n for n in item.also_upgrade if n not in specs)
    answer = _run_lock(root, executable, specs, timeout)
    if isinstance(answer, str):
        return answer
    code, stdout, stderr = answer
    if code == 0 and output is not None:
        output[:] = [stdout + "\n" + stderr]
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


# --- the Python floor (requires-python) --------------------------------------

_REQUIRES_PYTHON = re.compile(
    r"""^(?P<lead>\s*requires-python\s*=\s*)(?P<q>["'])(?P<spec>[^"']*)(?P=q)"""
)


def raise_floor(spec: str, floor: str) -> str | None:
    """``requires-python`` raised to at least ``floor``; None if that cannot be written.

    ``>=3.9`` → ``>=3.10``; ``>=3.9,<4`` → ``>=3.10,<4`` (upper bounds kept).
    A spec that already admits nothing below ``floor`` comes back unchanged.
    None when an upper bound excludes ``floor`` or a clause is not a plain
    bound (``~=``, ``==3.9.*``): those are for a person to rewrite.
    """
    clauses = [c.strip() for c in spec.split(",") if c.strip()]
    parsed = [_CLAUSE.match(c) for c in clauses]
    if any(p is None for p in parsed):
        return None
    out: list[str] = []
    covered = False
    for match in parsed:
        assert match is not None
        op, bound = match.group(1), match.group(2)
        if op in (">=", ">"):
            if version_key(bound) >= version_key(floor):
                covered = True
                out.append(f"{op}{bound}")
            continue  # a lower floor is replaced
        if op in ("<", "<=", "!=") and "*" not in bound:
            if not _satisfies(floor, op, bound):
                return None
            out.append(f"{op}{bound}")
            continue
        return None
    if not covered:
        out.insert(0, f">={floor}")
    return (", " if ", " in spec else ",").join(out)


def _old_floor(spec: str) -> str:
    """The lowest Python a ``requires-python`` admits, from its ``>=`` clause."""
    bounds = [m.group(2) for c in spec.split(",") if (m := _CLAUSE.match(c)) and m.group(1) == ">="]
    return max(bounds, key=version_key) if bounds else ""


def dropped_pythons(old: str, new: str) -> str:
    """``3.8``, ``3.10`` → ``3.8 and 3.9``: the minor versions a raised floor stops supporting."""
    a, b = old.split("."), new.split(".")
    if len(a) < 2 or len(b) < 2 or a[0] != "3" or b[0] != "3":
        return ""
    if not (a[1].isdigit() and b[1].isdigit()):
        return ""
    minors = [f"3.{m}" for m in range(int(a[1]), int(b[1]))]
    if any(p.isdigit() and int(p) for p in b[2:]):
        minors.append(f"3.{b[1]} below {new}")
    if not minors:
        return ""
    return minors[0] if len(minors) == 1 else ", ".join(minors[:-1]) + " and " + minors[-1]


def _set_requires_python(text: str, old: str, new: str) -> str:
    """Replace ``requires-python`` in the ``[project]`` table only."""
    lines = text.splitlines(keepends=True)
    span = _section(lines, "project")
    if span is None:
        return text
    for i in range(*span):
        match = _REQUIRES_PYTHON.match(lines[i])
        if match and match.group("spec") == old:
            q = match.group("q")
            lines[i] = match.group("lead") + q + new + q + lines[i][match.end() :]
            break
    return "".join(lines)


def _floor_edits(project: Path, floor: str) -> tuple[list[PlanEdit], str, str]:
    """(edits, dropped versions, problem) for raising every member's floor to ``floor``."""
    edits: list[PlanEdit] = []
    olds: list[str] = []
    for path in _member_pyprojects(project):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        spec = (data.get("project") or {}).get("requires-python")
        if not isinstance(spec, str):
            continue
        rel = str(path.resolve().relative_to(project.resolve())).replace("\\", "/")
        new = raise_floor(spec, floor)
        if new is None:
            problem = f"{rel} declares requires-python {spec!r}, which depquiet will not rewrite."
            return [], "", problem
        if new != spec:
            text = path.read_text(encoding="utf-8")
            if _set_requires_python(text, spec, new) == text:
                return [], "", f"depquiet could not edit requires-python in {rel} safely."
            edits.append(PlanEdit(rel, "python", spec, new, kind="python"))
            if _old_floor(spec):
                olds.append(_old_floor(spec))
    if not edits:
        return [], "", "no pyproject.toml declares a requires-python below the fix's floor."
    lowest = min(olds, key=version_key) if olds else ""
    return edits, dropped_pythons(lowest, floor) if lowest else "", ""


def _plan_python_floor(
    project: Path,
    executable: str,
    kept: list[PlanItem],
    waiting: list[PlanItem],
    floors: dict[str, str],
    result: ScanResult,
    timeout: int,
    include_filtered: bool = False,
    retry: list[PlanItem] | None = None,
) -> tuple[PythonFloor, str]:
    """Check, on a copy, which fixes install once requires-python is raised.

    Returns the option and uv's report of that resolution ("" if none did).

    The floor is the highest any waiting fix needs, so one edit covers them
    all. The fixes already in the plan stay in the check: the floor is
    proposed only if everything resolves together.

    ``retry``: fixes left out for a reason that names requires-python (one
    that only fits together with a newer package, say). Once the floor is
    raised they often resolve, so they are tried again on the same copy.
    """
    retry = retry or []
    floor = max(floors.values(), key=version_key)
    edits, dropped, problem = _floor_edits(project, floor)
    option = PythonFloor(floor, edits=edits, dropped=dropped, problem=problem)
    if problem:
        option.still_blocked = [i.package for i in waiting]
        return option, ""
    trying = [*waiting, *retry]
    with tempfile.TemporaryDirectory(prefix="depquiet-fixplan-") as tmp:
        root = Path(tmp) / "project"
        shutil.copytree(project, root, ignore=_COPY_IGNORE, symlinks=True)
        _apply(root, [e for i in kept for e in i.edits] + edits)
        local: list[str] = []
        reason = _resolves(root, executable, [*kept, *trying], timeout, local)
        if reason is None:
            unblocked = list(trying)
        else:
            unblocked = []
            for item in trying:
                reason = _resolves(root, executable, [*kept, *unblocked, item], timeout, local)
                if reason is None:
                    unblocked.append(item)
                elif item.package in floors:
                    item.why = (
                        f"needs Python >={floors[item.package]}, and with requires-python "
                        f"raised to >={floor} it still does not resolve: {reason}"
                    )
                else:
                    item.why = (
                        f"still does not resolve with requires-python raised to >={floor}: {reason}"
                    )
        if unblocked and local:
            refined = _refine_floor(
                project, root, executable, [*kept, *unblocked], floor, edits, local[0], timeout
            )
            if refined is not None:
                option.refined_from = floor
                option.floor, option.edits, option.dropped, local[0], option.avoids = refined
    option.unblocked = [i.package for i in unblocked]
    option.still_blocked = [i.package for i in waiting if i not in unblocked]
    keys = {_pep503(i.package) for i in unblocked}
    option.alerts = sum(
        1
        for r in result.results
        if (include_filtered or r.verdict is not Verdict.FILTERED)
        and _pep503(r.vuln.package) in keys
    )
    return option, (local[0] if unblocked and local else "")


_PYTHON_SPLIT = re.compile(r"python_(?:full_)?version\s*(?:<|>=)\s*'(\d+\.\d+(?:\.\d+)?)'")


def _refine_floor(
    project: Path,
    root: Path,
    executable: str,
    items: list[PlanItem],
    floor: str,
    edits: list[PlanEdit],
    report: str,
    timeout: int,
) -> tuple[str, list[PlanEdit], str, str, list[str]] | None:
    """A slightly higher floor, when the one the fixes asked for still moves packages back.

    On a public uv SDK, ``>=3.11`` let every fix in, but uv split the
    lock at 3.11.5 and gave Python 3.11.0-3.11.4 beautifulsoup4 4.6.3 (2018).
    uv's split points are in the lock it writes, not in its dry-run report:
    the lock is written on another temporary copy, and the splits above the
    floor are tried, lowest first, until one resolves without a downgrade.
    Returns (floor, edits, dropped, report, packages it keeps current), or None.
    """
    held = [c.package for c in _uv_lock_changes(report, items) if c.downgrade]
    if not held:
        return None
    specs: list[str] = []
    for item in items:
        specs.append(f"{item.package}=={item.version}")
        specs.extend(n for n in item.also_upgrade if n not in specs)
    scratch = root.parent / "split-probe"
    shutil.copytree(root, scratch, ignore=_COPY_IGNORE, symlinks=True)
    try:
        answer = _write_lock(scratch, executable, specs, timeout)
        if isinstance(answer, str) or answer[0] != 0:
            return None
        lock_text = (scratch / "uv.lock").read_text(encoding="utf-8")
    except OSError:
        return None
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    splits = sorted(
        {v for v in _PYTHON_SPLIT.findall(lock_text) if version_key(v) > version_key(floor)},
        key=version_key,
    )
    current = edits
    for candidate in splits[:3]:
        new_edits, dropped, problem = _floor_edits(project, candidate)
        if problem:
            continue
        _revert(root, current)
        _apply(root, new_edits)
        out: list[str] = []
        if _resolves(root, executable, items, timeout, out) is None and out:
            still = [c for c in _uv_lock_changes(out[0], items) if c.downgrade]
            if not still:
                return candidate, new_edits, dropped, out[0], held
        _revert(root, new_edits)
        _apply(root, current)
    return None


def _project_floor(project: Path) -> str:
    """The lowest Python any member's ``requires-python`` admits ("" when none says)."""
    floors: list[str] = []
    for path in _member_pyprojects(project):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        spec = (data.get("project") or {}).get("requires-python")
        if isinstance(spec, str) and _old_floor(spec):
            floors.append(_old_floor(spec))
    return min(floors, key=version_key) if floors else ""


def _avoid_split(
    project: Path, executable: str, included: list[PlanItem], report: str, timeout: int
) -> tuple[PythonFloor, str] | None:
    """The floor that keeps one copy of a package, when the plan fits only by splitting.

    Real case (NVIDIA warp, 2026-11-20): requires-python >=3.11, and soupsieve 4.0
    (which needs 3.11.5) still resolves: uv splits the lock and gives the oldest
    Pythons beautifulsoup4 4.6.3 (2018), which does not use soupsieve at all. On
    an own fixture the split is at 3.11.5. The plan is valid, but the reviewer
    should know that raising requires-python to the split point keeps one
    current beautifulsoup4. Returns (option, uv's report), or None.
    """
    if not any(c.downgrade for c in _uv_lock_changes(report, included)):
        return None
    current = _project_floor(project)
    if not current:
        return None
    with tempfile.TemporaryDirectory(prefix="depquiet-fixplan-") as tmp:
        root = Path(tmp) / "project"
        shutil.copytree(project, root, ignore=_COPY_IGNORE, symlinks=True)
        _apply(root, [e for i in included for e in i.edits])
        refined = _refine_floor(project, root, executable, included, current, [], report, timeout)
    if refined is None:
        return None
    floor, edits, dropped, new_report, held = refined
    option = PythonFloor(floor, edits=edits, dropped=dropped, refined_from=current, avoids=held)
    return option, new_report


# Shown when the project has no lockfile --fix-plan can work with.
UNSUPPORTED_NOTE = (
    "--fix-plan works on uv projects (uv.lock) and Poetry projects (poetry.lock). "
    "On npm, --fix installs the fixes."
)
# No alert left to act on has a fixed version: there is nothing to plan, which
# is not the same as a plan that failed.
NOTHING_TO_FIX = "Nothing to fix: no Python alert left to act on has a fixed version."


def build_fix_plan(
    result: ScanResult,
    project: Path,
    checks: dict[str, FixCheck],
    *,
    timeout: int = 300,
    raise_python_floor: bool = False,
    include_filtered: bool = False,
) -> FixPlan:
    # The project first: fix_targets counts Python alerts only, so on an npm
    # project "nothing to fix" would be false.
    if not (project / "uv.lock").is_file():
        return FixPlan("unsupported", note=UNSUPPORTED_NOTE)
    targets = fix_targets(result, include_filtered=include_filtered)
    if not targets:
        return FixPlan("none", note=NOTHING_TO_FIX)
    found = shutil.which("uv")
    if found is None:
        return FixPlan("unsupported", note="--fix-plan needs uv on PATH.")
    executable = found
    installed = _locked_versions(project)
    newest = _locked_versions(project, highest=True)
    items: list[PlanItem] = []
    # Fixes held back only by the project's Python floor: checked again below,
    # once the plan without them is known.
    floors: dict[str, str] = {}
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
        elif check.reason == "python" and check.python_floor:
            floors[package] = check.python_floor
            item.why = check.next_step
            # In a lock forked by Python version, the newer fork may already be
            # past the fix: aim there, so that fork is not moved back down.
            ahead = newest.get(_pep503(package), "")
            if ahead and version_key(ahead) > version_key(version):
                item.fixed_in, item.version = version, ahead
        else:
            item.why = check.next_step or check.detail
        items.append(item)

    candidates = [i for i in items if not i.why]
    waiting = [i for i in items if i.package in floors]
    if not candidates and not waiting:
        return FixPlan("none", items=items, note="No fix could be planned.")

    report: list[str] = []
    if candidates:
        _verify_candidates(project, executable, candidates, timeout, report)
    option = None
    if waiting:
        kept = [i for i in candidates if i.included]
        retry = [
            i for i in items if not i.included and i not in waiting and "requires-python" in i.why
        ]
        for item in retry:
            item.edits, item.also_upgrade = [], []
        option, floor_report = _plan_python_floor(
            project,
            executable,
            kept,
            waiting,
            floors,
            result,
            timeout,
            include_filtered,
            retry,
        )
        unblocked = [i for i in [*waiting, *retry] if i.package in option.unblocked]
        for item in unblocked:
            if raise_python_floor:
                item.included = True
                item.python_floor = option.floor
            else:
                need = (
                    f"needs Python >={floors[item.package]}"
                    if item.package in floors
                    else ("does not fit with the project's current requires-python")
                )
                item.why = (
                    f"{need}: raising requires-python to >={option.floor} lets it install "
                    "(verified; --raise-python-floor adds that change to the plan)."
                )
        if raise_python_floor and unblocked:
            option.adopted = True
            report[:] = [floor_report]

    if waiting and not (option is not None and option.adopted):
        items += _partial_fixes(
            project, executable, items, floors, result, installed, timeout, include_filtered, report
        )
    if option is None and report and any(i.included for i in items):
        split = _avoid_split(
            project, executable, [i for i in items if i.included], report[0], timeout
        )
        if split is not None:
            option, split_report = split
            if raise_python_floor:
                option.adopted = True
                report[:] = [split_report]
    if report:
        _count_carried(items, report[0])
    included = [i for i in items if i.included]
    edits = [e for i in included for e in i.edits]
    if option is not None and option.adopted:
        edits += option.edits
    diff = _diff(project, edits)
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
    if option is not None and option.adopted:
        note += (
            f" The plan raises requires-python to >={option.floor}: users on older Python "
            "versions can no longer install the project."
        )
    plan = FixPlan(
        status,
        items=items,
        diff=diff,
        note=note,
        python_floor=option,
        include_filtered=include_filtered,
    )
    if included and report:
        plan.lock_changes = _uv_lock_changes(report[0], included)
    return plan


def _final_versions(report: str) -> dict[str, list[str]]:
    """Package -> every version it ends at, from uv's Update/Add lines."""
    found: dict[str, list[str]] = {}
    for line in report.splitlines():
        match = re.match(r"^\s*(Update|Add)\s+([A-Za-z0-9][A-Za-z0-9._-]*)\s+(.*)$", line)
        if not match:
            continue
        tail = match.group(3).split("->")[-1]
        versions = re.findall(r"v([0-9][^\s,]*)", tail)
        if versions:
            found[_pep503(match.group(2))] = versions
    return found


def _count_carried(items: list[PlanItem], report: str) -> None:
    """A fix left out can still land: the verified lock may move its package past it.

    On a public uv SDK, ``jupyterlab==4.5.11`` did not resolve with the
    rest, while the same verified lock moved jupyterlab 4.5.7 → 4.6.6. The
    alert closes, so the plan counts it, at the version the lock reaches.
    """
    final = _final_versions(report)
    for item in items:
        if item.included:
            continue
        versions = final.get(_pep503(item.package), [])
        if versions and all(version_key(v) >= version_key(item.version) for v in versions):
            reached = max(versions, key=version_key)
            item.fixed_in = item.fixed_in or (item.version if reached != item.version else "")
            item.version = reached
            item.included, item.carried, item.why = True, True, ""


def _partial_fixes(
    project: Path,
    executable: str,
    items: list[PlanItem],
    floors: dict[str, str],
    result: ScanResult,
    installed: dict[str, str],
    timeout: int,
    include_filtered: bool,
    report: list[str],
) -> list[PlanItem]:
    """The newest fix that still installs on the project's Python, for fixes that need a newer one.

    Each advisory has its own fix. In a real run, soupsieve 2.8.3 had 8: 5
    fixed by releases that install on Python 3.10 (2.8.4 to 2.10), 3 only by
    releases that need 3.11.5. Keeping requires-python >=3.10, moving to 2.10
    still closes 5 of them; Dependabot reported only "cannot update". Each
    candidate is checked with uv together with the fixes already in the plan.
    """
    kept = [i for i in items if i.included]
    found: list[PlanItem] = []
    for blocked in items:
        if blocked.included or blocked.package not in floors:
            continue
        key = _pep503(blocked.package)
        fixes = [
            f.vuln.fix_version
            for f in result.results
            if _pep503(f.vuln.package) == key
            and f.vuln.fix_version
            and not f.vuln.fix_package
            and (include_filtered or f.verdict is not Verdict.FILTERED)
        ]
        now = installed.get(key, blocked.installed)
        options = sorted(
            {
                v
                for v in fixes
                if version_key(v) < version_key(blocked.fixed_in or blocked.version)
                and (not now or version_key(v) > version_key(now))
            },
            key=version_key,
            reverse=True,
        )
        for version in options[:3]:
            trial = PlanItem(blocked.package, version, now)
            output: list[str] = []
            with tempfile.TemporaryDirectory(prefix="depquiet-partial-") as tmp:
                root = Path(tmp) / "project"
                shutil.copytree(project, root, ignore=_COPY_IGNORE, symlinks=True)
                _apply(root, [e for i in kept for e in i.edits])
                if _resolves(root, executable, [*kept, trial], timeout, output) is not None:
                    continue
            closes = sum(1 for v in fixes if version_key(v) <= version_key(version))
            trial.included = True
            trial.partial = (
                f"closes {closes} of {len(fixes)} alerts; the other "
                f"{len(fixes) - closes} need Python >={floors[blocked.package]}"
            )
            report[:] = output
            kept.append(trial)
            found.append(trial)
            break
    return found


def _verify_candidates(
    project: Path, executable: str, candidates: list[PlanItem], timeout: int, report: list[str]
) -> None:
    """Mark the largest set of candidates that resolves together as included."""
    with tempfile.TemporaryDirectory(prefix="depquiet-fixplan-") as tmp:
        root = Path(tmp) / "project"
        shutil.copytree(project, root, ignore=_COPY_IGNORE, symlinks=True)
        everything = [e for i in candidates for e in i.edits]
        _apply(root, everything)
        failure = _resolves(root, executable, candidates, timeout, report)
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
                reason = _resolves(root, executable, [*kept, item], timeout, report)
                if reason is None:
                    item.included = True
                    kept.append(item)
                else:
                    _revert(root, item.edits)
                    item.why = f"does not resolve together with the rest: {reason}"


# A lock forked by Python version lists each locked version: ``Update x v1.0, v2.0 -> v2.0``.
_LOCK_LINE = re.compile(
    r"^\s*(Update|Add|Remove)\s+([A-Za-z0-9][A-Za-z0-9._-]*)\s+(v[^\s,]+(?:,\s*v[^\s,]+)*)"
    r"(?:\s+->\s+(v[^\s,]+(?:,\s*v[^\s,]+)*))?",
    re.M,
)


def _uv_lock_changes(report: str, included: list[PlanItem]) -> list[LockChange]:
    """What the verified plan moves in uv.lock besides its fixes, from uv's own report."""
    planned = {_pep503(i.package) for i in included}
    planned |= {_pep503(s.split("==")[0]) for i in included for s in i.also_upgrade}
    changes: list[LockChange] = []
    for verb, name, versions, second in _LOCK_LINE.findall(report):
        if _pep503(name) in planned:
            continue
        first = ", ".join(v.strip()[1:] for v in versions.split(","))
        if verb == "Update":
            last = ", ".join(v.strip()[1:] for v in second.split(",") if v.strip())
            changes.append(LockChange(name, first, last))
        elif verb == "Add":
            changes.append(LockChange(name, "", first))
        else:
            changes.append(LockChange(name, first, ""))
    return sorted(changes, key=lambda c: c.order)


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


def apply_fix_plan(plan: FixPlan, project: Path, *, timeout: int = 900) -> str:
    """Apply a verified plan to the project itself: edit the files, then relock.

    Returns "" on success, or what went wrong. On any failure every file is
    put back exactly as it was, the lock file included, so a failed apply never
    leaves the project half-changed.
    """
    tool = plan.tool
    if tool == "npm":
        from depquiet.npmplan import apply_npm_plan

        return apply_npm_plan(plan, project, timeout=timeout)
    lockfile = lockfile_name(tool)
    executable = shutil.which(tool)
    if executable is None:
        return f"{tool} is not on PATH."
    if not plan.included:
        return "the plan has no fix to apply."
    seen = unique_edits(plan.edits)
    touched = sorted({e.file for e in seen} | {lockfile})
    before = {name: (project / name).read_bytes() for name in touched if (project / name).is_file()}

    def restore() -> None:
        for name, data in before.items():
            (project / name).write_bytes(data)

    env = dict(os.environ)
    if tool == "poetry":
        # Only the lock file changes: never create or touch a virtualenv.
        env.update(POETRY_VIRTUALENVS_CREATE="false", NO_COLOR="1")
        cmd = [executable, *plan.command.split()[1:], "--no-interaction", "--no-ansi"]
    else:
        cmd = [executable, "lock", *plan.command.split()[2:]]
    try:
        _apply(project, seen)
        r = subprocess.run(
            cmd,
            cwd=project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        restore()
        return f"{tool} timed out after {timeout} s; nothing was changed."
    except OSError as e:
        restore()
        return f"could not apply the plan ({e}); nothing was changed."
    if r.returncode != 0:
        restore()
        tail = " ".join((r.stderr or r.stdout).split())[-300:]
        return f"{tool} lock failed, nothing was changed: {tail}"
    return ""


def _how(item: PlanItem) -> str:
    text = _how_change(item)
    return f"{text}; it leaves {item.leaves}" if item.leaves else text


def _how_change(item: PlanItem) -> str:
    own = [e for e in item.edits if _pep503(e.package) == _pep503(item.package)]
    if item.carried:
        return "moves past the fix with the rest of the plan"
    if item.partial:
        return f"the newest fix the current Python range allows: {item.partial}"
    if item.python_floor:
        return f"raises `requires-python` to `>={item.python_floor}`, which the fix needs"
    if item.published:
        text = (
            "exempted from the `exclude-newer` cooldown, only up to this release "
            f"(published {item.published[:10]})"
        )
        return text + (f"; remove the entry after {item.expires}" if item.expires else "")
    if item.also_upgrade:
        moved = ", ".join(f"`{s.replace('==', '` → ')}" for s in item.also_upgrade)
        return f"also moves {moved}, which held it back"
    overrides = [e.scope for e in item.edits if e.kind == "override"]
    if overrides:
        return f"`overrides` scoped to {', '.join(f'`{o}`' for o in overrides)}, which pins it"
    if own:
        return "widens the project's own requirement"
    return "lockfile upgrade"


def _id_list(ids: list[str], shown: int = 6) -> str:
    """Up to ``shown`` advisory ids, then how many more: a table row never undercounts."""
    if not ids:
        return "-"
    return first_items(ids, shown)


def fix_plan_markdown(plan: FixPlan, result: ScanResult, version: str = "") -> str:
    """The plan as a pull request description."""

    def cell(text: str) -> str:
        return " ".join(str(text).split()).replace("|", "\\|")

    advisories: dict[str, list[str]] = {}
    fixed_by: dict[str, str] = {}  # advisory -> its fix version, for partial fixes
    for r in result.results:
        if plan.include_filtered or r.verdict is not Verdict.FILTERED:
            known = advisories.setdefault(_pep503(r.vuln.package), [])
            if r.vuln.cve not in known:
                known.append(r.vuln.cve)
            fixed_by[r.vuln.cve] = r.vuln.fix_version or ""
    n = len(plan.included)
    resolver = resolver_name(plan.tool)
    files = {
        "poetry": "`pyproject.toml` requirements and `poetry.lock`",
        "npm": "`package.json` (requirements and `overrides`) and `package-lock.json`",
    }.get(plan.tool, "`pyproject.toml`/`uv.toml` requirements and `uv.lock`")
    if plan.python_floor is not None and plan.python_floor.adopted:
        requirements = any(e.kind != "python" for i in plan.included for e in i.edits)
        files = (
            "`pyproject.toml` requirements and `requires-python`, and `uv.lock`"
            if requirements
            else "`requires-python` in `pyproject.toml`, and `uv.lock`"
        )
    confirmed = "this fix installs" if n == 1 else f"these {n} fixes install together"
    lines = [
        "## Security fixes verified by depquiet",
        "",
        f"{resolver} resolver confirmed that {confirmed}. This pull request changes only {files}.",
        "",
        "| Package | From | To | Advisories | How |",
        "|---|---|---|---|---|",
    ]
    for item in plan.included:
        known = advisories.get(_pep503(item.package), [])
        if item.partial:  # only the advisories this release closes
            known = [
                a
                for a in known
                if fixed_by.get(a) and version_key(fixed_by[a]) <= version_key(item.version)
            ]
        ids = _id_list(known)
        major = " **(major version change)**" if item.major_jump else ""
        lines.append(
            f"| `{cell(item.package)}` | {cell(item.installed or '?')} "
            f"| {cell(item.version)}{major} | {cell(ids)} | {cell(_how(item))} |"
        )
    if plan.lock_changes:
        lockfile = lockfile_name(plan.tool)
        lines += ["", f"### Other changes in `{lockfile}`", ""]
        lines += [f"- {cell(c.describe())}" for c in plan.lock_changes]
        if plan.downgrade_warning():
            lines += ["", f"**{plan.downgrade_warning()}**"]
    floor = plan.python_floor
    if floor is not None and floor.adopted:
        lines += [
            "",
            "### Python floor",
            "",
            f"Raises `requires-python` to `>={floor.floor}`, "
            + (
                f"so every Python gets the same {cell(first_items(floor.avoids, 4))}"
                if not floor.unblocked
                else (
                    "which this fix needs"
                    if len(floor.unblocked) == 1
                    else "which these fixes need"
                )
                + f": {', '.join(f'`{cell(n)}`' for n in floor.unblocked)}"
            )
            + ". Python "
            + (floor.dropped or f"below {floor.floor}")
            + (" are" if " and " in floor.dropped else " is")
            + " no longer supported: fine for an application, a breaking change for "
            "users of a published library.",
        ]
        if floor.refined_from:
            lines += [
                "",
                f"`>={floor.floor}` rather than `>={floor.refined_from}`: with "
                f"`>={floor.refined_from}`, uv splits the lock at {floor.floor} and older "
                f"Pythons get older {cell(first_items(floor.avoids, 4))}.",
            ]
    if plan.left_out:
        lines += ["", "### Not included", ""]
        lines += [
            f"- `{cell(i.package)}` → {cell(i.version)}: {cell(clip(i.why, 300))}"
            for i in plan.left_out
        ]
    by = f" {version}" if version else ""
    lines += [
        "",
        "### Before merging",
        "",
        "- " + plan.note,
        *(["- " + plan.downgrade_warning()] if plan.downgrade_warning() else []),
        "- depquiet checked that the versions resolve, not that your code works with them: "
        "let your tests decide.",
        "",
        "---",
        f"Opened by [depquiet](https://github.com/samuelrojas-dev/depquiet){by}.",
    ]
    return "\n".join(lines) + "\n"


def python_floor_lines(option: PythonFloor | None, tool: str = "uv") -> list[str]:
    """What raising requires-python would do, in plain lines ([] when not relevant)."""
    if option is None:
        return []
    lines = ["", "Python floor:"]
    if option.problem:
        lines.append(f"  some fixes need a newer Python, but {option.problem}")
        return lines
    if not option.unblocked and option.avoids:
        avoids = first_items(option.avoids, 4)
        lines.append(
            f"  Raising requires-python to >={option.floor} "
            f"{'keeps' if option.adopted else 'would keep'} one current {avoids} for every "
            f"Python, verified with uv's resolver: with >={option.refined_from}, uv splits the "
            f"lock at {option.floor} and gives older Pythons an older {avoids}."
        )
        drop = f"Python {option.dropped}" if option.dropped else f"Python below {option.floor}"
        lines.append(
            f"  It drops {drop}: fine for an application, a breaking change for users of a "
            "published library."
        )
        if not option.adopted:
            lines.append("  Add --raise-python-floor to put that change in the plan.")
        return lines
    if not option.unblocked:
        lines.append(
            f"  raising requires-python to >={option.floor} does not let the waiting fixes "
            "install either."
        )
        return lines
    fixes = "fix" if len(option.unblocked) == 1 else "fixes"
    alerts = "alert" if option.alerts == 1 else "alerts"
    lines.append(
        f"  Raising requires-python to >={option.floor} "
        f"{'lets' if option.adopted else 'would let'} {len(option.unblocked)} {fixes} "
        f"install ({', '.join(option.unblocked)}; {option.alerts} {alerts}), verified with "
        f"{'Poetry' if tool == 'poetry' else 'uv'}'s resolver."
    )
    drop = f"Python {option.dropped}" if option.dropped else f"Python below {option.floor}"
    lines.append(
        f"  It drops {drop}: fine for an application, a breaking change for users of a "
        "published library."
    )
    if option.refined_from:
        lines.append(
            f"  >={option.floor}, not >={option.refined_from}: with >={option.refined_from}, uv "
            f"splits the lock at {option.floor} and gives older Pythons older "
            f"{first_items(option.avoids, 4)}."
        )
    if option.still_blocked:
        lines.append(f"  Still blocked even then: {', '.join(option.still_blocked)}.")
    if not option.adopted:
        lines.append("  Add --raise-python-floor to put that change in the plan.")
    return lines


def print_fix_plan(plan: FixPlan, file: Any) -> None:
    """Human summary (to stderr); the diff itself is written by the caller."""
    print("\n🔧 Fix plan", file=file)
    if plan.status == "unsupported" or (plan.status == "none" and not plan.items):
        print(f"   {plan.note}", file=file)
        return
    for item in plan.included:
        jump = "  (major version change)" if item.major_jump else ""
        own = [e for e in item.edits if _pep503(e.package) == _pep503(item.package)]
        if item.carried:
            how = "moves past the fix with the rest of the plan"
        elif item.partial:
            how = f"the newest fix your Python range allows ({item.partial})"
        elif item.python_floor:
            how = f"raise requires-python to >={item.python_floor}, which the fix needs"
        elif item.published:
            how = (
                f"exempt it from your exclude-newer cooldown, only up to this release "
                f"(published {item.published[:10]}"
                + (f"; remove the entry after {item.expires}" if item.expires else "")
                + ")"
            )
        elif item.also_upgrade:
            moved = ", ".join(s.replace("==", " → ") for s in item.also_upgrade)
            how = f"also move {moved}, which holds it back"
        elif any(e.kind == "override" for e in item.edits):
            scopes = ", ".join(e.scope for e in item.edits if e.kind == "override")
            how = f"override it under {scopes}"
        elif own:
            how = "widen your requirement"
        else:
            how = "upgrade"
        print(
            f"   ✓ {item.package} {item.installed or '?'} → {item.version}: {how}{jump}",
            file=file,
        )
        for held in item.held_by:
            print(f"     ({held})", file=file)
        if item.audit_note:
            print(f"     (instead of what npm audit offers: {item.audit_note})", file=file)
        if item.leaves:
            print(f"     (it leaves {item.leaves})", file=file)
        if item.carried:
            print(
                f"     (asking for {item.fixed_in or item.version} itself did not resolve; "
                f"the verified lock takes it to {item.version}, past the fix)",
                file=file,
            )
        elif item.fixed_in:
            print(
                f"     (fixed in {item.fixed_in}; {item.version} is already in your lock "
                "for newer Pythons, so that copy is not moved back)",
                file=file,
            )
    floor = plan.python_floor
    for item in plan.left_out:
        why = item.why
        if floor is not None and not floor.adopted and item.package in floor.unblocked:
            why = "needs a newer Python: see Python floor below"
        print(f"   ✗ {item.package} → {item.version or '?'}: {clip(why, 200)}", file=file)
    if plan.lock_changes:
        lockfile = lockfile_name(plan.tool)
        print(f"\n   It also changes {lockfile}:", file=file)
        for change in plan.lock_changes:
            print(f"     · {change.describe()}", file=file)
        if plan.downgrade_warning():
            print(f"   {plan.downgrade_warning()}", file=file)
    for line in python_floor_lines(plan.python_floor, plan.tool):
        print(f"   {line}" if line else "", file=file)
    if plan.included:
        partial = sum(1 for i in plan.included if i.partial)
        packages = len({_pep503(i.package) for i in plan.items})
        full = len(plan.included) - partial
        fixes = f"{partial} partial fix{'es' if partial > 1 else ''}"
        if plan.status == "verified":
            verdict = "all fixes resolve together"
        elif full:
            verdict = f"{full} of {packages} fixes resolve together"
            verdict += f", plus {fixes} on your current Python range" if partial else ""
        else:
            verb = "resolves" if partial == 1 else "resolve together"
            verdict = f"{fixes} on your current Python range {verb}"
        resolver = resolver_name(plan.tool)
        print(f"\n   Verified with {resolver} resolver: {verdict}.", file=file)
        print(f"   Then run: {plan.command}", file=file)
        print(f"   {plan.note}", file=file)
