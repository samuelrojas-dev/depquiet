"""Fix plans for Poetry projects.

The same promise as the uv plan in ``fixplan``: one change that lets the
fixes install together, verified with the project's own resolver, on a
temporary copy. Poetry differs from uv in two ways that shape this module:

* ``poetry update --lock urllib3`` never fails when another package holds
  urllib3 back; it resolves and leaves urllib3 where it was. So the holders
  are read from ``poetry.lock``, which records every package's constraints
  on its dependencies, and the result is checked by reading the new lock.
* Poetry has no ``--upgrade-package name==version``. ``poetry update`` moves
  a package to the newest version the constraints allow. The plan says which
  version each package actually ends on, and exact pins in ``pyproject.toml``
  keep it exact (a pinned ``requests = "2.31.0"`` becomes the fix version).

When a fix needs a newer Python than ``requires-python`` allows, Poetry
says so (``soupsieve (4.0.0) requires Python >=3.11.5``) only when the fix is
required directly, so the plan asks it that way on a copy, then checks the
raised floor with Poetry exactly as the uv plan does (``--raise-python-floor``).

Dependabot cannot raise a parent package to fix a vulnerable transitive
dependency in Python projects (dependabot-core#16337), Poetry included.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from depquiet.fixcheck import _lowest_python, _pep503, fix_targets
from depquiet.fixplan import (
    _CLAUSE,
    _COPY_IGNORE,
    _REQUIREMENT,
    NOTHING_TO_FIX,
    FixPlan,
    LockChange,
    PlanEdit,
    PlanItem,
    PythonFloor,
    _apply,
    _diff,
    _floor_edits,
    _requirement_strings,
    _satisfies,
    unique_edits,
    widen,
)
from depquiet.models import ScanResult, Verdict, version_key

_ROUNDS = 3  # how many levels of holders to follow (a holder held by another)


def is_poetry_project(project: Path) -> bool:
    return (project / "poetry.lock").is_file() and not (project / "uv.lock").is_file()


# --- Poetry constraints -----------------------------------------------------------


def _bump(version: str, index: int) -> str:
    parts = [int(p) if p.isdigit() else 0 for p in version.split(".")]
    parts += [0] * (index + 1 - len(parts))
    return ".".join(str(p) for p in [*parts[:index], parts[index] + 1])


def _clauses(constraint: str) -> list[tuple[str, str]] | None:
    """A Poetry constraint as PEP 440 clauses; None when it cannot be read."""
    text = constraint.strip()
    if not text or text == "*":
        return []
    if "||" in text or "|" in text:
        return None
    out: list[tuple[str, str]] = []
    for part in (p.strip() for p in re.split(r",|\s+(?=[<>=!~^])", text) if p.strip()):
        if part.startswith("^"):
            base = part[1:].strip()
            if not re.fullmatch(r"\d+(\.\d+)*", base):
                return None
            numbers = [int(p) for p in base.split(".")]
            # ^ allows changes that keep the leftmost non-zero number.
            index = next((i for i, n in enumerate(numbers) if n != 0), len(numbers) - 1)
            out += [(">=", base), ("<", _bump(base, index))]
        elif part.startswith("~") and not part.startswith("~="):
            base = part[1:].strip()
            if not re.fullmatch(r"\d+(\.\d+)*", base):
                return None
            index = 0 if base.count(".") == 0 else 1
            out += [(">=", base), ("<", _bump(base, index))]
        elif re.fullmatch(r"\d[\w.]*(\.\*)?", part):
            out.append(("==", part))  # a bare version is an exact pin in Poetry
        else:
            match = _CLAUSE.match(part.replace(" ", ""))
            if match is None:
                return None
            out.append((match.group(1), match.group(2)))
    return out


def allows(constraint: str, version: str) -> bool | None:
    """Whether a Poetry constraint admits ``version``; None when it cannot be read."""
    clauses = _clauses(constraint)
    if clauses is None:
        return None
    return all(_satisfies(version, op, bound) for op, bound in clauses)


def widen_poetry(constraint: str, version: str) -> str | None:
    """The constraint changed just enough to admit ``version``.

    Returns None when it already admits it or cannot be read. The style is
    kept: an exact pin stays exact, ``^`` stays ``^``, ``~`` stays ``~``, and
    a range gets its failing bounds moved the way :func:`fixplan.widen` does.
    """
    text = constraint.strip()
    if allows(text, version) is not False:
        return None
    if text.startswith("^"):
        return f"^{version}"
    if text.startswith("~") and not text.startswith("~="):
        return f"~{version}"
    if re.fullmatch(r"(==)?\s*\d[\w.]*", text):
        return f"=={version}" if text.startswith("==") else version
    widened = widen("x" + text.replace(" ", ""), version)
    return widened[1:] if widened else None


# --- reading the project ----------------------------------------------------------


def _lock(project: Path) -> dict[str, dict[str, Any]]:
    """Locked packages by normalized name: version and constraints on dependencies."""
    try:
        data = tomllib.loads((project / "poetry.lock").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    packages: dict[str, dict[str, Any]] = {}
    for pkg in data.get("package", []):
        name = pkg.get("name")
        if not isinstance(name, str):
            continue
        needs: dict[str, list[str]] = {}
        for dep, spec in (pkg.get("dependencies") or {}).items():
            entries = spec if isinstance(spec, list) else [spec]
            found = [
                e if isinstance(e, str) else str(e.get("version", "*"))
                for e in entries
                if isinstance(e, (str, dict))
            ]
            needs[_pep503(dep)] = found
        packages[_pep503(name)] = {
            "name": name,
            "version": str(pkg.get("version", "")),
            "needs": needs,
        }
    return packages


def _holders(lock: dict[str, dict[str, Any]], package: str, version: str) -> list[str]:
    """Locked packages whose constraint on ``package`` does not admit ``version``."""
    key = _pep503(package)
    held = [
        str(pkg["name"])
        for pkg in lock.values()
        if any(allows(spec, version) is False for spec in pkg["needs"].get(key, []))
    ]
    return sorted(held)


def _poetry_tables(data: dict[str, Any]) -> list[dict[str, Any]]:
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    tables += [(g or {}).get("dependencies") for g in (poetry.get("group") or {}).values()]
    return [t for t in tables if isinstance(t, dict)]


def _own_constraints(project: Path, package: str) -> tuple[list[str], list[str]]:
    """How ``pyproject.toml`` constrains ``package``: (Poetry-table constraints,
    PEP 621 requirement strings)."""
    try:
        data = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return [], []
    key = _pep503(package)
    table: list[str] = []
    for deps in _poetry_tables(data):
        for name, spec in deps.items():
            if _pep503(name) != key:
                continue
            entries = spec if isinstance(spec, list) else [spec]
            for entry in entries:
                if isinstance(entry, str):
                    table.append(entry)
                elif isinstance(entry, dict) and isinstance(entry.get("version"), str):
                    table.append(entry["version"])
    pep621 = [
        req
        for req in dict.fromkeys(_requirement_strings(data))
        if (m := _REQUIREMENT.match(req)) and _pep503(m.group("name")) == key
    ]
    return list(dict.fromkeys(table)), pep621


def _edits_to_allow(project: Path, package: str, version: str) -> list[PlanEdit] | None:
    """Edits that make the project's own requirements admit ``version``.

    None when one of them excludes it and cannot be rewritten safely.
    """
    table, pep621 = _own_constraints(project, package)
    edits: list[PlanEdit] = []
    for old in table:
        verdict = allows(old, version)
        if verdict is None:
            return None
        if verdict is False:
            new = widen_poetry(old, version)
            if new is None:
                return None
            edits.append(PlanEdit("pyproject.toml", package, old, new, kind="poetry"))
    for req in pep621:
        new = widen(req, version)
        if new is not None and new != req:
            edits.append(PlanEdit("pyproject.toml", package, req, new))
    return edits


def _relax(project: Path, package: str, floor: str) -> list[PlanEdit]:
    """Probe edits: let ``package`` move anywhere from ``floor`` up."""
    table, pep621 = _own_constraints(project, package)
    edits = [
        PlanEdit("pyproject.toml", package, old, f">={floor}", kind="poetry")
        for old in table
        if old.strip() != "*"
    ]
    for req in pep621:
        match = _REQUIREMENT.match(req)
        if match:
            name = match.group("name") + (match.group("extras") or "")
            edits.append(
                PlanEdit(
                    "pyproject.toml", package, req, f"{name}>={floor}{match.group('marker') or ''}"
                )
            )
    return edits


# --- running Poetry ---------------------------------------------------------------


def update_command(names: list[str]) -> list[str]:
    return ["update", "--lock", "--no-interaction", "--no-ansi", *names]


def _run_update(
    root: Path, executable: str, names: list[str], timeout: int, limit: int | None = 400
) -> tuple[int, str]:
    env = {**os.environ, "POETRY_VIRTUALENVS_CREATE": "false", "NO_COLOR": "1"}
    try:
        r = subprocess.run(
            [executable, *update_command(names)],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return 1, f"poetry update timed out after {timeout} s"
    except OSError as e:
        return 1, str(e)
    text = " ".join((r.stderr or r.stdout).split())
    return r.returncode, text[-limit:] if limit else text


def _copy(project: Path, parent: Path, name: str) -> Path:
    dest = parent / name
    shutil.copytree(project, dest, ignore=_COPY_IGNORE, symlinks=True)
    return dest


def _reaches(lock: dict[str, dict[str, Any]], package: str, version: str) -> bool:
    locked = lock.get(_pep503(package), {}).get("version", "")
    return bool(locked) and version_key(str(locked)) >= version_key(version)


# --- the plan ---------------------------------------------------------------------


def _plan_one(
    project: Path, work: Path, executable: str, item: PlanItem, timeout: int
) -> tuple[list[PlanEdit], list[str]] | str:
    """Edits and co-updates that bring one package to its fix, or why not.

    Works on a fresh copy: relax the holders' own requirements, let Poetry
    resolve, and read which versions it chose.
    """
    own = _edits_to_allow(project, item.package, item.version)
    if own is None:
        return (
            f"pyproject.toml constrains {item.package} in a form depquiet does not rewrite; "
            f"allow {item.version} by hand."
        )
    start = _lock(project)
    probe = _copy(project, work, f"probe-{_pep503(item.package)}")
    _apply(probe, own)
    holders: list[str] = []
    relaxed: list[PlanEdit] = []
    detail = ""
    for _ in range(_ROUNDS):
        code, detail = _run_update(probe, executable, [item.package, *holders], timeout)
        if code != 0:
            return f"Poetry could not resolve it: {detail}"
        now = _lock(probe)
        if _reaches(now, item.package, item.version):
            break
        new = [h for h in _holders(now, item.package, item.version) if h not in holders]
        if not new:
            names = ", ".join(_holders(now, item.package, item.version)) or "another requirement"
            return (
                f"held below {item.version} by {names}, and no newer release of it allows the fix."
            )
        for holder in new:
            floor = str(start.get(_pep503(holder), {}).get("version", "")) or "0"
            edits = _relax(probe, holder, floor)
            _apply(probe, edits)
            relaxed += edits
        holders += new
    else:
        return f"still below {item.version} after moving {', '.join(holders)}."

    resolved = _lock(probe)
    final = list(own)
    moved: list[str] = []
    for holder in holders:
        chosen = str(resolved.get(_pep503(holder), {}).get("version", ""))
        if not chosen:
            continue
        moved.append(f"{holder}=={chosen}")
        allowing = _edits_to_allow(project, holder, chosen)
        if allowing is None:
            return f"pyproject.toml constrains {holder} in a form depquiet does not rewrite."
        final += allowing
    return final, moved


# --- the Python floor -------------------------------------------------------------

# "soupsieve (4.1.1) requires Python >=3.11.5": one line per release Poetry tried.
_REQUIRES_PYTHON = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*) \(([^)\s]+)\) requires Python "
    r"([<>=!~][^\s,]*(?:,[<>=!~][^\s,]*)*)"
)


def _require(root: Path, package: str, version: str) -> bool:
    """Make ``package>=version`` a direct requirement of the copy at ``root``."""
    path = root / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    lines = text.splitlines(keepends=True)
    section = ""
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.strip("[]").strip()
            if section == "tool.poetry.dependencies" and not isinstance(
                (data.get("project") or {}).get("dependencies"), list
            ):
                table = (data.get("tool") or {}).get("poetry", {}).get("dependencies") or {}
                if any(_pep503(n) == _pep503(package) for n in table):
                    return False
                lines.insert(i + 1, f'{package} = ">={version}"\n')
                break
            continue
        if section == "project" and re.match(r"\s*dependencies\s*=\s*\[", line):
            lines[i] = line.replace("[", f'["{package}>={version}", ', 1)
            break
    else:
        return False
    path.write_text("".join(lines), encoding="utf-8")
    return True


def _python_need(project: Path, work: Path, executable: str, item: PlanItem, timeout: int) -> str:
    """The lowest Python the fix installs on, when requires-python is what keeps it out.

    ``poetry update`` on a transitive package resolves and quietly keeps the
    old version, so the fix is required directly on a copy: then Poetry names
    the Python each release needs. "" when that is not the obstacle.
    """
    probe = _copy(project, work, f"python-{_pep503(item.package)}")
    if not _require(probe, item.package, item.version):
        return ""
    code, detail = _run_update(probe, executable, [item.package], timeout, limit=None)
    if code == 0:
        return ""
    floors = [
        _lowest_python(spec)
        for name, version, spec in _REQUIRES_PYTHON.findall(detail)
        if _pep503(name) == _pep503(item.package)
        and version_key(version) >= version_key(item.version)
    ]
    floors = [f for f in floors if f]
    return min(floors, key=version_key) if floors else ""


def _poetry_python(project: Path) -> str:
    """The ``python`` constraint of ``[tool.poetry.dependencies]``, "" when absent."""
    try:
        data = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    deps = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    value = deps.get("python", "")
    return value if isinstance(value, str) else ""


def build_poetry_plan(
    result: ScanResult,
    project: Path,
    *,
    timeout: int = 600,
    include_filtered: bool = False,
    raise_python_floor: bool = False,
) -> FixPlan:
    """A verified fix plan for a Poetry project (see the module docstring).

    Fixes left out because they need a newer Python get a Python floor option,
    verified with Poetry on a copy whose requires-python is raised; with
    ``raise_python_floor`` the plan adopts it. Without it, the newest release
    that still installs on the current Python goes in as a partial fix.
    """
    plan, floors = _floor_plan(
        result,
        project,
        timeout=timeout,
        include_filtered=include_filtered,
        raise_python_floor=raise_python_floor,
    )
    if floors and not (plan.python_floor is not None and plan.python_floor.adopted):
        _add_partial_fixes(plan, project, floors, result, timeout, include_filtered)
    return plan


def _add_partial_fixes(
    plan: FixPlan,
    project: Path,
    floors: dict[str, str],
    result: ScanResult,
    timeout: int,
    include_filtered: bool,
) -> None:
    """Add the newest release each held-back fix can reach on the current Python.

    ``poetry update`` on soupsieve with requires-python >=3.10 moved it from
    2.8.3 to 2.10 (seen with Poetry 2.4): not the 4.0 fix, but 2.10 closes the
    advisories fixed in 2.8.4 to 2.10. Checked with the plan's other fixes.
    """
    executable = shutil.which("poetry")
    if executable is None:
        return
    kept = [i for i in plan.included]
    found: list[PlanItem] = []
    final: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="depquiet-partial-") as tmp:
        work = Path(tmp)
        for blocked in [i for i in plan.items if not i.included and i.package in floors]:
            key = _pep503(blocked.package)
            fixes = [
                f.vuln.fix_version
                for f in result.results
                if _pep503(f.vuln.package) == key
                and f.vuln.fix_version
                and not f.vuln.fix_package
                and (include_filtered or f.verdict is not Verdict.FILTERED)
            ]
            copy = _copy(project, work, f"partial-{key}")
            _apply(copy, unique_edits([e for i in kept for e in i.edits]))
            code, _detail = _run_update(copy, executable, [*_names(kept), blocked.package], timeout)
            after = _lock(copy)
            if code != 0 or key not in after:
                continue
            if not all(_reaches(after, i.package, i.version) for i in kept):
                continue
            reached = str(after[key]["version"])
            closes = sum(1 for v in fixes if version_key(v) <= version_key(reached))
            if not closes or version_key(reached) <= version_key(blocked.installed or "0"):
                continue
            item = PlanItem(blocked.package, reached, blocked.installed, included=True)
            item.partial = (
                f"closes {closes} of {len(fixes)} alerts; the other "
                f"{len(fixes) - closes} need Python >={floors[blocked.package]}"
            )
            kept.append(item)
            found.append(item)
            final = after
    if not found:
        return
    plan.items += found
    plan.status = "partial"
    if plan.note == "No fix could be verified.":
        plan.note = (
            "Verified with Poetry's resolver only: run your tests. These are partial fixes: "
            "the full fixes need a newer Python."
        )
    planned = {_pep503(i.package) for i in kept}
    planned |= {_pep503(s.split("==")[0]) for i in kept for s in i.also_upgrade}
    plan.lock_changes = _lock_changes(_lock(project), final, planned)


def _floor_plan(
    result: ScanResult,
    project: Path,
    *,
    timeout: int,
    include_filtered: bool,
    raise_python_floor: bool,
) -> tuple[FixPlan, dict[str, str]]:
    """The plan and the Python each held-back fix needs (package -> floor)."""
    plan = _build_poetry_plan(result, project, timeout=timeout, include_filtered=include_filtered)
    blocked = [i for i in plan.items if not i.included and i.why]
    executable = shutil.which("poetry")
    if not blocked or executable is None:
        return plan, {}
    with tempfile.TemporaryDirectory(prefix="depquiet-floor-") as tmp:
        work = Path(tmp)
        floors = {
            i.package: need
            for i in blocked
            if (need := _python_need(project, work, executable, i, timeout))
        }
        if not floors:
            return plan, {}
        floor = max(floors.values(), key=version_key)
        edits, dropped, problem = _floor_edits(project, floor)
        if not problem and _poetry_python(project):
            problem = (
                f"pyproject.toml also sets python = {_poetry_python(project)!r} in "
                "[tool.poetry.dependencies]; depquiet only raises requires-python, so raise "
                "both by hand."
            )
        option = PythonFloor(floor, edits=edits, dropped=dropped, problem=problem)
        plan.python_floor = option
        for item in blocked:
            if item.package in floors:
                item.why = (
                    f"needs Python >={floors[item.package]}, and requires-python allows older "
                    f"versions: raise it to >={floor} (--raise-python-floor checks that)."
                )
        if problem:
            option.still_blocked = list(floors)
            return plan, floors
        raised = _copy(project, work, "raised")
        _apply(raised, edits)
        trial = _build_poetry_plan(
            result, raised, timeout=timeout, include_filtered=include_filtered
        )
    was = {i.package for i in plan.included}
    unblocked = [i for i in trial.included if i.package not in was]
    option.unblocked = [i.package for i in unblocked]
    option.still_blocked = [p for p in floors if p not in option.unblocked]
    keys = {_pep503(p) for p in option.unblocked}
    option.alerts = sum(
        1
        for r in result.results
        if (include_filtered or r.verdict is not Verdict.FILTERED)
        and _pep503(r.vuln.package) in keys
    )
    if not unblocked:
        return plan, floors
    if not raise_python_floor:
        for item in plan.items:
            if item.package in option.unblocked:
                wanted = floors.get(item.package)
                item.why = (
                    (
                        f"needs Python >={wanted}"
                        if wanted
                        else "does not fit the current Python range"
                    )
                    + f": raising requires-python to >={floor} lets it install (verified; "
                    "--raise-python-floor adds that change to the plan)."
                )
        return plan, floors
    option.adopted = True
    for item in trial.items:
        if item.package in option.unblocked:
            item.python_floor = floor
    trial.python_floor = option
    trial.diff = _diff(
        project, unique_edits([*[e for i in trial.included for e in i.edits], *edits])
    )
    trial.note += (
        f" The plan raises requires-python to >={floor}: users on older Python versions can "
        "no longer install the project."
    )
    return trial, floors


def _build_poetry_plan(
    result: ScanResult, project: Path, *, timeout: int = 600, include_filtered: bool = False
) -> FixPlan:
    """The plan within the project's current requires-python."""
    if not fix_targets(result, include_filtered=include_filtered):
        return FixPlan("none", note=NOTHING_TO_FIX, tool="poetry")
    executable = shutil.which("poetry")
    if executable is None:
        return FixPlan(
            "unsupported",
            note="--fix-plan needs poetry on PATH for a Poetry project.",
            tool="poetry",
        )
    lock = _lock(project)
    targets = {
        package: version
        for package, version in fix_targets(result, include_filtered=include_filtered).items()
        if _pep503(package) in lock and not _reaches(lock, package, version)
    }
    if not targets:
        return FixPlan("none", note=NOTHING_TO_FIX, tool="poetry")

    items = [
        PlanItem(package=p, version=v, installed=str(lock[_pep503(p)]["version"]))
        for p, v in sorted(targets.items())
    ]
    with tempfile.TemporaryDirectory(prefix="depquiet-plan-") as tmp:
        work = Path(tmp)
        for item in items:
            planned = _plan_one(project, work, executable, item, timeout)
            if isinstance(planned, str):
                item.why = planned
            else:
                item.edits, item.also_upgrade = planned

        # Verify the candidates together, exactly as they will be applied. If
        # the set does not resolve, add them one at a time and keep what does.
        runs = 0

        def verified(trial: list[PlanItem]) -> tuple[bool, dict[str, dict[str, Any]], str]:
            nonlocal runs
            runs += 1
            copy = _copy(project, work, f"verify-{runs}")
            _apply(copy, unique_edits([e for i in trial for e in i.edits]))
            code, detail = _run_update(copy, executable, _names(trial), timeout)
            after = _lock(copy)
            ok = code == 0 and all(_reaches(after, i.package, i.version) for i in trial)
            return ok, after, detail if code != 0 else ""

        candidates = [i for i in items if not i.why]
        included: list[PlanItem] = []
        final: dict[str, dict[str, Any]] = {}
        if candidates:
            ok, final, _ = verified(candidates)
            if ok:
                included = list(candidates)
            else:
                for candidate in candidates:
                    ok, after, detail = verified([*included, candidate])
                    if ok:
                        included.append(candidate)
                        final = after
                    else:
                        candidate.why = (
                            f"does not resolve together with the other fixes: {detail}"
                            if detail
                            else "another fix in the plan holds it back."
                        )
        for item in items:
            item.included = item in included
            if item.included:
                item.version = str(final[_pep503(item.package)]["version"])

    chosen = [i for i in items if i.included]
    if not chosen:
        return FixPlan("none", items=items, note="No fix could be verified.", tool="poetry")
    fixed_names = {_pep503(i.package) for i in chosen}
    fixed_names |= {_pep503(s.split("==")[0]) for i in chosen for s in i.also_upgrade}
    lock_changes = _lock_changes(_lock(project), final, fixed_names)
    status = "verified" if len(chosen) == len(items) else "partial"
    plan = FixPlan(
        status,
        items=items,
        diff=_diff(project, unique_edits([e for i in chosen for e in i.edits])),
        note=(
            "Verified with Poetry's resolver only: run your tests, above all for a major "
            "version change. poetry update moves each package to the newest version your "
            "constraints allow, which can be newer than the fix."
        ),
        tool="poetry",
        lock_changes=lock_changes,
        include_filtered=include_filtered,
    )
    return plan


def _lock_changes(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]], planned: set[str]
) -> list[LockChange]:
    """Packages the verified poetry.lock moves besides the planned fixes."""
    changes: list[LockChange] = []
    for name in sorted(set(before) | set(after)):
        if name in planned:
            continue
        old = str(before.get(name, {}).get("version", ""))
        new = str(after.get(name, {}).get("version", ""))
        if old != new:
            shown = after.get(name, before.get(name, {})).get("name", name)
            changes.append(LockChange(str(shown), old, new))
    return sorted(changes, key=lambda c: c.order)


def _names(items: list[PlanItem]) -> list[str]:
    names: list[str] = []
    for item in items:
        for name in [item.package, *[s.split("==")[0] for s in item.also_upgrade]]:
            if name not in names:
                names.append(name)
    return names
