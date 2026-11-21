"""npm fix plans: the smallest change that lets each fix install, verified with npm.

npm audit already proposes a fix for most vulnerable packages. Where no version
of the parent accepts the fix within its declared range, its answer is a
semver-major change, and in a pilot of 153 popular lockfiles (2026-11-21) 221 of
399 such changes were *downgrades*: @tailwindcss/typography 0.5.19 pins
postcss-selector-parser exactly to 6.0.10, so ``npm audit fix --force`` moves
typography back to 0.5.4. The fixed postcss-selector-parser 6.1.6 is on the
same line as 6.0.10; an ``overrides`` entry scoped to typography installs it
and moves nothing else.

For each vulnerable package the plan:

- reads from the lock which package holds each vulnerable copy and with what
  range (no network needed);
- picks the lowest fixed release on the installed version's own line (caret
  semantics), or the lowest fixed release at all when the line has none;
- needs nothing but ``npm update`` when every range already admits it, widens
  the project's own requirement when the project is the one holding it, and
  otherwise adds an override scoped to the parent that holds it;
- applies that to a temporary copy and runs ``npm update --package-lock-only
  --ignore-scripts``: npm's resolver decides, no install script runs, and the
  project itself is not touched. What npm locks is read back from the copy.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from depquiet.fixplan import FixPlan, LockChange, PlanEdit, PlanItem
from depquiet.models import ScanResult, Verdict, first_items, version_key
from depquiet.npm_semver import match_npm_range

LOCK = "package-lock.json"
MANIFEST = "package.json"
_DEP_KEYS = ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies")
_ROOT_KEYS = ("dependencies", "devDependencies", "optionalDependencies")
_STABLE = re.compile(r"\d+\.\d+\.\d+\Z")
_COPY_IGNORE = shutil.ignore_patterns("node_modules", ".git")

Releases = Callable[[str], list[str]]


def is_npm_project(project: Path) -> bool:
    """A package.json with an npm lockfile, and no Python lock that another plan handles."""
    return (
        (project / MANIFEST).is_file()
        and (project / LOCK).is_file()
        and not (project / "uv.lock").exists()
        and not (project / "poetry.lock").exists()
    )


def _packages(project: Path) -> dict[str, dict[str, Any]]:
    data = json.loads((project / LOCK).read_text(encoding="utf-8"))
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict) or not packages:
        raise ValueError("lockfileVersion 1 has no packages map")
    return {k: v for k, v in packages.items() if isinstance(v, dict)}


def _name(key: str, info: dict[str, Any]) -> str:
    name = info.get("name")
    return name if isinstance(name, str) else key.rsplit("node_modules/", 1)[-1]


def _resolve(packages: dict[str, dict[str, Any]], start: str, name: str) -> str | None:
    """The lock key ``name`` resolves to from ``start``, as Node looks it up."""
    base = start
    while True:
        key = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if key in packages:
            return key
        if not base:
            return None
        cut = base.rfind("node_modules/")
        base = base[:cut].rstrip("/") if cut > 0 else ""


def _holders(packages: dict[str, dict[str, Any]], name: str, copy: str) -> list[tuple[str, str]]:
    """(lock key, declared range) of every entry whose ``name`` resolves to ``copy``."""
    found = []
    for key, info in packages.items():
        if info.get("link"):
            continue
        for dep_key in _DEP_KEYS:
            declared = info.get(dep_key)
            if isinstance(declared, dict) and isinstance(declared.get(name), str):
                if _resolve(packages, key, name) == copy:
                    found.append((key, declared[name]))
                break
    return found


def _line(version: str) -> tuple[int, ...]:
    """The caret line of a version: ^1.2.3 stays on 1.x, ^0.1.7 on 0.1.x."""
    major, minor, patch = (int(p) for p in version.split("."))
    return (major,) if major else (0, minor) if minor else (0, 0, patch)


def _vulnerable(version: str, ranges: list[str]) -> bool:
    return any(match_npm_range(version, r)[0] != "not_matched" for r in ranges)


def fixed_release(installed: str, ranges: list[str], releases: list[str]) -> str:
    """Lowest release above ``installed`` outside every range: same line first, "" if none."""
    if not _STABLE.match(installed):
        return ""
    newer = sorted(
        (r for r in releases if _STABLE.match(r) and version_key(r) > version_key(installed)),
        key=version_key,
    )
    fixed = [r for r in newer if not _vulnerable(r, ranges)]
    same = [r for r in fixed if _line(r) == _line(installed)]
    return (same or fixed or [""])[0]


def _keep_operator(declared: str, version: str) -> str:
    """``^1.2.3`` → ``^1.4.0``, ``~1.2.3`` → ``~1.4.0``, ``1.2.3`` → ``1.4.0``."""
    match = re.fullmatch(r"\s*([~^]?)\d+\.\d+\.\d+\s*", declared)
    return f"{match.group(1)}{version}" if match else f"^{version}"


def _npm(executable: str, args: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    env = dict(os.environ, npm_config_update_notifier="false", npm_config_fund="false")
    try:
        r = subprocess.run(
            [executable, *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return 1, f"npm timed out after {timeout} s"
    except OSError as e:
        return 1, str(e)
    return r.returncode, (r.stderr or r.stdout)


def registry_releases(executable: str, project: Path, timeout: int = 60) -> Releases:
    """Every published version of a package, from the registry the project's npm uses."""
    cache: dict[str, list[str]] = {}

    def releases(name: str) -> list[str]:
        if name not in cache:
            try:
                r = subprocess.run(
                    [executable, "view", name, "versions", "--json"],
                    cwd=project,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=dict(os.environ, npm_config_update_notifier="false"),
                )
                data = json.loads(r.stdout or "[]") if r.returncode == 0 else []
            except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
                data = []
            if isinstance(data, str):
                data = [data]
            cache[name] = [v for v in data if isinstance(v, str)]
        return cache[name]

    return releases


def _versions(packages: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for key, info in packages.items():
        if key and isinstance(info.get("version"), str) and not info.get("link"):
            found.setdefault(_name(key, info), set()).add(info["version"])
    return found


def _lock_changes(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]], skip: set[str]
) -> list[LockChange]:
    old, new = _versions(before), _versions(after)
    changes = []

    def fmt(versions: set[str]) -> str:
        return ", ".join(sorted(versions, key=version_key))

    for name in sorted(set(old) | set(new)):
        if name in skip or old.get(name) == new.get(name):
            continue
        changes.append(LockChange(name, fmt(old.get(name, set())), fmt(new.get(name, set()))))
    return sorted(changes, key=lambda c: c.order)


def _manifest_text(data: dict[str, Any], original: str) -> str:
    indent = re.search(r'\n([ \t]+)"', original)
    text = json.dumps(data, indent=indent.group(1) if indent else 2, ensure_ascii=False)
    return text + ("\n" if original.endswith("\n") else "")


def _ranges(result: ScanResult, include_filtered: bool) -> dict[str, list[str]]:
    """Advisory ranges per vulnerable package, from the scan."""
    found: dict[str, list[str]] = {}
    for r in result.results:
        if r.verdict is Verdict.FILTERED and not include_filtered:
            continue
        vuln = r.vuln
        rng = vuln.advisory_range or (vuln.version if vuln.version_kind == "range" else "")
        if not rng:
            continue
        known = found.setdefault(vuln.package, [])
        if rng not in known:
            known.append(rng)
    return found


def _audit_fixes(
    result: ScanResult, packages: dict[str, dict[str, Any]]
) -> dict[str, tuple[str, str, str, str]]:
    """Package → (parent, current, target, kind) from npm audit's own fix.

    kind: "upgrade" (newer, same caret line: npm can do it within semver),
    "downgrade" or "major". A plain upgrade of the parent is the better fix:
    the plan takes it instead of overriding what the parent pulls in.
    """
    found: dict[str, tuple[str, str, str, str]] = {}
    for r in result.results:
        parent, target = r.vuln.fix_package, r.vuln.fix_version
        if not parent or not target or r.vuln.package in found:
            continue
        current = (packages.get(f"node_modules/{parent}") or {}).get("version")
        if not (isinstance(current, str) and _STABLE.match(current) and _STABLE.match(target)):
            continue
        if version_key(target) < version_key(current):
            kind = "downgrade"
        elif _line(target) == _line(current):
            kind = "upgrade"
        else:
            kind = "major"
        found[r.vuln.package] = (parent, current, target, kind)
    return found


def _bundler(packages: dict[str, dict[str, Any]], key: str) -> str:
    """ "npm 11.10.1" for a copy shipped inside that package's tarball (``inBundle``)."""
    base = key
    while (cut := base.rfind("/node_modules/")) > 0:
        base = base[:cut]
        info = packages.get(base) or {}
        if not info.get("inBundle"):
            return f"{_name(base, info)} {info.get('version', '?')}"
    return "its parent"


def _bundled_notes(packages: dict[str, dict[str, Any]], name: str, ranges: list[str]) -> list[str]:
    """Vulnerable copies shipped inside another package: only its next release changes them."""
    notes = []
    for key, info in packages.items():
        if (
            key
            and info.get("inBundle")
            and _name(key, info) == name
            and _vulnerable(str(info.get("version")), ranges)
        ):
            bundler = _bundler(packages, key)
            note = (
                f"{name} {info['version']} is bundled inside {bundler}: only a new release of "
                f"{bundler.split(' ')[0]} can change it"
            )
            if note not in notes:
                notes.append(note)
    return notes


def _plan_package(
    name: str,
    ranges: list[str],
    packages: dict[str, dict[str, Any]],
    manifest: dict[str, Any],
    releases: Releases,
) -> tuple[PlanItem, dict[str, dict[str, str]], dict[tuple[str, str], str], dict[str, str]]:
    """One package: the item, its overrides, root requirement changes, copies it leaves.

    A copy is left (with the reason) when its only fixed releases are on a newer
    major line and a parent pins it below: upscayl, 2026-11-21, where every fixed
    glob is 14.x and @next/eslint-plugin-next pins 10.3.10. The package's other
    copies still get their fix.
    """
    skipped: dict[str, str] = {}
    found_copies = [
        (key, info["version"], bool(info.get("inBundle")))
        for key, info in packages.items()
        if key
        and _name(key, info) == name
        and isinstance(info.get("version"), str)
        and _vulnerable(info["version"], ranges)
    ]
    copies = [(key, version) for key, version, bundled in found_copies if not bundled]
    item = PlanItem(package=name, version="")
    overrides: dict[str, dict[str, str]] = {}
    requirements: dict[tuple[str, str], str] = {}
    item.held_by = _bundled_notes(packages, name, ranges)
    if not copies:
        item.why = (
            "; ".join(item.held_by) if item.held_by else "no vulnerable copy in package-lock.json"
        )
        return item, overrides, requirements, skipped
    item.installed = ", ".join(sorted({v for _, v in copies}, key=version_key))
    found = manifest.get("overrides")
    existing: dict[str, Any] = found if isinstance(found, dict) else {}
    targets = []
    for key, version in copies:
        target = fixed_release(version, ranges, releases(name))
        if not target:
            item.why = f"no published release of {name} above {version} is outside the advisories"
            return item, {}, {}, {}
        copy_overrides: dict[str, str] = {}
        copy_requirements: dict[tuple[str, str], str] = {}
        copy_held: list[str] = []
        for holder, declared in _holders(packages, name, key):
            # Round 1's `npm update` left this copy vulnerable even though the holder's
            # range admits the fix (minimatch 3.1.2 under eslint in upscayl, npm 9.2,
            # 2026-11-21; npm 10.9 moved a nested copy on an own fixture). An override
            # pinned inside that range moves it and asks nothing the holder did not allow.
            within = match_npm_range(target, declared)[0] == "matched"
            if holder == "":
                section = next(
                    (s for s in _ROOT_KEYS if name in (manifest.get(s) or {})), "dependencies"
                )
                copy_requirements[(section, name)] = _keep_operator(declared, target)
                continue
            parent = _name(holder, packages[holder])
            parent_version = packages[holder].get("version", "?")
            if not within and _line(target) != _line(version):
                skipped[key] = (
                    f"{name} {version} under {parent} {parent_version}: every fixed release is "
                    f"on a newer major line ({target} and up), outside what {parent} requires "
                    f"({declared}); an override across a major version is not safe, upgrading "
                    f"{parent} is the fix"
                )
                break
            if "node_modules/" not in holder:  # a workspace package declares it
                item.why = (
                    f"workspace {holder} requires {name}@{declared}: change it there "
                    f"to allow {target}"
                )
                return item, {}, {}, {}
            if name in existing and not isinstance(existing[name], dict):
                item.why = f"your package.json already overrides {name} to {existing[name]}"
                return item, {}, {}, {}
            if parent in existing and not isinstance(existing[parent], dict):
                item.why = (
                    f"{parent} holds {name}@{declared}, and your package.json already "
                    f"overrides {parent} itself"
                )
                return item, {}, {}, {}
            copy_overrides[parent] = target
            held = (
                f"{parent} {parent_version} accepts the fix, but npm update left {name} "
                f"{version} under it"
                if within
                else f"{parent} {parent_version} requires {name}@{declared}"
            )
            if held not in copy_held:
                copy_held.append(held)
        if key in skipped:
            continue
        targets.append(target)
        for parent, value in copy_overrides.items():
            overrides.setdefault(parent, {})[name] = value
        requirements.update(copy_requirements)
        item.held_by += [h for h in copy_held if h not in item.held_by]
    if not targets:
        item.why = "; ".join(skipped.values())
        return item, {}, {}, skipped
    item.version = max(targets, key=version_key)
    return item, overrides, requirements, skipped


def build_npm_plan(
    result: ScanResult,
    project: Path,
    *,
    include_filtered: bool = False,
    timeout: int = 600,
    releases: Releases | None = None,
) -> FixPlan:
    """Plan in two rounds, each verified with npm on a temporary copy.

    1. What npm can do within semver: ``npm update`` for every vulnerable
       package, and npm audit's own fix when it is a plain upgrade of a parent
       (widening the project's requirement on it when that pins it).
    2. For what is still vulnerable in the lock round 1 produced: an override
       scoped to the parent that now holds it, read from that lock, so it
       never points at a parent version round 1 replaced.
    """
    executable = shutil.which("npm")
    if executable is None:
        return FixPlan("unsupported", tool="npm", note="npm is not on PATH.")
    try:
        packages = _packages(project)
    except (OSError, ValueError) as e:
        return FixPlan(
            "unsupported",
            tool="npm",
            note=f"--fix-plan reads package-lock.json version 2 or 3 ({e}).",
        )
    manifest_text = (project / MANIFEST).read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    releases = releases or registry_releases(executable, project)
    ranges = _ranges(result, include_filtered)
    audit_fixes = _audit_fixes(result, packages)

    skipped: dict[str, dict[str, str]] = {}  # package -> copies it leaves, with why

    def vulnerable_keys(lock: dict[str, dict[str, Any]], name: str) -> list[str]:
        """Copies the plan can change: not bundled, not left for a parent upgrade."""
        return [
            key
            for key, info in lock.items()
            if key
            and not info.get("inBundle")
            and key not in skipped.get(name, {})
            and _name(key, info) == name
            and _vulnerable(str(info.get("version")), ranges[name])
        ]

    def vulnerable_copies(lock: dict[str, dict[str, Any]], name: str) -> list[str]:
        return [f"{name} {lock[k]['version']}" for k in vulnerable_keys(lock, name)]

    def edited(
        requirements: dict[tuple[str, str], str], overrides: dict[str, dict[str, str]]
    ) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(manifest_text)
        for (section, dep), value in requirements.items():
            data.setdefault(section, {})[dep] = value
        if overrides:
            merged = data.setdefault("overrides", {})
            for parent, pins in overrides.items():
                merged.setdefault(parent, {}).update(pins)
        return data

    def trial(data: dict[str, Any], update: list[str]) -> tuple[str, dict[str, dict[str, Any]]]:
        """npm's answer on a copy: ("", lock) or (problem, {})."""
        with tempfile.TemporaryDirectory(prefix="depquiet-npmplan-") as tmp:
            root = Path(tmp) / "project"
            shutil.copytree(project, root, ignore=_COPY_IGNORE, symlinks=True)
            (root / MANIFEST).write_text(_manifest_text(data, manifest_text), encoding="utf-8")
            args = ["update", *update, "--package-lock-only", "--ignore-scripts", "--no-audit"]
            code, output = _npm(executable, args, root, timeout)
            if code != 0:
                return " ".join(output.split())[-300:] or "npm failed", {}
            return "", _packages(root)

    items = {name: PlanItem(package=name, version="") for name in sorted(ranges)}
    original_keys = {name: vulnerable_keys(packages, name) for name in items}
    for name, item in items.items():
        found = sorted(
            {c.split(" ", 1)[1] for c in vulnerable_copies(packages, name)}, key=version_key
        )
        item.installed = ", ".join(found)
        item.held_by = _bundled_notes(packages, name, ranges[name])
        if not found:
            item.why = "; ".join(item.held_by) or "no vulnerable copy in package-lock.json"

    # Round 1: within semver.
    requirements: dict[tuple[str, str], str] = {}
    owners: dict[tuple[str, str], str] = {}  # requirement -> the package it is for
    update: list[str] = []
    for name, item in items.items():
        if item.why:
            continue
        update.append(name)
        fix = audit_fixes.get(name)
        if fix is None:
            continue
        parent, current, target, kind = fix
        if kind != "upgrade":
            change = "back from" if kind == "downgrade" else "to a new major version, from"
            item.audit_note = (
                f"npm audit fix --force would move {parent} {change} {current} to {target}"
            )
            continue
        if parent != name:
            item.also_upgrade = [f"{parent}=={target}"]
            update.append(parent)
        for section in _ROOT_KEYS:
            declared = (manifest.get(section) or {}).get(parent)
            if isinstance(declared, str) and match_npm_range(target, declared)[0] != "matched":
                requirements[(section, parent)] = _keep_operator(declared, target)
                owners[(section, parent)] = parent if parent in items else name
    update = list(dict.fromkeys(update))
    if not update:
        return FixPlan(
            "none", items=list(items.values()), tool="npm", note="Nothing in the plan yet."
        )
    problem, round1 = trial(edited(requirements, {}), update)
    if problem:  # npm cannot even update within semver: keep the lock as it is
        requirements, owners, round1 = {}, {}, packages
        for item in items.values():
            item.also_upgrade = []

    # Round 2: overrides for what round 1 left vulnerable, read from round 1's lock.
    overrides: dict[str, dict[str, str]] = {}
    round2_names: list[str] = []
    base = edited(requirements, {})
    for name, item in items.items():
        if item.why or not vulnerable_copies(round1, name):
            continue
        planned, pins, extra, left_copies = _plan_package(
            name, ranges[name], round1, base, releases
        )
        item.held_by = planned.held_by
        skipped[name] = left_copies
        if planned.why:
            item.why = planned.why
            continue
        candidate = {p: dict(v) for p, v in overrides.items()}
        for parent, values in pins.items():
            candidate.setdefault(parent, {}).update(values)
        both = {**requirements, **extra}
        problem, lock = trial(edited(both, candidate), [*update, name])
        if problem:
            item.why = f"npm could not lock the override: {problem}"
            continue
        if vulnerable_copies(lock, name):
            item.why = f"npm still locks {first_items(vulnerable_copies(lock, name), 3)}"
            continue
        overrides, requirements = candidate, both
        for key in extra:
            owners.setdefault(key, name)
        round2_names.append(name)

    final_data = edited(requirements, overrides)
    problem, final = trial(final_data, list(dict.fromkeys([*update, *round2_names])))
    if problem:
        final = round1
    for name, item in items.items():
        if item.why:
            continue
        left = vulnerable_copies(final, name)
        if left:
            item.why = f"npm still locks {first_items(left, 3)}"
            continue
        item.included = True
        if skipped.get(name):
            item.leaves = "; ".join(skipped[name].values())
        # What the vulnerable copies became, not the newest copy anywhere in the
        # lock: upscayl's yaml 1.10.2 is not "→ 2.9.1" because a 2.x copy exists.
        replaced = {
            str(final[key]["version"])
            for key in original_keys.get(name, [])
            if key in final and key not in skipped.get(name, {})
        }
        item.version = ", ".join(sorted(replaced, key=version_key)) or max(
            _versions(final).get(name, {""}), key=version_key
        )
        item.edits = [
            PlanEdit(MANIFEST, name, "", pins[name], "override", scope=parent)
            for parent, pins in overrides.items()
            if name in pins
        ] + [
            PlanEdit(MANIFEST, dep, str((manifest.get(section) or {}).get(dep, "")), value)
            for (section, dep), value in requirements.items()
            if owners.get((section, dep)) == name
        ]

    plan = FixPlan(
        "none", items=list(items.values()), tool="npm", include_filtered=include_filtered
    )
    if not plan.included:
        plan.note = "Nothing in the plan yet."
        return plan
    new_text = _manifest_text(final_data, manifest_text)
    plan.manifest = new_text
    if new_text != manifest_text:
        plan.diff = "".join(
            difflib.unified_diff(
                manifest_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a/{MANIFEST}",
                tofile=f"b/{MANIFEST}",
            )
        )
    plan.lock_changes = _lock_changes(packages, final, {i.package for i in plan.included})
    plan.status = "verified" if not plan.left_out else "partial"
    plan.note = "Verified with npm only (--package-lock-only, no install scripts): run your tests."
    if overrides:
        plan.note += (
            " An override installs a version its parent did not ask for: check that parent's "
            "tests or changelog."
        )
    return plan


def apply_npm_plan(plan: FixPlan, project: Path, *, timeout: int = 900) -> str:
    """Write the planned package.json and update package-lock.json; "" on success."""
    executable = shutil.which("npm")
    if executable is None:
        return "npm is not on PATH."
    names = plan.command.split()[2:]
    if not names:
        return "the plan has no fix to apply."
    before = {n: (project / n).read_bytes() for n in (MANIFEST, LOCK) if (project / n).is_file()}
    if plan.manifest:
        (project / MANIFEST).write_text(plan.manifest, encoding="utf-8")
    code, output = _npm(
        executable,
        ["update", *names, "--package-lock-only", "--ignore-scripts", "--no-audit"],
        project,
        timeout,
    )
    if code != 0:
        for name, data in before.items():
            (project / name).write_bytes(data)
        return f"npm update failed, nothing was changed: {' '.join(output.split())[-300:]}"
    return ""
