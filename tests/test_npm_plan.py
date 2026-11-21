"""npm fix plans, with a scripted npm.

The cases come from a real run on an own fixture (express 4.19.2, glob 7.2.0
with minimatch 3.0.4, @tailwindcss/typography 0.5.19; npm 10.9, 2026-11-21):
npm audit offered typography 0.5.19 → 0.5.4 for postcss-selector-parser, the
plan overrode postcss-selector-parser under typography instead, and npm audit
reported 0 vulnerabilities after --apply.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import depquiet.npmplan as npmplan
from depquiet.fixplan import fix_plan_markdown, print_fix_plan
from depquiet.models import ScanResult, Severity, TriageResult, Verdict, Vulnerability
from depquiet.npmplan import _resolve, build_npm_plan, fixed_release, is_npm_project

RELEASES = {
    "postcss-selector-parser": ["6.0.10", "6.1.4", "6.1.5", "6.1.6", "7.0.0"],
    "minimatch": ["3.0.4", "3.0.5", "3.1.5", "9.0.0"],
    "qs": ["6.11.0", "6.16.2"],
    "left-pad": ["1.0.0"],
    "glob": ["10.3.10", "10.5.0", "14.0.2"],
}


def _lock(entries: dict[str, tuple[str, dict[str, str]]], root: dict[str, str]) -> dict[str, Any]:
    packages: dict[str, Any] = {"": {"name": "demo", "version": "1.0.0", "dependencies": root}}
    for key, (version, deps) in entries.items():
        packages[key] = {"version": version, **({"dependencies": deps} if deps else {})}
    return {"name": "demo", "lockfileVersion": 3, "packages": packages}


BASE = {
    "node_modules/@tailwindcss/typography": ("0.5.19", {"postcss-selector-parser": "6.0.10"}),
    "node_modules/postcss-selector-parser": ("6.0.10", {}),
    "node_modules/glob": ("7.2.0", {"minimatch": "^3.0.4"}),
    "node_modules/minimatch": ("3.0.4", {}),
    "node_modules/express": ("4.19.2", {"qs": "6.11.0"}),
    "node_modules/qs": ("6.11.0", {}),
}
ROOT = {"@tailwindcss/typography": "0.5.19", "glob": "7.2.0", "express": "4.19.2"}


def _project(tmp_path: Path, entries=BASE, root=ROOT, extra: dict | None = None) -> Path:
    manifest = {"name": "demo", "version": "1.0.0", "dependencies": dict(root), **(extra or {})}
    (tmp_path / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps(_lock(entries, root)), encoding="utf-8")
    return tmp_path


def _finding(package: str, rng: str, fix_package: str = "", fix_version: str = "") -> TriageResult:
    return TriageResult(
        vuln=Vulnerability(
            f"GHSA-{package}",
            package,
            rng,
            Severity.HIGH,
            fix_version=fix_version,
            fix_package=fix_package,
            version_kind="range",
            advisory_range=rng,
        ),
        verdict=Verdict.ACTION,
    )


def _result(*findings: TriageResult) -> ScanResult:
    return ScanResult(
        project_path=".", package_manager="npm", total_dependencies=6, results=list(findings)
    )


def _fake_npm(monkeypatch, *, fail: bool = False) -> list[list[str]]:
    """Like npm on the fixture: overrides pin a package, `npm update` moves within ranges."""
    calls: list[list[str]] = []

    def run(executable: str, args: list[str], cwd: Path, timeout: int):
        calls.append(list(args))
        if fail:
            return 1, "npm ERR! ERESOLVE could not resolve"
        manifest = json.loads((cwd / "package.json").read_text(encoding="utf-8"))
        lock = json.loads((cwd / "package-lock.json").read_text(encoding="utf-8"))
        packages = lock["packages"]
        overrides = manifest.get("overrides", {})
        root = manifest.get("dependencies", {})
        packages[""]["dependencies"] = root
        if root.get("express") == "4.22.3":
            packages["node_modules/express"] = {
                "version": "4.22.3",
                "dependencies": {"qs": "^6.14.1"},
            }
            packages["node_modules/qs"] = {"version": "6.16.2"}
        pin = overrides.get("@tailwindcss/typography", {}).get("postcss-selector-parser")
        if pin:
            packages["node_modules/postcss-selector-parser"] = {"version": pin}
        if "minimatch" in args and "node_modules/minimatch" in packages:
            # Like npm 9.2 in upscayl: only the hoisted copy moves (never a bundled one).
            packages["node_modules/minimatch"] = {"version": "3.1.5"}
        for parent, pins in overrides.items():
            if isinstance(pins, dict):
                for dep, version in pins.items():
                    nested = f"node_modules/{parent}/node_modules/{dep}"
                    if nested in packages:
                        packages[nested] = {"version": version}
        (cwd / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
        return 0, ""

    monkeypatch.setattr(npmplan.shutil, "which", lambda name: "/usr/bin/npm")
    monkeypatch.setattr(npmplan, "_npm", run)
    return calls


def _releases(name: str) -> list[str]:
    return RELEASES.get(name, [])


def _plan(tmp_path, monkeypatch, *findings, **project_kw):
    _fake_npm(monkeypatch)
    project = _project(tmp_path, **project_kw)
    return build_npm_plan(_result(*findings), project, releases=_releases), project


PSP = _finding("postcss-selector-parser", "<6.1.5", "@tailwindcss/typography", "0.5.4")


def test_a_pinned_transitive_gets_an_override_scoped_to_its_parent(tmp_path, monkeypatch) -> None:
    plan, project = _plan(tmp_path, monkeypatch, PSP)
    [item] = plan.included
    assert (item.package, item.installed, item.version) == (
        "postcss-selector-parser",
        "6.0.10",
        "6.1.5",
    )
    assert [(e.kind, e.scope, e.new) for e in item.edits] == [
        ("override", "@tailwindcss/typography", "6.1.5")
    ]
    assert item.held_by == [
        "@tailwindcss/typography 0.5.19 requires postcss-selector-parser@6.0.10"
    ]
    assert item.audit_note == (
        "npm audit fix --force would move @tailwindcss/typography back from 0.5.19 to 0.5.4"
    )
    assert '"postcss-selector-parser": "6.1.5"' in plan.diff
    assert plan.status == "verified" and plan.tool == "npm"
    assert plan.command == "npm update postcss-selector-parser"
    # The project itself is never touched.
    assert "overrides" not in (project / "package.json").read_text(encoding="utf-8")


def test_the_same_line_comes_first() -> None:
    assert fixed_release("6.0.10", ["<6.1.5"], RELEASES["postcss-selector-parser"]) == "6.1.5"
    assert fixed_release("3.0.4", ["<3.0.5"], RELEASES["minimatch"]) == "3.0.5"
    # 0.x: ^0.1.7 stays on 0.1.x
    assert fixed_release("0.1.7", ["<0.1.10"], ["0.1.9", "0.1.12", "0.2.0"]) == "0.1.12"
    assert fixed_release("0.1.7", ["<0.1.10"], ["0.1.9", "0.2.0"]) == "0.2.0"
    assert fixed_release("1.0.0", ["<2.0.0"], ["1.0.0", "1.5.0"]) == ""


def test_npm_audits_plain_parent_upgrade_comes_before_any_override(tmp_path, monkeypatch) -> None:
    qs = _finding("qs", "<6.14.1", "express", "4.22.3")
    plan, _ = _plan(tmp_path, monkeypatch, qs)
    [item] = plan.included
    assert item.also_upgrade == ["express==4.22.3"]
    assert [(e.package, e.old, e.new, e.kind) for e in item.edits] == [
        ("express", "4.19.2", "4.22.3", "requirement")
    ]
    assert plan.command == "npm update qs express"
    assert "overrides" not in plan.diff and '"express": "4.22.3"' in plan.diff


def test_an_in_range_fix_needs_only_npm_update(tmp_path, monkeypatch) -> None:
    plan, _ = _plan(tmp_path, monkeypatch, _finding("minimatch", "<3.0.5"))
    [item] = plan.included
    assert (item.version, item.edits, plan.diff) == ("3.1.5", [], "")
    assert plan.command == "npm update minimatch"


def test_every_kind_together(tmp_path, monkeypatch, capsys) -> None:
    import sys

    findings = [
        PSP,
        _finding("qs", "<6.14.1", "express", "4.22.3"),
        _finding("minimatch", "<3.0.5"),
    ]
    plan, _ = _plan(tmp_path, monkeypatch, *findings)
    assert {i.package for i in plan.included} == {"postcss-selector-parser", "qs", "minimatch"}
    print_fix_plan(plan, sys.stdout)
    out = capsys.readouterr().out
    assert (
        "✓ postcss-selector-parser 6.0.10 → 6.1.5: override it under @tailwindcss/typography" in out
    )
    assert "instead of what npm audit offers: npm audit fix --force would move" in out
    assert "Verified with npm's resolver: all fixes resolve together." in out
    md = fix_plan_markdown(plan, _result(*findings))
    assert (
        "npm's resolver confirmed" in md and "`package.json` (requirements and `overrides`)" in md
    )
    data = plan.to_dict()
    psp = next(i for i in data["included"] if i["package"] == "postcss-selector-parser")
    assert psp["edits"][0]["scope"] == "@tailwindcss/typography"
    assert psp["npm_audit_note"].startswith("npm audit fix --force")


def test_no_fixed_release_is_left_out(tmp_path, monkeypatch) -> None:
    entries = {**BASE, "node_modules/left-pad": ("1.0.0", {})}
    plan, _ = _plan(tmp_path, monkeypatch, _finding("left-pad", "<=1.0.0"), entries=entries)
    [item] = plan.left_out
    assert "no published release of left-pad above 1.0.0" in item.why
    assert plan.status == "none" and plan.diff == ""


def test_an_existing_override_of_the_package_is_respected(tmp_path, monkeypatch) -> None:
    extra = {"overrides": {"postcss-selector-parser": "6.0.10"}}
    plan, _ = _plan(tmp_path, monkeypatch, PSP, extra=extra)
    [item] = plan.left_out
    assert item.why == "your package.json already overrides postcss-selector-parser to 6.0.10"


def test_a_workspace_that_pins_it_is_named(tmp_path, monkeypatch) -> None:
    entries = {
        "packages/web": ("1.0.0", {"postcss-selector-parser": "6.0.10"}),
        "node_modules/postcss-selector-parser": ("6.0.10", {}),
    }
    plan, _ = _plan(tmp_path, monkeypatch, PSP, entries=entries, root={})
    [item] = plan.left_out
    assert item.why.startswith("workspace packages/web requires postcss-selector-parser@6.0.10")


def test_npm_failing_keeps_the_plan_empty(tmp_path, monkeypatch) -> None:
    _fake_npm(monkeypatch, fail=True)
    plan = build_npm_plan(_result(PSP), _project(tmp_path), releases=_releases)
    assert plan.included == []
    assert "npm could not lock the override" in plan.left_out[0].why


def test_node_resolution_walks_up() -> None:
    packages = {
        "node_modules/a": {},
        "node_modules/a/node_modules/b": {},
        "node_modules/b": {},
        "node_modules/@s/c": {},
    }
    assert _resolve(packages, "node_modules/a", "b") == "node_modules/a/node_modules/b"
    assert _resolve(packages, "node_modules/@s/c", "b") == "node_modules/b"
    assert _resolve(packages, "", "b") == "node_modules/b"
    assert _resolve(packages, "node_modules/a/node_modules/b", "a") == "node_modules/a"
    assert _resolve(packages, "packages/web", "zzz") is None


def test_only_npm_projects(tmp_path) -> None:
    project = _project(tmp_path)
    assert is_npm_project(project)
    (project / "uv.lock").write_text("", encoding="utf-8")
    assert not is_npm_project(project)


def test_apply_writes_the_manifest_and_restores_on_failure(tmp_path, monkeypatch) -> None:
    plan, project = _plan(tmp_path, monkeypatch, PSP)
    before = (project / "package-lock.json").read_text(encoding="utf-8")
    _fake_npm(monkeypatch, fail=True)
    problem = npmplan.apply_npm_plan(plan, project)
    assert problem.startswith("npm update failed, nothing was changed")
    assert (project / "package-lock.json").read_text(encoding="utf-8") == before
    assert "overrides" not in (project / "package.json").read_text(encoding="utf-8")
    _fake_npm(monkeypatch)
    assert npmplan.apply_npm_plan(plan, project) == ""
    assert '"postcss-selector-parser": "6.1.5"' in (project / "package.json").read_text("utf-8")
    lock = json.loads((project / "package-lock.json").read_text(encoding="utf-8"))
    assert lock["packages"]["node_modules/postcss-selector-parser"]["version"] == "6.1.5"


@pytest.mark.parametrize(
    ("declared", "expected"),
    [("^1.2.3", "^1.4.0"), ("~1.2.3", "~1.4.0"), ("1.2.3", "1.4.0"), (">=1 <2", "^1.4.0")],
)
def test_requirement_keeps_its_operator(declared, expected) -> None:
    assert npmplan._keep_operator(declared, "1.4.0") == expected


def test_a_bundled_copy_is_named_not_chased(tmp_path, monkeypatch) -> None:
    """nodemon (2026-11-21): npm 11.10.1 ships minimatch 10.2.2 inside its own tarball."""
    entries = {
        "node_modules/minimatch": ("3.0.4", {}),
        "node_modules/glob": ("7.2.0", {"minimatch": "^3.0.4"}),
        "node_modules/npm": ("11.10.1", {"minimatch": "^3.0.4"}),
        "node_modules/npm/node_modules/minimatch": ("3.0.4", {}),
    }
    project = _project(tmp_path, entries=entries, root={"glob": "7.2.0", "npm": "11.10.1"})
    lock = json.loads((project / "package-lock.json").read_text(encoding="utf-8"))
    lock["packages"]["node_modules/npm/node_modules/minimatch"]["inBundle"] = True
    (project / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    _fake_npm(monkeypatch)
    plan = build_npm_plan(_result(_finding("minimatch", "<3.0.5")), project, releases=_releases)
    [item] = plan.included
    assert item.held_by == [
        "minimatch 3.0.4 is bundled inside npm 11.10.1: only a new release of npm can change it"
    ]
    assert not any(e.kind == "override" for e in item.edits)


def test_only_bundled_copies_are_left_out_with_the_reason(tmp_path, monkeypatch) -> None:
    entries = {
        "node_modules/npm": ("11.10.1", {}),
        "node_modules/npm/node_modules/minimatch": ("3.0.4", {}),
    }
    project = _project(tmp_path, entries=entries, root={"npm": "11.10.1"})
    lock = json.loads((project / "package-lock.json").read_text(encoding="utf-8"))
    lock["packages"]["node_modules/npm/node_modules/minimatch"]["inBundle"] = True
    (project / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    _fake_npm(monkeypatch)
    plan = build_npm_plan(_result(_finding("minimatch", "<3.0.5")), project, releases=_releases)
    [item] = plan.left_out
    assert item.why.startswith("minimatch 3.0.4 is bundled inside npm 11.10.1")


def test_a_nested_copy_npm_update_leaves_gets_an_override_within_range(
    tmp_path, monkeypatch
) -> None:
    """upscayl (npm 9.2, 2026-11-21): eslint accepts minimatch ^3.0.4; its 3.1.2 stayed."""
    entries = {
        "node_modules/eslint": ("8.57.0", {"minimatch": "^3.0.4"}),
        "node_modules/eslint/node_modules/minimatch": ("3.0.4", {}),
        "node_modules/minimatch": ("9.0.0", {}),
    }
    plan, _ = _plan(
        tmp_path,
        monkeypatch,
        _finding("minimatch", "<3.0.5"),
        entries=entries,
        root={"eslint": "8.57.0"},
    )
    [item] = plan.included
    assert [(e.kind, e.scope, e.new) for e in item.edits] == [("override", "eslint", "3.0.5")]
    assert item.held_by == [
        "eslint 8.57.0 accepts the fix, but npm update left minimatch 3.0.4 under it"
    ]


def test_no_override_across_a_major_version(tmp_path, monkeypatch) -> None:
    """upscayl: every fixed glob is 14.x; @next/eslint-plugin-next pins 10.3.10 exactly."""
    entries = {
        "node_modules/@next/eslint-plugin-next": ("14.2.7", {"glob": "10.3.10"}),
        "node_modules/glob": ("10.3.10", {}),
    }
    plan, _ = _plan(
        tmp_path,
        monkeypatch,
        _finding("glob", ">=9.0.0 <=14.0.1"),
        entries=entries,
        root={"@next/eslint-plugin-next": "14.2.7"},
    )
    [item] = plan.left_out
    assert "on a newer major line (14.0.2 and up)" in item.why
    assert "upgrading @next/eslint-plugin-next is the fix" in item.why
    assert plan.diff == ""
