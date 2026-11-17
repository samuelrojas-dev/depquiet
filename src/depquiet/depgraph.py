"""Dependency graph: which packages are direct, and what pulls in the rest.

Import-level reachability only makes sense for *direct* dependencies. A
transitive dependency is almost never imported by the application itself:
an Express app imports ``express``, never ``path-to-regexp`` or ``qs``, yet
Express calls both on every request. Treating "not imported" as "unreachable"
for those packages silently dismisses real, exploitable vulnerabilities.

So the reachability filter needs two facts the scanners do not reliably give
us (most scanner formats either omit directness or hard-code it):

1. **Is the package direct?** Taken from the project's own manifests and
   lockfiles, never from the scanner.
2. **For a transitive package, which direct dependencies pull it in?**
   Taken from lockfiles that record dependency edges.

When either fact is unknown the caller must not filter on reachability.
Being unable to prove a package is unused is not evidence that it is.

Supported sources:

========================  ==================  ==================
Ecosystem                 Direct deps         Edges
========================  ==================  ==================
npm                       package.json /      package-lock.json,
                          package-lock root   yarn.lock (v1/berry)
Python                    uv.lock roots,      uv.lock, poetry.lock,
                          pyproject.toml,     requirements.txt
                          Pipfile,            ``# via`` comments
                          requirements.in,    (pip-compile)
                          requirements.txt*
Rust                      Cargo.lock roots    Cargo.lock
Ruby                      Gemfile.lock        Gemfile.lock
PHP                       composer.json       composer.lock
.NET                      packages.lock.json  packages.lock.json
Dart                      pubspec.lock        (none)
Go                        go.mod              (none)
Java (Maven)              pom.xml             (none)
========================  ==================  ==================

Commands the project runs (``package.json`` scripts, ``Procfile``,
``Dockerfile*``) are recorded too: a dependency invoked as a command, like
``pm2 start``, is in use even though nothing imports it.

\\* A requirements.txt where *every* line is pinned with ``==`` and that has no
``# via`` annotations is indistinguishable from ``pip freeze`` output, which
lists transitive packages as if they were direct. Such files are not used as
a source of direct dependencies.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Directness = Literal["direct", "transitive", "unknown"]

_SKIP_DIRS = {"node_modules", ".git", "vendor", "target", ".venv", "venv", "dist", "build"}


def _norm(name: str) -> str:
    """Case-insensitive key. Package names in every supported ecosystem
    compare case-insensitively in practice (npm forbids uppercase, PyPI,
    NuGet and Composer are case-insensitive)."""
    return name.strip().lower()


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _keys(name: str) -> set[str]:
    """Both lookup forms of a name: plain (npm, Cargo, ...) and PEP 503 (Python)."""
    return {_norm(name), _pep503(name)}


@dataclass
class DependencyGraph:
    """Direct dependencies plus parent -> child edges, keyed by normalized name."""

    direct: set[str] = field(default_factory=set)
    # Subset of ``direct`` declared for production in at least one manifest.
    # direct - prod_direct = dev-only (devDependencies, require-dev, Pipfile
    # dev-packages, Poetry dev groups).
    prod_direct: set[str] = field(default_factory=set)
    edges: dict[str, set[str]] = field(default_factory=dict)
    # Packages the lockfiles say are transitive even without edges
    # (pubspec.lock, go.mod ``// indirect``, NuGet "Transitive").
    known_transitive: set[str] = field(default_factory=set)
    # True once any manifest listing direct dependencies was read.
    has_manifest: bool = False
    sources: list[str] = field(default_factory=list)
    # normalized key -> name as written in the manifest
    display: dict[str, str] = field(default_factory=dict)
    # Executables each package installs (lockfile ``bin``): command -> packages.
    bins: dict[str, set[str]] = field(default_factory=dict)
    # Words appearing in commands the project runs: package.json scripts,
    # Procfile, Dockerfiles. A dependency run as a command is in use even if
    # nothing imports it (pm2, cross-env, next, ...).
    commands: set[str] = field(default_factory=set)
    coverage_complete: bool = True
    coverage_observations: list[str] = field(default_factory=list)
    scope_path: str = "."
    workspace_graphs: dict[str, DependencyGraph] = field(default_factory=dict)
    # Python projects whose pyproject.toml leaves ``dependencies`` to the build
    # backend (``dynamic``) and gives no static source for them here.
    dynamic_projects: set[str] = field(default_factory=set)
    # uv.lock's record of each project/workspace member: name -> (production
    # dependency names, development dependency names).
    lock_members: dict[str, tuple[list[str], list[str]]] = field(default_factory=dict)
    _ecosystems: dict[str, set[str]] = field(default_factory=dict, repr=False)

    # -- construction -----------------------------------------------------

    def add_direct(self, name: str, *, python: bool = False, dev: bool = False) -> None:
        if name:
            key = _pep503(name) if python else _norm(name)
            self.direct.add(key)
            self.display.setdefault(key, name.strip())
            if not dev:
                self.prod_direct.add(key)

    def add_edge(self, parent: str, child: str) -> None:
        if parent and child and _norm(parent) != _norm(child):
            self.edges.setdefault(_norm(parent), set()).add(_norm(child))

    def merge(self, other: DependencyGraph) -> None:
        self.direct |= other.direct
        self.prod_direct |= other.prod_direct
        self.known_transitive |= other.known_transitive
        for parent, children in other.edges.items():
            self.edges.setdefault(parent, set()).update(children)
        self.has_manifest = self.has_manifest or other.has_manifest
        self.sources.extend(other.sources)
        for key, name in other.display.items():
            self.display.setdefault(key, name)
        for cmd, pkgs in other.bins.items():
            self.bins.setdefault(cmd, set()).update(pkgs)
        self.commands |= other.commands
        self.coverage_complete = self.coverage_complete and other.coverage_complete
        self.coverage_observations.extend(other.coverage_observations)
        self.dynamic_projects |= other.dynamic_projects
        self.lock_members.update(other.lock_members)
        # A name shared by two ecosystems (``glob`` on npm and crates.io) is one
        # node here. Its edges, roots and production declarations are the union
        # of both packages, so every filter that needs an absence (dev-only,
        # unused) sees a superset of the real paths and stays conservative.
        for name, ecosystems in other._ecosystems.items():
            self._ecosystems.setdefault(name, set()).update(ecosystems)

    # -- queries ----------------------------------------------------------

    def directness(self, package: str) -> Directness:
        """Classify a package as direct, transitive or unknown."""
        if _norm(package) in self.direct or _pep503(package) in self.direct:
            # _pep503 only matches entries that came from Python manifests,
            # since only those are stored in that form.
            return "direct"
        if _norm(package) in self.known_transitive:
            return "transitive"
        if not self.has_manifest:
            return "unknown"
        # A manifest lists every direct dependency of its ecosystem, but we
        # don't know the package's ecosystem. If some edge points at it, it is
        # certainly transitive; otherwise it is either transitive or belongs to
        # an ecosystem whose manifest we didn't read.
        keys = _keys(package)
        if any(keys & children for children in self.edges.values()):
            return "transitive"
        return "unknown"

    def is_executed(self, package: str) -> bool:
        """True when a command the project runs invokes one of the package's executables.

        Uses the executables recorded in the lockfile, plus the package's own
        name (``@scope/tool`` -> ``tool``), the usual binary name, for
        lockfiles that don't record them. A spurious match only makes depquiet
        filter less.
        """
        if not self.commands:
            return False
        keys = _keys(package)
        names = {cmd for cmd, pkgs in self.bins.items() if pkgs & keys}
        names.add(package.rsplit("/", 1)[-1].lower())
        return bool(names & self.commands)

    def is_dev_only(self, names: list[str]) -> bool:
        """True when every name is a direct dependency declared as dev-only.

        A package declared both as a dependency and a devDependency (or in a
        second manifest as a regular dependency) counts as production.
        """
        if not self.coverage_complete:
            return False
        keys = [_keys(n) for n in names]
        return bool(keys) and all(k & self.direct and not k & self.prod_direct for k in keys)

    def declared_for_production(self, package: str) -> bool:
        """True when a manifest declares ``package`` as a production dependency.

        A lockfile can disagree (a stale ``"dev": true`` after the package
        moved to ``dependencies``); the manifest is what the next install uses.
        """
        return bool(_keys(package) & self.prod_direct)

    def direct_ancestors(self, package: str) -> set[str]:
        """Direct dependencies whose dependency closure contains ``package``.

        Returns an empty set when no path from a direct dependency is known.
        Names are returned as written in the manifest.
        """
        parents: dict[str, set[str]] = {}
        for parent, children in self.edges.items():
            for child in children:
                parents.setdefault(child, set()).add(parent)

        found: set[str] = set()
        seen = set(_keys(package))
        queue = deque(seen)
        while queue:
            node = queue.popleft()
            for parent in parents.get(node, ()):
                if parent in seen:
                    continue
                seen.add(parent)
                if parent in self.direct:
                    found.add(self.display.get(parent, parent))
                queue.append(parent)
        return found

    # -- loading ----------------------------------------------------------

    @classmethod
    def from_project(cls, project: Path, *, ecosystem: str | None = None) -> DependencyGraph:
        """Build the graph from every supported manifest/lockfile in ``project``.

        ``ecosystem`` ("npm", "python", ...) keeps only that ecosystem's
        manifests and lockfiles, for a report known to come from one package
        manager: an npm advisory for ``glob`` is not about the crate of the
        same name, and a Cargo.lock path to that crate is not a path to it.
        Command files (Dockerfile, Procfile) always count. Without it every
        ecosystem is merged by name, which only adds paths.

        Unreadable, malformed or ambiguous inputs leave recorded incomplete
        coverage. They cannot justify development-only or absence decisions.
        Declared npm/uv members have local graphs; other layouts retain the
        bounded legacy discovery with explicit error reporting.
        """
        from depquiet.workspaces import discover_workspaces

        project = project.resolve()
        graph = cls()
        try:
            if not project.is_dir():
                graph.coverage_complete = False
                graph.coverage_observations.append(
                    ".: project directory is missing or inaccessible"
                )
                return graph
        except OSError as exc:
            graph.coverage_complete = False
            graph.coverage_observations.append(f".: inspect project directory: {exc}")
            return graph
        discovery = discover_workspaces(project)
        members = {
            member: {name for name in files if _in_ecosystem(name, ecosystem)}
            for member, files in discovery.members.items()
        }
        if discovery.declared and any(members.values()):
            return _workspace_graph(
                project,
                {member: files for member, files in members.items() if files or member == "."},
                discovery.observations,
                ecosystem,
            )
        graph = _load_scope(project, project, recursive=True, ecosystem=ecosystem)
        for note in discovery.observations:
            _incomplete(graph, note)
        _flag_unlisted_dynamic(graph, graph)
        return graph


def _flag_unlisted_dynamic(graph: DependencyGraph, locks: DependencyGraph) -> None:
    """A project with build-time dependencies that no lockfile spells out.

    Its manifest lists nothing, so "no production path" would only mean
    "no path this tool was shown".
    """
    for name in sorted(graph.dynamic_projects - set(locks.lock_members)):
        _incomplete(
            graph,
            f"{name}: pyproject.toml declares dynamic dependencies and no uv.lock lists them",
        )


def _incomplete(graph: DependencyGraph, note: str) -> None:
    graph.coverage_complete = False
    if note not in graph.coverage_observations:
        graph.coverage_observations.append(note)


def _in_ecosystem(filename: str, ecosystem: str | None) -> bool:
    return ecosystem is None or _source_ecosystem(filename) in ("", ecosystem)


def _load_scope(
    scope: Path,
    project: Path,
    *,
    recursive: bool,
    skip: set[Path] | None = None,
    locks_edges_only: bool = False,
    ecosystem: str | None = None,
) -> DependencyGraph:
    graph = DependencyGraph(scope_path=scope.relative_to(project).as_posix())
    for path in _iter_files(
        scope,
        max_depth=3 if recursive else 0,
        on_error=lambda path, error: _incomplete(
            graph,
            f"{path.relative_to(project).as_posix()}: enumerate/inspect graph source: {error}",
        ),
    ):
        if (skip and path in skip) or not _in_ecosystem(path.name, ecosystem):
            continue
        _merge_source(
            graph, path, project, edges_only=locks_edges_only and path.name in _WORKSPACE_LOCKS
        )
    if graph.has_manifest:
        from depquiet.pynames import IMPLICIT_PLUGINS

        for parent, plugins in IMPLICIT_PLUGINS.items():
            if parent in graph.direct or any(
                parent in children for children in graph.edges.values()
            ):
                for plugin in plugins:
                    graph.add_edge(parent, plugin)
    return graph


def _merge_source(
    graph: DependencyGraph, path: Path, project: Path, *, edges_only: bool = False
) -> None:
    loader = _LOADERS.get(path.name)
    if loader is None and path.name.startswith("requirements") and path.suffix == ".txt":
        loader = _load_requirements_txt
    if loader is None and path.name.startswith("Dockerfile."):
        loader = _load_commands_file
    if loader is None:
        return
    try:
        part = loader(path)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        ET.ParseError,
    ) as exc:
        _incomplete(
            graph, f"{path.relative_to(project).as_posix()}: read/parse graph source: {exc}"
        )
        return
    if part is not None:
        if edges_only:
            part.direct.clear()
            part.prod_direct.clear()
            part.has_manifest = False
            part.commands.clear()
        part.sources.append(path.relative_to(project).as_posix())
        namespace = _source_ecosystem(path.name)
        if namespace:
            names = part.direct | part.known_transitive | set(part.edges)
            names |= {name for children in part.edges.values() for name in children}
            for name in names:
                for key in _keys(name):
                    part._ecosystems.setdefault(key, set()).add(namespace)
        graph.merge(part)


_WORKSPACE_LOCKS = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "uv.lock",
}


def _source_ecosystem(filename: str) -> str:
    if filename in {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    }:
        return "npm"
    if filename in {
        "pyproject.toml",
        "uv.lock",
        "poetry.lock",
        "Pipfile",
        "requirements.in",
    } or filename.startswith("requirements"):
        return "python"
    return {
        "Cargo.lock": "rust",
        "Gemfile.lock": "ruby",
        "composer.json": "php",
        "composer.lock": "php",
        "packages.lock.json": "dotnet",
        "pubspec.lock": "dart",
        "go.mod": "go",
        "pom.xml": "maven",
    }.get(filename, "")


def _workspace_graph(
    project: Path,
    members: dict[str, set[str]],
    observations: list[str],
    ecosystem: str | None = None,
) -> DependencyGraph:
    aggregate = DependencyGraph()
    shared = DependencyGraph()
    files = _iter_files(
        project,
        max_depth=0,
        on_error=lambda path, error: _incomplete(
            shared, f"{path.relative_to(project).as_posix()}: inspect shared lock: {error}"
        ),
    )
    shared_paths = {path for path in files if path.name in _WORKSPACE_LOCKS}
    in_scope = {path for path in shared_paths if _in_ecosystem(path.name, ecosystem)}
    if any(path.name == "npm-shrinkwrap.json" for path in in_scope):
        selected = {path for path in in_scope if path.name != "package-lock.json"}
    else:
        selected = in_scope
    # Locks contribute edges by package name. Several locked versions of one
    # name, and edges to optional packages that were never installed, make
    # those edges a superset of any single installation, which cannot hide a
    # path from a declared dependency to a reported package.
    for path in sorted(selected):
        _merge_source(shared, path, project, edges_only=True)
    scopes: dict[str, DependencyGraph] = {}
    for member in sorted(members):
        scope = project / member
        local = _load_scope(
            scope,
            project,
            recursive=False,
            skip=shared_paths,
            locks_edges_only=True,
            ecosystem=ecosystem,
        )
        for note in observations:
            _incomplete(local, note)
        # Workspace package names connect references to another declared
        # member, while its dependencies remain transitive in this scope.
        for filename in members[member]:
            try:
                text = (scope / filename).read_text(encoding="utf-8")
                data = json.loads(text) if filename == "package.json" else tomllib.loads(text)
                name = (
                    data.get("name")
                    if filename == "package.json"
                    else (data.get("project") or {}).get("name")
                )
                if isinstance(name, str) and name:
                    key = _norm(name) if filename == "package.json" else _pep503(name)
                    if filename != "package.json" and key in shared.lock_members:
                        # uv.lock records what this member depends on, including
                        # dependencies its pyproject.toml leaves to the build
                        # backend (``dynamic``) and so does not list.
                        prod, dev = shared.lock_members[key]
                        for dep in prod:
                            local.add_direct(dep, python=True)
                        for dep in dev:
                            local.add_direct(dep, python=True, dev=True)
                        local.has_manifest = True
                    # Two members with one name (often the root and a package)
                    # share a node: a reference to it reaches the production
                    # dependencies of both, which only adds paths.
                    # A member's development tools are not its exported
                    # production dependencies when another member uses it.
                    for child in local.prod_direct:
                        shared.add_edge(key, child)
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                _incomplete(local, f"{member}/{filename}: read workspace manifest: {exc}")
        _flag_unlisted_dynamic(local, shared)
        scopes[member] = local
    for local in scopes.values():
        local.merge(shared)
        closure = set(local.direct)
        pending = deque(closure)
        while pending:
            for child in local.edges.get(pending.popleft(), set()):
                if child not in closure:
                    closure.add(child)
                    pending.append(child)
        local.edges = {
            parent: children & closure
            for parent, children in local.edges.items()
            if parent in closure
        }
        local.known_transitive = (local.known_transitive & closure) | (closure - local.direct)
        local.bins = {
            command: packages & closure
            for command, packages in local.bins.items()
            if packages & closure
        }
        aggregate.merge(local)
    aggregate.workspace_graphs = scopes
    return aggregate


def _is_graph_source_name(name: str) -> bool:
    return (
        name in _LOADERS
        or (name.startswith("requirements") and name.endswith(".txt"))
        or name.startswith("Dockerfile.")
    )


def _may_hide_graph_source(entry: Path, depth: int, max_depth: int) -> bool:
    if _is_graph_source_name(entry.name):
        return True
    try:
        is_dir = entry.is_dir()
    except OSError:
        return True
    return (
        is_dir
        and depth < max_depth
        and entry.name not in _SKIP_DIRS
        and not entry.name.startswith(".")
    )


def _iter_files(
    project: Path,
    max_depth: int = 3,
    *,
    on_error: Callable[[Path, OSError], None] | None = None,
) -> list[Path]:
    """Manifest files up to ``max_depth`` levels deep (monorepos), skipping vendored dirs."""
    out: list[Path] = []

    def walk(d: Path, depth: int) -> None:
        try:
            entries = sorted(d.iterdir())
        except OSError as exc:
            if on_error:
                on_error(d, exc)
            return
        for e in entries:
            try:
                if e.is_symlink() or not e.resolve().is_relative_to(project.resolve()):
                    # Never followed. Only a link that could stand in for a
                    # manifest, a lockfile or a directory holding one leaves
                    # the graph incomplete; a linked README or data file cannot.
                    if on_error and _may_hide_graph_source(e, depth, max_depth):
                        on_error(e, OSError("symlink or graph source escapes project"))
                    continue
                if e.is_dir():
                    if (
                        depth < max_depth
                        and e.name not in _SKIP_DIRS
                        and not e.name.startswith(".")
                    ):
                        walk(e, depth + 1)
                elif e.is_file():
                    out.append(e)
            except (OSError, RuntimeError) as exc:
                if on_error:
                    on_error(e, exc if isinstance(exc, OSError) else OSError(str(exc)))

    walk(project, 0)
    return out


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

_NPM_DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _load_package_json(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("package.json must be an object")
    g = DependencyGraph(has_manifest=True)
    for key in _NPM_DEP_KEYS:
        dependencies = data.get(key, {})
        if not isinstance(dependencies, dict) or not all(
            isinstance(name, str) and isinstance(spec, str) for name, spec in dependencies.items()
        ):
            raise ValueError(f"package.json {key} must be a dependency object")
        for name in dependencies:
            g.add_direct(name, dev=key == "devDependencies")
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        raise ValueError("package.json scripts must be an object")
    for script in scripts.values():
        if isinstance(script, str):
            g.commands |= _command_words(script)
    return g


_WORD = re.compile(r"[A-Za-z0-9@._/-]+")


def _command_words(text: str) -> set[str]:
    """Words of a shell command line, plus the basename of path-like words
    (``./node_modules/.bin/pm2`` -> ``pm2``)."""
    words: set[str] = set()
    for w in _WORD.findall(text):
        words.add(w.lower())
        words.add(w.rsplit("/", 1)[-1].lower())
    return words


def _load_commands_file(path: Path) -> DependencyGraph:
    """Procfile / Dockerfile: only contributes command words."""
    g = DependencyGraph()
    g.commands = _command_words(path.read_text(encoding="utf-8", errors="replace"))
    return g


def _npm_name_from_key(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


def _load_package_lock(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("npm lock must be an object")
    g = DependencyGraph()
    packages: dict[str, Any] = data.get("packages") or {}
    if not isinstance(packages, dict):
        raise ValueError("npm lock packages must be an object")
    if packages:
        root = packages.get("") or {}
        if not isinstance(root, dict):
            raise ValueError("npm lock root must be an object")
        if root:
            g.has_manifest = True
            for key in _NPM_DEP_KEYS:
                for name in root.get(key) or {}:
                    g.add_direct(name, dev=key == "devDependencies")
        # ``"string-width-cjs": "npm:string-width@^4"`` installs string-width
        # under another folder name. Dependents and manifests list the alias,
        # advisories name the real package, so the alias points at the real name.
        aliases: dict[str, set[str]] = {}
        for key, info in packages.items():
            if key and isinstance(info, dict) and isinstance(info.get("name"), str):
                installed_as = _npm_name_from_key(key)
                if "node_modules/" in key and installed_as != info["name"]:
                    aliases.setdefault(installed_as, set()).add(info["name"])
        for key, info in packages.items():
            if not isinstance(info, dict):
                raise ValueError("npm lock package entries must be objects")
            if not key:
                continue
            parent = info.get("name") or _npm_name_from_key(key)
            bin_field = info.get("bin")
            if isinstance(bin_field, dict):
                for cmd in bin_field:
                    g.bins.setdefault(cmd.lower(), set()).add(_norm(parent))
            elif isinstance(bin_field, str):
                cmd = parent.rsplit("/", 1)[-1].lower()
                g.bins.setdefault(cmd, set()).add(_norm(parent))
            for dep_key in ("dependencies", "optionalDependencies", "peerDependencies"):
                dependencies = info.get(dep_key) or {}
                if not isinstance(dependencies, dict):
                    raise ValueError(f"npm lock {dep_key} must be an object")
                for child in dependencies:
                    g.add_edge(parent, child)
        for alias, targets in aliases.items():
            for real in targets:
                g.add_edge(alias, real)
        return g

    # lockfileVersion 1: nested "dependencies" with "requires"
    def walk(deps: dict[str, Any]) -> None:
        if not isinstance(deps, dict):
            raise ValueError("npm lock dependencies must be an object")
        for name, info in deps.items():
            if not isinstance(info, dict):
                raise ValueError("npm lock dependency entries must be objects")
            for child in info.get("requires") or {}:
                g.add_edge(name, child)
            walk(info.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return g


_YARN_DEP_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")
_YARN_HEADER = re.compile(r'^"?(@?[^@"\s,]+)@')
_YARN_ALIAS = re.compile(r"@npm:((?:@[^/@\s]+/)?[^/@\s:]+)@")


def _load_yarn_lock(path: Path) -> DependencyGraph:
    """yarn.lock v1 and berry: headers at column 0, deps indented under ``dependencies:``."""
    g = DependencyGraph()
    current: list[str] = []
    in_deps = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0:
            m = _YARN_HEADER.match(line)
            current = [m.group(1)] if m else []
            # ``"x-cjs@npm:x@^4"`` installs x under the name x-cjs: its
            # dependencies belong to both names, and the alias leads to x.
            real = _YARN_ALIAS.search(line)
            if current and real and real.group(1) != current[0]:
                g.add_edge(current[0], real.group(1))
                current.append(real.group(1))
            in_deps = False
        elif indent == 2:
            in_deps = line.rstrip(":") in _YARN_DEP_SECTIONS
        elif indent >= 4 and in_deps and current:
            name = line.split(":", 1)[0] if ":" in line.split(" ", 1)[0] else line.split(" ", 1)[0]
            for parent in current:
                g.add_edge(parent, name.strip('"'))
    return g


def _load_pnpm_lock(path: Path) -> DependencyGraph:
    """pnpm-lock.yaml: direct dependencies of every importer, and package edges.

    pnpm declares its workspaces in ``pnpm-workspace.yaml``, not in
    ``package.json``, and the lockfile lists each one as an importer with its
    own dependencies. They are merged into one project here: a package is
    development-only when no importer lists it, or a parent of it, for
    production.
    """
    from depquiet.pnpm_lock import parse_pnpm_lock

    lock = parse_pnpm_lock(path)
    g = DependencyGraph()
    for importer in lock.importers.values():
        for name, dev in importer.items():
            g.add_direct(name, dev=dev)
    for parent, children in lock.edges.items():
        for child in children:
            g.add_edge(parent, child)
    return g


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _req_name(spec: str) -> str:
    m = _REQ_NAME.match(spec)
    return m.group(1) if m else ""


# Words that mark a dependency group as tooling for people working on the
# project. A group is a named list and nothing more: zulip keeps what its
# servers run in a group called ``prod``. Only a recognisable name makes a
# group development-only; any other group counts as production.
_DEV_GROUP_WORDS = frozenset(
    [
        "dev",
        "precommit",
        "develop",
        "development",
        "test",
        "tests",
        "testing",
        "pytest",
        "tox",
        "nox",
        "e2e",
        "lint",
        "linting",
        "docs",
        "doc",
        "documentation",
        "typing",
        "types",
        "typecheck",
        "mypy",
        "format",
        "formatting",
        "style",
        "ci",
        "bench",
        "benchmark",
        "benchmarks",
        "coverage",
        "qa",
        "debug",
        "profiling",
        "notebook",
        "notebooks",
        "stubs",
    ]
)


def _is_dev_group(name: object) -> bool:
    """``dev``, ``test``, ``docs-build``, ``db-test``: yes. ``prod``, ``release``: no."""
    if not isinstance(name, str):
        return False
    lowered = name.lower().replace("pre-commit", "precommit").replace("pre_commit", "precommit")
    return any(word in _DEV_GROUP_WORDS for word in re.split(r"[^a-z0-9]+", lowered))


def _is_group_include(spec: object, groups: dict[str, object]) -> bool:
    """A PEP 735 ``{include-group = "name"}`` entry naming a group that exists.

    Each group is read on its own and classified by its own name, and a
    production listing anywhere wins, so an include adds nothing: ``dev``
    including ``prod`` leaves those packages production dependencies.
    """
    return (
        isinstance(spec, dict)
        and set(spec) == {"include-group"}
        and isinstance(spec["include-group"], str)
        and spec["include-group"] in groups
    )


def _uv_default_groups(data: dict[str, Any], groups: dict[str, object]) -> set[str]:
    """Groups uv installs even in a production sync, so they are production.

    ``uv sync`` installs ``tool.uv.default-groups``, and the usual production
    command, ``uv sync --no-dev``, leaves out only the group named ``dev``:
    with ``default-groups = "all"`` or ``["docs"]`` a docs group ships.
    """
    uv = ((data.get("tool") or {}).get("uv")) or {}
    declared = uv.get("default-groups") if isinstance(uv, dict) else None
    if declared == "all":
        names = set(groups)
    elif isinstance(declared, list):
        names = {g for g in declared if isinstance(g, str)}
    else:
        return set()
    return names - {"dev"}


def _load_pyproject(path: Path) -> DependencyGraph | None:
    """PEP 621, PEP 735 dependency groups and Poetry.

    Extras (optional-dependencies) ship to users, so they count as production.
    PEP 735 and Poetry groups are development-only when their name says so
    (``dev``, ``test``, ``docs``...); any other group is production.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries: list[tuple[str, bool]] = []  # (name, dev)
    project = data.get("project") or {}
    if not isinstance(project, dict):
        raise ValueError("pyproject project must be a table")
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list) or not all(
        isinstance(spec, str) for spec in dependencies
    ):
        raise ValueError("pyproject dependencies must be a string array")
    optional = project.get("optional-dependencies") or {}
    groups = data.get("dependency-groups") or {}
    if not isinstance(optional, dict) or not isinstance(groups, dict):
        raise ValueError("pyproject dependency groups must be tables")
    for group in optional.values():
        if not isinstance(group, list) or not all(isinstance(spec, str) for spec in group):
            raise ValueError("pyproject optional-dependencies entry is malformed")
    for group in groups.values():
        if not isinstance(group, list) or not all(
            isinstance(spec, str) or _is_group_include(spec, groups) for spec in group
        ):
            raise ValueError("pyproject dependency group is malformed or uses unsupported includes")
    entries += [(_req_name(s), False) for s in project.get("dependencies") or []]
    for group in (project.get("optional-dependencies") or {}).values():
        entries += [(_req_name(s), False) for s in group]
    dynamic_fields = project.get("dynamic") or []
    unlisted = isinstance(dynamic_fields, list) and bool(
        {"dependencies", "optional-dependencies"}
        & {f for f in dynamic_fields if isinstance(f, str)}
    )
    if unlisted:
        static = _static_dynamic_dependencies(data, path.parent)
        if static is not None:
            entries += [(_req_name(s), False) for s in static]
            unlisted = False
    shipped = _uv_default_groups(data, groups)
    for group_name, group in (data.get("dependency-groups") or {}).items():
        dev = _is_dev_group(group_name) and group_name not in shipped
        entries += [(_req_name(s), dev) for s in group if isinstance(s, str)]
    poetry = (data.get("tool") or {}).get("poetry") or {}
    entries += [(n, False) for n in poetry.get("dependencies") or {}]
    entries += [(n, True) for n in poetry.get("dev-dependencies") or {}]
    for group_name, grp in (poetry.get("group") or {}).items():
        dev = _is_dev_group(group_name)
        entries += [(n, dev) for n in (grp or {}).get("dependencies") or {}]
    # ``all = ["myproject[a,b]"]`` names the project itself to combine extras.
    # The project is not one of its own dependencies: as a root it would be
    # "imported" by every file in the repository and vouch for everything.
    own = _pep503(str(project.get("name") or poetry.get("name") or ""))
    entries = [(n, dev) for n, dev in entries if n and n.lower() != "python" and _pep503(n) != own]
    if not entries and not unlisted:
        return DependencyGraph(has_manifest=True) if project else None
    g = DependencyGraph(has_manifest=True)
    for n, dev in entries:
        g.add_direct(n, python=True, dev=dev)
    if unlisted:
        g.dynamic_projects.add(own or path.parent.name)
    return g


def _static_dynamic_dependencies(data: dict[str, Any], base: Path) -> list[str] | None:
    """Dependencies declared ``dynamic`` but written out elsewhere in the file.

    Returns the requirement strings when a known backend table holds them:
    the hatch ``uv-dynamic-versioning`` metadata hook, or setuptools reading
    plain requirement files next to the manifest. ``None`` means they are only
    known at build time, or the files could not be read in full.
    """
    tool = data.get("tool") or {}
    if not isinstance(tool, dict):
        return None
    hook = tool.get("hatch") or {}
    for key in ("metadata", "hooks", "uv-dynamic-versioning"):
        hook = hook.get(key) if isinstance(hook, dict) else None
    if isinstance(hook, dict) and ("dependencies" in hook or "optional-dependencies" in hook):
        specs = [s for s in hook.get("dependencies") or [] if isinstance(s, str)]
        extras = hook.get("optional-dependencies") or {}
        if isinstance(extras, dict):
            for group in extras.values():
                specs += [s for s in group or [] if isinstance(s, str)]
        return specs
    setuptools = tool.get("setuptools")
    dynamic = setuptools.get("dynamic") if isinstance(setuptools, dict) else None
    if not isinstance(dynamic, dict):
        return None
    extras = dynamic.get("optional-dependencies")
    tables = [dynamic.get("dependencies"), *(extras.values() if isinstance(extras, dict) else [])]
    files: list[str] = []
    for table in tables:
        if table is None:
            continue
        listed = table.get("file") if isinstance(table, dict) else None
        listed = [listed] if isinstance(listed, str) else listed
        if not isinstance(listed, list) or not all(isinstance(f, str) for f in listed):
            return None
        files += listed
    requirements: list[str] = []
    for name in files:
        target = base / name
        try:
            inside = target.resolve().is_relative_to(base.resolve())
            lines = target.read_text(encoding="utf-8").splitlines() if inside else None
        except OSError:
            lines = None
        if lines is None:
            return None
        for raw in lines:
            line = raw.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                # ``-r other.txt``, ``-c``, ``-e``: more than this file says.
                return None
            requirements.append(line)
    return requirements if files else None


def _load_pipfile(path: Path) -> DependencyGraph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph(has_manifest=True)
    for section in ("packages", "dev-packages"):
        for name in data.get(section) or {}:
            g.add_direct(name, python=True, dev=section == "dev-packages")
    return g


def _load_requirements_in(path: Path) -> DependencyGraph:
    g = DependencyGraph(has_manifest=True)
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            g.add_direct(_req_name(line), python=True)
    return g


def _load_requirements_txt(path: Path) -> DependencyGraph | None:
    """requirements.txt, with pip-compile ``# via`` annotations when present."""
    lines = path.read_text(encoding="utf-8").splitlines()
    reqs: list[str] = []
    via: dict[str, list[str]] = {}
    current: str | None = None
    collecting = False
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            comment = stripped.lstrip("#").strip()
            if current and comment.startswith("via"):
                rest = comment[3:].strip()
                collecting = not rest
                if rest:
                    via.setdefault(current, []).append(rest)
            elif current and collecting and comment:
                via.setdefault(current, []).append(comment)
            continue
        if stripped.startswith("-"):
            current, collecting = None, False
            continue
        spec = stripped.split(" #", 1)[0].strip()
        current = _req_name(spec)
        collecting = False
        if current:
            reqs.append(spec)
            via.setdefault(current, [])

    if not reqs:
        return None

    g = DependencyGraph()
    annotated = any(via.values())
    if annotated:
        g.has_manifest = True
        for name, parents in via.items():
            for p in parents:
                if p.startswith("-r") or p.startswith("-c") or p.endswith((".in", ".toml", ".cfg")):
                    g.add_direct(name, python=True)
                else:
                    g.add_edge(_pep503(_req_name(p)), _pep503(name))
        return g

    if all("==" in r for r in reqs):
        # Looks like `pip freeze`: directness unknown. Contribute nothing.
        return None

    g.has_manifest = True
    for r in reqs:
        g.add_direct(_req_name(r), python=True)
    return g


def _uv_names(entries: object) -> list[str]:
    return [e["name"] for e in entries or [] if isinstance(e, dict) and e.get("name")]  # type: ignore[attr-defined]


def _load_uv_lock(path: Path) -> DependencyGraph:
    """uv.lock: every package lists its dependencies; workspace roots are direct.

    Roots are the packages whose ``source`` is the project itself
    (``virtual`` or ``editable``). Their ``dependencies`` and
    ``optional-dependencies`` (extras) ship to users; ``dev-dependencies``
    holds the PEP 735 groups, development-only when named like tooling.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    packages = data.get("package") or []
    # The project and its workspace members. They are where dependencies come
    # from, never dependencies themselves, even when an extra refers back to
    # the project (``all = ["myproject[a,b]"]``).
    own = {
        _pep503(pkg.get("name", ""))
        for pkg in packages
        if "virtual" in (pkg.get("source") or {}) or "editable" in (pkg.get("source") or {})
    }
    for pkg in packages:
        name = pkg.get("name", "")
        source = pkg.get("source") or {}
        prod = _uv_names(pkg.get("dependencies"))
        for extra in (pkg.get("optional-dependencies") or {}).values():
            prod += _uv_names(extra)
        dev: list[str] = []
        for group_name, group in (pkg.get("dev-dependencies") or {}).items():
            # uv files every PEP 735 group under ``dev-dependencies``, whatever
            # it is for. A group not named like tooling is production.
            if _is_dev_group(group_name):
                dev += _uv_names(group)
            else:
                prod += _uv_names(group)
        if "virtual" in source or "editable" in source:
            g.has_manifest = True
            g.lock_members[_pep503(name)] = (list(prod), list(dev))
            for d in prod:
                if _pep503(d) not in own:
                    g.add_direct(d, python=True)
            for d in dev:
                if _pep503(d) not in own:
                    g.add_direct(d, python=True, dev=True)
        # Development groups belong to whoever works on the project. A package
        # that depends on the project (a plugin, another workspace member) does
        # not install them, so they are roots of their own, not edges from it.
        for d in prod:
            g.add_edge(_pep503(name), _pep503(d))
    return g


def _load_poetry_lock(path: Path) -> DependencyGraph:
    """poetry.lock: edges only. Direct dependencies come from pyproject.toml."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    for pkg in data.get("package") or []:
        for dep in pkg.get("dependencies") or {}:
            g.add_edge(_pep503(pkg.get("name", "")), _pep503(dep))
    return g


# ---------------------------------------------------------------------------
# Rust, Ruby, PHP, .NET, Dart, Go, Maven
# ---------------------------------------------------------------------------


def _load_cargo_lock(path: Path) -> DependencyGraph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    for pkg in data.get("package") or []:
        name = pkg.get("name", "")
        deps = [d.split(" ", 1)[0] for d in pkg.get("dependencies") or []]
        if "source" not in pkg:  # local workspace crate: its deps are direct
            g.has_manifest = True
            for d in deps:
                g.add_direct(d)
        for d in deps:
            g.add_edge(name, d)
    return g


_GEM_LINE = re.compile(r"^(\s*)([A-Za-z0-9_.-]+)(?:\s|!|$)")


def _load_gemfile_lock(path: Path) -> DependencyGraph:
    g = DependencyGraph()
    section = ""
    in_specs = False
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw and not raw.startswith(" "):
            section = raw.strip()
            in_specs = False
            continue
        if raw.strip() == "specs:":
            in_specs = True
            continue
        m = _GEM_LINE.match(raw)
        if not m:
            continue
        indent, name = len(m.group(1)), m.group(2)
        if section == "DEPENDENCIES" and indent == 2:
            g.has_manifest = True
            g.add_direct(name)
        elif in_specs and indent == 4:
            current = name
        elif in_specs and indent == 6 and current:
            g.add_edge(current, name)
    return g


def _composer_real(name: str) -> bool:
    return "/" in name  # skips "php", "ext-json", "lib-icu"


def _load_composer_json(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph(has_manifest=True)
    for key in ("require", "require-dev"):
        for name in data.get(key) or {}:
            if _composer_real(name):
                g.add_direct(name, dev=key == "require-dev")
    return g


def _load_composer_lock(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    for key in ("packages", "packages-dev"):
        for pkg in data.get(key) or []:
            for child in pkg.get("require") or {}:
                if _composer_real(child):
                    g.add_edge(pkg.get("name", ""), child)
    return g


def _load_nuget_lock(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    g = DependencyGraph()
    for framework in (data.get("dependencies") or {}).values():
        for name, info in (framework or {}).items():
            kind = (info or {}).get("type", "")
            if kind == "Direct":
                g.has_manifest = True
                g.add_direct(name)
            elif kind == "Transitive":
                g.known_transitive.add(_norm(name))
            for child in (info or {}).get("dependencies") or {}:
                g.add_edge(name, child)
    return g


def _load_pubspec_lock(path: Path) -> DependencyGraph:
    g = DependencyGraph()
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^  [A-Za-z0-9_]+:\s*$", raw):
            current = raw.strip().rstrip(":")
            continue
        m = re.match(r'^    dependency:\s*"?([^"]+)"?', raw)
        if m and current:
            kind = m.group(1).strip()
            if kind.startswith("direct"):
                g.has_manifest = True
                g.add_direct(current)
            elif kind == "transitive":
                g.known_transitive.add(_norm(current))
    return g


def _load_go_mod(path: Path) -> DependencyGraph:
    g = DependencyGraph(has_manifest=True)
    in_block = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :]
        elif not in_block:
            continue
        if not line or line.startswith("//"):
            continue
        module = line.split()[0]
        if "// indirect" in line:
            g.known_transitive.add(_norm(module))
        else:
            g.add_direct(module)
    return g


def _load_pom(path: Path) -> DependencyGraph:
    root = ET.parse(path).getroot()
    ns = root.tag.split("}", 1)[0] + "}" if root.tag.startswith("{") else ""
    g = DependencyGraph(has_manifest=True)
    for dep in root.iter(f"{ns}dependency"):
        group = dep.findtext(f"{ns}groupId") or ""
        artifact = dep.findtext(f"{ns}artifactId") or ""
        if group and artifact:
            g.add_direct(f"{group}:{artifact}")
    return g


_LOADERS: dict[str, Any] = {
    "package.json": _load_package_json,
    "package-lock.json": _load_package_lock,
    "npm-shrinkwrap.json": _load_package_lock,
    "yarn.lock": _load_yarn_lock,
    "pnpm-lock.yaml": _load_pnpm_lock,
    "pyproject.toml": _load_pyproject,
    "Pipfile": _load_pipfile,
    "requirements.in": _load_requirements_in,
    "uv.lock": _load_uv_lock,
    "poetry.lock": _load_poetry_lock,
    "Cargo.lock": _load_cargo_lock,
    "Gemfile.lock": _load_gemfile_lock,
    "composer.json": _load_composer_json,
    "composer.lock": _load_composer_lock,
    "packages.lock.json": _load_nuget_lock,
    "pubspec.lock": _load_pubspec_lock,
    "go.mod": _load_go_mod,
    "pom.xml": _load_pom,
    "Procfile": _load_commands_file,
    "Dockerfile": _load_commands_file,
}
