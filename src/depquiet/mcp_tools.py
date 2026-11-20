"""The MCP-facing signatures of depquiet's two tools: parameter and result schemas.

``mcp_server.triage_alerts`` and ``mcp_server.plan_fixes`` are plain Python and
run without the SDK. This module wraps them with ``Annotated`` parameters and
``TypedDict`` results, which the SDK turns into the input and output schemas an
agent reads: what each argument means and what comes back. It imports pydantic
at the top, so only ``build_server`` imports it (``depquiet[mcp]`` brings
pydantic with the SDK).

No ``from __future__ import annotations`` here: the SDK resolves these
annotations at runtime, and string annotations would hide ``Field``.
"""

from typing import Annotated, Any, NotRequired

from pydantic import Field
from typing_extensions import TypedDict

from depquiet import mcp_server

TRIAGE_DESCRIPTION = (
    "Scan a project's locked dependencies for known vulnerabilities and sort every alert "
    "into action (fix now), review (worth a look, not urgent) or filtered (deprioritized: "
    "dev-only, test-only...), with the reasons. Use it first, to see which alerts matter; "
    "then call plan_fixes for the change that closes them. Works on Python (uv, Poetry, pip "
    "requirements) and JavaScript (npm, pnpm) projects. Read-only: runs pip-audit or the "
    "package manager's audit, which query their advisory databases over the network, plus "
    "EPSS and CISA KEV lookups unless offline=true."
)

PLAN_DESCRIPTION = (
    "Work out the change that closes a project's action alerts and check it with the "
    "project's own resolver (uv lock --dry-run, or Poetry) on a temporary copy. Returns the "
    "requirement edits as a unified diff, the lock command to run, every version the lock "
    "moves (downgrades included), the alerts left out and why, and whether raising "
    "requires-python would unblock more fixes. Use it after triage_alerts reports action "
    "alerts; only uv and Poetry projects get a plan (for others it explains why there is "
    "none). Read-only: never edits or relocks the project; show the user the plan and apply "
    "the diff only when they agree. Needs network access, and resolving can build source "
    "distributions and take a few minutes on large projects."
)

Path = Annotated[
    str,
    Field(
        description=(
            "Absolute path of the project folder: the one holding pyproject.toml, uv.lock, "
            "poetry.lock, requirements*.txt or package.json."
        )
    ),
]


class Alert(TypedDict, total=False):
    """One vulnerability alert. Empty fields are left out."""

    cve: Annotated[str, Field(description="Advisory ID: a CVE, GHSA or PYSEC ID.")]
    title: str
    package: Annotated[str, Field(description="The vulnerable package.")]
    version: Annotated[str, Field(description="The locked version that is vulnerable.")]
    severity: str
    verdict: Annotated[str, Field(description="action, review or filtered.")]
    reasons: Annotated[list[str], Field(description="Why the alert got that verdict.")]
    fix_version: Annotated[str, Field(description="First version with the fix.")]
    fix_package: Annotated[
        str, Field(description="The direct dependency to upgrade, when it differs from package.")
    ]
    is_dev: bool
    dependency_type: Annotated[str, Field(description="direct, transitive or unknown.")]
    introduced_by: Annotated[list[str], Field(description="Dependency path to the package.")]
    python_scope: Annotated[
        str,
        Field(description='Like "<3.11.5": only Pythons below it install the vulnerable copy.'),
    ]
    epss_score: Annotated[float, Field(description="EPSS exploit probability, 0 to 1.")]
    url: str


class TriageResult(TypedDict):
    ok: Annotated[bool, Field(description="false when the scan could not run; see error.")]
    error: NotRequired[str]
    details: NotRequired[Annotated[str, Field(description="The end of depquiet's stderr.")]]
    project: NotRequired[str]
    total: NotRequired[Annotated[int, Field(description="Number of alerts.")]]
    counts: NotRequired[Annotated[dict[str, int], Field(description="Alerts per verdict.")]]
    alerts: NotRequired[list[Alert]]
    notes: NotRequired[Annotated[str | None, Field(description="Scanner warnings, if any.")]]
    next: NotRequired[
        Annotated[str | None, Field(description="The suggested next call, when there is one.")]
    ]


class PlanResult(TypedDict):
    ok: Annotated[bool, Field(description="false when no plan could be made; see error.")]
    error: NotRequired[str]
    details: NotRequired[Annotated[str, Field(description="The end of depquiet's stderr.")]]
    project: NotRequired[str]
    plan: NotRequired[
        Annotated[
            dict[str, Any],
            Field(
                description=(
                    "The plan: status, tool (uv or poetry), command, note, included (packages "
                    "the plan fixes, with target versions and edits), left_out (with why), "
                    "lock_changes (from/to) and python_floor."
                )
            ),
        ]
    ]
    diff: NotRequired[
        Annotated[
            str | None,
            Field(description="Unified diff of the requirement edits; null when none are needed."),
        ]
    ]
    pull_request_description: NotRequired[
        Annotated[str | None, Field(description="The plan as Markdown, ready for a PR body.")]
    ]
    notes: NotRequired[str | None]
    hint: NotRequired[
        Annotated[
            str | None,
            Field(description="Set when raise_python_floor=true would let more fixes in."),
        ]
    ]
    applied: NotRequired[
        Annotated[bool, Field(description="Always false: the project is never changed.")]
    ]


def triage_alerts(
    path: Path,
    offline: Annotated[
        bool,
        Field(
            description=(
                "Skip the EPSS and CISA KEV downloads (cached copies are still used). The "
                "scanner itself still needs its advisory database."
            )
        ),
    ] = False,
) -> TriageResult:
    return mcp_server.triage_alerts(path, offline)  # type: ignore[return-value]


def plan_fixes(
    path: Path,
    raise_python_floor: Annotated[
        bool,
        Field(
            description=(
                "When a fix needs a newer Python than requires-python allows, "
                "raise requires-python in the plan (checked with the resolver). This drops "
                "support for older Pythons: ask the user first."
            )
        ),
    ] = False,
    include_filtered: Annotated[
        bool,
        Field(
            description=(
                "Also plan fixes for filtered alerts (dev-only, test-only...). They need no "
                "action, but Dependabot keeps them open until the package moves."
            )
        ),
    ] = False,
) -> PlanResult:
    return mcp_server.plan_fixes(path, raise_python_floor, include_filtered)  # type: ignore[return-value]
