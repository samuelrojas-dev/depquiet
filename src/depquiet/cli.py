"""CLI entry point — `depquiet` or `python -m depquiet`.

Usage:
    depquiet                     # auto-detect, scan, triage
    depquiet --path ./my-app     # scan a specific directory
    depquiet --offline           # skip EPSS API (fully offline)
    depquiet --sarif out.sarif   # write SARIF for GitHub Code Scanning
    depquiet --json              # machine-readable JSON output
    depquiet --epss-threshold 0.05  # custom EPSS threshold
    cat audit.json | depquiet --stdin  # pipe in npm audit / pip-audit JSON
    depquiet diff base.json head.json  # compare two scans
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from depquiet import __version__
from depquiet.annotations import build_annotations, write_annotations
from depquiet.assessment import assess_finding, decision_trace_to_json
from depquiet.baseline import apply_baseline, load_baseline
from depquiet.config import load_config
from depquiet.diff import diff_scans, diff_to_json, format_diff, format_diff_markdown
from depquiet.engine import scan
from depquiet.finding_identity import parse_report, validate_project_id
from depquiet.fix import apply_fixes, print_fix_report
from depquiet.fixcheck import check_fixes
from depquiet.fixplan import FixPlan, build_fix_plan, print_fix_plan, stale_exemptions
from depquiet.html_report import write_html
from depquiet.ignore import apply_ignores, load_ignore, print_ignore_warnings
from depquiet.kev import KevCatalog, apply_kev, fetch_kev_catalog, load_kev_from_file
from depquiet.license import LicenseReport, print_license_report, scan_licenses
from depquiet.models import ScanResult
from depquiet.output import print_scan_result
from depquiet.policy import load_policy
from depquiet.sarif import write_sarif
from depquiet.sbom import write_sbom
from depquiet.summary import write_summary
from depquiet.vex import build_vex, write_vex


def _write_diff_summary(path: Path, text: str) -> None:
    """Replace a summary only after its complete UTF-8 text is written."""
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=".depquiet-diff-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)


def diff_main(argv: list[str]) -> int:
    """Run the `depquiet diff` subcommand. Returns exit code."""
    parser = argparse.ArgumentParser(
        prog="depquiet diff",
        description="Compare two depquiet scans to show new, fixed, and changed findings.",
    )
    parser.add_argument(
        "base",
        type=Path,
        help="Path to the base/before scan JSON (from depquiet --json)",
    )
    parser.add_argument(
        "head",
        type=Path,
        help="Path to the head/after scan JSON (from depquiet --json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON diff to stdout",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Output GitHub-flavored Markdown (for PR comments or step summaries)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        metavar="FILE",
        help="Write Markdown diff summary to FILE (for $GITHUB_STEP_SUMMARY)",
    )
    parser.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Exit 1 if any new ACTION findings are detected",
    )
    identity = parser.add_mutually_exclusive_group()
    identity.add_argument(
        "--instances", action="store_true", help="Compare project-scoped instance contexts"
    )
    identity.add_argument(
        "--legacy-identities",
        action="store_true",
        help="Explicitly use legacy reported-version identities",
    )
    parser.add_argument("--project-id", help="Bind missing report scopes to this stable project ID")
    args = parser.parse_args(argv)

    # Validate input files exist
    for path in (args.base, args.head):
        if not path.is_file():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 1

    try:
        mode = True if args.instances else False if args.legacy_identities else None
        diff = diff_scans(args.base, args.head, project_id=args.project_id, instance_aware=mode)
        if args.json_output:
            output = json.dumps(diff_to_json(diff), indent=2)
        elif args.markdown:
            output = format_diff_markdown(diff)
        else:
            output = format_diff(diff)

        # Validate inputs and render before producing any successful artifact.
        if args.summary:
            md = format_diff_markdown(diff)
            _write_diff_summary(args.summary, md + "\n")
    except (OSError, ValueError, TypeError) as exc:
        print(f"Error: cannot compare scans: {exc}", file=sys.stderr)
        return 2

    print(output)

    if args.fail_on_new and diff.has_new_action:
        return 1
    return 0


def baseline_main(argv: list[str]) -> int:
    """Create an explicit v2 acceptance document from a completed saved scan."""
    from depquiet.baseline import create_baseline

    parser = argparse.ArgumentParser(prog="depquiet baseline")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Create a scoped instance baseline v2")
    create.add_argument("scan", type=Path, help="Completed depquiet JSON report")
    create.add_argument("--output", "-o", type=Path, required=True)
    create.add_argument("--project-id", help="Explicit stable scope if missing from the report")
    create.add_argument("--reason", default="", help="Reason supplied by the baseline author")
    create.add_argument("--author", default="", help="Author metadata supplied by the caller")
    args = parser.parse_args(argv)
    try:
        if args.scan.resolve() == args.output.resolve():
            raise ValueError("baseline output must differ from its source scan")
        raw = args.scan.read_bytes()
        report = parse_report(raw)
        document = create_baseline(
            report,
            project_id=args.project_id,
            reason=args.reason,
            author=args.author,
            source_scan_sha256=hashlib.sha256(raw).hexdigest(),
            source_scan_hash_kind="file_bytes",
        )
        _write_diff_summary(args.output, json.dumps(document, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError, TypeError) as exc:
        print(f"Error: cannot create baseline v2: {exc}", file=sys.stderr)
        return 2
    print(
        f"Baseline v2 written to {args.output}: {len(document['accepted'])} accepted contexts, "
        f"{len(document['unaccepted'])} contexts remain unaccepted.",
        file=sys.stderr,
    )
    return 0


def explain_main(argv: list[str]) -> int:
    """Run the `depquiet explain` subcommand. Returns exit code."""
    from depquiet.explain import (
        explain_triage,
        find_cve,
        find_cve_in_json,
        format_explanation,
        format_explanation_json,
    )

    parser = argparse.ArgumentParser(
        prog="depquiet explain",
        description="Explain why a CVE received its verdict.",
    )
    parser.add_argument(
        "cve",
        help="CVE ID to explain (e.g. CVE-2021-44228)",
    )
    parser.add_argument(
        "--from-json",
        type=Path,
        metavar="FILE",
        dest="from_json",
        help="Read from a previous depquiet --json output instead of scanning",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON explanation",
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="FILE",
        help="Path to config file (default: .depquiet.yaml in project root)",
    )
    args = parser.parse_args(argv)

    tr = None

    if args.from_json:
        # Load from a saved JSON scan
        if not args.from_json.is_file():
            print(f"Error: file not found: {args.from_json}", file=sys.stderr)
            return 1
        try:
            data = json.loads(args.from_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"Error: invalid JSON in {args.from_json}", file=sys.stderr)
            return 1
        try:
            tr = find_cve_in_json(data, args.cve)
        except (ValueError, TypeError) as exc:
            print(f"Error: invalid saved scan evidence: {exc}", file=sys.stderr)
            return 2
    else:
        # Run a live scan
        config = load_config(args.path, config_path=args.config)
        merged = config.merge_cli()
        result = scan(
            project=args.path,
            epss_threshold=merged.epss_threshold,
            skip_epss=merged.offline,
            template_dirs=merged.template_dirs or None,
            always_flag=merged.always_flag or None,
        )
        if not result.scanned:
            print(f"depquiet: nothing scanned: {result.note}", file=sys.stderr)
            return 2
        tr = find_cve(result, args.cve)

    if tr is None:
        print(f"CVE not found: {args.cve}", file=sys.stderr)
        print(
            "Hint: the CVE must appear in your project's vulnerability scan.",
            file=sys.stderr,
        )
        return 1

    exp = explain_triage(tr)

    if args.json_output:
        print(format_explanation_json(exp))
    else:
        print(format_explanation(exp))

    return 0


def stats_main(argv: list[str]) -> int:
    """Run the `depquiet stats` subcommand. Returns exit code."""
    from depquiet.stats import (
        compute_stats,
        format_stats,
        format_stats_json,
        stats_from_json,
    )

    parser = argparse.ArgumentParser(
        prog="depquiet stats",
        description="Show aggregate scan statistics.",
    )
    parser.add_argument(
        "--from-json",
        type=Path,
        metavar="FILE",
        dest="from_json",
        help="Read from a previous depquiet --json output instead of scanning",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON statistics",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Number of top packages to show (default: 10)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="FILE",
        help="Path to config file (default: .depquiet.yaml in project root)",
    )
    args = parser.parse_args(argv)

    if args.from_json:
        if not args.from_json.is_file():
            print(f"Error: file not found: {args.from_json}", file=sys.stderr)
            return 1
        try:
            data = json.loads(args.from_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"Error: invalid JSON in {args.from_json}", file=sys.stderr)
            return 1
        stats = stats_from_json(data, top_n=args.top)
    else:
        config = load_config(args.path, config_path=args.config)
        merged = config.merge_cli()
        result = scan(
            project=args.path,
            epss_threshold=merged.epss_threshold,
            skip_epss=merged.offline,
            template_dirs=merged.template_dirs or None,
            always_flag=merged.always_flag or None,
        )
        if not result.scanned:
            print(f"depquiet: nothing scanned: {result.note}", file=sys.stderr)
            return 2
        stats = compute_stats(
            result.results,
            result.total_dependencies,
            top_n=args.top,
        )

    if args.json_output:
        print(format_stats_json(stats))
    else:
        print(format_stats(stats))

    return 0


def init_main(argv: list[str]) -> int:
    """Run the `depquiet init` subcommand. Returns exit code."""
    from depquiet.init import init_command

    parser = argparse.ArgumentParser(
        prog="depquiet init",
        description="Generate a .depquiet.yaml config for this project.",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="Project directory (default: current directory)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Non-interactive mode — accept all defaults",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing .depquiet.yaml",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="Write config to FILE instead of <project>/.depquiet.yaml",
    )
    args = parser.parse_args(argv)
    return init_command(args.path, yes=args.yes, force=args.force, output=args.output)


def _utf8_streams() -> None:
    """Never crash on output encoding.

    Output uses symbols (✅, ⚠️, →) that Windows code pages such as cp1252
    can't encode; with stdout redirected (``depquiet > report.txt``, CI logs)
    Python falls back to that code page and printing raised
    UnicodeEncodeError. Switch non-UTF-8 streams to UTF-8.
    """
    for stream in (sys.stdout, sys.stderr):
        enc = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if enc != "utf8" and hasattr(stream, "reconfigure"):
            with contextlib.suppress(ValueError, OSError):
                stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    """Run the depquiet CLI. Returns exit code."""
    _utf8_streams()
    # Dispatch to subcommands before argparse sees them
    effective = argv if argv is not None else sys.argv[1:]
    if effective and effective[0] == "diff":
        return diff_main(effective[1:])
    if effective and effective[0] == "baseline":
        return baseline_main(effective[1:])
    if effective and effective[0] == "init":
        return init_main(effective[1:])
    if effective and effective[0] == "explain":
        return explain_main(effective[1:])
    if effective and effective[0] == "stats":
        return stats_main(effective[1:])

    parser = argparse.ArgumentParser(
        prog="depquiet",
        description=(
            "Silence the noise. Surface the signal. Triage vulnerability alerts in seconds."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""common runs:
  depquiet                          scan the project in this directory
  depquiet --json                   machine-readable report
  depquiet --check-fixes            uv: can each fix be installed, and what blocks it
  depquiet --fix-plan plan.diff     uv: one verified pyproject.toml change for all fixes
  depquiet --fail-on high           fail CI on high or critical ACTION alerts

other commands:
  depquiet explain <ID>             why one alert got its verdict
  depquiet diff OLD.json NEW.json   new, fixed and changed findings between two scans
  depquiet baseline ...             record accepted findings (see depquiet baseline -h)

Python projects need pip-audit (pip install pip-audit) or uv; npm projects need npm.""",
    )
    parser.add_argument("--version", action="version", version=f"depquiet {__version__}")
    parser.add_argument(
        "--project-id", help="Stable project scope for instance baselines and diffs"
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip EPSS API lookup (fully offline mode)",
    )
    parser.add_argument(
        "--scanner",
        choices=["npm", "pnpm", "pip", "uv"],
        help="Scanner to run when the project has both npm and Python dependencies "
        "(default: every ecosystem the project declares, one run each, merged into one report)",
    )
    parser.add_argument(
        "--sarif",
        type=Path,
        metavar="FILE",
        help="Write SARIF output to FILE",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON to stdout",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read audit JSON from stdin instead of running a scanner",
    )
    parser.add_argument(
        "--from-sbom",
        type=Path,
        metavar="FILE",
        dest="from_sbom",
        help=(
            "Read a CycloneDX or SPDX JSON SBOM as input. "
            "Extracts vulnerabilities or queries OSV.dev for advisories."
        ),
    )
    parser.add_argument(
        "--epss-threshold",
        type=float,
        default=None,
        metavar="N",
        help="Filter alerts whose EPSS score is below N (0-1, e.g. 0.05). Off by default: "
        "EPSS only orders the report, since a low score is about the internet, not your app",
    )
    parser.add_argument(
        "--templates",
        type=Path,
        action="append",
        metavar="DIR",
        help="Extra directory of community templates (can be repeated)",
    )
    parser.add_argument(
        "--sbom",
        type=Path,
        metavar="FILE",
        help="Write CycloneDX 1.5 SBOM to FILE (.json or .xml)",
    )
    parser.add_argument(
        "--sbom-format",
        choices=["json", "xml", "spdx"],
        default=None,
        metavar="FMT",
        help=(
            "SBOM format: json (CycloneDX, default), xml (CycloneDX), "
            "or spdx (SPDX 2.3 JSON). Inferred from --sbom extension if omitted."
        ),
    )
    parser.add_argument(
        "--policy",
        type=Path,
        metavar="FILE",
        help="Path to policy file (default: .depquiet-policy.yaml in project root)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="FILE",
        help="Path to config file (default: .depquiet.yaml in project root)",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Auto-fix ACTION items that have a known fix version",
    )
    parser.add_argument(
        "--check-fixes",
        action="store_true",
        help="For uv projects: ask uv's resolver (uv lock --dry-run) whether each suggested "
        "fix can be installed, and what blocks it if not. Needs uv and network access. "
        "Like uv lock, it may run build hooks: use on trusted code only",
    )
    parser.add_argument(
        "--fix-plan",
        nargs="?",
        const="-",
        default=None,
        metavar="FILE",
        help="For uv projects: compute the pyproject.toml changes that let the suggested "
        "fixes install together, verify them with uv's resolver on a copy of the project, "
        "and print the diff (or write it to FILE, for git apply). Implies --check-fixes. "
        "Changes nothing in the project. Trusted code only, like --check-fixes",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what --fix would do without changing anything",
    )
    parser.add_argument(
        "--license",
        action="store_true",
        dest="license_scan",
        help="Run license compliance analysis on all dependencies",
    )
    parser.add_argument(
        "--ignore",
        type=Path,
        metavar="FILE",
        help="Path to ignore file (default: .depquiet-ignore in project root)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        metavar="FILE",
        help="Write GitHub-flavored Markdown summary to FILE (for $GITHUB_STEP_SUMMARY)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        metavar="FILE",
        help=(
            "Path to a previous depquiet --json output. "
            "Only NEW findings not in the baseline trigger ACTION/REVIEW verdicts."
        ),
    )
    parser.add_argument(
        "--kev",
        action="store_true",
        help=(
            "Check vulnerabilities against the CISA Known Exploited Vulnerabilities "
            "(KEV) catalog. KEV-listed CVEs are auto-escalated to ACTION."
        ),
    )
    parser.add_argument(
        "--kev-file",
        type=Path,
        metavar="FILE",
        help="Path to a local KEV catalog JSON file (for air-gapped environments)",
    )
    parser.add_argument(
        "--html",
        type=Path,
        metavar="FILE",
        help="Write a self-contained interactive HTML report to FILE",
    )
    parser.add_argument(
        "--annotations",
        type=Path,
        metavar="FILE",
        help="Write GitHub Check Run annotations JSON to FILE",
    )
    parser.add_argument(
        "--vex",
        type=Path,
        metavar="FILE",
        help="Write an OpenVEX document to FILE (vulnerability exploitability exchange)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "moderate", "low", "none"],
        default=None,
        metavar="SEVERITY",
        help=(
            "Exit 1 only when ACTION items at or above SEVERITY exist "
            "(critical, high, moderate, low, none). Default: low (any ACTION fails)."
        ),
    )

    args = parser.parse_args(argv)

    # Load project config file
    try:
        config = load_config(args.path, config_path=args.config)
    except ValueError as exc:
        print(f"Error: invalid project configuration: {exc}", file=sys.stderr)
        return 2

    # CLI flags override config; None means not passed (EPSS filtering off
    # unless the config turns it on).
    cli_threshold: float | None = args.epss_threshold
    if cli_threshold is not None and not 0.0 <= cli_threshold <= 1.0:
        # EPSS is a probability: 5 would filter every scored alert as low.
        parser.error(
            f"--epss-threshold {cli_threshold:g}: EPSS is a probability between 0 and 1 "
            "(0.05 for 5%%)"
        )

    # Detect which CLI flags were explicitly passed (vs argparse defaults)
    _raw = argv if argv is not None else sys.argv[1:]

    def _has(flag: str) -> bool:
        return flag in _raw or any(arg.startswith(flag + "=") for arg in _raw)

    merged = config.merge_cli(
        project_id=args.project_id,
        epss_threshold=cli_threshold,
        template_dirs=args.templates,
        offline=args.offline,
        fail_on=args.fail_on if _has("--fail-on") else None,
        kev=args.kev if _has("--kev") else False,
        kev_file=args.kev_file if _has("--kev-file") else None,
        license_scan=args.license_scan if _has("--license") else False,
        policy=args.policy if _has("--policy") else None,
        ignore=args.ignore if _has("--ignore") else None,
        baseline=args.baseline if _has("--baseline") else None,
        sarif=args.sarif if _has("--sarif") else None,
        html=args.html if _has("--html") else None,
        summary=args.summary if _has("--summary") else None,
        sbom=args.sbom if _has("--sbom") else None,
        sbom_format=args.sbom_format if _has("--sbom-format") else None,
        vex=args.vex if _has("--vex") else None,
        annotations=args.annotations if _has("--annotations") else None,
    )
    try:
        if merged.project_id or args.project_id is not None:
            validate_project_id(merged.project_id)
    except ValueError as exc:
        print(f"Error: invalid project scope: {exc}", file=sys.stderr)
        return 2

    # Read piped input or SBOM file
    audit_json: dict[str, Any] | None = None
    # Unreadable input is exit 2, never 1: 1 means "findings", and a CI step
    # that tolerates findings would pass a scan that never happened.
    if args.from_sbom:
        if not args.from_sbom.is_file():
            print(f"Error: file not found: {args.from_sbom}", file=sys.stderr)
            return 2
        try:
            audit_json = json.loads(args.from_sbom.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            print(f"Error: invalid JSON in {args.from_sbom}", file=sys.stderr)
            return 2
        if not isinstance(audit_json, dict):
            print(
                f"Error: {args.from_sbom} is not an SBOM (expected a JSON object)", file=sys.stderr
            )
            return 2
    elif args.stdin:
        try:
            raw = json.load(sys.stdin)
        except json.JSONDecodeError:
            print("Error: invalid JSON on stdin", file=sys.stderr)
            return 2
        if not isinstance(raw, (dict, list)):
            print("Error: stdin is not a scanner report (expected a JSON object)", file=sys.stderr)
            return 2
        # Dependabot exports are JSON arrays — wrap for the engine
        audit_json = {"alerts": raw} if isinstance(raw, list) else raw

    # Load policy (from CLI, config, or project default)
    policy = load_policy(args.path, policy_path=merged.policy)

    # Run scan
    result = scan(
        project=args.path,
        epss_threshold=merged.epss_threshold,
        skip_epss=merged.offline,
        template_dirs=merged.template_dirs or None,
        audit_json=audit_json,
        always_flag=merged.always_flag or None,
        policy=policy,
        scanner=args.scanner,
    )
    result.project_id = merged.project_id
    if not result.scanned:
        print(f"depquiet: nothing scanned: {result.note}", file=sys.stderr)
        return 2

    # Apply suppressions (from CLI, config, or project default)
    ignore_file = load_ignore(args.path, ignore_path=merged.ignore)
    if ignore_file is not None:
        apply_ignores(result, ignore_file)
        print_ignore_warnings(ignore_file)

    # Apply baseline — demote known findings to FILTERED
    if merged.baseline:
        try:
            baseline_keys = load_baseline(merged.baseline)
            bl = apply_baseline(result, baseline_keys, source_path=str(merged.baseline))
        except (OSError, ValueError, TypeError) as exc:
            print(f"Error: cannot apply baseline: {exc}", file=sys.stderr)
            return 2
        if not args.json_output:
            print(
                f"\n📊 Baseline: {bl.known_findings} known findings suppressed, "
                f"{bl.new_findings} new findings remain\n"
            )

    # Apply KEV escalation — auto-escalate actively exploited CVEs
    if merged.kev or merged.kev_file:
        kev_catalog: KevCatalog | None
        if merged.kev_file:
            try:
                kev_catalog = load_kev_from_file(merged.kev_file)
            except (OSError, ValueError) as exc:
                print(f"Error: cannot read KEV file {merged.kev_file}: {exc}", file=sys.stderr)
                return 2
        else:
            kev_catalog = fetch_kev_catalog(offline=merged.offline)
        if kev_catalog is not None:
            kev_result = apply_kev(result, kev_catalog)
            if not args.json_output:
                parts = [f"🛡️  KEV: {kev_result.kev_matches} of {kev_result.total_checked}"]
                parts[0] += " CVEs on the CISA KEV catalog"
                if kev_result.escalated > 0:
                    parts.append(f"{kev_result.escalated} escalated to ACTION")
                print("\n" + " — ".join(parts) + "\n")
        else:
            # stderr, so --json users see that KEV was not checked
            why = "offline with no cache" if merged.offline else "download failed, no cache"
            print(f"⚠️  KEV catalog unavailable ({why}); KEV was not checked", file=sys.stderr)

    # A per-package cut-off older than the project's own cooldown holds that
    # package back, possibly on a vulnerable release. Checked on every scan:
    # it only reads the project's config.
    for package, entry, cutoff in stale_exemptions(args.path):
        print(
            f"⚠️  exclude-newer-package holds {package} at releases before {entry}, older "
            f"than your cooldown's cut-off ({cutoff}): uv keeps {package} on old releases. "
            "Remove the entry.",
            file=sys.stderr,
        )

    fix_plan = None
    if args.check_fixes or args.fix_plan is not None:
        flag = "--fix-plan" if args.fix_plan is not None else "--check-fixes"
        if merged.offline:
            print(f"depquiet: {flag} needs network access; skipped (--offline).", file=sys.stderr)
        else:
            checks, check_note = check_fixes(result, args.path)
            if check_note:
                print(f"depquiet: {check_note.replace('--check-fixes', flag)}", file=sys.stderr)
            elif args.fix_plan is not None:
                fix_plan = build_fix_plan(result, args.path, checks)

    # Compute license data before serializing so --json emits one document.
    license_report = None
    if merged.license or args.license_scan:
        license_report = scan_licenses(
            args.path, package_manager=result.package_manager, offline=merged.offline
        )

    # Output
    if args.json_output:
        _print_json(result, license_report=license_report, fix_plan=fix_plan)
    else:
        print_scan_result(result)
    if fix_plan is not None:
        print_fix_plan(fix_plan, sys.stderr)
        if fix_plan.diff and args.fix_plan != "-":
            Path(args.fix_plan).write_text(fix_plan.diff, encoding="utf-8")
            print(
                f"   Diff written to {args.fix_plan} (apply with: git apply {args.fix_plan})",
                file=sys.stderr,
            )
        elif fix_plan.diff and not args.json_output:
            print(fix_plan.diff)

    if merged.sarif:
        write_sarif(result, merged.sarif)

    if merged.sbom:
        sbom_fmt = merged.sbom_format
        if sbom_fmt is None:
            name_lower = merged.sbom.name.lower()
            if name_lower.endswith(".spdx.json") or name_lower.endswith(".spdx"):
                sbom_fmt = "spdx"
            elif merged.sbom.suffix.lower() == ".xml":
                sbom_fmt = "xml"
            else:
                sbom_fmt = "json"
        write_sbom(result, merged.sbom, fmt=sbom_fmt)

    if merged.summary:
        write_summary(result, merged.summary)

    if merged.html:
        write_html(result, merged.html)

    if merged.annotations:
        ann_report = build_annotations(result)
        write_annotations(ann_report, merged.annotations)

    if merged.vex:
        vex_doc = build_vex(result)
        write_vex(vex_doc, merged.vex)

    # License compliance (from CLI or config)
    if license_report is not None:
        if not args.json_output:
            print_license_report(license_report)
        if license_report.has_issues:
            return 1

    # Auto-fix
    if args.fix or args.dry_run:
        fix_report = apply_fixes(result, args.path, dry_run=args.dry_run)
        print_fix_report(fix_report, dry_run=args.dry_run)
        # After fixing, only fail if there are still unfixed ACTION items
        remaining = len(fix_report.failed) + len(fix_report.skipped) + len(fix_report.manual)
        if remaining > 0:
            return 1
        return 0

    # Exit code: 1 if ACTION items meet the severity threshold
    # --fail-on / config fail_on controls the minimum severity that triggers failure
    if _should_fail(result, merged.fail_on):
        return 1
    return 0


# Severity ordering: critical > high > moderate > low > info
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "moderate": 2,
    "low": 1,
    "info": 0,
}


def _should_fail(result: ScanResult, fail_on: str | None) -> bool:
    """Check whether any ACTION items meet the severity threshold.

    When fail_on is None (default), any ACTION item triggers failure.
    When fail_on is "none", the build never fails on findings.
    Otherwise, only ACTION items at or above the specified severity count.
    """
    if fail_on == "none":
        return False

    if not result.action:
        return False

    if fail_on is None:
        # Default: any ACTION item triggers failure
        return True

    threshold = _SEVERITY_RANK.get(fail_on, 1)
    unknown = 0
    for tr in result.action:
        if not tr.vuln.severity_known:
            # pip-audit and uv audit give no severity: a placeholder must not
            # let a critical advisory through a "high" gate.
            unknown += 1
            continue
        rank = _SEVERITY_RANK.get(tr.vuln.severity.value, 0)
        if rank >= threshold:
            return True
    if unknown:
        print(
            f"depquiet: --fail-on {fail_on}: {unknown} ACTION alert(s) come without a "
            "severity from the scanner (pip-audit and uv audit report none), so they "
            "count as meeting the threshold.",
            file=sys.stderr,
        )
        return True
    return False


def _print_json(
    result: ScanResult,
    *,
    license_report: LicenseReport | None = None,
    fix_plan: FixPlan | None = None,
) -> None:
    """Print machine-readable JSON output."""
    results_list: list[dict[str, Any]] = []
    out: dict[str, Any] = {
        "project": result.project_path,
        "project_id": result.project_id,
        "package_manager": result.package_manager,
        "total_dependencies": result.total_dependencies,
        "scanned": result.scanned,
        "note": result.note,
        "summary": {
            "total": len(result.results),
            "action": len(result.action),
            "review": len(result.review),
            "filtered": len(result.filtered),
            "filter_rate": round(result.filter_rate, 1),
        },
        "results": results_list,
    }
    for tr in result.results:
        entry: dict[str, Any] = {
            # Only in a report that merges ecosystems ("npm+pip"): who reported it.
            **({"package_manager": tr.vuln.package_manager} if tr.vuln.package_manager else {}),
            "cve": tr.vuln.cve,
            "package": tr.vuln.package,
            "version": tr.vuln.version,
            "version_kind": tr.vuln.version_kind,
            "advisory_range": tr.vuln.advisory_range,
            "components": [component.to_dict() for component in tr.vuln.components],
            "component_notes": list(tr.vuln.component_notes),
            "component_resolution_complete": tr.vuln.component_resolution_complete,
            "severity": tr.vuln.severity_label,
            **({} if tr.vuln.severity_known else {"severity_known": False}),
            **({"aliases": tr.vuln.aliases} if tr.vuln.aliases else {}),
            "title": tr.vuln.title,
            "url": tr.vuln.url,
            "verdict": tr.verdict.value,
            "reasons": [r.value for r in tr.reasons],
            "epss_score": tr.epss_score,
            "epss_percentile": tr.epss_percentile,
            "is_dev": tr.vuln.is_dev,
            "is_direct": tr.vuln.is_direct,
            "fix_version": tr.vuln.fix_version,
            "fix_package": tr.vuln.fix_package,
            "reachable_imports": tr.reachable_imports,
            "dependency_type": tr.dependency_type,
            "introduced_by": tr.introduced_by,
            "template_id": tr.template_id,
            "template_reason": tr.template_reason,
            "assessment": assess_finding(tr).to_dict(),
            "evidence": asdict(tr.evidence),
            "decision_trace": decision_trace_to_json(tr),
            **({"fix_check": tr.fix_check.to_dict()} if tr.fix_check is not None else {}),
        }
        if tr.kev_entry is not None:
            entry["kev"] = {
                "vendor": tr.kev_entry.vendor,
                "product": tr.kev_entry.product,
                "name": tr.kev_entry.name,
                "description": tr.kev_entry.description,
                "date_added": tr.kev_entry.date_added,
                "due_date": tr.kev_entry.due_date,
                "required_action": tr.kev_entry.required_action,
                "ransomware_use": tr.kev_entry.ransomware_use,
            }
        results_list.append(entry)

    if license_report is not None:
        out["license"] = _license_json(license_report)
    if fix_plan is not None:
        out["fix_plan"] = fix_plan.to_dict()

    json.dump(out, sys.stdout, indent=2)
    print()  # trailing newline


def _license_json(report: LicenseReport) -> dict[str, Any]:
    """Build the license section of a machine-readable scan report."""
    return {
        "project": report.project_path,
        "package_manager": report.package_manager,
        "total": len(report.packages),
        "summary": {
            "low": len(report.low),
            "medium": len(report.medium),
            "high": len(report.high),
            "critical": len(report.critical),
            "unknown": len(report.unknown),
        },
        "issues": [
            {
                "package": p.package,
                "version": p.version,
                "license": p.license_id,
                "license_raw": p.license_raw,
                "risk": p.risk.value,
            }
            for p in report.packages
            if p.risk.value in ("high", "critical", "unknown")
        ],
    }
