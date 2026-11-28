"""Fixes from an outside-user audit of 0.46.0: each test pins one finding."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

from depquiet.cli import main
from depquiet.filters.epss import EpssFilter
from depquiet.fixplan import NOTHING_TO_FIX, UNSUPPORTED_NOTE, build_fix_plan
from depquiet.models import (
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
    strip_control,
)
from depquiet.output import print_scan_result
from depquiet.poetryplan import build_poetry_plan

ROOT = Path(__file__).resolve().parent.parent

AUDIT = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.31.0",
            "vulns": [
                {
                    "id": "PYSEC-2026-1",
                    "fix_versions": ["2.32.0"],
                    "aliases": ["CVE-2026-0001"],
                    "description": "One advisory",
                }
            ],
        }
    ]
}

# A scan of piped pip-audit output; the project path follows.
SCAN = ["--stdin", "--offline", "--scanner", "pip", "--path"]


def _stdin(monkeypatch, data=AUDIT) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(data)))


def _result(*vulns: Vulnerability) -> ScanResult:
    return ScanResult(
        project_path=".",
        package_manager="pip",
        total_dependencies=len({v.package for v in vulns}),
        results=[TriageResult(vuln=v, verdict=Verdict.ACTION) for v in vulns],
    )


def _vuln(package="requests", fix="2.32.0", **kw) -> Vulnerability:
    return Vulnerability("PYSEC-2026-1", package, "2.31.0", Severity.HIGH, fix_version=fix, **kw)


# 1. EPSS: a failed lookup is counted and reported, never silent.


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _answer(monkeypatch, body: object) -> None:
    def fake(req, timeout=10):
        if isinstance(body, Exception):
            raise body
        return _Response(json.dumps(body).encode())

    monkeypatch.setattr("depquiet.filters.epss.urllib.request.urlopen", fake)


def test_epss_network_failure_is_counted(monkeypatch) -> None:
    import urllib.error

    _answer(monkeypatch, urllib.error.URLError("down"))
    epss = EpssFilter()
    assert epss.lookup(["CVE-2026-0001", "CVE-2026-0002"]) == {}
    assert epss.failed == 2


@pytest.mark.parametrize(
    "body",
    [[], {"data": "x"}, {"data": None}, "text", {"nodata": []}],
)
def test_epss_unreadable_answer_is_counted_not_a_crash(monkeypatch, body) -> None:
    _answer(monkeypatch, body)
    epss = EpssFilter()
    assert epss.lookup(["CVE-2026-0001"]) == {}
    assert epss.failed == 1


def test_epss_skips_bad_entries_and_keeps_good_ones(monkeypatch) -> None:
    _answer(
        monkeypatch,
        {
            "data": [
                "junk",
                {"cve": "CVE-2026-0002", "epss": "abc"},
                {"cve": "CVE-2026-0003", "epss": [1]},
                {"cve": "CVE-2026-0004", "epss": "7"},  # not a probability
                {"cve": "CVE-2026-0001", "epss": "0.5", "percentile": "0.9"},
            ]
        },
    )
    epss = EpssFilter()
    assert epss.lookup(["CVE-2026-0001", "CVE-2026-0002"]) == {"CVE-2026-0001": (0.5, 0.9)}
    assert epss.failed == 0


def test_cli_warns_when_epss_is_unavailable(tmp_path, monkeypatch, capsys) -> None:
    import urllib.error

    monkeypatch.setattr("depquiet.engine.resolve_cve_aliases", lambda vulns: 0)
    _answer(monkeypatch, urllib.error.URLError("down"))
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    _stdin(monkeypatch)
    assert main(["--path", str(tmp_path), "--stdin", "--scanner", "pip"]) == 1
    err = capsys.readouterr().err
    assert "EPSS unavailable for 1 CVE " in err
    assert "not ordered by their EPSS score" in err


def test_offline_scan_has_no_epss_warning(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    _stdin(monkeypatch)
    main(["--path", str(tmp_path), "--stdin", "--offline", "--scanner", "pip"])
    assert "EPSS unavailable" not in capsys.readouterr().err


# 3. README quotes what Dependabot shows, not an internal error id.


def test_readme_quotes_dependabots_visible_message() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "update_not_possible" not in readme
    assert "non-vulnerable version" in readme


# 4. The Action installs the tools it runs at pinned versions.


@pytest.mark.parametrize("tool", ["pip-audit", "uv", "poetry"])
def test_action_pins_every_tool_it_installs(tool) -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    installs = re.findall(r"pip install --disable-pip-version-check (\S+)", action)
    assert any(re.fullmatch(rf"{tool}==\d+(\.\d+)+", spec) for spec in installs), installs
    assert tool not in installs  # never the floating latest


# 5 and 8. Flags and paths that cannot work fail before any scan runs.


@pytest.fixture
def no_scan(monkeypatch):
    def boom(**kwargs):
        raise AssertionError("scan must not run")

    monkeypatch.setattr("depquiet.cli.scan", boom)


@pytest.mark.parametrize("flag", [["--apply"], ["--fix-plan-report", "r.md"]])
def test_flag_without_fix_plan_fails_before_scanning(tmp_path, capsys, no_scan, flag) -> None:
    assert main(["--path", str(tmp_path), *flag]) == 2
    assert f"{flag[0]} needs --fix-plan" in capsys.readouterr().err


def test_missing_path_says_so(tmp_path, capsys, no_scan) -> None:
    missing = tmp_path / "nope"
    assert main(["--path", str(missing)]) == 2
    err = capsys.readouterr().err
    assert "no such directory" in err and "nope" in err


# 6 and 7. Fix plan messages: nothing to fix is not a failure; Poetry and npm
# are named when the lockfile is not uv's.


def test_fix_plan_with_nothing_to_fix_says_so(tmp_path) -> None:
    (tmp_path / "uv.lock").write_text("version = 1\n")
    plan = build_fix_plan(_result(), tmp_path, {})
    assert plan.status == "none" and plan.note == NOTHING_TO_FIX
    assert "No fix could be planned" not in plan.note


def test_poetry_plan_with_nothing_to_fix_says_so_without_poetry(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("depquiet.poetryplan.shutil.which", lambda name: None)
    plan = build_poetry_plan(_result(), tmp_path)
    assert plan.note == NOTHING_TO_FIX


def test_fix_plan_on_a_project_without_uv_lock_names_poetry_and_npm(tmp_path) -> None:
    plan = build_fix_plan(_result(_vuln()), tmp_path, {})
    assert plan.status == "unsupported" and plan.note == UNSUPPORTED_NOTE
    assert "Poetry" in plan.note and "--fix" in plan.note


def test_npm_alerts_never_read_as_nothing_to_fix(tmp_path) -> None:
    (tmp_path / "package-lock.json").write_text("{}")
    npm = _vuln("lodash", "4.18.1", package_manager="npm")
    plan = build_fix_plan(_result(npm), tmp_path, {})
    assert plan.status == "unsupported" and plan.note == UNSUPPORTED_NOTE


def test_cli_fix_plan_on_requirements_names_poetry(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    monkeypatch.setattr("depquiet.engine.resolve_cve_aliases", lambda vulns: 0)
    monkeypatch.setattr("depquiet.filters.epss.EpssFilter.lookup", lambda self, cves: {})
    _stdin(monkeypatch)
    main(["--path", str(tmp_path), "--stdin", "--scanner", "pip", "--fix-plan"])
    err = capsys.readouterr().err
    assert (
        "--fix-plan works on projects with a uv.lock, a poetry.lock or a package-lock.json" in err
    )
    assert "--fix installs the fixes" not in err
    assert "--fix-plan works on projects with a uv.lock." not in err


# 9. Escape sequences in scanner text never reach the terminal.


def test_control_characters_are_stripped_from_scanner_text() -> None:
    v = Vulnerability(
        "GHSA-\x1b[31mx",
        "pkg\x07",
        "1.0",
        Severity.LOW,
        title="safe\x1b]0;pwned\x07 text\x1b[2J\x9b\nnext\tline",
        aliases=["CVE-1\x1b"],
    )
    assert v.cve == "GHSA-[31mx" and v.package == "pkg" and v.aliases == ["CVE-1"]
    assert v.title == "safe]0;pwned text[2J\nnext\tline"
    assert strip_control("a\x00b\x7fc") == "abc"


def test_crafted_report_prints_no_escape_byte(tmp_path, monkeypatch, capsys) -> None:
    data = json.loads(json.dumps(AUDIT))
    data["dependencies"][0]["vulns"][0]["description"] = "x\x1b[2J\x1b]0;t\x07 y"
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    _stdin(monkeypatch, data)
    main(["--path", str(tmp_path), "--stdin", "--offline", "--scanner", "pip"])
    out = capsys.readouterr()
    assert "\x1b]" not in out.out and "\x07" not in out.out and "\x1b[2J" not in out.out


# 10. is_direct in JSON comes from the graph, never from a scanner placeholder.


def _json_results(tmp_path, monkeypatch, capsys) -> list[dict]:
    _stdin(monkeypatch)
    main(["--path", str(tmp_path), "--stdin", "--offline", "--scanner", "pip", "--json"])
    return json.loads(capsys.readouterr().out)["results"]


def test_is_direct_is_null_when_no_file_says(tmp_path, monkeypatch, capsys) -> None:
    # A fully pinned requirements.txt may be pip freeze output: no direct deps known.
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    [row] = _json_results(tmp_path, monkeypatch, capsys)
    assert row["dependency_type"] == "unknown"
    assert row["is_direct"] is None


def test_is_direct_follows_the_dependency_graph(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["requests"]\n'
    )
    [row] = _json_results(tmp_path, monkeypatch, capsys)
    assert row["dependency_type"] == "direct"
    assert row["is_direct"] is True


def test_npm_keeps_the_scanners_own_direct_flag() -> None:
    from depquiet.cli import _is_direct

    tr = TriageResult(vuln=_vuln(is_direct=False), verdict=Verdict.ACTION)
    tr.dependency_type = "unknown"
    assert _is_direct(tr, "npm") is False
    assert _is_direct(tr, "pip") is None


def test_explain_reads_a_null_is_direct() -> None:
    from depquiet import explain

    source = Path(explain.__file__).read_text(encoding="utf-8")
    assert 'entry.get("is_direct") is not False' in source


# 12. Counts agree in number.


def test_counts_agree_in_number(capsys) -> None:
    print_scan_result(_result(_vuln()))
    out = capsys.readouterr().out
    assert "(1 vulnerable package)" in out
    assert "ACTION REQUIRED: 1 alert\x1b" in out or "ACTION REQUIRED: 1 alert\n" in out
    assert "Total: 1 alert —" in out
    assert "1 alerts" not in out and "1 vulnerable packages" not in out


def test_plural_counts_keep_the_plural(capsys) -> None:
    print_scan_result(_result(_vuln(), _vuln("urllib3", "2.0")))
    out = capsys.readouterr().out
    assert "(2 vulnerable packages)" in out and "Total: 2 alerts —" in out


# 13. Notes about the scan come after the report's header.


def _combined(monkeypatch) -> io.StringIO:
    both = io.StringIO()
    monkeypatch.setattr("sys.stdout", both)
    monkeypatch.setattr("sys.stderr", both)
    return both


def test_kev_warning_prints_after_the_report(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("depquiet.kev._DEFAULT_CACHE_DIR", tmp_path / "cache")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    _stdin(monkeypatch)
    both = _combined(monkeypatch)
    main(["--path", str(tmp_path), "--stdin", "--offline", "--scanner", "pip", "--kev"])
    text = both.getvalue()
    assert text.index("scan —") < text.index("KEV catalog unavailable")


def test_kev_notice_prints_after_the_report(tmp_path, monkeypatch) -> None:
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}))
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    _stdin(monkeypatch)
    both = _combined(monkeypatch)
    main([*SCAN, str(tmp_path), "--kev-file", str(kev)])
    text = both.getvalue()
    assert text.index("scan —") < text.index("KEV: 1 of 1")


def test_json_output_stays_one_document_with_kev(tmp_path, monkeypatch, capsys) -> None:
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}))
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    _stdin(monkeypatch)
    main([*SCAN, str(tmp_path), "--json", "--kev-file", str(kev)])
    json.loads(capsys.readouterr().out)  # no notice mixed into stdout


# 14. A scanner error and the next sentence are separated.


def test_scanner_error_sentences_do_not_run_together() -> None:
    from depquiet.engine import _sentence

    assert _sentence("pip-audit: bad (at line 1, column 6)") == (
        "pip-audit: bad (at line 1, column 6)."
    )
    assert _sentence("done.") == "done."
    assert _sentence("done.  ") == "done."


# 15. Python 3.14 is tested and declared.


def test_python_314_is_tested_and_declared() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert '"3.14"' in ci
    assert "Programming Language :: Python :: 3.14" in (ROOT / "pyproject.toml").read_text(
        encoding="utf-8"
    )


# Cut lists and texts say so: a table row with 6 of 7 advisories read as all of them.


def test_pr_table_says_how_many_advisories_it_leaves_out() -> None:
    from depquiet.fixplan import _id_list

    ids = [f"PYSEC-2026-{i}" for i in range(7)]
    assert _id_list(ids) == ", ".join(ids[:6]) + " and 1 more"
    assert _id_list(ids[:6]) == ", ".join(ids[:6])
    assert _id_list([]) == "-"


def test_clip_marks_a_cut() -> None:
    from depquiet.models import clip

    assert clip("short", 10) == "short"
    cut = clip("word " * 20, 12)
    assert cut.endswith("…") and len(cut) <= 12


def test_report_says_how_many_parents_and_imports_are_not_listed(capsys) -> None:
    tr = TriageResult(vuln=_vuln("urllib3", "2.0"), verdict=Verdict.ACTION)
    tr.dependency_type = "transitive"
    tr.introduced_by = ["a", "b", "c", "d", "e"]
    tr.reachable_imports = [f"m{i}.py" for i in range(5)]
    result = _result()
    result.results = [tr]
    print_scan_result(result)
    out = capsys.readouterr().out
    assert "via a, b, c and 2 more" in out
    assert "and 2 more (depquiet explain shows all)" in out
